use super::WranglerResult;
use anyhow::{Context, Result, bail};
use base64::Engine;
use crypto_box::aead::Aead;
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Debug, Serialize, Deserialize)]
pub struct WranglerRequestPayload {
    pub public_key: String,
    pub access_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WranglerResponsePayload {
    pub client_ip: String,
    pub dns: String,
    pub wg_port: u16,
}

/// Packs `nonce[24] || pubkey[32] || be16(len(ciphertext)) || crypto_box_easy(plaintext)`
/// matching `hma-proxy/internal/hma/wrangler.go`.
pub fn pack_wrangler_packet(
    client_secret: &SecretKey,
    server_public: &PublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let salsa = SalsaBox::new(server_public, client_secret);
    let ciphertext = salsa
        .encrypt((&nonce_bytes).into(), plaintext)
        .map_err(|_| anyhow::anyhow!("crypto_box_easy encryption failed"))?;
    let ct_len = u16::try_from(ciphertext.len()).context("wrangler ciphertext exceeds u16")?;

    let mut packet = Vec::with_capacity(24 + 32 + 2 + ciphertext.len());
    packet.extend_from_slice(&nonce_bytes);
    packet.extend_from_slice(client_secret.public_key().as_bytes());
    packet.extend_from_slice(&ct_len.to_be_bytes());
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

/// Unpacks `nonce[24] || pubkey[32] || be16(len(ciphertext)) || crypto_box_easy(plaintext)`.
pub fn unpack_wrangler_packet(
    recipient_secret: &SecretKey,
    packet: &[u8],
) -> Result<(PublicKey, Vec<u8>)> {
    if packet.len() < 24 + 32 + 2 {
        bail!("wrangler packet too short ({} bytes)", packet.len());
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&packet[0..24]);
    let mut sender_pub_bytes = [0u8; 32];
    sender_pub_bytes.copy_from_slice(&packet[24..56]);
    let ct_len = u16::from_be_bytes([packet[56], packet[57]]) as usize;
    if packet.len() < 58 + ct_len {
        bail!("wrangler packet truncated");
    }
    let sender_pub = PublicKey::from(sender_pub_bytes);
    let salsa = SalsaBox::new(&sender_pub, recipient_secret);
    let plaintext = salsa
        .decrypt((&nonce).into(), &packet[58..58 + ct_len])
        .map_err(|_| anyhow::anyhow!("crypto_box_easy decryption failed"))?;
    Ok((sender_pub, plaintext))
}

/// Performs UDP Wrangler registration with `3 attempts x 3s` timeout.
pub async fn wrangler_register(
    server_addr: SocketAddr,
    server_pub_b64: &str,
    access_token: &str,
) -> Result<WranglerResult> {
    let server_pub_raw = base64::engine::general_purpose::STANDARD
        .decode(server_pub_b64.trim())
        .context("invalid base64 server WireGuard public key")?;
    let server_pub_bytes: [u8; 32] = server_pub_raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("server public key must be 32 bytes"))?;
    let server_pub = PublicKey::from(server_pub_bytes);

    let mut priv_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut priv_bytes);
    let client_secret = SecretKey::from(priv_bytes);
    let client_pub_b64 =
        base64::engine::general_purpose::STANDARD.encode(client_secret.public_key().as_bytes());

    let req_payload = serde_json::to_vec(&WranglerRequestPayload {
        public_key: client_pub_b64,
        access_token: access_token.to_string(),
    })?;
    let packet = pack_wrangler_packet(&client_secret, &server_pub, &req_payload)?;

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(server_addr).await?;

    let mut buf = vec![0u8; 2048];
    let mut last_err = None;
    for _attempt in 0..3 {
        sock.send(&packet).await?;
        match tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let (_sender, plain) = unpack_wrangler_packet(&client_secret, &buf[..n])?;
                let parsed: WranglerResponsePayload = serde_json::from_slice(&plain)
                    .context("invalid decrypted wrangler JSON response")?;
                let client_ip: Ipv4Addr = parsed
                    .client_ip
                    .split('/')
                    .next()
                    .unwrap_or(&parsed.client_ip)
                    .parse()
                    .context("invalid client_ip")?;
                let dns: Ipv4Addr = parsed.dns.parse().context("invalid dns ip")?;
                let server_ip = match server_addr.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    std::net::IpAddr::V6(_) => bail!("HMA Wrangler expects IPv4 server"),
                };
                return Ok(WranglerResult {
                    server_ip,
                    server_public_key: server_pub_bytes,
                    client_private_key: priv_bytes,
                    client_ip,
                    dns,
                    wg_port: parsed.wg_port,
                });
            }
            Ok(Err(e)) => last_err = Some(anyhow::Error::from(e)),
            Err(_) => last_err = Some(anyhow::anyhow!("wrangler UDP timeout (3s)")),
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("wrangler registration failed")))
}
