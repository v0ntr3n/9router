use super::{WranglerResult, deserialize_port_list};
use anyhow::{Context, Result, bail};
use base64::Engine;
use crypto_box::aead::Aead;
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Verified HMA Wrangler request JSON matching `hma-proxy/internal/hma/wrangler.go`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WranglerRequestPayload {
    pub at: String,
    pub ac: u8,
    pub cores: u8,
}

/// Verified HMA Wrangler response JSON matching `hma-proxy/internal/hma/wrangler.go`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WranglerResponsePayload {
    pub sc: u16,
    #[serde(default)]
    pub st: String,
    #[serde(default)]
    pub ctip: String,
    #[serde(default)]
    pub cdns: String,
    #[serde(default, deserialize_with = "deserialize_port_list")]
    pub wgps: Vec<u16>,
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
    // Standard WireGuard / Curve25519 key clamping
    priv_bytes[0] &= 248;
    priv_bytes[31] &= 127;
    priv_bytes[31] |= 64;
    let client_secret = SecretKey::from(priv_bytes);

    let req_payload = serde_json::to_vec(&WranglerRequestPayload {
        at: access_token.to_string(),
        ac: 1,
        cores: 1,
    })?;
    let packet = pack_wrangler_packet(&client_secret, &server_pub, &req_payload)?;

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(server_addr).await?;

    let mut buf = vec![0u8; 4096];
    let mut last_err = None;
    for _attempt in 0..3 {
        sock.send(&packet).await?;
        match tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let (_sender, plain) = unpack_wrangler_packet(&client_secret, &buf[..n])?;
                let parsed: WranglerResponsePayload = serde_json::from_slice(&plain)
                    .context("invalid decrypted wrangler JSON response")?;
                if !(200..300).contains(&parsed.sc) {
                    bail!(
                        "wrangler rejected request (sc={}): {}",
                        parsed.sc,
                        parsed.st
                    );
                }
                let wg_port = *parsed
                    .wgps
                    .first()
                    .context("wrangler response missing wgps port")?;
                let client_ip: Ipv4Addr = parsed
                    .ctip
                    .split('/')
                    .next()
                    .unwrap_or(&parsed.ctip)
                    .parse()
                    .context("invalid ctip client IP")?;
                let dns: Ipv4Addr = if parsed.cdns.trim().is_empty() {
                    Ipv4Addr::new(10, 0, 0, 1)
                } else {
                    parsed
                        .cdns
                        .split(',')
                        .next()
                        .unwrap_or(&parsed.cdns)
                        .trim()
                        .parse()
                        .context("invalid cdns DNS IP")?
                };
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
                    wg_port,
                });
            }
            Ok(Err(e)) => last_err = Some(anyhow::Error::from(e)),
            Err(_) => last_err = Some(anyhow::anyhow!("wrangler UDP timeout (3s)")),
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("wrangler registration failed")))
}
