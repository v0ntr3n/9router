use super::tunnel::WireGuardNetstack;
use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// In-process `127.0.0.1:<ephemeral-port>` HTTP CONNECT + SOCKS5 loopback proxy bridge
/// guarded by per-launch random credentials.
pub struct LoopbackBridge {
    addr: SocketAddr,
    username: String,
    password: String,
    shutdown: Arc<Notify>,
}

impl LoopbackBridge {
    pub async fn start(netstack: Option<Arc<WireGuardNetstack>>) -> Result<Self> {
        let mut user_bytes = [0u8; 8];
        let mut pass_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut user_bytes);
        rand::thread_rng().fill_bytes(&mut pass_bytes);
        let username = hex::encode(user_bytes);
        let password = hex::encode(pass_bytes);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("failed to bind loopback proxy bridge on 127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(Notify::new());

        let u = username.clone();
        let p = password.clone();
        let shut = Arc::clone(&shutdown);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shut.notified() => break,
                    accept = listener.accept() => {
                        if let Ok((stream, _)) = accept {
                            let u = u.clone();
                            let p = p.clone();
                            let ns = netstack.clone();
                            tokio::spawn(async move {
                                let _ = handle_client(stream, &u, &p, ns).await;
                            });
                        }
                    }
                }
            }
        });

        Ok(Self {
            addr,
            username,
            password,
            shutdown,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn http_proxy_url(&self) -> String {
        format!("http://{}:{}@{}", self.username, self.password, self.addr)
    }

    pub fn socks5_proxy_url(&self) -> String {
        format!("socks5://{}:{}@{}", self.username, self.password, self.addr)
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}

async fn handle_client(
    client: TcpStream,
    expected_user: &str,
    expected_pass: &str,
    netstack: Option<Arc<WireGuardNetstack>>,
) -> Result<()> {
    let mut first = [0u8; 1];
    client.peek(&mut first).await?;
    if first[0] == 0x05 {
        handle_socks5(client, expected_user, expected_pass, netstack).await
    } else {
        handle_http_connect(client, expected_user, expected_pass, netstack).await
    }
}

async fn handle_http_connect(
    mut client: TcpStream,
    expected_user: &str,
    expected_pass: &str,
    netstack: Option<Arc<WireGuardNetstack>>,
) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let req_text = String::from_utf8_lossy(&buf[..n]);
    let mut lines = req_text.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            .await?;
        return Ok(());
    }

    let expected_b64 = base64::engine::general_purpose::STANDARD
        .encode(format!("{expected_user}:{expected_pass}"));
    let expected_header = format!("basic {expected_b64}");
    let auth_ok = lines.any(|line| {
        if let Some((k, v)) = line.split_once(':') {
            k.trim().eq_ignore_ascii_case("proxy-authorization")
                && v.trim().eq_ignore_ascii_case(&expected_header)
        } else {
            false
        }
    });

    if !auth_ok {
        client
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"9router-rs\"\r\n\r\n")
            .await?;
        return Ok(());
    }

    let (host, port_str) = parts[1]
        .rsplit_once(':')
        .context("invalid CONNECT host:port")?;
    let port: u16 = port_str.parse().context("invalid CONNECT port")?;

    let (mut upstream, _slot_guard) = match netstack {
        Some(ref ns) => {
            let (s, g) = ns.dial_tcp(host, port).await?;
            (s, Some(g))
        }
        None => (TcpStream::connect((host, port)).await?, None),
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

async fn handle_socks5(
    mut client: TcpStream,
    expected_user: &str,
    expected_pass: &str,
    netstack: Option<Arc<WireGuardNetstack>>,
) -> Result<()> {
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        bail!("invalid SOCKS5 version");
    }
    let mut methods = vec![0u8; header[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0x02) {
        client.write_all(&[0x05, 0xFF]).await?;
        return Ok(());
    }
    // Require RFC 1929 username/password auth (method 0x02)
    client.write_all(&[0x05, 0x02]).await?;

    let mut auth_hdr = [0u8; 2];
    client.read_exact(&mut auth_hdr).await?;
    if auth_hdr[0] != 0x01 {
        client.write_all(&[0x01, 0x01]).await?;
        return Ok(());
    }
    let mut user_buf = vec![0u8; auth_hdr[1] as usize];
    client.read_exact(&mut user_buf).await?;
    let mut plen = [0u8; 1];
    client.read_exact(&mut plen).await?;
    let mut pass_buf = vec![0u8; plen[0] as usize];
    client.read_exact(&mut pass_buf).await?;

    if user_buf != expected_user.as_bytes() || pass_buf != expected_pass.as_bytes() {
        client.write_all(&[0x01, 0x01]).await?;
        return Ok(());
    }
    client.write_all(&[0x01, 0x00]).await?;

    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }

    let host = match req[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            let mut dlen = [0u8; 1];
            client.read_exact(&mut dlen).await?;
            let mut domain = vec![0u8; dlen[0] as usize];
            client.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        _ => {
            client
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };
    let mut pbuf = [0u8; 2];
    client.read_exact(&mut pbuf).await?;
    let port = u16::from_be_bytes(pbuf);

    let (mut upstream, _slot_guard) = match netstack {
        Some(ref ns) => {
            let (s, g) = ns.dial_tcp(&host, port).await?;
            (s, Some(g))
        }
        None => (TcpStream::connect((host.as_str(), port)).await?, None),
    };

    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}
