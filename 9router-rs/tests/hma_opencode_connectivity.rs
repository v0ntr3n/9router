//! Offline proxy regression plus opt-in live HMA/OpenCode connectivity check.
//! Run the ignored test only with authorized HMA credentials.

use ninerouter_rs::config::load_opencode_profile;
use ninerouter_rs::hma::TunnelState;
use ninerouter_rs::hma::client::HmaClient;
use ninerouter_rs::hma::manager::{EXIT_IP_PROBE_URL, HmaManager};
use ninerouter_rs::providers::ProviderErrorKind;
use ninerouter_rs::providers::opencode::OpenCodeAdapter;
use ninerouter_rs::translator::ir::WireFormat;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[tokio::test]
async fn opencode_adapter_uses_explicit_proxy_without_direct_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let adapter = OpenCodeAdapter::new(load_opencode_profile(dir.path()).unwrap());

    // The proxy observes CONNECT but never opens an upstream connection.
    // This test requires neither an HMA account nor an OpenCode API call.
    let mock = async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 8192, "oversized CONNECT header");
            header.push(socket.read_u8().await.unwrap());
        }
        let header = String::from_utf8(header).unwrap();
        assert!(
            header.starts_with("CONNECT opencode.ai:443 HTTP/1."),
            "unexpected proxy destination or method"
        );
        socket
            .write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
    };
    let request = adapter.send(
        WireFormat::OpenAiChat,
        json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "connectivity test"}],
            "stream": true
        }),
        "offline-proxy-test",
        Some(&proxy),
    );
    let joined = async { tokio::join!(mock, request) };
    let ((), result) = timeout(Duration::from_secs(15), joined)
        .await
        .expect("proxy regression timed out");

    match result {
        Err(error) => assert_eq!(error.kind, ProviderErrorKind::TunnelError),
        Ok(_) => panic!("failed CONNECT must not return an upstream response"),
    }
}

async fn resolve_hma_token(manager: &HmaManager) -> Result<String, String> {
    if let Ok(token) = std::env::var("HMA_ACCESS_TOKEN")
        && !token.trim().is_empty()
    {
        return Ok(token.trim().to_string());
    }
    let activation = std::env::var("HMA_ACTIVATION_CODE")
        .or_else(|_| std::env::var("HMA_WALLET_KEY"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "set HMA_ACCESS_TOKEN or HMA_ACTIVATION_CODE".to_string())?;
    let license = manager
        .client()
        .lookup_license(&activation)
        .await
        .map_err(|_| "HMA license lookup failed".to_string())?;
    let fingerprint = HmaClient::generate_device_fingerprint();
    let reg = manager
        .client()
        .associate_license(&activation, &license.container_id, &fingerprint)
        .await
        .map_err(|_| "HMA license association failed".to_string())?;
    Ok(reg.access_token)
}

async fn probe_direct_ip() -> Option<IpAddr> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(8))
        .build()
        .ok()?;
    let resp = client.get(EXIT_IP_PROBE_URL).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().await.ok()?.trim().parse::<IpAddr>().ok()
}

#[tokio::test]
#[ignore = "requires live HMA credentials and external network access"]
async fn live_hma_reaches_opencode_models() {
    let country = std::env::var("HMA_COUNTRY").expect("set HMA_COUNTRY");
    let key = std::env::var("OPENCODE_API_KEY").ok();
    let manager = HmaManager::new(30).expect("create HMA manager");

    // One tunnel, one location, one API request. No rotation or retry on
    // authentication errors, rate limits or other upstream rejection.
    let result = timeout(Duration::from_secs(90), async {
        let direct_ip = probe_direct_ip().await;
        let token = resolve_hma_token(&manager).await?;
        let initial = manager
            .start_or_switch(&token, &country, None)
            .await
            .map_err(|_| "HMA tunnel setup failed".to_string())?;
        if initial.state != TunnelState::Connected {
            return Err("HMA tunnel did not connect".to_string());
        }
        let expected_ip = initial
            .exit_ip
            .as_deref()
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .ok_or("HMA did not report a valid exit IP")?;
        if let Some(host_ip) = direct_ip
            && expected_ip == host_ip
        {
            return Err("HMA exit IP matched direct host IP; tunnel was bypassed".to_string());
        }
        let observed_ip = manager
            .check_active_exit_ip()
            .await
            .map_err(|_| "HMA exit IP probe failed")?
            .parse::<IpAddr>()
            .map_err(|_| "HMA exit IP probe returned invalid IP")?;
        if observed_ip != expected_ip {
            return Err("HMA exit IP changed during the test".to_string());
        }

        let proxy_url = manager
            .active_proxy_url()
            .ok_or("HMA has no active proxy")?;
        let proxy = reqwest::Proxy::all(&proxy_url).map_err(|_| "invalid HMA proxy URL")?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .proxy(proxy)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| "could not build proxy-only HTTP client")?;
        let before = manager.metrics();
        let mut request = client.get("https://opencode.ai/zen/v1/models");
        if let Some(key) = key.as_deref() {
            request = request.bearer_auth(key);
        }
        let response = request
            .send()
            .await
            .map_err(|_| "OpenCode HTTPS transport through HMA failed")?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!(
                "OpenCode returned HTTP {status} through HMA; API success not verified"
            ));
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| "OpenCode returned invalid JSON")?;
        let model_count = body
            .get("data")
            .and_then(Value::as_array)
            .filter(|models| {
                !models.is_empty()
                    && models.iter().all(|m| {
                        m.get("id")
                            .and_then(Value::as_str)
                            .is_some_and(|id| !id.is_empty())
                    })
            })
            .map(Vec::len)
            .ok_or_else(|| "OpenCode returned no valid model entries".to_string())?;
        let after = manager.metrics();
        if after.tx_bytes <= before.tx_bytes || after.rx_bytes <= before.rx_bytes {
            return Err("HMA traffic counters did not advance in both directions".to_string());
        }
        println!(
            "OpenCode models API: HTTP {status} ({model_count} models); HMA exit IP {expected_ip}; TX +{} B, RX +{} B",
            after.tx_bytes - before.tx_bytes,
            after.rx_bytes - before.rx_bytes
        );
        Ok::<(), String>(())
    })
    .await;

    manager.stop().await;
    result
        .expect("live connectivity check timed out")
        .expect("live connectivity check failed");
}
