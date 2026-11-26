//! Offline proxy regression plus opt-in live HMA/OpenCode connectivity check.
//! Run the ignored test only with authorized HMA credentials.

use ninerouter_rs::config::load_opencode_profile;
use ninerouter_rs::hma::TunnelState;
use ninerouter_rs::hma::manager::HmaManager;
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
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
    let ((), result) = timeout(Duration::from_secs(15), async {
        tokio::join!(mock, request)
    })
    .await
    .expect("proxy regression timed out");

    match result {
        Err(error) => assert_eq!(error.kind, ProviderErrorKind::TunnelError),
        Ok(_) => panic!("failed CONNECT must not return an upstream response"),
    }
}

#[tokio::test]
#[ignore = "requires live HMA credentials and external network access"]
async fn live_hma_reaches_opencode_models() {
    let token = std::env::var("HMA_ACCESS_TOKEN").expect("set HMA_ACCESS_TOKEN");
    let country = std::env::var("HMA_COUNTRY").expect("set HMA_COUNTRY");
    let key = std::env::var("OPENCODE_API_KEY").ok();
    let manager = HmaManager::new(30).expect("create HMA manager");

    // One tunnel, one location, one API request. No rotation or retry on
    // authentication errors, rate limits or other upstream rejection.
    let result = timeout(Duration::from_secs(90), async {
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
        if !body
            .get("data")
            .and_then(Value::as_array)
            .is_some_and(|models| {
                !models.is_empty()
                    && models.iter().all(|m| {
                        m.get("id")
                            .and_then(Value::as_str)
                            .is_some_and(|id| !id.is_empty())
                    })
            })
        {
            return Err("OpenCode returned no valid model entries".to_string());
        }
        let after = manager.metrics();
        if after.tx_bytes <= before.tx_bytes || after.rx_bytes <= before.rx_bytes {
            return Err("HMA traffic counters did not advance in both directions".to_string());
        }
        println!("OpenCode models API: HTTP {status}; HMA TX/RX increased");
        Ok::<(), String>(())
    })
    .await;

    manager.stop().await;
    result
        .expect("live connectivity check timed out")
        .expect("live connectivity check failed");
}
