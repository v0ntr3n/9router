use base64::Engine;
use crypto_box::SecretKey;
use ninerouter_rs::hma::bridge::LoopbackBridge;
use ninerouter_rs::hma::manager::HmaManager;
use ninerouter_rs::hma::wrangler::{
    WranglerResponsePayload, pack_wrangler_packet, unpack_wrangler_packet, wrangler_register,
};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[tokio::test]
async fn wrangler_udp_roundtrip_matches_wire_layout() {
    let mut srv_priv = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut srv_priv);
    let srv_secret = SecretKey::from(srv_priv);
    let srv_pub_b64 =
        base64::engine::general_purpose::STANDARD.encode(srv_secret.public_key().as_bytes());

    let mock_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_udp.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let (n, peer) = mock_udp.recv_from(&mut buf).await.unwrap();
        let (client_pub, plain) = unpack_wrangler_packet(&srv_secret, &buf[..n]).unwrap();
        let req_val: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(req_val["at"], "test-hma-token");
        assert_eq!(req_val["ac"], 1);
        assert_eq!(req_val["cores"], 1);

        let resp_json = serde_json::to_vec(&WranglerResponsePayload {
            sc: 200,
            st: "OK".to_string(),
            ctip: "10.200.0.2/32".to_string(),
            cdns: "10.200.0.1".to_string(),
            wgps: vec![51820],
        })
        .unwrap();
        let resp_pkt = pack_wrangler_packet(&srv_secret, &client_pub, &resp_json).unwrap();
        mock_udp.send_to(&resp_pkt, peer).await.unwrap();
    });

    let res = wrangler_register(mock_addr, &srv_pub_b64, "test-hma-token")
        .await
        .unwrap();
    server_task.await.unwrap();
    assert_eq!(res.client_ip.to_string(), "10.200.0.2");
    assert_eq!(res.dns.to_string(), "10.200.0.1");
    assert_eq!(res.wg_port, 51820);
}

#[tokio::test]
async fn loopback_bridge_rejects_unauthenticated_connect_and_socks5() {
    let bridge = LoopbackBridge::start(None).await.unwrap();

    // HTTP CONNECT without Proxy-Authorization -> 407
    let mut s = TcpStream::connect(bridge.addr()).await.unwrap();
    s.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut resp = vec![0u8; 256];
    let n = s.read(&mut resp).await.unwrap();
    assert!(String::from_utf8_lossy(&resp[..n]).contains("407"));

    // SOCKS5 offering only no-auth (0x00) -> rejected (0xFF)
    let mut s2 = TcpStream::connect(bridge.addr()).await.unwrap();
    s2.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = [0u8; 2];
    s2.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0xFF]);

    bridge.shutdown();
}

#[test]
fn hma_manager_enforces_rotation_cooldown() {
    let mgr = HmaManager::new(30).unwrap();
    assert!(mgr.can_rotate_now());
    mgr.record_rotation_attempt();
    assert!(!mgr.can_rotate_now());
}
