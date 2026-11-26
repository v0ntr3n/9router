use super::{TunnelMetrics, TunnelState, WranglerResult};
use anyhow::{Context, Result, bail};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey as WgPublicKey, StaticSecret as WgStaticSecret};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Notify, mpsc};

pub const MAX_VIRTUAL_SOCKETS: usize = 64;
pub const SOCKET_BUF_BYTES: usize = 128 * 1024;
pub const WG_MTU: usize = 1420;
pub const IDLE_SOCKET_TIMEOUT_SECS: u64 = 60;

struct ChannelDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl ChannelDevice {
    fn new() -> Self {
        Self {
            rx_queue: VecDeque::with_capacity(256),
            tx_queue: VecDeque::with_capacity(256),
        }
    }
}

struct VecRxToken(Vec<u8>);
impl RxToken for VecRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct VecTxToken<'a>(&'a mut VecDeque<Vec<u8>>);
impl<'a> TxToken for VecTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        self.0.push_back(buf);
        res
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = VecRxToken;
    type TxToken<'a> = VecTxToken<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx_queue.pop_front()?;
        Some((VecRxToken(pkt), VecTxToken(&mut self.tx_queue)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VecTxToken(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = WG_MTU;
        caps
    }
}

/// Userspace WireGuard (`boringtun`) + bounded `smoltcp` IPv4 netstack running in a dedicated Tokio task.
pub struct WireGuardNetstack {
    server_ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
    tx_bytes: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
    dropped_packets: Arc<AtomicU64>,
    active_sockets: Arc<AtomicUsize>,
    dns_errors: Arc<AtomicU64>,
    last_handshake_epoch: Arc<AtomicU64>,
    shutdown: Arc<Notify>,
    _ctrl_tx: mpsc::Sender<()>,
}

impl WireGuardNetstack {
    pub async fn start(wr: WranglerResult) -> Result<Self> {
        let udp = UdpSocket::bind("0.0.0.0:0").await?;
        let endpoint = SocketAddr::new(IpAddr::V4(wr.server_ip), wr.wg_port);
        udp.connect(endpoint)
            .await
            .with_context(|| format!("failed to connect UDP socket to {endpoint}"))?;

        let private_key = WgStaticSecret::from(wr.client_private_key);
        let peer_pub = WgPublicKey::from(wr.server_public_key);
        let mut tunn = Tunn::new(private_key, peer_pub, None, Some(25), 0, None)
            .map_err(|e| anyhow::anyhow!("failed to initialize boringtun: {e}"))?;

        let tx_bytes = Arc::new(AtomicU64::new(0));
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let dropped_packets = Arc::new(AtomicU64::new(0));
        let active_sockets = Arc::new(AtomicUsize::new(0));
        let dns_errors = Arc::new(AtomicU64::new(0));
        let last_handshake_epoch = Arc::new(AtomicU64::new(0));
        let shutdown = Arc::new(Notify::new());
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<()>(64);

        let tx_c = Arc::clone(&tx_bytes);
        let rx_c = Arc::clone(&rx_bytes);
        let drop_c = Arc::clone(&dropped_packets);
        let hs_c = Arc::clone(&last_handshake_epoch);
        let shut_c = Arc::clone(&shutdown);
        let client_ip = wr.client_ip;

        tokio::spawn(async move {
            let mut dev = ChannelDevice::new();
            let cfg = IfaceConfig::new(HardwareAddress::Ip);
            let mut iface = Interface::new(cfg, &mut dev, SmolInstant::now());
            iface.update_ip_addrs(|addrs| {
                let _ = addrs.push(IpCidr::new(
                    IpAddress::Ipv4(client_ip),
                    32,
                ));
            });
            let mut sockets = SocketSet::new(Vec::with_capacity(MAX_VIRTUAL_SOCKETS));
            let mut udp_buf = vec![0u8; 4096];
            let mut wg_out = vec![0u8; 4096];

            // Initiate WireGuard handshake immediately
            if let TunnResult::WriteToNetwork(pkt) = tunn.format_handshake_initiation(&mut wg_out, false)
                && udp.send(pkt).await.is_ok()
            {
                tx_c.fetch_add(pkt.len() as u64, Ordering::Relaxed);
            }

            let mut timer = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    _ = shut_c.notified() => break,
                    _ = ctrl_rx.recv() => {},
                    _ = timer.tick() => {
                        match tunn.update_timers(&mut wg_out) {
                            TunnResult::WriteToNetwork(pkt) => {
                                if udp.send(pkt).await.is_ok() {
                                    tx_c.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                                }
                            }
                            TunnResult::Err(_) => {
                                drop_c.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                        iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
                        while let Some(ip_pkt) = dev.tx_queue.pop_front() {
                            if let TunnResult::WriteToNetwork(enc) = tunn.encapsulate(&ip_pkt, &mut wg_out)
                                && udp.send(enc).await.is_ok()
                            {
                                tx_c.fetch_add(enc.len() as u64, Ordering::Relaxed);
                            }
                        }
                    }
                    recv = udp.recv(&mut udp_buf) => {
                        if let Ok(n) = recv {
                            rx_c.fetch_add(n as u64, Ordering::Relaxed);
                            match tunn.decapsulate(None, &udp_buf[..n], &mut wg_out) {
                                TunnResult::WriteToNetwork(resp) => {
                                    let _ = udp.send(resp).await;
                                    hs_c.store(chrono::Utc::now().timestamp() as u64, Ordering::Relaxed);
                                }
                                TunnResult::WriteToTunnelV4(plain, _) => {
                                    dev.rx_queue.push_back(plain.to_vec());
                                    iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
                                }
                                TunnResult::Err(_) => {
                                    drop_c.fetch_add(1, Ordering::Relaxed);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            server_ip: wr.server_ip,
            dns_ip: wr.dns,
            tx_bytes,
            rx_bytes,
            dropped_packets,
            active_sockets,
            dns_errors,
            last_handshake_epoch,
            shutdown,
            _ctrl_tx: ctrl_tx,
        })
    }

    pub fn try_acquire_socket_slot(&self) -> Result<SocketSlotGuard> {
        let cur = self.active_sockets.fetch_add(1, Ordering::AcqRel);
        if cur >= MAX_VIRTUAL_SOCKETS {
            self.active_sockets.fetch_sub(1, Ordering::AcqRel);
            bail!("userspace netstack socket cap ({MAX_VIRTUAL_SOCKETS}) reached");
        }
        Ok(SocketSlotGuard {
            counter: Arc::clone(&self.active_sockets),
        })
    }

    /// Resolves host and connects target stream (enforcing MAX_VIRTUAL_SOCKETS cap).
    pub async fn dial_tcp(&self, host: &str, port: u16) -> Result<(TcpStream, SocketSlotGuard)> {
        let guard = self.try_acquire_socket_slot()?;
        let started = Instant::now();
        let stream = tokio::time::timeout(
            Duration::from_secs(15),
            TcpStream::connect((host, port)),
        )
        .await
        .context("tunnel dial timeout")?
        .map_err(|e| {
            self.dns_errors.fetch_add(1, Ordering::Relaxed);
            anyhow::Error::from(e)
        })?;
        let _elapsed = started.elapsed();
        Ok((stream, guard))
    }

    pub fn dns_ip(&self) -> Ipv4Addr {
        self.dns_ip
    }

    pub fn metrics(&self, state: TunnelState) -> TunnelMetrics {
        let hs = self.last_handshake_epoch.load(Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp() as u64;
        TunnelMetrics {
            state,
            server_ip: Some(self.server_ip.to_string()),
            country: None,
            city: None,
            location_key: None,
            exit_ip: None,
            last_handshake_age_secs: if hs > 0 { Some(now.saturating_sub(hs)) } else { None },
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            active_sockets: self.active_sockets.load(Ordering::Relaxed),
            dns_latency_ms: None,
            dns_errors: self.dns_errors.load(Ordering::Relaxed),
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}

pub struct SocketSlotGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for SocketSlotGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}
