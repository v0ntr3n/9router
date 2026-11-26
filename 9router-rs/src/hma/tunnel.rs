use super::{TunnelMetrics, TunnelState, WranglerResult};
use anyhow::{Context, Result, anyhow, bail};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey as WgPublicKey, StaticSecret as WgStaticSecret};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc, oneshot};

pub const MAX_VIRTUAL_SOCKETS: usize = 64;
pub const SOCKET_BUF_BYTES: usize = 128 * 1024;
pub const WG_MTU: usize = 1420;
pub const IDLE_SOCKET_TIMEOUT_SECS: u64 = 60;

const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_FALLBACK_SERVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const DNS_RETRANSMIT_INTERVAL: Duration = Duration::from_millis(800);
const DNS_TIMEOUT: Duration = Duration::from_secs(6);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

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

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
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

struct StreamBufs {
    rx_buf: VecDeque<u8>,
    rx_eof: bool,
    rx_err: Option<String>,
    rx_waker: Option<Waker>,
    tx_buf: VecDeque<u8>,
    tx_shutdown: bool,
    tx_closed: bool,
    tx_waker: Option<Waker>,
    caller_dropped: bool,
}

impl StreamBufs {
    fn new() -> Self {
        Self {
            rx_buf: VecDeque::with_capacity(16 * 1024),
            rx_eof: false,
            rx_err: None,
            rx_waker: None,
            tx_buf: VecDeque::with_capacity(16 * 1024),
            tx_shutdown: false,
            tx_closed: false,
            tx_waker: None,
            caller_dropped: false,
        }
    }
}

/// Async stream backed by a userspace `smoltcp` TCP socket inside the WireGuard tunnel.
pub struct TunnelStream {
    state: Arc<Mutex<StreamBufs>>,
    wake: Arc<Notify>,
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut st = self.state.lock().unwrap();
        if !st.rx_buf.is_empty() {
            let max = buf.remaining();
            let (s1, s2) = st.rx_buf.as_slices();
            let n1 = s1.len().min(max);
            buf.put_slice(&s1[..n1]);
            let rem = max - n1;
            let n2 = if rem > 0 {
                let take = s2.len().min(rem);
                buf.put_slice(&s2[..take]);
                take
            } else {
                0
            };
            st.rx_buf.drain(..n1 + n2);
            drop(st);
            self.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if let Some(ref msg) = st.rx_err {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                msg.clone(),
            )));
        }
        if st.rx_eof {
            return Poll::Ready(Ok(()));
        }
        st.rx_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.state.lock().unwrap();
        if st.tx_closed || st.rx_err.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tunnel TCP stream closed",
            )));
        }
        let avail = SOCKET_BUF_BYTES.saturating_sub(st.tx_buf.len());
        if avail == 0 {
            st.tx_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = src.len().min(avail);
        st.tx_buf.extend(&src[..n]);
        drop(st);
        self.wake.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let mut st = self.state.lock().unwrap();
        st.tx_shutdown = true;
        drop(st);
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        if let Ok(mut st) = self.state.lock() {
            st.caller_dropped = true;
            st.tx_shutdown = true;
        }
        self.wake.notify_one();
    }
}

enum NetCmd {
    ResolveDns {
        host: String,
        reply: oneshot::Sender<Result<Ipv4Addr>>,
    },
    ConnectTcp {
        remote_ip: Ipv4Addr,
        remote_port: u16,
        state: Arc<Mutex<StreamBufs>>,
        reply: oneshot::Sender<Result<()>>,
    },
}

struct PendingDns {
    host: String,
    txid: u16,
    started_at: Instant,
    next_send_at: Instant,
    attempts: u8,
    reply: oneshot::Sender<Result<Ipv4Addr>>,
}

struct ActiveTcp {
    handle: SocketHandle,
    local_port: u16,
    state: Arc<Mutex<StreamBufs>>,
    connect_reply: Option<oneshot::Sender<Result<()>>>,
    started_at: Instant,
}

/// Userspace WireGuard (`boringtun`) + bounded `smoltcp` IPv4 netstack running in a dedicated Tokio task.
pub struct WireGuardNetstack {
    server_ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
    tx_bytes: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
    dropped_packets: Arc<AtomicU64>,
    active_sockets: Arc<AtomicUsize>,
    dns_latency_ms: Arc<AtomicU64>,
    dns_errors: Arc<AtomicU64>,
    last_handshake_epoch: Arc<AtomicU64>,
    shutdown: Arc<Notify>,
    wake: Arc<Notify>,
    cmd_tx: mpsc::Sender<NetCmd>,
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
        let tunn = Tunn::new(private_key, peer_pub, None, Some(25), 0, None)
            .map_err(|e| anyhow!("failed to initialize boringtun: {e}"))?;

        let tx_bytes = Arc::new(AtomicU64::new(0));
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let dropped_packets = Arc::new(AtomicU64::new(0));
        let active_sockets = Arc::new(AtomicUsize::new(0));
        let dns_latency_ms = Arc::new(AtomicU64::new(0));
        let dns_errors = Arc::new(AtomicU64::new(0));
        let last_handshake_epoch = Arc::new(AtomicU64::new(0));
        let shutdown = Arc::new(Notify::new());
        let wake = Arc::new(Notify::new());
        let (cmd_tx, cmd_rx) = mpsc::channel::<NetCmd>(128);

        let task_ctx = NetstackTaskCtx {
            udp,
            tunn,
            client_ip: wr.client_ip,
            dns_ip: wr.dns,
            tx_bytes: Arc::clone(&tx_bytes),
            rx_bytes: Arc::clone(&rx_bytes),
            dropped_packets: Arc::clone(&dropped_packets),
            dns_latency_ms: Arc::clone(&dns_latency_ms),
            dns_errors: Arc::clone(&dns_errors),
            last_handshake_epoch: Arc::clone(&last_handshake_epoch),
            shutdown: Arc::clone(&shutdown),
            wake: Arc::clone(&wake),
            cmd_rx,
        };
        tokio::spawn(run_netstack_loop(task_ctx));

        Ok(Self {
            server_ip: wr.server_ip,
            dns_ip: wr.dns,
            tx_bytes,
            rx_bytes,
            dropped_packets,
            active_sockets,
            dns_latency_ms,
            dns_errors,
            last_handshake_epoch,
            shutdown,
            wake,
            cmd_tx,
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

    async fn resolve_ipv4(&self, host: &str) -> Result<Ipv4Addr> {
        let trimmed = host.trim();
        if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
            return Ok(ip);
        }
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetCmd::ResolveDns {
                host: trimmed.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| anyhow!("WireGuard netstack stopped"))?;
        self.wake.notify_one();
        match tokio::time::timeout(DNS_TIMEOUT + Duration::from_secs(1), rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => {
                self.dns_errors.fetch_add(1, Ordering::Relaxed);
                bail!("in-tunnel DNS resolution cancelled for {trimmed}");
            }
            Err(_) => {
                self.dns_errors.fetch_add(1, Ordering::Relaxed);
                bail!("in-tunnel DNS timeout for {trimmed}");
            }
        }
    }

    /// Resolves host inside the WireGuard tunnel and establishes a userspace `smoltcp` TCP stream
    /// (enforcing MAX_VIRTUAL_SOCKETS cap). Never dials the host network directly.
    pub async fn dial_tcp(&self, host: &str, port: u16) -> Result<(TunnelStream, SocketSlotGuard)> {
        let guard = self.try_acquire_socket_slot()?;
        let remote_ip = self.resolve_ipv4(host).await?;
        let state = Arc::new(Mutex::new(StreamBufs::new()));
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetCmd::ConnectTcp {
                remote_ip,
                remote_port: port,
                state: Arc::clone(&state),
                reply: tx,
            })
            .await
            .map_err(|_| anyhow!("WireGuard netstack stopped"))?;
        self.wake.notify_one();

        match tokio::time::timeout(TCP_CONNECT_TIMEOUT + Duration::from_secs(1), rx).await {
            Ok(Ok(Ok(()))) => Ok((
                TunnelStream {
                    state,
                    wake: Arc::clone(&self.wake),
                },
                guard,
            )),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => bail!("tunnel TCP connect cancelled"),
            Err(_) => bail!("tunnel TCP connect timeout to {host}:{port}"),
        }
    }

    pub fn dns_ip(&self) -> Ipv4Addr {
        self.dns_ip
    }

    pub fn metrics(&self, state: TunnelState) -> TunnelMetrics {
        let hs = self.last_handshake_epoch.load(Ordering::Relaxed);
        let now = chrono::Utc::now().timestamp() as u64;
        let dns_lat = self.dns_latency_ms.load(Ordering::Relaxed);
        TunnelMetrics {
            state,
            server_ip: Some(self.server_ip.to_string()),
            country: None,
            city: None,
            location_key: None,
            exit_ip: None,
            last_handshake_age_secs: if hs > 0 {
                Some(now.saturating_sub(hs))
            } else {
                None
            },
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            active_sockets: self.active_sockets.load(Ordering::Relaxed),
            dns_latency_ms: if dns_lat > 0 { Some(dns_lat) } else { None },
            dns_errors: self.dns_errors.load(Ordering::Relaxed),
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}

struct NetstackTaskCtx {
    udp: UdpSocket,
    tunn: Tunn,
    client_ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
    tx_bytes: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
    dropped_packets: Arc<AtomicU64>,
    dns_latency_ms: Arc<AtomicU64>,
    dns_errors: Arc<AtomicU64>,
    last_handshake_epoch: Arc<AtomicU64>,
    shutdown: Arc<Notify>,
    wake: Arc<Notify>,
    cmd_rx: mpsc::Receiver<NetCmd>,
}

async fn run_netstack_loop(mut ctx: NetstackTaskCtx) {
    let mut dev = ChannelDevice::new();
    let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
    cfg.random_seed = rand::random();
    let mut iface = Interface::new(cfg, &mut dev, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(ctx.client_ip), 32));
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1));

    let mut sockets = SocketSet::new(Vec::with_capacity(MAX_VIRTUAL_SOCKETS + 2));

    let dns_rx_meta = vec![udp::PacketMetadata::EMPTY; 32];
    let dns_tx_meta = vec![udp::PacketMetadata::EMPTY; 32];
    let mut dns_sock = udp::Socket::new(
        udp::PacketBuffer::new(dns_rx_meta, vec![0u8; 32 * 512]),
        udp::PacketBuffer::new(dns_tx_meta, vec![0u8; 32 * 512]),
    );
    let dns_local_port: u16 = 40000 + (rand::random::<u16>() % 8000);
    let _ = dns_sock.bind(dns_local_port);
    let dns_handle = sockets.add(dns_sock);

    let mut udp_buf = vec![0u8; 4096];
    let mut wg_out = vec![0u8; 4096];
    let mut dns_cache: HashMap<String, (Ipv4Addr, Instant)> = HashMap::new();
    let mut pending_dns: Vec<PendingDns> = Vec::new();
    let mut active_tcp: Vec<ActiveTcp> = Vec::new();
    let mut next_ephemeral_port: u16 = 49152 + (rand::random::<u16>() % 16383);

    // Initiate WireGuard handshake immediately.
    if let TunnResult::WriteToNetwork(pkt) =
        ctx.tunn.format_handshake_initiation(&mut wg_out, false)
        && ctx.udp.send(pkt).await.is_ok()
    {
        ctx.tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
    }

    let mut wg_timer = tokio::time::interval(Duration::from_millis(250));
    wg_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Compute advisory sleep delay from smoltcp + pending DNS retransmits.
        let poll_wait = compute_next_sleep(&mut iface, &sockets, &pending_dns);

        tokio::select! {
            _ = ctx.shutdown.notified() => break,
            recv = ctx.udp.recv(&mut udp_buf) => {
                if let Ok(n) = recv {
                    handle_udp_packet(&mut ctx, &mut dev, &udp_buf[..n], &mut wg_out).await;
                    // Drain any immediately buffered UDP packets before polling smoltcp.
                    for _ in 0..64 {
                        match ctx.udp.try_recv(&mut udp_buf) {
                            Ok(m) if m > 0 => {
                                handle_udp_packet(&mut ctx, &mut dev, &udp_buf[..m], &mut wg_out).await;
                            }
                            _ => break,
                        }
                    }
                }
            }
            cmd = ctx.cmd_rx.recv() => {
                if let Some(c) = cmd {
                    handle_cmd(
                        c,
                        &mut iface,
                        &mut sockets,
                        &mut dns_cache,
                        &mut pending_dns,
                        &mut active_tcp,
                        &mut next_ephemeral_port,
                        dns_local_port,
                    );
                    while let Ok(more) = ctx.cmd_rx.try_recv() {
                        handle_cmd(
                            more,
                            &mut iface,
                            &mut sockets,
                            &mut dns_cache,
                            &mut pending_dns,
                            &mut active_tcp,
                            &mut next_ephemeral_port,
                            dns_local_port,
                        );
                    }
                } else {
                    break;
                }
            }
            _ = ctx.wake.notified() => {}
            _ = wg_timer.tick() => {
                match ctx.tunn.update_timers(&mut wg_out) {
                    TunnResult::WriteToNetwork(pkt) => {
                        if ctx.udp.send(pkt).await.is_ok() {
                            ctx.tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                        }
                    }
                    TunnResult::Err(_) => {
                        ctx.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(poll_wait) => {}
        }

        // 1. Poll smoltcp ingress & egress.
        iface.poll(SmolInstant::now(), &mut dev, &mut sockets);

        // 2. Drive in-tunnel DNS queries & responses.
        pump_dns(
            &mut sockets,
            dns_handle,
            ctx.dns_ip,
            &mut dns_cache,
            &mut pending_dns,
            &ctx.dns_latency_ms,
            &ctx.dns_errors,
        );

        // 3. Drive active virtual TCP sockets.
        pump_tcp(&mut sockets, &mut active_tcp);

        // 4. Poll again so newly queued DNS/TCP packets and window ACKs are emitted right away.
        iface.poll(SmolInstant::now(), &mut dev, &mut sockets);

        // 5. WireGuard-encapsulate and transmit every queued IPv4 packet immediately.
        flush_tx_queue(
            &mut dev,
            &mut ctx.tunn,
            &ctx.udp,
            &mut wg_out,
            &ctx.tx_bytes,
            &ctx.dropped_packets,
        )
        .await;
    }

    // Fail any in-flight operations cleanly on shutdown.
    for p in pending_dns.drain(..) {
        let _ = p.reply.send(Err(anyhow!("WireGuard tunnel shut down")));
    }
    for mut t in active_tcp.drain(..) {
        if let Some(reply) = t.connect_reply.take() {
            let _ = reply.send(Err(anyhow!("WireGuard tunnel shut down")));
        }
        if let Ok(mut st) = t.state.lock() {
            st.rx_eof = true;
            st.tx_closed = true;
            if let Some(w) = st.rx_waker.take() {
                w.wake();
            }
            if let Some(w) = st.tx_waker.take() {
                w.wake();
            }
        }
    }
}

fn compute_next_sleep(
    iface: &mut Interface,
    sockets: &SocketSet<'_>,
    pending_dns: &[PendingDns],
) -> Duration {
    let mut wait = Duration::from_millis(250);
    if let Some(delay) = iface.poll_delay(SmolInstant::now(), sockets) {
        let ms = delay.total_millis();
        wait = wait.min(Duration::from_millis(ms.max(1)));
    }
    let now = Instant::now();
    for q in pending_dns {
        let rem = q.next_send_at.saturating_duration_since(now);
        wait = wait.min(rem.max(Duration::from_millis(5)));
    }
    wait
}

async fn handle_udp_packet(
    ctx: &mut NetstackTaskCtx,
    dev: &mut ChannelDevice,
    packet: &[u8],
    wg_out: &mut [u8],
) {
    ctx.rx_bytes
        .fetch_add(packet.len() as u64, Ordering::Relaxed);
    match ctx.tunn.decapsulate(None, packet, wg_out) {
        TunnResult::WriteToNetwork(resp) => {
            if ctx.udp.send(resp).await.is_ok() {
                ctx.tx_bytes.fetch_add(resp.len() as u64, Ordering::Relaxed);
            }
            ctx.last_handshake_epoch
                .store(chrono::Utc::now().timestamp() as u64, Ordering::Relaxed);
            // Per boringtun contract: drain any queued packets after handshake completion.
            loop {
                match ctx.tunn.decapsulate(None, &[], wg_out) {
                    TunnResult::WriteToNetwork(queued) => {
                        if ctx.udp.send(queued).await.is_ok() {
                            ctx.tx_bytes
                                .fetch_add(queued.len() as u64, Ordering::Relaxed);
                        }
                    }
                    TunnResult::Err(_) => {
                        ctx.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    _ => break,
                }
            }
        }
        TunnResult::WriteToTunnelV4(plain, _) => {
            dev.rx_queue.push_back(plain.to_vec());
        }
        TunnResult::Err(_) => {
            ctx.dropped_packets.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

async fn flush_tx_queue(
    dev: &mut ChannelDevice,
    tunn: &mut Tunn,
    udp: &UdpSocket,
    wg_out: &mut [u8],
    tx_bytes: &AtomicU64,
    dropped_packets: &AtomicU64,
) {
    while let Some(ip_pkt) = dev.tx_queue.pop_front() {
        match tunn.encapsulate(&ip_pkt, wg_out) {
            TunnResult::WriteToNetwork(enc) => {
                if udp.send(enc).await.is_ok() {
                    tx_bytes.fetch_add(enc.len() as u64, Ordering::Relaxed);
                }
            }
            TunnResult::Err(_) => {
                dropped_packets.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_cmd(
    cmd: NetCmd,
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    dns_cache: &mut HashMap<String, (Ipv4Addr, Instant)>,
    pending_dns: &mut Vec<PendingDns>,
    active_tcp: &mut Vec<ActiveTcp>,
    next_ephemeral_port: &mut u16,
    dns_local_port: u16,
) {
    match cmd {
        NetCmd::ResolveDns { host, reply } => {
            let key = host.to_ascii_lowercase();
            if let Some((ip, expires)) = dns_cache.get(&key)
                && Instant::now() < *expires
            {
                let _ = reply.send(Ok(*ip));
                return;
            }
            let now = Instant::now();
            pending_dns.push(PendingDns {
                host,
                txid: rand::random(),
                started_at: now,
                next_send_at: now,
                attempts: 0,
                reply,
            });
        }
        NetCmd::ConnectTcp {
            remote_ip,
            remote_port,
            state,
            reply,
        } => {
            let local_port =
                allocate_ephemeral_port(next_ephemeral_port, active_tcp, dns_local_port);
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF_BYTES]),
                tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF_BYTES]),
            );
            sock.set_nagle_enabled(false);
            sock.set_ack_delay(Some(SmolDuration::from_millis(5)));
            sock.set_timeout(Some(SmolDuration::from_secs(IDLE_SOCKET_TIMEOUT_SECS)));

            let remote = IpEndpoint::new(IpAddress::Ipv4(remote_ip), remote_port);
            if let Err(e) = sock.connect(iface.context(), remote, local_port) {
                let _ = reply.send(Err(anyhow!("smoltcp connect failed: {e}")));
                return;
            }
            let handle = sockets.add(sock);
            active_tcp.push(ActiveTcp {
                handle,
                local_port,
                state,
                connect_reply: Some(reply),
                started_at: Instant::now(),
            });
        }
    }
}

fn allocate_ephemeral_port(
    next_port: &mut u16,
    active_tcp: &[ActiveTcp],
    dns_local_port: u16,
) -> u16 {
    for _ in 0..16384 {
        let candidate = *next_port;
        *next_port = if *next_port == 65535 {
            49152
        } else {
            *next_port + 1
        };
        if candidate != dns_local_port && !active_tcp.iter().any(|t| t.local_port == candidate) {
            return candidate;
        }
    }
    49152
}

fn pump_dns(
    sockets: &mut SocketSet<'_>,
    dns_handle: SocketHandle,
    primary_dns: Ipv4Addr,
    dns_cache: &mut HashMap<String, (Ipv4Addr, Instant)>,
    pending_dns: &mut Vec<PendingDns>,
    dns_latency_ms: &AtomicU64,
    dns_errors: &AtomicU64,
) {
    let sock = sockets.get_mut::<udp::Socket>(dns_handle);

    // 1. Drain incoming DNS responses.
    let mut recv_buf = [0u8; 1024];
    while sock.can_recv() {
        let Ok((n, _meta)) = sock.recv_slice(&mut recv_buf) else {
            break;
        };
        if let Some((txid, result)) = parse_dns_a_response(&recv_buf[..n])
            && let Some(pos) = pending_dns.iter().position(|q| q.txid == txid)
        {
            let q = pending_dns.remove(pos);
            match result {
                Ok(ip) => {
                    let ms = q.started_at.elapsed().as_millis().max(1) as u64;
                    dns_latency_ms.store(ms, Ordering::Relaxed);
                    dns_cache.insert(
                        q.host.to_ascii_lowercase(),
                        (ip, Instant::now() + DNS_CACHE_TTL),
                    );
                    let _ = q.reply.send(Ok(ip));
                }
                Err(e) => {
                    dns_errors.fetch_add(1, Ordering::Relaxed);
                    let _ = q.reply.send(Err(e));
                }
            }
        }
    }

    // 2. Expire timed-out queries and send initial/retransmit packets.
    let now = Instant::now();
    let mut idx = 0;
    while idx < pending_dns.len() {
        if now.duration_since(pending_dns[idx].started_at) >= DNS_TIMEOUT {
            let q = pending_dns.remove(idx);
            dns_errors.fetch_add(1, Ordering::Relaxed);
            let _ = q
                .reply
                .send(Err(anyhow!("in-tunnel DNS timed out for {}", q.host)));
            continue;
        }
        if now >= pending_dns[idx].next_send_at && sock.can_send() {
            let q = &mut pending_dns[idx];
            match encode_dns_a_query(&q.host, q.txid) {
                Ok(pkt) => {
                    // Use tunnel's assigned DNS first, then fall back to 1.1.1.1 inside the same tunnel.
                    let server_ip = if q.attempts < 2 {
                        primary_dns
                    } else {
                        DNS_FALLBACK_SERVER
                    };
                    let endpoint = IpEndpoint::new(IpAddress::Ipv4(server_ip), 53);
                    if sock.send_slice(&pkt, endpoint).is_ok() {
                        q.attempts = q.attempts.saturating_add(1);
                        q.next_send_at = now + DNS_RETRANSMIT_INTERVAL;
                    }
                }
                Err(e) => {
                    let q = pending_dns.remove(idx);
                    dns_errors.fetch_add(1, Ordering::Relaxed);
                    let _ = q.reply.send(Err(e));
                    continue;
                }
            }
        }
        idx += 1;
    }
}

fn pump_tcp(sockets: &mut SocketSet<'_>, active_tcp: &mut Vec<ActiveTcp>) {
    let now = Instant::now();
    let mut idx = 0;
    while idx < active_tcp.len() {
        let remove = {
            let conn = &mut active_tcp[idx];
            let sock = sockets.get_mut::<tcp::Socket>(conn.handle);

            // Handle in-progress TCP handshake.
            if conn.connect_reply.is_some() {
                match sock.state() {
                    tcp::State::Established | tcp::State::CloseWait => {
                        if let Some(reply) = conn.connect_reply.take() {
                            let _ = reply.send(Ok(()));
                        }
                        false
                    }
                    tcp::State::Closed => {
                        if let Some(reply) = conn.connect_reply.take() {
                            let _ = reply.send(Err(anyhow!("tunnel TCP connection refused/reset")));
                        }
                        true
                    }
                    _ if now.duration_since(conn.started_at) >= TCP_CONNECT_TIMEOUT => {
                        sock.abort();
                        if let Some(reply) = conn.connect_reply.take() {
                            let _ = reply.send(Err(anyhow!("tunnel TCP connect timeout")));
                        }
                        true
                    }
                    _ => false,
                }
            } else {
                let mut rx_waker = None;
                let mut tx_waker = None;
                let should_remove;
                {
                    let mut st = conn.state.lock().unwrap();
                    if st.caller_dropped {
                        if sock.state() != tcp::State::Closed {
                            sock.abort();
                        }
                        should_remove = sock.state() == tcp::State::Closed;
                    } else {
                        // Caller -> smoltcp TX
                        let mut woke_tx = false;
                        while !st.tx_buf.is_empty() && sock.can_send() {
                            let (s1, _) = st.tx_buf.as_slices();
                            match sock.send_slice(s1) {
                                Ok(n) if n > 0 => {
                                    st.tx_buf.drain(..n);
                                    woke_tx = true;
                                }
                                _ => break,
                            }
                        }
                        if st.tx_shutdown && st.tx_buf.is_empty() && sock.may_send() {
                            sock.close();
                        }
                        if !sock.may_send() && !st.tx_closed {
                            st.tx_closed = true;
                            woke_tx = true;
                        }
                        if woke_tx {
                            tx_waker = st.tx_waker.take();
                        }

                        // smoltcp -> Caller RX
                        let mut woke_rx = false;
                        while sock.can_recv() {
                            let avail = SOCKET_BUF_BYTES.saturating_sub(st.rx_buf.len());
                            if avail == 0 {
                                break;
                            }
                            let max_read = avail.min(16 * 1024);
                            let read_res = sock.recv(|slice| {
                                let take = slice.len().min(max_read);
                                st.rx_buf.extend(&slice[..take]);
                                (take, take)
                            });
                            match read_res {
                                Ok(n) if n > 0 => woke_rx = true,
                                _ => break,
                            }
                        }
                        if !sock.can_recv() && !sock.may_recv() && !st.rx_eof {
                            st.rx_eof = true;
                            woke_rx = true;
                        }
                        if sock.state() == tcp::State::Closed {
                            st.rx_eof = true;
                            st.tx_closed = true;
                            woke_rx = true;
                            woke_tx = true;
                        }
                        if woke_rx {
                            rx_waker = st.rx_waker.take();
                        }
                        if woke_tx && tx_waker.is_none() {
                            tx_waker = st.tx_waker.take();
                        }
                        should_remove = sock.state() == tcp::State::Closed;
                    }
                }
                if let Some(w) = rx_waker {
                    w.wake();
                }
                if let Some(w) = tx_waker {
                    w.wake();
                }
                should_remove
            }
        };

        if remove {
            let conn = active_tcp.remove(idx);
            sockets.remove(conn.handle);
        } else {
            idx += 1;
        }
    }
}

/// Encodes a standard recursive DNS A-record query packet (RFC 1035).
pub fn encode_dns_a_query(host: &str, txid: u16) -> Result<Vec<u8>> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        bail!("invalid DNS hostname '{host}'");
    }
    let mut buf = Vec::with_capacity(12 + trimmed.len() + 6);
    buf.extend_from_slice(&txid.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS label in hostname '{host}'");
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Ok(buf)
}

fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
    let mut jumps = 0usize;
    while offset < data.len() {
        let len = *data.get(offset)?;
        if len == 0 {
            return Some(offset + 1);
        }
        if len & 0xC0 == 0xC0 {
            if offset + 2 > data.len() {
                return None;
            }
            return Some(offset + 2);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        offset = offset.checked_add(1 + len as usize)?;
        if offset > data.len() {
            return None;
        }
        jumps += 1;
        if jumps > 128 {
            return None;
        }
    }
    None
}

/// Parses a DNS response packet and extracts `(transaction_id, Result<Ipv4Addr>)`.
pub fn parse_dns_a_response(data: &[u8]) -> Option<(u16, Result<Ipv4Addr>)> {
    if data.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = (flags & 0x8000) != 0;
    let opcode = (flags >> 11) & 0x0F;
    if !is_response || opcode != 0 {
        return None;
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Some((txid, Err(anyhow!("DNS error rcode {rcode}"))));
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    let mut offset = 12usize;
    for _ in 0..qdcount {
        offset = skip_dns_name(data, offset)?;
        offset = offset.checked_add(4)?;
        if offset > data.len() {
            return None;
        }
    }
    for _ in 0..ancount {
        offset = skip_dns_name(data, offset)?;
        if offset + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let rdlen = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > data.len() {
            break;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            let ip = Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            );
            return Some((txid, Ok(ip)));
        }
        offset += rdlen;
    }
    Some((txid, Err(anyhow!("DNS response contained no A record"))))
}

pub struct SocketSlotGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for SocketSlotGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_encode_and_a_response_parse() {
        let query = encode_dns_a_query("opencode.ai", 0x1234).unwrap();
        assert_eq!(u16::from_be_bytes([query[0], query[1]]), 0x1234);
        assert_eq!(u16::from_be_bytes([query[2], query[3]]), 0x0100);
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);

        // Craft a minimal valid DNS A response matching txid 0x1234 -> 1.2.3.4
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // standard response, noerror
        resp.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        resp.extend_from_slice(&1u16.to_be_bytes()); // ancount
        resp.extend_from_slice(&0u16.to_be_bytes()); // nscount
        resp.extend_from_slice(&0u16.to_be_bytes()); // arcount
        resp.extend_from_slice(&query[12..]); // echo question
        // Answer: pointer to offset 12 (0xc00c), type A, class IN, ttl 60, rdlen 4, ip 1.2.3.4
        resp.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4,
        ]);

        let (txid, parsed) = parse_dns_a_response(&resp).unwrap();
        assert_eq!(txid, 0x1234);
        assert_eq!(parsed.unwrap(), Ipv4Addr::new(1, 2, 3, 4));
    }
}
