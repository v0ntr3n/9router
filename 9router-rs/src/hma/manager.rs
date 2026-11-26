use super::bridge::LoopbackBridge;
use super::client::HmaClient;
use super::tunnel::WireGuardNetstack;
use super::wrangler::wrangler_register;
use super::{HmaGeoCountry, TunnelMetrics, TunnelState};
use anyhow::{Context, Result, bail};
use arc_swap::ArcSwapOption;
use reqwest::Client;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const EXIT_IP_PROBE_URL: &str = "https://api.ipify.org";
pub const EXIT_IP_PROBE_TIMEOUT_SECS: u64 = 8;
pub const DRAIN_WINDOW_SECS: u64 = 30;

pub type IpChangeCallback = Arc<dyn Fn(&str) + Send + Sync>;

pub struct TunnelHandle {
    pub country: String,
    pub city: String,
    pub location_key: String,
    pub exit_ip: String,
    pub netstack: Arc<WireGuardNetstack>,
    pub bridge: Arc<LoopbackBridge>,
}

pub struct HmaManager {
    client: HmaClient,
    active: ArcSwapOption<TunnelHandle>,
    last_rotation: Mutex<Option<Instant>>,
    rotation_cooldown_secs: u64,
    on_ip_change: Mutex<Option<IpChangeCallback>>,
}

impl HmaManager {
    pub fn new(rotation_cooldown_secs: u64) -> Result<Self> {
        Ok(Self {
            client: HmaClient::new()?,
            active: ArcSwapOption::from(None),
            last_rotation: Mutex::new(None),
            rotation_cooldown_secs,
            on_ip_change: Mutex::new(None),
        })
    }

    pub fn set_on_ip_change(&self, cb: IpChangeCallback) {
        if let Ok(mut guard) = self.on_ip_change.lock() {
            *guard = Some(cb);
        }
    }

    pub fn client(&self) -> &HmaClient {
        &self.client
    }

    pub async fn list_countries(&self, access_token: Option<&str>) -> Result<Vec<HmaGeoCountry>> {
        self.client.get_geos(access_token).await
    }

    pub fn active_proxy_url(&self) -> Option<String> {
        self.active
            .load()
            .as_ref()
            .map(|h| h.bridge.http_proxy_url())
    }

    pub fn metrics(&self) -> TunnelMetrics {
        match self.active.load().as_ref() {
            Some(handle) => {
                let mut m = handle.netstack.metrics(TunnelState::Connected);
                m.country = Some(handle.country.clone());
                m.city = Some(handle.city.clone());
                m.location_key = Some(handle.location_key.clone());
                m.exit_ip = Some(handle.exit_ip.clone());
                m
            }
            None => TunnelMetrics::default(),
        }
    }

    pub fn can_rotate_now(&self) -> bool {
        let Ok(guard) = self.last_rotation.lock() else {
            return false;
        };
        match *guard {
            None => true,
            Some(ts) => ts.elapsed() >= Duration::from_secs(self.rotation_cooldown_secs),
        }
    }

    pub fn record_rotation_attempt(&self) {
        if let Ok(mut guard) = self.last_rotation.lock() {
            *guard = Some(Instant::now());
        }
    }

    pub async fn verify_exit_ip_via_proxy(proxy_url: &str) -> Result<String> {
        let proxy = reqwest::Proxy::all(proxy_url).context("invalid loopback bridge proxy URL")?;
        let hc = Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(EXIT_IP_PROBE_TIMEOUT_SECS))
            .build()?;
        let resp = hc.get(EXIT_IP_PROBE_URL).send().await?;
        if !resp.status().is_success() {
            bail!("exit-IP probe returned HTTP {}", resp.status());
        }
        Ok(resp.text().await?.trim().to_string())
    }

    pub async fn check_active_exit_ip(&self) -> Result<String> {
        let proxy_url = self
            .active_proxy_url()
            .context("no active HMA tunnel is running")?;
        Self::verify_exit_ip_via_proxy(&proxy_url).await
    }

    /// Make-before-break start/switch: boots candidate tunnel + loopback bridge, verifies exit IP via
    /// `https://api.ipify.org` (8s timeout), atomically swaps ArcSwap, triggers cache flush callback,
    /// and drains old tunnel up to 30s before closing.
    pub async fn start_or_switch(
        &self,
        access_token: &str,
        country: &str,
        city: Option<&str>,
    ) -> Result<TunnelMetrics> {
        let geos = self.client.get_geos(Some(access_token)).await?;
        let (loc_key, country_name, city_name) = HmaClient::resolve_location(&geos, country, city)?;
        let servers = self
            .client
            .discover_wireguard(access_token, &loc_key)
            .await?;

        let mut wr_result = None;
        let mut last_err = None;
        for srv in servers {
            let Some(wg) = srv.wireguard else { continue };
            let Ok(ip) = srv.ip.parse::<IpAddr>() else {
                continue;
            };
            for port in wg.wrangler_ports {
                match wrangler_register(SocketAddr::new(ip, port), &wg.public_key, access_token)
                    .await
                {
                    Ok(res) => {
                        wr_result = Some(res);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            if wr_result.is_some() {
                break;
            }
        }
        let wr = wr_result.ok_or_else(|| {
            last_err.unwrap_or_else(|| anyhow::anyhow!("no HMA servers available"))
        })?;

        let netstack = Arc::new(WireGuardNetstack::start(wr).await?);
        let bridge = Arc::new(LoopbackBridge::start(Some(Arc::clone(&netstack))).await?);

        let exit_ip = match Self::verify_exit_ip_via_proxy(&bridge.http_proxy_url()).await {
            Ok(ip) => ip,
            Err(e) => {
                bridge.shutdown();
                netstack.shutdown();
                return Err(
                    e.context("new HMA tunnel failed exit-IP verification; kept prior state")
                );
            }
        };

        let new_handle = Arc::new(TunnelHandle {
            country: country_name,
            city: city_name,
            location_key: loc_key,
            exit_ip: exit_ip.clone(),
            netstack,
            bridge,
        });

        let previous = self.active.swap(Some(new_handle));
        self.record_rotation_attempt();

        if let Ok(guard) = self.on_ip_change.lock()
            && let Some(ref cb) = *guard
        {
            cb(&exit_ip);
        }

        if let Some(old) = previous {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(DRAIN_WINDOW_SECS)).await;
                old.bridge.shutdown();
                old.netstack.shutdown();
            });
        }

        Ok(self.metrics())
    }

    pub async fn stop(&self) {
        if let Some(old) = self.active.swap(None) {
            old.bridge.shutdown();
            old.netstack.shutdown();
        }
    }
}
