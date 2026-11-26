use super::{HmaGeoCountry, HmaServer, HmaWireGuardInfo};
use anyhow::{Context, Result, bail};
use rand::RngCore;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const AVAST_LICENSE_URL: &str =
    "https://my-win.avast.com/v1/query/get-exact-application-licenses";
pub const SE_PLATFORM_BASE: &str = "https://api.se-platform.com";
const GEOS_CACHE_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Clone)]
pub struct LicenseInfo {
    pub container_id: String,
    pub product_name: String,
}

#[derive(Debug, Clone)]
pub struct RegistrationResult {
    pub device_udid: String,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub struct HmaClient {
    http: Client,
    geos_cache: Mutex<Option<(Instant, Vec<HmaGeoCountry>)>>,
}

impl HmaClient {
    pub fn new() -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("HMA-VPN/5.0 (Windows NT 10.0; Win64; x64)")
            .build()
            .context("failed to build HMA HTTP client")?;
        Ok(Self {
            http,
            geos_cache: Mutex::new(None),
        })
    }

    pub fn generate_device_fingerprint() -> String {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Calls Avast license lookup (`https://my-win.avast.com/v1/query/get-exact-application-licenses`)
    /// with required `Vaar-*` headers (matching hma-proxy/internal/hma/client.go).
    pub async fn lookup_license(&self, wallet_key: &str) -> Result<LicenseInfo> {
        let device_id = Self::generate_device_fingerprint();
        let resp = self
            .http
            .post(AVAST_LICENSE_URL)
            .header("Vaar-Version", "0")
            .header("Vaar-Header-App-Id", "hma-vpn-win")
            .header("Vaar-Header-Device-Id", &device_id)
            .header("Vaar-Header-Device-Platform", "WIN")
            .header("Vaar-Header-App-Product-Brand", "PRIVAX")
            .header("Vaar-Header-App-Product-Edition", "HMA_VPN_CONSUMER")
            .header("Vaar-Header-App-Product-Mode", "PAID")
            .header("Vaar-Header-App-IPM-Product", "78")
            .json(&json!({ "walletKeys": [wallet_key] }))
            .send()
            .await
            .context("Avast license lookup request failed")?;

        if !resp.status().is_success() {
            bail!("Avast license lookup returned HTTP {}", resp.status());
        }
        let body: Value = resp.json().await.context("invalid license lookup JSON")?;
        let container_id = body
            .pointer("/licenses/0/containerId")
            .or_else(|| body.pointer("/0/containerId"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .context("containerId missing from Avast license response")?;
        let product_name = body
            .pointer("/licenses/0/productName")
            .and_then(Value::as_str)
            .unwrap_or("HMA VPN")
            .to_string();

        Ok(LicenseInfo {
            container_id,
            product_name,
        })
    }

    /// Associates license container with `https://api.se-platform.com`.
    pub async fn associate_license(
        &self,
        wallet_key: &str,
        container_id: &str,
        fingerprint: &str,
    ) -> Result<RegistrationResult> {
        let url = format!("{SE_PLATFORM_BASE}/v1/auth/licenses/associate");
        let resp = self
            .http
            .post(&url)
            .header("SE-Client-Platform", "WIN")
            .header("SE-Client-Version", "5.0.0")
            .header("X-NLok-Tenant-ID", "hma")
            .json(&json!({
                "wallet_key": wallet_key,
                "container_id": container_id,
                "device_fingerprint": fingerprint,
            }))
            .send()
            .await
            .context("HMA associate_license failed")?;

        if !resp.status().is_success() {
            bail!("HMA associate_license returned HTTP {}", resp.status());
        }
        let body: Value = resp.json().await?;
        Ok(RegistrationResult {
            device_udid: body
                .get("device_udid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            access_token: body
                .get("access_token")
                .and_then(Value::as_str)
                .context("missing access_token")?
                .to_string(),
            refresh_token: body
                .get("refresh_token")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }

    pub async fn renew_token(&self, device_udid: &str, refresh_token: &str) -> Result<TokenPair> {
        let url = format!("{SE_PLATFORM_BASE}/v1/auth/tokens/renew");
        let resp = self
            .http
            .post(&url)
            .header("SE-Client-Platform", "WIN")
            .header("X-NLok-Tenant-ID", "hma")
            .json(&json!({
                "device_udid": device_udid,
                "refresh_token": refresh_token,
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("HMA renew_token returned HTTP {}", resp.status());
        }
        let body: Value = resp.json().await?;
        Ok(TokenPair {
            access_token: body
                .get("access_token")
                .and_then(Value::as_str)
                .context("missing access_token in renew response")?
                .to_string(),
            refresh_token: body
                .get("refresh_token")
                .and_then(Value::as_str)
                .unwrap_or(refresh_token)
                .to_string(),
        })
    }

    pub async fn get_geos(&self, access_token: Option<&str>) -> Result<Vec<HmaGeoCountry>> {
        if let Ok(guard) = self.geos_cache.lock()
            && let Some((ts, ref cached)) = *guard
            && ts.elapsed() < GEOS_CACHE_TTL
        {
            return Ok(cached.clone());
        }

        let url = format!("{SE_PLATFORM_BASE}/v1/geos");
        let mut req = self
            .http
            .get(&url)
            .header("SE-Client-Platform", "WIN")
            .header("X-NLok-Tenant-ID", "hma");
        if let Some(tok) = access_token.filter(|t| !t.is_empty()) {
            req = req.bearer_auth(tok);
        }
        let resp = req.send().await.context("HMA get_geos request failed")?;
        if !resp.status().is_success() {
            bail!("HMA get_geos returned HTTP {}", resp.status());
        }
        let geos: Vec<HmaGeoCountry> = resp.json().await.context("invalid geos JSON")?;
        if let Ok(mut guard) = self.geos_cache.lock() {
            *guard = Some((Instant::now(), geos.clone()));
        }
        Ok(geos)
    }

    pub fn resolve_location(
        geos: &[HmaGeoCountry],
        country_query: &str,
        city_query: Option<&str>,
    ) -> Result<(String, String, String)> {
        let q = country_query.trim().to_lowercase();
        let city_q = city_query.unwrap_or("").trim().to_lowercase();

        for g in geos {
            if !g.state.eq_ignore_ascii_case("active") {
                continue;
            }
            if g.location_key.to_lowercase() == q {
                return Ok((g.location_key.clone(), g.country.clone(), String::new()));
            }
            for c in &g.cities {
                if c.state.eq_ignore_ascii_case("active") && c.location_key.to_lowercase() == q {
                    return Ok((
                        c.location_key.clone(),
                        g.country.clone(),
                        c.location_city.clone(),
                    ));
                }
            }
            if g.country_code.to_lowercase() == q || g.country.to_lowercase() == q {
                if !city_q.is_empty() {
                    if let Some(c) = g.cities.iter().find(|c| {
                        c.state.eq_ignore_ascii_case("active")
                            && c.location_city.to_lowercase().contains(&city_q)
                    }) {
                        return Ok((
                            c.location_key.clone(),
                            g.country.clone(),
                            c.location_city.clone(),
                        ));
                    }
                    bail!("city '{city_q}' not found in {}", g.country);
                }
                return Ok((g.location_key.clone(), g.country.clone(), String::new()));
            }
        }
        bail!("HMA location '{country_query}' not found")
    }

    pub async fn discover_wireguard(
        &self,
        access_token: &str,
        location_key: &str,
    ) -> Result<Vec<HmaServer>> {
        #[derive(Deserialize)]
        struct RawServer {
            ip: String,
            wireguard: Option<HmaWireGuardInfo>,
        }
        let url = format!(
            "{SE_PLATFORM_BASE}/v1/servers/wireguard?location_key={}",
            location_key
        );
        let resp = self
            .http
            .get(&url)
            .header("SE-Client-Platform", "WIN")
            .header("X-NLok-Tenant-ID", "hma")
            .bearer_auth(access_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("HMA discover_wireguard returned HTTP {}", resp.status());
        }
        let raw: Vec<RawServer> = resp.json().await?;
        Ok(raw
            .into_iter()
            .map(|r| HmaServer {
                ip: r.ip,
                wireguard: r.wireguard,
            })
            .collect())
    }
}
