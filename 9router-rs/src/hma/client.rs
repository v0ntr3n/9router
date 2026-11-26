use super::{HmaGeoCountry, HmaServer, HmaWireGuardInfo};
use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::RngCore;
use reqwest::{Client, RequestBuilder};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const AVAST_LICENSE_URL: &str =
    "https://my-win.avast.com/v1/query/get-exact-application-licenses";
pub const SE_PLATFORM_BASE: &str = "https://api.se-platform.com";

const CLIENT_VERSION: &str = "5.10.0";
const CLIENT_TYPE: &str = "hma101";
const CLIENT_NAME: &str = "GVPN";
const CLIENT_API_KEY: &str = "DECE424681E71043331A3DB13CB0905E03EB605478F1584055ED0EECE80A3E01";
const TENANT_ID: &str = "3bfdc5ab-a90f-4503-8349-34d0991d33a3";
const CLIENT_LOCALE: &str = "en-US";
const SDK_VERSION: &str = "win-5.10.0";
const PLATFORM_ID: &str = "win-x86-64";
const OS_TYPE: &str = "Windows 10 Pro";
const OS_VERSION: &str = "10.0.19045";
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
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("HMA-VPN/5.10.0 (Windows NT 10.0; Win64; x64)");

        // Respect SSL_CERT_FILE when present (for corporate proxies or sandboxed TLS inspection).
        if let Ok(cert_path) = std::env::var("SSL_CERT_FILE")
            && !cert_path.trim().is_empty()
            && let Ok(pem_bytes) = std::fs::read(&cert_path)
            && let Ok(certs) = reqwest::Certificate::from_pem_bundle(&pem_bytes)
        {
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        let http = builder.build().context("failed to build HMA HTTP client")?;
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

    fn apply_base_headers(req: RequestBuilder) -> RequestBuilder {
        req.header("SE-Client-Version", CLIENT_VERSION)
            .header("SE-Client-Type", CLIENT_TYPE)
            .header("SE-Client-Name", CLIENT_NAME)
            .header("SE-Client-API-Key", CLIENT_API_KEY)
            .header("X-NLok-Tenant-ID", TENANT_ID)
            .header("Accept", "application/json")
            .header("Cache-Control", "no-cache")
    }

    fn apply_device_headers(req: RequestBuilder) -> RequestBuilder {
        req.header("SE-Client-Locale", CLIENT_LOCALE)
            .header("SE-SDK-Version", SDK_VERSION)
            .header("SE-Platform-ID", PLATFORM_ID)
            .header("SE-Operating-System-Type", OS_TYPE)
            .header("SE-Operating-System-Version", OS_VERSION)
    }

    /// Calls Avast license lookup (`https://my-win.avast.com/v1/query/get-exact-application-licenses`)
    /// with verified `Vaar-*` headers matching `hma-proxy/internal/hma/client.go`.
    pub async fn lookup_license(&self, wallet_key: &str) -> Result<LicenseInfo> {
        let wallet_key = wallet_key.trim();
        let mut dev_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut dev_bytes);
        let device_id = hex::encode(dev_bytes);
        let app_uuid = Uuid::new_v4().to_string();

        let resp = self
            .http
            .post(AVAST_LICENSE_URL)
            .header("Accept", "application/json")
            .header("Vaar-Version", "0")
            .header("Vaar-Header-App-Id", &app_uuid)
            .header("Vaar-Header-Device-Id", &device_id)
            .header("Vaar-Header-Device-Platform", "WIN")
            .header("Vaar-Header-App-Product-Brand", "PRIVAX")
            .header("Vaar-Header-App-Product-Edition", "HMA_VPN_CONSUMER")
            .header("Vaar-Header-App-Product-Mode", "PAID")
            .header("Vaar-Header-App-Build-Version", CLIENT_VERSION)
            .header("Vaar-Header-App-IPM-Product", "78")
            .json(&json!({ "walletKeys": [wallet_key] }))
            .send()
            .await
            .context("Avast license lookup request failed")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("Avast license lookup returned HTTP {status}: {text}");
        }
        let body: Value = serde_json::from_str(&text).context("invalid license lookup JSON")?;
        let raw_id = body
            .pointer("/0/id")
            .or_else(|| body.pointer("/licenses/0/containerId"))
            .or_else(|| body.pointer("/0/containerId"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .context("license id missing from Avast license response")?;
        let container_id = raw_id.replace('-', "");
        let product_name = body
            .pointer("/0/product/name")
            .or_else(|| body.pointer("/licenses/0/productName"))
            .and_then(Value::as_str)
            .unwrap_or("HMA VPN")
            .to_string();

        Ok(LicenseInfo {
            container_id,
            product_name,
        })
    }

    /// Associates license container with `POST /aladdin/v1/authorization/associate-license`.
    pub async fn associate_license(
        &self,
        wallet_key: &str,
        container_id: &str,
        fingerprint: &str,
    ) -> Result<RegistrationResult> {
        let url = format!("{SE_PLATFORM_BASE}/aladdin/v1/authorization/associate-license");
        let container_id = container_id.trim().replace('-', "");
        let req = Self::apply_device_headers(Self::apply_base_headers(self.http.post(&url)))
            .header("Content-Type", "application/json; charset=utf-8")
            .json(&json!({
                "wallet_key": wallet_key.trim(),
                "container_id": container_id,
                "device_fingerprint": fingerprint,
            }));

        let resp = req.send().await.context("HMA associate_license failed")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("HMA associate_license returned HTTP {status}: {text}");
        }
        let parsed: Value = serde_json::from_str(&text)?;
        let root = parsed.get("data").unwrap_or(&parsed);

        let access_token = root
            .pointer("/token/access_token")
            .or_else(|| root.get("access_token"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .context("missing access_token in associate-license response")?
            .to_string();
        let refresh_token = root
            .pointer("/token/refresh_token")
            .or_else(|| root.get("refresh_token"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let device_udid = root
            .pointer("/credentials/device_udid")
            .or_else(|| root.get("device_udid"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        Ok(RegistrationResult {
            device_udid,
            access_token,
            refresh_token,
        })
    }

    /// Refreshes an expired access token via `POST /elysium/v1/renew`.
    pub async fn renew_token(&self, device_udid: &str, refresh_token: &str) -> Result<TokenPair> {
        let url = format!("{SE_PLATFORM_BASE}/elysium/v1/renew");
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("nsv:{device_udid}"));
        let resp = Self::apply_base_headers(self.http.post(&url))
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Authorization", format!("Basic {basic}"))
            .json(&json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }))
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("HMA renew_token returned HTTP {status}: {text}");
        }
        let parsed: Value = serde_json::from_str(&text)?;
        let root = parsed.get("data").unwrap_or(&parsed);
        Ok(TokenPair {
            access_token: root
                .get("access_token")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .context("missing access_token in renew response")?
                .to_string(),
            refresh_token: root
                .get("refresh_token")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(refresh_token)
                .to_string(),
        })
    }

    /// Fetches available HMA countries and cities via `GET /discovery/v12/geos`.
    pub async fn get_geos(&self, access_token: Option<&str>) -> Result<Vec<HmaGeoCountry>> {
        if let Ok(guard) = self.geos_cache.lock()
            && let Some((ts, ref cached)) = *guard
            && ts.elapsed() < GEOS_CACHE_TTL
        {
            return Ok(cached.clone());
        }

        let url = format!("{SE_PLATFORM_BASE}/discovery/v12/geos");
        let mut req =
            Self::apply_base_headers(self.http.get(&url)).header("SE-Client-Locale", CLIENT_LOCALE);
        if let Some(tok) = access_token.filter(|t| !t.is_empty()) {
            req = req.bearer_auth(tok);
        }
        let resp = req.send().await.context("HMA get_geos request failed")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("HMA get_geos returned HTTP {status}: {text}");
        }

        #[derive(Deserialize)]
        struct GeosData {
            geos: Vec<HmaGeoCountry>,
        }
        #[derive(Deserialize)]
        struct GeosEnvelope {
            data: GeosData,
        }

        let env: GeosEnvelope = serde_json::from_str(&text).context("invalid geos JSON")?;
        let geos = env.data.geos;
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

    /// Discovers WireGuard servers via `GET /discovery/v9/discover?location_key=<key>&protocol=wireguard`.
    pub async fn discover_wireguard(
        &self,
        access_token: &str,
        location_key: &str,
    ) -> Result<Vec<HmaServer>> {
        #[derive(Deserialize)]
        struct RawServer {
            ip: String,
            #[serde(default)]
            protocol: String,
            wireguard: Option<HmaWireGuardInfo>,
        }
        #[derive(Deserialize)]
        struct DiscoverData {
            ips: Vec<RawServer>,
        }
        #[derive(Deserialize)]
        struct DiscoverEnvelope {
            data: DiscoverData,
        }

        let mut req = Self::apply_base_headers(
            self.http
                .get(format!("{SE_PLATFORM_BASE}/discovery/v9/discover")),
        )
        .bearer_auth(access_token);
        if location_key.trim().is_empty() {
            req = req.query(&[("protocol", "wireguard")]);
        } else {
            req = req.query(&[("location_key", location_key), ("protocol", "wireguard")]);
        }

        let resp = req.send().await.context("HMA discover_wireguard failed")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("HMA discover_wireguard returned HTTP {status}: {text}");
        }
        let env: DiscoverEnvelope =
            serde_json::from_str(&text).context("invalid discover_wireguard JSON")?;
        let servers: Vec<HmaServer> = env
            .data
            .ips
            .into_iter()
            .filter(|r| {
                r.protocol.eq_ignore_ascii_case("wireguard")
                    && r.wireguard
                        .as_ref()
                        .is_some_and(|wg| !wg.public_key.is_empty())
            })
            .map(|r| HmaServer {
                ip: r.ip,
                wireguard: r.wireguard,
            })
            .collect();
        if servers.is_empty() {
            bail!("no wireguard servers found for location '{location_key}'");
        }
        Ok(servers)
    }
}
