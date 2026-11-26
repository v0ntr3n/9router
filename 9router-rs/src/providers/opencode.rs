use super::opencode_fingerprint::{
    FingerprintReport, MAX_TRANSLATED_SESSIONS, OpenCodeSessionStore, apply_opencode_fingerprint,
    restore_tool_names_in_text,
};
use super::{ProviderError, ProviderErrorKind, UpstreamResponse};
use crate::config::schema::OpenCodeProfile;
use crate::translator::ir::WireFormat;
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ERROR_PEEK_CAP: usize = 8 * 1024;

pub struct OpenCodeAdapter {
    profile: Arc<OpenCodeProfile>,
    sessions: Arc<OpenCodeSessionStore>,
    cached_proxy_url: Mutex<Option<String>>,
    #[cfg(not(feature = "boring-tls"))]
    cached_client: Mutex<Option<reqwest::Client>>,
    #[cfg(feature = "boring-tls")]
    cached_wreq: Mutex<Option<wreq::Client>>,
}

impl OpenCodeAdapter {
    pub fn new(profile: OpenCodeProfile) -> Self {
        Self {
            profile: Arc::new(profile),
            sessions: Arc::new(OpenCodeSessionStore::new(MAX_TRANSLATED_SESSIONS)),
            cached_proxy_url: Mutex::new(None),
            #[cfg(not(feature = "boring-tls"))]
            cached_client: Mutex::new(None),
            #[cfg(feature = "boring-tls")]
            cached_wreq: Mutex::new(None),
        }
    }

    pub fn profile(&self) -> &OpenCodeProfile {
        &self.profile
    }

    pub fn sessions(&self) -> &OpenCodeSessionStore {
        &self.sessions
    }

    /// Flushes pooled HTTP/TLS clients and OpenCode session LRU entries when HMA exit IP changes.
    pub fn on_hma_ip_changed(&self) {
        self.sessions.clear_all();
        if let Ok(mut p) = self.cached_proxy_url.lock() {
            *p = None;
        }
        #[cfg(not(feature = "boring-tls"))]
        if let Ok(mut c) = self.cached_client.lock() {
            *c = None;
        }
        #[cfg(feature = "boring-tls")]
        if let Ok(mut c) = self.cached_wreq.lock() {
            *c = None;
        }
    }

    pub fn classify_error(status: u16, body_peek: &str) -> ProviderErrorKind {
        let lower = body_peek.to_ascii_lowercase();
        match status {
            429 => {
                if lower.contains("overloaded") {
                    ProviderErrorKind::Overloaded
                } else {
                    ProviderErrorKind::FreeUsageLimit
                }
            }
            403 => ProviderErrorKind::FingerprintRejected,
            401 => ProviderErrorKind::AuthFailed,
            500..=599 => ProviderErrorKind::Upstream5xx,
            _ => ProviderErrorKind::ClientError(status),
        }
    }

    fn endpoint_for(&self, format: WireFormat) -> &str {
        match format {
            WireFormat::OpenAiResponses => &self.profile.base_url_responses,
            WireFormat::AnthropicMessages => &self.profile.base_url_messages,
            WireFormat::OpenAiChat => &self.profile.base_url_chat,
        }
    }

    pub async fn send(
        &self,
        format: WireFormat,
        mut body: Value,
        caller_session_key: &str,
        proxy_url: Option<&str>,
    ) -> Result<(UpstreamResponse, FingerprintReport), ProviderError> {
        let session_id = self.sessions.get_or_mint(caller_session_key);
        let report = apply_opencode_fingerprint(&mut body, &self.profile, session_id.clone());
        let url = self.endpoint_for(format).to_string();

        let result = self
            .dispatch_http(&url, format, &body, &session_id, proxy_url, report.aliased_tools.clone())
            .await;

        if let Err(ref err) = result
            && matches!(
                err.kind,
                ProviderErrorKind::FingerprintRejected | ProviderErrorKind::FreeUsageLimit
            )
        {
            self.sessions
                .invalidate_if_matches(caller_session_key, &session_id);
        }

        result.map(|resp| (resp, report))
    }

    #[cfg(not(feature = "boring-tls"))]
    fn get_or_build_client(&self, proxy_url: Option<&str>) -> Result<reqwest::Client, ProviderError> {
        let mut cached_p = self.cached_proxy_url.lock().unwrap();
        let mut cached_c = self.cached_client.lock().unwrap();
        let wanted = proxy_url.map(ToOwned::to_owned);
        if *cached_p == wanted
            && let Some(ref client) = *cached_c
        {
            return Ok(client.clone());
        }
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(120));
        if let Some(p) = proxy_url {
            let proxy = reqwest::Proxy::all(p).map_err(|e| ProviderError {
                kind: ProviderErrorKind::TunnelError,
                status: 502,
                message: e.to_string(),
            })?;
            builder = builder.proxy(proxy);
        }
        let client = builder.build().map_err(|e| ProviderError {
            kind: ProviderErrorKind::TunnelError,
            status: 502,
            message: e.to_string(),
        })?;
        *cached_p = wanted;
        *cached_c = Some(client.clone());
        Ok(client)
    }

    #[cfg(not(feature = "boring-tls"))]
    async fn dispatch_http(
        &self,
        url: &str,
        format: WireFormat,
        body: &Value,
        session_id: &str,
        proxy_url: Option<&str>,
        aliased_tools: HashMap<String, String>,
    ) -> Result<UpstreamResponse, ProviderError> {
        let client = self.get_or_build_client(proxy_url)?;
        let mut req = client
            .post(url)
            .header("Authorization", "Bearer public")
            .header("User-Agent", &self.profile.user_agent)
            .header("x-opencode-client", &self.profile.client_header)
            .header("x-opencode-session", session_id)
            .header("x-opencode-session-id", session_id)
            .header("x-session-affinity", session_id)
            .header("x-session-id", session_id)
            .header("x-opencode-project", &self.profile.project_header)
            .json(body);
        if format == WireFormat::AnthropicMessages {
            req = req.header("anthropic-version", &self.profile.anthropic_version);
        }

        let resp = req.send().await.map_err(|e| ProviderError {
            kind: ProviderErrorKind::TunnelError,
            status: 502,
            message: e.to_string(),
        })?;

        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("text/event-stream")
            .to_string();

        if status >= 400 {
            let raw = resp.bytes().await.unwrap_or_default();
            let peek = String::from_utf8_lossy(&raw[..raw.len().min(ERROR_PEEK_CAP)]).to_string();
            return Err(ProviderError {
                kind: Self::classify_error(status, &peek),
                status,
                message: peek,
            });
        }

        let is_sse = content_type.contains("text/event-stream");
        let stream = resp.bytes_stream().map(move |chunk| match chunk {
            Ok(b) => {
                if aliased_tools.is_empty() {
                    Ok(b)
                } else {
                    let text = String::from_utf8_lossy(&b);
                    Ok(Bytes::from(restore_tool_names_in_text(&text, &aliased_tools)))
                }
            }
            Err(e) => Err(e.to_string()),
        });

        Ok(UpstreamResponse {
            status,
            content_type,
            is_sse,
            stream: Box::pin(stream),
        })
    }

    #[cfg(feature = "boring-tls")]
    fn get_or_build_wreq(&self, proxy_url: Option<&str>) -> Result<wreq::Client, ProviderError> {
        let mut cached_p = self.cached_proxy_url.lock().unwrap();
        let mut cached_c = self.cached_wreq.lock().unwrap();
        let wanted = proxy_url.map(ToOwned::to_owned);
        if *cached_p == wanted
            && let Some(ref client) = *cached_c
        {
            return Ok(client.clone());
        }
        let cipher_list = self.profile.cipher_list.join(":");
        let mut builder = wreq::Client::builder()
            .timeout(Duration::from_secs(120))
            .tls_cipher_list(cipher_list);
        if let Some(p) = proxy_url {
            let proxy = wreq::Proxy::all(p).map_err(|e| ProviderError {
                kind: ProviderErrorKind::TunnelError,
                status: 502,
                message: e.to_string(),
            })?;
            builder = builder.proxy(proxy);
        }
        let client = builder.build().map_err(|e| ProviderError {
            kind: ProviderErrorKind::TunnelError,
            status: 502,
            message: e.to_string(),
        })?;
        *cached_p = wanted;
        *cached_c = Some(client.clone());
        Ok(client)
    }

    #[cfg(feature = "boring-tls")]
    async fn dispatch_http(
        &self,
        url: &str,
        format: WireFormat,
        body: &Value,
        session_id: &str,
        proxy_url: Option<&str>,
        aliased_tools: HashMap<String, String>,
    ) -> Result<UpstreamResponse, ProviderError> {
        let client = self.get_or_build_wreq(proxy_url)?;
        let mut req = client
            .post(url)
            .header("Authorization", "Bearer public")
            .header("User-Agent", &self.profile.user_agent)
            .header("x-opencode-client", &self.profile.client_header)
            .header("x-opencode-session", session_id)
            .header("x-opencode-session-id", session_id)
            .header("x-session-affinity", session_id)
            .header("x-session-id", session_id)
            .header("x-opencode-project", &self.profile.project_header)
            .json(body);
        if format == WireFormat::AnthropicMessages {
            req = req.header("anthropic-version", &self.profile.anthropic_version);
        }

        let resp = req.send().await.map_err(|e| ProviderError {
            kind: ProviderErrorKind::TunnelError,
            status: 502,
            message: e.to_string(),
        })?;

        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("text/event-stream")
            .to_string();

        if status >= 400 {
            let raw = resp.bytes().await.unwrap_or_default();
            let peek = String::from_utf8_lossy(&raw[..raw.len().min(ERROR_PEEK_CAP)]).to_string();
            return Err(ProviderError {
                kind: Self::classify_error(status, &peek),
                status,
                message: peek,
            });
        }

        let is_sse = content_type.contains("text/event-stream");
        let stream = resp.bytes_stream().map(move |chunk| match chunk {
            Ok(b) => {
                if aliased_tools.is_empty() {
                    Ok(b)
                } else {
                    let text = String::from_utf8_lossy(&b);
                    Ok(Bytes::from(restore_tool_names_in_text(&text, &aliased_tools)))
                }
            }
            Err(e) => Err(e.to_string()),
        });

        Ok(UpstreamResponse {
            status,
            content_type,
            is_sse,
            stream: Box::pin(stream),
        })
    }
}
