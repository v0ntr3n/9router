use super::{ProviderError, ProviderErrorKind, UpstreamResponse};
use crate::translator::ir::WireFormat;
use futures_util::StreamExt;
use serde_json::Value;
use std::time::Duration;

const ERROR_PEEK_CAP: usize = 8 * 1024;

pub struct OpenAiAdapter {
    base_url: String,
}

impl OpenAiAdapter {
    pub fn new(base_url: Option<String>) -> Self {
        Self {
            base_url: base_url.unwrap_or_else(|| "https://api.openai.com".to_string()),
        }
    }

    pub async fn send(
        &self,
        format: WireFormat,
        body: &Value,
        api_key: &str,
        proxy_url: Option<&str>,
    ) -> Result<UpstreamResponse, ProviderError> {
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

        let path = match format {
            WireFormat::OpenAiResponses => "/v1/responses",
            _ => "/v1/chat/completions",
        };
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);

        let resp = client
            .post(&url)
            .bearer_auth(api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| ProviderError {
                kind: ProviderErrorKind::TunnelError,
                status: 502,
                message: e.to_string(),
            })?;

        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();

        if status >= 400 {
            let raw = resp.bytes().await.unwrap_or_default();
            let peek = String::from_utf8_lossy(&raw[..raw.len().min(ERROR_PEEK_CAP)]).to_string();
            let kind = match status {
                401 | 403 => ProviderErrorKind::AuthFailed,
                429 => ProviderErrorKind::Overloaded,
                500..=599 => ProviderErrorKind::Upstream5xx,
                _ => ProviderErrorKind::ClientError(status),
            };
            return Err(ProviderError {
                kind,
                status,
                message: peek,
            });
        }

        let is_sse = content_type.contains("text/event-stream");
        let stream = resp.bytes_stream().map(|c| c.map_err(|e| e.to_string()));
        Ok(UpstreamResponse {
            status,
            content_type,
            is_sse,
            stream: Box::pin(stream),
        })
    }
}
