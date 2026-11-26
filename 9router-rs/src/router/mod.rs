pub mod budget;

use crate::config::schema::{AppConfig, ProviderSettings};
use crate::config::secrets::SecretsBundle;
use crate::hma::manager::HmaManager;
use crate::providers::anthropic::AnthropicAdapter;
use crate::providers::openai::OpenAiAdapter;
use crate::providers::opencode::OpenCodeAdapter;
use crate::providers::{ProviderError, ProviderErrorKind, ProviderId, UpstreamResponse};
use crate::telemetry::{FallbackEventRecord, TelemetryHub};
use crate::translator;
use crate::translator::ir::WireFormat;
use arc_swap::ArcSwap;
use budget::BudgetTracker;
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

const UNSUPPORTED_OAUTH_PREFIXES: &[&str] = &[
    "kiro/",
    "cursor/",
    "gemini/",
    "vertex/",
    "antigravity/",
    "copilot/",
    "github/",
    "codex/",
    "qoder/",
    "iflow/",
    "bedrock/",
    "azure/",
    "ollama/",
    "deepseek-web/",
    "chatgpt-web/",
];

#[derive(Debug, Clone)]
pub enum RouteResolveError {
    UnsupportedProvider(String),
    ModelNotFound(String),
}

#[derive(Debug, Clone)]
pub struct RouteTarget {
    pub provider: ProviderId,
    pub upstream_model: String,
}

pub struct RoutedOutcome {
    pub provider: ProviderId,
    pub egress: String,
    pub fallback_count: u8,
    pub response: UpstreamResponse,
}

pub struct RouterEngine {
    pub config: Arc<ArcSwap<AppConfig>>,
    pub secrets: Arc<ArcSwap<SecretsBundle>>,
    pub hma: Arc<HmaManager>,
    pub opencode: Arc<OpenCodeAdapter>,
    pub openai: Arc<OpenAiAdapter>,
    pub anthropic: Arc<AnthropicAdapter>,
    pub budget: Arc<BudgetTracker>,
    pub telemetry: Arc<TelemetryHub>,
    opencode_sem: Arc<Semaphore>,
    openai_sem: Arc<Semaphore>,
    anthropic_sem: Arc<Semaphore>,
}

impl RouterEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<ArcSwap<AppConfig>>,
        secrets: Arc<ArcSwap<SecretsBundle>>,
        hma: Arc<HmaManager>,
        opencode: Arc<OpenCodeAdapter>,
        openai: Arc<OpenAiAdapter>,
        anthropic: Arc<AnthropicAdapter>,
        budget: Arc<BudgetTracker>,
        telemetry: Arc<TelemetryHub>,
    ) -> Self {
        let cfg = config.load();
        let oc_permits = cfg.providers.opencode.max_concurrency.max(1);
        let oa_permits = cfg.providers.openai.max_concurrency.max(1);
        let an_permits = cfg.providers.anthropic.max_concurrency.max(1);
        Self {
            config,
            secrets,
            hma,
            opencode,
            openai,
            anthropic,
            budget,
            telemetry,
            opencode_sem: Arc::new(Semaphore::new(oc_permits)),
            openai_sem: Arc::new(Semaphore::new(oa_permits)),
            anthropic_sem: Arc::new(Semaphore::new(an_permits)),
        }
    }

    pub fn resolve_target(
        cfg: &AppConfig,
        raw_model: &str,
    ) -> Result<RouteTarget, RouteResolveError> {
        let m = raw_model.trim();
        let lower = m.to_ascii_lowercase();
        for bad in UNSUPPORTED_OAUTH_PREFIXES {
            if lower.starts_with(bad) {
                return Err(RouteResolveError::UnsupportedProvider(format!(
                    "Provider prefix '{bad}' is not supported in 9router-rs (only opencode, openai, anthropic)"
                )));
            }
        }
        if let Some((prefix, rest)) = m.split_once('/') {
            if let Some(provider) = ProviderId::from_name(prefix) {
                return Ok(RouteTarget {
                    provider,
                    upstream_model: rest.to_string(),
                });
            }
            return Err(RouteResolveError::UnsupportedProvider(format!(
                "Unsupported provider prefix '{prefix}/'"
            )));
        }
        if let Some(mapped) = cfg.routing.unprefixed_model_map.get(m)
            && let Some(provider) = ProviderId::from_name(mapped)
        {
            return Ok(RouteTarget {
                provider,
                upstream_model: m.to_string(),
            });
        }
        Err(RouteResolveError::ModelNotFound(format!(
            "Model '{m}' is not mapped to opencode, openai, or anthropic"
        )))
    }

    pub fn rewrite_fallback_model(
        cfg: &AppConfig,
        original_model: &str,
        target: ProviderId,
    ) -> String {
        let key = format!("{}->{}", original_model, target.as_str());
        if let Some(explicit) = cfg.fallback.model_fallback_map.get(&key) {
            return explicit.clone();
        }
        cfg.fallback
            .default_models
            .get(target.as_str())
            .cloned()
            .unwrap_or_else(|| original_model.to_string())
    }

    fn settings_for(cfg: &AppConfig, provider: ProviderId) -> &ProviderSettings {
        match provider {
            ProviderId::OpenCode => &cfg.providers.opencode,
            ProviderId::OpenAi => &cfg.providers.openai,
            ProviderId::Anthropic => &cfg.providers.anthropic,
        }
    }

    fn semaphore_for(&self, provider: ProviderId) -> &Arc<Semaphore> {
        match provider {
            ProviderId::OpenCode => &self.opencode_sem,
            ProviderId::OpenAi => &self.openai_sem,
            ProviderId::Anthropic => &self.anthropic_sem,
        }
    }

    pub async fn route_request(
        &self,
        request_id: &str,
        inbound_format: WireFormat,
        raw_body: Value,
        session_key: &str,
    ) -> Result<RoutedOutcome, (u16, String, String)> {
        let cfg = self.config.load();
        let secrets = self.secrets.load();

        let raw_model = raw_body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let primary = Self::resolve_target(&cfg, &raw_model).map_err(|e| match e {
            RouteResolveError::UnsupportedProvider(msg) => {
                (400, "unsupported_provider".into(), msg)
            }
            RouteResolveError::ModelNotFound(msg) => (404, "model_not_found".into(), msg),
        })?;

        // Build candidate chain: primary first, then configured fallback providers
        let mut chain = vec![primary.clone()];
        for name in &cfg.fallback.order {
            if let Some(pid) = ProviderId::from_name(name)
                && pid != primary.provider
            {
                let rewritten = Self::rewrite_fallback_model(&cfg, &primary.upstream_model, pid);
                chain.push(RouteTarget {
                    provider: pid,
                    upstream_model: rewritten,
                });
            }
        }

        let mut last_err: Option<ProviderError> = None;
        for (attempt_idx, target) in chain.iter().enumerate() {
            let is_fallback = attempt_idx > 0;
            if is_fallback && !primary.provider.is_paid() && target.provider.is_paid() {
                if !cfg.fallback.allow_free_to_paid {
                    continue;
                }
                if let Err(budget_msg) = self.budget.check_budget(&cfg.budget, session_key) {
                    return Err((429, "budget_exceeded".to_string(), budget_msg));
                }
            }

            let psettings = Self::settings_for(&cfg, target.provider);
            if !psettings.enabled {
                continue;
            }

            let _permit = self
                .semaphore_for(target.provider)
                .acquire()
                .await
                .map_err(|e| (503, "concurrency_error".to_string(), e.to_string()))?;

            let proxy_url = if psettings.use_hma {
                self.hma.active_proxy_url()
            } else {
                None
            };
            let egress = if proxy_url.is_some() { "hma" } else { "direct" }.to_string();

            let upstream_format = target.provider.native_format(&target.upstream_model);
            let same_format = inbound_format == upstream_format;

            let mut outgoing_body = if same_format {
                let mut cloned = raw_body.clone();
                cloned["model"] = Value::String(target.upstream_model.clone());
                cloned
            } else {
                let mut ir = translator::decode_request(inbound_format, &raw_body)
                    .map_err(|e| (400, "invalid_request".to_string(), e.to_string()))?;
                ir.model = target.upstream_model.clone();
                translator::encode_request(upstream_format, &ir)
            };
            outgoing_body["model"] = Value::String(target.upstream_model.clone());

            let max_tries = (psettings.max_retries as usize) + 1;
            for retry_idx in 0..max_tries {
                let dispatch_res = match target.provider {
                    ProviderId::OpenCode => self
                        .opencode
                        .send(
                            upstream_format,
                            outgoing_body.clone(),
                            session_key,
                            proxy_url.as_deref(),
                        )
                        .await
                        .map(|(resp, _)| resp),
                    ProviderId::OpenAi => match secrets.openai_api_key.as_deref() {
                        Some(key) => {
                            self.openai
                                .send(upstream_format, &outgoing_body, key, proxy_url.as_deref())
                                .await
                        }
                        None => Err(ProviderError {
                            kind: ProviderErrorKind::AuthFailed,
                            status: 401,
                            message: "OpenAI API key is not configured".to_string(),
                        }),
                    },
                    ProviderId::Anthropic => match secrets.anthropic_api_key.as_deref() {
                        Some(key) => {
                            self.anthropic
                                .send(&outgoing_body, key, proxy_url.as_deref())
                                .await
                        }
                        None => Err(ProviderError {
                            kind: ProviderErrorKind::AuthFailed,
                            status: 401,
                            message: "Anthropic API key is not configured".to_string(),
                        }),
                    },
                };

                match dispatch_res {
                    Ok(mut resp) => {
                        if is_fallback {
                            self.telemetry.record_fallback(FallbackEventRecord {
                                ts_utc: chrono::Utc::now().to_rfc3339(),
                                request_id: request_id.to_string(),
                                from: primary.provider.as_str().to_string(),
                                to: target.provider.as_str().to_string(),
                                reason: last_err
                                    .as_ref()
                                    .map(|e| e.to_string())
                                    .unwrap_or_else(|| "fallback".to_string()),
                            });
                        }
                        // If cross-format SSE, translate stream chunks back into inbound_format
                        if !same_format && resp.is_sse {
                            let model_for_sse = target.upstream_model.clone();
                            let src_stream = resp.stream;
                            let translated =
                                src_stream.map(move |chunk: Result<Bytes, String>| match chunk {
                                    Ok(b) => {
                                        let text = String::from_utf8_lossy(&b);
                                        let mut out = String::new();
                                        for line in text.lines() {
                                            if let Some(data) = line.strip_prefix("data: ") {
                                                for ev in translator::decode_sse_chunk(
                                                    upstream_format,
                                                    None,
                                                    data,
                                                ) {
                                                    for encoded in translator::encode_sse_event(
                                                        inbound_format,
                                                        &ev,
                                                        &model_for_sse,
                                                    ) {
                                                        out.push_str(&encoded);
                                                    }
                                                }
                                            }
                                        }
                                        Ok(Bytes::from(out))
                                    }
                                    Err(e) => Err(e),
                                });
                            resp.stream = Box::pin(translated);
                        }
                        return Ok(RoutedOutcome {
                            provider: target.provider,
                            egress,
                            fallback_count: attempt_idx as u8,
                            response: resp,
                        });
                    }
                    Err(err) => {
                        let retryable = matches!(
                            err.kind,
                            ProviderErrorKind::Overloaded | ProviderErrorKind::Upstream5xx
                        );
                        last_err = Some(err);
                        if retryable && retry_idx + 1 < max_tries {
                            let delay = psettings
                                .base_backoff_ms
                                .saturating_mul(1u64 << retry_idx.min(4))
                                .min(psettings.max_backoff_ms);
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                            continue;
                        }
                        break;
                    }
                }
            }
        }

        let err = last_err.unwrap_or(ProviderError {
            kind: ProviderErrorKind::Upstream5xx,
            status: 503,
            message: "All configured providers failed".to_string(),
        });
        Err((err.status, format!("{:?}", err.kind), err.message))
    }
}
