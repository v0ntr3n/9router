use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::reload;

pub const MAX_RECENT_EVENTS: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEventRecord {
    pub ts_utc: String,
    pub request_id: String,
    pub provider: String,
    pub egress: String,
    pub status: u16,
    pub ttft_ms: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub fallback_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackEventRecord {
    pub ts_utc: String,
    pub request_id: String,
    pub from: String,
    pub to: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RtkStatsSnapshot {
    pub requests_compressed: u64,
    pub tokens_saved_est: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    pub version: String,
    pub git_sha: String,
    pub target: String,
    pub build_timestamp: String,
}

impl BuildInfo {
    pub fn current() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_sha: option_env!("NINEROUTER_GIT_SHA")
                .unwrap_or("unknown")
                .to_string(),
            target: option_env!("NINEROUTER_TARGET")
                .unwrap_or("unknown")
                .to_string(),
            build_timestamp: option_env!("NINEROUTER_BUILD_TIMESTAMP")
                .unwrap_or("0")
                .to_string(),
        }
    }
}

pub struct TelemetryHub {
    recent_requests: Mutex<VecDeque<RequestEventRecord>>,
    recent_fallbacks: Mutex<VecDeque<FallbackEventRecord>>,
    rtk_stats: Mutex<RtkStatsSnapshot>,
    reload_handle: Option<Arc<dyn Fn(&str) -> Result<()> + Send + Sync>>,
}

impl TelemetryHub {
    pub fn new(reload_handle: Option<Arc<dyn Fn(&str) -> Result<()> + Send + Sync>>) -> Self {
        Self {
            recent_requests: Mutex::new(VecDeque::with_capacity(MAX_RECENT_EVENTS)),
            recent_fallbacks: Mutex::new(VecDeque::with_capacity(MAX_RECENT_EVENTS)),
            rtk_stats: Mutex::new(RtkStatsSnapshot::default()),
            reload_handle,
        }
    }

    pub fn record_request(&self, ev: RequestEventRecord) {
        if let Ok(mut q) = self.recent_requests.lock() {
            if q.len() >= MAX_RECENT_EVENTS {
                q.pop_front();
            }
            q.push_back(ev);
        }
    }

    pub fn record_fallback(&self, mut ev: FallbackEventRecord) {
        ev.reason = redact_secrets(&ev.reason);
        if let Ok(mut q) = self.recent_fallbacks.lock() {
            if q.len() >= MAX_RECENT_EVENTS {
                q.pop_front();
            }
            q.push_back(ev);
        }
    }

    pub fn record_rtk_savings(&self, tokens_saved: u64) {
        if tokens_saved == 0 {
            return;
        }
        if let Ok(mut stats) = self.rtk_stats.lock() {
            stats.requests_compressed += 1;
            stats.tokens_saved_est += tokens_saved;
        }
    }

    pub fn recent_requests(&self) -> Vec<RequestEventRecord> {
        self.recent_requests
            .lock()
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn recent_fallbacks(&self) -> Vec<FallbackEventRecord> {
        self.recent_fallbacks
            .lock()
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn rtk_stats(&self) -> RtkStatsSnapshot {
        self.rtk_stats
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    pub fn set_log_level(&self, level: &str) -> Result<()> {
        if let Some(ref handle) = self.reload_handle {
            handle(level)?;
        }
        Ok(())
    }
}

fn secret_patterns() -> &'static Vec<Regex> {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            Regex::new(r"(?i)(Bearer\s+)[A-Za-z0-9._\-+/=]{8,}").unwrap(),
            Regex::new(r"(?i)(x-api-key\s*[:=]\s*)[A-Za-z0-9._\-+/=]{8,}").unwrap(),
            Regex::new(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{12,}\b").unwrap(),
            Regex::new(r"\b[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}\b").unwrap(),
            Regex::new(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}").unwrap(),
            Regex::new(r"(?i)(https?://|socks5://)([^:@/\s]+):([^@/\s]+)@").unwrap(),
            Regex::new(r"(?i)(private_key|wallet_key|access_token|refresh_token|api_key)\s*[:=]\s*\x22?[^\s,\x22}]+").unwrap(),
        ]
    })
}

/// Redacts API keys, Bearer tokens, JWTs, HMA wallet keys, WireGuard private keys, and proxy credentials.
pub fn redact_secrets(input: &str) -> String {
    let mut out = input.to_string();
    let patterns = secret_patterns();
    out = patterns[0].replace_all(&out, "${1}[REDACTED]").into_owned();
    out = patterns[1].replace_all(&out, "${1}[REDACTED]").into_owned();
    out = patterns[2].replace_all(&out, "[REDACTED_KEY]").into_owned();
    out = patterns[3].replace_all(&out, "[REDACTED_WALLET]").into_owned();
    out = patterns[4].replace_all(&out, "[REDACTED_JWT]").into_owned();
    out = patterns[5].replace_all(&out, "${1}[REDACTED]:[REDACTED]@").into_owned();
    out = patterns[6].replace_all(&out, "${1}=[REDACTED]").into_owned();
    out
}

pub fn init_tracing(
    data_dir: &Path,
    initial_level: &str,
) -> Result<(
    Arc<TelemetryHub>,
    tracing_appender::non_blocking::WorkerGuard,
)> {
    let log_dir = data_dir.join("logs");
    fs::create_dir_all(&log_dir)?;
    let file_appender = tracing_appender::rolling::daily(&log_dir, "9router-rs.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let filter = EnvFilter::try_new(initial_level).unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter_layer, reload_handle) = reload::Layer::new(filter);

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let subscriber = tracing_subscriber::registry()
        .with(filter_layer)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .json(),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false));

    let _ = subscriber.try_init();

    let reload_fn: Arc<dyn Fn(&str) -> Result<()> + Send + Sync> =
        Arc::new(move |lvl: &str| {
            let new_filter = EnvFilter::try_new(lvl)?;
            reload_handle.reload(new_filter)?;
            Ok(())
        });

    Ok((Arc::new(TelemetryHub::new(Some(reload_fn))), guard))
}

pub fn install_panic_hook(data_dir: &Path) {
    let panic_log = data_dir.join("logs").join("panic.log");
    let build = BuildInfo::current();
    std::panic::set_hook(Box::new(move |info| {
        let msg = redact_secrets(&format!(
            "[{}] PANIC version={} sha={} target={}: {}\n",
            chrono::Utc::now().to_rfc3339(),
            build.version,
            build.git_sha,
            build.target,
            info
        ));
        if let Some(parent) = panic_log.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&panic_log)
            .and_then(|mut f| std::io::Write::write_all(&mut f, msg.as_bytes()));
        eprintln!("{msg}");
    }));
}
