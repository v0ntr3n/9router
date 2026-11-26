use crate::config::atomic_write;
use crate::config::schema::{BudgetConfig, PricingConfig};
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyUsageRecord {
    pub date_utc: String,
    pub usd_spent: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl DailyUsageRecord {
    pub fn today() -> Self {
        Self {
            date_utc: Utc::now().format("%Y-%m-%d").to_string(),
            usd_spent: 0.0,
            input_tokens: 0,
            output_tokens: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct SessionSpend {
    usd: f64,
    window_start: Instant,
}

pub struct BudgetTracker {
    data_dir: PathBuf,
    pricing: PricingConfig,
    daily: Mutex<DailyUsageRecord>,
    sessions: Mutex<HashMap<String, SessionSpend>>,
}

impl BudgetTracker {
    pub fn load(data_dir: &Path, pricing: PricingConfig) -> Self {
        let path = data_dir.join("usage_daily.json");
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let daily = fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<DailyUsageRecord>(&raw).ok())
            .filter(|r| r.date_utc == today)
            .unwrap_or_else(DailyUsageRecord::today);

        Self {
            data_dir: data_dir.to_path_buf(),
            pricing,
            daily: Mutex::new(daily),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn ensure_today_utc(rec: &mut DailyUsageRecord) {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        if rec.date_utc != today {
            *rec = DailyUsageRecord {
                date_utc: today,
                usd_spent: 0.0,
                input_tokens: 0,
                output_tokens: 0,
            };
        }
    }

    pub fn check_budget(&self, cfg: &BudgetConfig, session_key: &str) -> Result<(), String> {
        let mut daily = self.daily.lock().unwrap();
        Self::ensure_today_utc(&mut daily);

        if cfg.daily_usd_cap > 0.0 && daily.usd_spent >= cfg.daily_usd_cap {
            return Err(format!(
                "Daily spend cap (${:.2}) reached (${:.4} spent today UTC)",
                cfg.daily_usd_cap, daily.usd_spent
            ));
        }
        if cfg.daily_token_cap > 0
            && (daily.input_tokens + daily.output_tokens) >= cfg.daily_token_cap
        {
            return Err(format!(
                "Daily token cap ({}) reached",
                cfg.daily_token_cap
            ));
        }

        let mut sessions = self.sessions.lock().unwrap();
        if let Some(sess) = sessions.get_mut(session_key) {
            if sess.window_start.elapsed() >= Duration::from_secs(3600) {
                sess.usd = 0.0;
                sess.window_start = Instant::now();
            }
            if cfg.session_usd_cap > 0.0 && sess.usd >= cfg.session_usd_cap {
                return Err(format!(
                    "Session spend cap (${:.2}) reached (${:.4} spent)",
                    cfg.session_usd_cap, sess.usd
                ));
            }
        }
        Ok(())
    }

    pub fn record_paid_usage(
        &self,
        session_key: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> f64 {
        let usd = self.pricing.estimate_usd(model, input_tokens, output_tokens);
        {
            let mut daily = self.daily.lock().unwrap();
            Self::ensure_today_utc(&mut daily);
            daily.usd_spent += usd;
            daily.input_tokens += input_tokens;
            daily.output_tokens += output_tokens;
            if let Ok(bytes) = serde_json::to_vec_pretty(&*daily) {
                let _ = atomic_write(&self.data_dir.join("usage_daily.json"), &bytes);
            }
        }
        {
            let mut sessions = self.sessions.lock().unwrap();
            let entry = sessions
                .entry(session_key.to_string())
                .or_insert_with(|| SessionSpend {
                    usd: 0.0,
                    window_start: Instant::now(),
                });
            if entry.window_start.elapsed() >= Duration::from_secs(3600) {
                entry.usd = 0.0;
                entry.window_start = Instant::now();
            }
            entry.usd += usd;
        }
        usd
    }

    pub fn estimate_tokens_from_bytes(bytes: usize) -> u64 {
        bytes.div_ceil(4) as u64
    }

    pub fn snapshot(&self, session_key: &str) -> (f64, DailyUsageRecord) {
        let mut daily = self.daily.lock().unwrap();
        Self::ensure_today_utc(&mut daily);
        let sess_usd = self
            .sessions
            .lock()
            .unwrap()
            .get(session_key)
            .map(|s| s.usd)
            .unwrap_or(0.0);
        (sess_usd, daily.clone())
    }
}
