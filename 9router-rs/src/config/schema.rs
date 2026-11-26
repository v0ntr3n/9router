use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub schema_version: u32,
    pub server: ServerConfig,
    pub providers: ProvidersConfig,
    pub routing: RoutingConfig,
    pub fallback: FallbackConfig,
    pub budget: BudgetConfig,
    pub rtk: RtkConfig,
    pub hma: HmaConfig,
    pub logging: LoggingConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            server: ServerConfig::default(),
            providers: ProvidersConfig::default(),
            routing: RoutingConfig::default(),
            fallback: FallbackConfig::default(),
            budget: BudgetConfig::default(),
            rtk: RtkConfig::default(),
            hma: HmaConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn validate(&self) -> Result<()> {
        if self.server.port < 1024 {
            bail!("server.port must be >= 1024");
        }
        if !matches!(
            self.rtk.ponytail_level.as_str(),
            "off" | "lite" | "full" | "ultra"
        ) {
            bail!("rtk.ponytail_level must be one of: off, lite, full, ultra");
        }
        if !matches!(
            self.rtk.caveman_level.as_str(),
            "off" | "lite" | "full" | "ultra"
        ) {
            bail!("rtk.caveman_level must be one of: off, lite, full, ultra");
        }
        if self.budget.session_usd_cap < 0.0 || self.budget.daily_usd_cap < 0.0 {
            bail!("budget USD caps must be non-negative");
        }
        if self.fallback.hma_rotation_cooldown_secs < 5 {
            bail!("fallback.hma_rotation_cooldown_secs must be >= 5");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub port: u16,
    pub bind: String,
    pub require_local_api_key: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 20128,
            bind: "127.0.0.1".to_string(),
            require_local_api_key: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderSettings {
    pub enabled: bool,
    pub use_hma: bool,
    pub max_concurrency: usize,
    pub max_retries: u8,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for ProviderSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            use_hma: false,
            max_concurrency: 8,
            max_retries: 2,
            base_backoff_ms: 800,
            max_backoff_ms: 4000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProvidersConfig {
    pub opencode: ProviderSettings,
    pub openai: ProviderSettings,
    pub anthropic: ProviderSettings,
}

impl Default for ProvidersConfig {
    fn default() -> Self {
        Self {
            opencode: ProviderSettings {
                enabled: true,
                use_hma: true,
                ..Default::default()
            },
            openai: ProviderSettings::default(),
            anthropic: ProviderSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    pub default_provider: String,
    pub unprefixed_model_map: BTreeMap<String, String>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        let mut map = BTreeMap::new();
        map.insert("gpt-5-nano".to_string(), "opencode".to_string());
        map.insert("big-pickle".to_string(), "opencode".to_string());
        map.insert("glm-4.7-free".to_string(), "opencode".to_string());
        map.insert("kimi-k2.5-free".to_string(), "opencode".to_string());
        map.insert("minimax-m2.5-free".to_string(), "opencode".to_string());
        map.insert("gpt-4.1".to_string(), "openai".to_string());
        map.insert("gpt-4.1-mini".to_string(), "openai".to_string());
        map.insert("gpt-4o".to_string(), "openai".to_string());
        map.insert("claude-sonnet-4-5".to_string(), "anthropic".to_string());
        map.insert("claude-opus-4-1".to_string(), "anthropic".to_string());
        map.insert("claude-haiku-3-5".to_string(), "anthropic".to_string());
        Self {
            default_provider: "opencode".to_string(),
            unprefixed_model_map: map,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FallbackConfig {
    pub allow_free_to_paid: bool,
    pub order: Vec<String>,
    pub default_models: BTreeMap<String, String>,
    pub model_fallback_map: BTreeMap<String, String>,
    pub rotate_hma_on_429: bool,
    pub hma_rotation_cooldown_secs: u64,
}

impl Default for FallbackConfig {
    fn default() -> Self {
        let mut defaults = BTreeMap::new();
        defaults.insert("anthropic".to_string(), "claude-sonnet-4-5".to_string());
        defaults.insert("openai".to_string(), "gpt-4.1".to_string());
        defaults.insert("opencode".to_string(), "big-pickle".to_string());
        Self {
            allow_free_to_paid: false,
            order: vec![
                "opencode".to_string(),
                "anthropic".to_string(),
                "openai".to_string(),
            ],
            default_models: defaults,
            model_fallback_map: BTreeMap::new(),
            rotate_hma_on_429: true,
            hma_rotation_cooldown_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BudgetConfig {
    pub session_usd_cap: f64,
    pub daily_usd_cap: f64,
    pub daily_token_cap: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            session_usd_cap: 1.0,
            daily_usd_cap: 5.0,
            daily_token_cap: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RtkConfig {
    pub enabled: bool,
    pub caveman_level: String,
    pub ponytail_level: String,
    pub custom_prompt: String,
}

impl Default for RtkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            caveman_level: "off".to_string(),
            ponytail_level: "off".to_string(),
            custom_prompt: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HmaConfig {
    pub country: String,
    pub city: String,
    pub auto_connect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub max_total_mb: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            max_total_mb: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct OpenCodeProfile {
    pub user_agent: String,
    pub client_header: String,
    pub project_header: String,
    pub anthropic_version: String,
    pub base_url_chat: String,
    pub base_url_responses: String,
    pub base_url_messages: String,
    pub env_marker: String,
    pub cipher_list: Vec<String>,
    pub model_endpoints: BTreeMap<String, String>,
}

impl OpenCodeProfile {
    pub fn merge_override(mut self, ov: Self) -> Self {
        if !ov.user_agent.is_empty() {
            self.user_agent = ov.user_agent;
        }
        if !ov.client_header.is_empty() {
            self.client_header = ov.client_header;
        }
        if !ov.project_header.is_empty() {
            self.project_header = ov.project_header;
        }
        if !ov.anthropic_version.is_empty() {
            self.anthropic_version = ov.anthropic_version;
        }
        if !ov.base_url_chat.is_empty() {
            self.base_url_chat = ov.base_url_chat;
        }
        if !ov.base_url_responses.is_empty() {
            self.base_url_responses = ov.base_url_responses;
        }
        if !ov.base_url_messages.is_empty() {
            self.base_url_messages = ov.base_url_messages;
        }
        if !ov.env_marker.is_empty() {
            self.env_marker = ov.env_marker;
        }
        if !ov.cipher_list.is_empty() {
            self.cipher_list = ov.cipher_list;
        }
        for (k, v) in ov.model_endpoints {
            self.model_endpoints.insert(k, v);
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelPrice {
    pub input_per_m: f64,
    pub output_per_m: f64,
}

impl Default for ModelPrice {
    fn default() -> Self {
        Self {
            input_per_m: 15.0,
            output_per_m: 75.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PricingConfig {
    pub unknown_input_per_m: f64,
    pub unknown_output_per_m: f64,
    pub models: BTreeMap<String, ModelPrice>,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            unknown_input_per_m: 15.0,
            unknown_output_per_m: 75.0,
            models: BTreeMap::new(),
        }
    }
}

impl PricingConfig {
    pub fn estimate_usd(&self, model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
        let (in_rate, out_rate) = self
            .models
            .get(model)
            .map(|p| (p.input_per_m, p.output_per_m))
            .unwrap_or((self.unknown_input_per_m, self.unknown_output_per_m));
        (input_tokens as f64 / 1_000_000.0) * in_rate
            + (output_tokens as f64 / 1_000_000.0) * out_rate
    }
}
