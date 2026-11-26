pub mod import;
pub mod schema;
pub mod secrets;

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub use schema::{AppConfig, OpenCodeProfile, PricingConfig};
pub use secrets::{SecretMask, SecretsBundle, SecretsStatus};

pub const DEFAULT_OPENCODE_PROFILE_TOML: &str =
    include_str!("../../assets/opencode_profile.default.toml");
pub const DEFAULT_PRICING_TOML: &str = include_str!("../../assets/pricing.default.toml");

pub fn default_data_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("NINEROUTER_DATA_DIR") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("9router-rs");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("9router-rs");
    }
    PathBuf::from(".9router-rs")
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn load_config(data_dir: &Path) -> Result<AppConfig> {
    let path = data_dir.join("config.toml");
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let cfg: AppConfig =
        toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(cfg)
}

pub fn save_config(data_dir: &Path, cfg: &AppConfig) -> Result<()> {
    cfg.validate()?;
    let rendered = toml::to_string_pretty(cfg).context("failed to serialize config.toml")?;
    atomic_write(&data_dir.join("config.toml"), rendered.as_bytes())
}

pub fn load_opencode_profile(data_dir: &Path) -> Result<OpenCodeProfile> {
    let mut base: OpenCodeProfile = toml::from_str(DEFAULT_OPENCODE_PROFILE_TOML)
        .context("failed to parse embedded default opencode profile")?;
    let override_path = data_dir.join("opencode_profile.toml");
    if override_path.exists() {
        let raw = fs::read_to_string(&override_path)
            .with_context(|| format!("failed to read {}", override_path.display()))?;
        let ov: OpenCodeProfile = toml::from_str(&raw)
            .with_context(|| format!("failed to parse {}", override_path.display()))?;
        base = base.merge_override(ov);
    }
    Ok(base)
}

pub fn load_pricing() -> Result<PricingConfig> {
    toml::from_str(DEFAULT_PRICING_TOML).context("failed to parse embedded default pricing")
}
