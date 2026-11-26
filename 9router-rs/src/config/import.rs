use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use super::secrets::{SecretsBundle, load_secrets, save_secrets};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub imported_providers: Vec<String>,
    pub imported_hma: bool,
    pub skipped: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LegacyHmaState {
    wallet_key: Option<String>,
    container_id: Option<String>,
    device_fingerprint: Option<String>,
    device_udid: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

pub fn default_legacy_sqlite_path() -> Option<PathBuf> {
    #[cfg(windows)]
    if let Ok(appdata) = std::env::var("APPDATA") {
        return Some(
            PathBuf::from(appdata)
                .join("9router")
                .join("db")
                .join("data.sqlite"),
        );
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".9router").join("db").join("data.sqlite"))
}

pub fn default_legacy_hma_state_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(dir) = std::env::var("HMA_PROXY_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            paths.push(PathBuf::from(trimmed).join("state.json"));
        }
    }
    #[cfg(windows)]
    if let Ok(appdata) = std::env::var("APPDATA") {
        paths.push(PathBuf::from(&appdata).join("hma-proxy").join("state.json"));
        paths.push(
            PathBuf::from(appdata)
                .join("9router")
                .join("hma-proxy")
                .join("state.json"),
        );
    }
    if let Ok(home) = std::env::var("HOME") {
        paths.push(
            PathBuf::from(&home)
                .join(".config")
                .join("hma-proxy")
                .join("state.json"),
        );
        paths.push(
            PathBuf::from(home)
                .join(".9router")
                .join("hma-proxy")
                .join("state.json"),
        );
    }
    paths
}

pub fn import_legacy_from_paths(
    data_dir: &Path,
    sqlite_path: Option<&Path>,
    hma_state_path: Option<&Path>,
    overwrite: bool,
) -> Result<ImportResult> {
    let mut bundle: SecretsBundle = load_secrets(data_dir)?;
    let mut imported_providers = Vec::new();
    let mut skipped = Vec::new();
    let mut imported_hma = false;

    if let Some(db_path) = sqlite_path.filter(|p| p.exists()) {
        let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("failed to open legacy sqlite {}", db_path.display()))?;
        let mut stmt = conn.prepare(
            "SELECT provider, data FROM providerConnections \
             WHERE provider IN ('openai', 'anthropic') \
               AND authType = 'apikey' \
               AND isActive = 1 \
             ORDER BY updatedAt DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let provider: String = row.get(0)?;
            let data: String = row.get(1)?;
            Ok((provider, data))
        })?;

        let mut seen_openai = false;
        let mut seen_anthropic = false;
        for row in rows.flatten() {
            let (provider, data_raw) = row;
            let parsed: serde_json::Value = match serde_json::from_str(&data_raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let api_key = parsed
                .get("apiKey")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned);
            let Some(key) = api_key else { continue };

            if provider == "openai" && !seen_openai {
                seen_openai = true;
                if overwrite || bundle.openai_api_key.is_none() {
                    bundle.openai_api_key = Some(key);
                    imported_providers.push("openai".to_string());
                } else {
                    skipped.push("openai".to_string());
                }
            } else if provider == "anthropic" && !seen_anthropic {
                seen_anthropic = true;
                if overwrite || bundle.anthropic_api_key.is_none() {
                    bundle.anthropic_api_key = Some(key);
                    imported_providers.push("anthropic".to_string());
                } else {
                    skipped.push("anthropic".to_string());
                }
            }
        }
    }

    if let Some(state_path) = hma_state_path.filter(|p| p.exists()) {
        let raw = fs::read_to_string(state_path)
            .with_context(|| format!("failed to read {}", state_path.display()))?;
        let st: LegacyHmaState = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse {}", state_path.display()))?;
        let has_token = st
            .access_token
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
        if has_token {
            if overwrite || !bundle.hma_activated() {
                bundle.hma_wallet_key = st.wallet_key;
                bundle.hma_container_id = st.container_id;
                bundle.hma_device_fingerprint = st.device_fingerprint;
                bundle.hma_device_udid = st.device_udid;
                bundle.hma_access_token = st.access_token;
                bundle.hma_refresh_token = st.refresh_token;
                imported_hma = true;
            } else {
                skipped.push("hma".to_string());
            }
        }
    }

    if !imported_providers.is_empty() || imported_hma {
        save_secrets(data_dir, &bundle)?;
    }

    Ok(ImportResult {
        imported_providers,
        imported_hma,
        skipped,
    })
}

pub fn import_legacy_defaults(data_dir: &Path, overwrite: bool) -> Result<ImportResult> {
    let sqlite = default_legacy_sqlite_path();
    let hma = default_legacy_hma_state_paths()
        .into_iter()
        .find(|p| p.exists());
    import_legacy_from_paths(data_dir, sqlite.as_deref(), hma.as_deref(), overwrite)
}
