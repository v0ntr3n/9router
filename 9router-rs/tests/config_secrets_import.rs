use ninerouter_rs::config::import::import_legacy_from_paths;
use ninerouter_rs::config::secrets::{SecretsBundle, load_secrets, save_secrets};
use ninerouter_rs::config::{AppConfig, load_config, save_config};
use rusqlite::Connection;
use std::fs;
use tempfile::tempdir;

#[test]
fn config_tolerates_unknown_future_fields_on_downgrade() {
    let dir = tempdir().unwrap();
    let toml_with_unknown = r#"
schema_version = 2
future_flag = "ignored"

[server]
port = 20129
unknown_server_opt = true

[rtk]
enabled = true
ponytail_level = "full"
"#;
    fs::write(dir.path().join("config.toml"), toml_with_unknown).unwrap();

    let cfg = load_config(dir.path()).unwrap();
    assert_eq!(cfg.server.port, 20129);
    assert_eq!(cfg.rtk.ponytail_level, "full");
    save_config(dir.path(), &cfg).unwrap();
}

#[test]
fn config_rejects_invalid_ponytail_level() {
    let mut cfg = AppConfig::default();
    cfg.rtk.ponytail_level = "invalid".to_string();
    assert!(cfg.validate().is_err());
}

#[test]
fn secrets_roundtrip_and_masking() {
    let dir = tempdir().unwrap();
    let bundle = SecretsBundle {
        openai_api_key: Some("sk-proj-1234567890abcd".to_string()),
        anthropic_api_key: Some("sk-ant-api03-99998888wxyz".to_string()),
        hma_wallet_key: Some("ABCDEF-123456-GHIJKL".to_string()),
        hma_access_token: Some("eyJhbGciOiJIUzI1NiJ9.payload.sig".to_string()),
        ..Default::default()
    };
    save_secrets(dir.path(), &bundle).unwrap();
    let loaded = load_secrets(dir.path()).unwrap();
    assert_eq!(loaded, bundle);

    let status = loaded.status();
    assert!(status.openai.configured);
    assert_eq!(status.openai.last4.as_deref(), Some("abcd"));
    assert!(status.anthropic.configured);
    assert_eq!(status.anthropic.last4.as_deref(), Some("wxyz"));
    assert!(status.hma.configured);
}

#[test]
fn legacy_import_is_readonly_and_respects_skip_vs_overwrite() {
    let dir = tempdir().unwrap();
    let legacy_db = dir.path().join("legacy.sqlite");
    let legacy_hma = dir.path().join("state.json");

    {
        let conn = Connection::open(&legacy_db).unwrap();
        conn.execute(
            "CREATE TABLE providerConnections (
                id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                authType TEXT NOT NULL,
                isActive INTEGER NOT NULL,
                data TEXT NOT NULL,
                updatedAt TEXT NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO providerConnections VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                "1",
                "openai",
                "apikey",
                1,
                r#"{"apiKey":"sk-proj-legacy-openai-1111"}"#,
                "2026-11-26T00:00:00Z",
            ),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO providerConnections VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                "2",
                "anthropic",
                "apikey",
                1,
                r#"{"apiKey":"sk-ant-legacy-claude-2222"}"#,
                "2026-11-26T00:00:00Z",
            ),
        )
        .unwrap();
    }

    let hma_json = r#"{
        "wallet_key": "AAAAAA-BBBBBB-CCCCCC",
        "container_id": "cont-1",
        "device_fingerprint": "fp-1234",
        "device_udid": "udid-9999",
        "access_token": "hma-access-tok",
        "refresh_token": "hma-refresh-tok"
    }"#;
    fs::write(&legacy_hma, hma_json).unwrap();

    let db_mtime_before = fs::metadata(&legacy_db).unwrap().modified().unwrap();
    let hma_before = fs::read_to_string(&legacy_hma).unwrap();

    let target_dir = dir.path().join("target");
    let res = import_legacy_from_paths(&target_dir, Some(&legacy_db), Some(&legacy_hma), false)
        .unwrap();
    assert_eq!(res.imported_providers.len(), 2);
    assert!(res.imported_hma);
    assert!(res.skipped.is_empty());

    // Verify legacy sources were not modified
    assert_eq!(
        fs::metadata(&legacy_db).unwrap().modified().unwrap(),
        db_mtime_before
    );
    assert_eq!(fs::read_to_string(&legacy_hma).unwrap(), hma_before);

    // Re-running with overwrite = false preserves existing keys and skips them
    let res2 = import_legacy_from_paths(&target_dir, Some(&legacy_db), Some(&legacy_hma), false)
        .unwrap();
    assert!(res2.imported_providers.is_empty());
    assert!(!res2.imported_hma);
    assert_eq!(res2.skipped.len(), 3);

    // Re-running with overwrite = true replaces them
    let res3 =
        import_legacy_from_paths(&target_dir, Some(&legacy_db), Some(&legacy_hma), true).unwrap();
    assert_eq!(res3.imported_providers.len(), 2);
    assert!(res3.imported_hma);
}
