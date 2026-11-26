use ninerouter_rs::config::load_pricing;
use ninerouter_rs::config::schema::{AppConfig, BudgetConfig};
use ninerouter_rs::providers::ProviderId;
use ninerouter_rs::router::RouterEngine;
use ninerouter_rs::router::budget::BudgetTracker;
use ninerouter_rs::telemetry::redact_secrets;
use tempfile::tempdir;

#[test]
fn fallback_model_rewriting_and_unsupported_prefixes() {
    let cfg = AppConfig::default();
    assert_eq!(
        RouterEngine::rewrite_fallback_model(&cfg, "big-pickle", ProviderId::Anthropic),
        "claude-sonnet-4-5"
    );
    assert_eq!(
        RouterEngine::rewrite_fallback_model(&cfg, "big-pickle", ProviderId::OpenAi),
        "gpt-4.1"
    );
    assert!(RouterEngine::resolve_target(&cfg, "kiro/claude").is_err());
    assert!(RouterEngine::resolve_target(&cfg, "unknown-model-xyz").is_err());
}

#[test]
fn budget_caps_persist_daily_and_block_when_exceeded() {
    let dir = tempdir().unwrap();
    let pricing = load_pricing().unwrap();
    let tracker = BudgetTracker::load(dir.path(), pricing.clone());

    let budget_cfg = BudgetConfig {
        session_usd_cap: 0.50,
        daily_usd_cap: 1.00,
        daily_token_cap: 0,
    };

    assert!(tracker.check_budget(&budget_cfg, "sess-1").is_ok());
    // 100k output tokens on claude-sonnet-4-5 ($15/1M) = $1.50 -> exceeds both caps
    let spent = tracker.record_paid_usage("sess-1", "claude-sonnet-4-5", 10_000, 100_000);
    assert!(spent > 1.0);
    assert!(tracker.check_budget(&budget_cfg, "sess-1").is_err());

    // Reload from disk verifies daily persistence
    let reloaded = BudgetTracker::load(dir.path(), pricing);
    let (_, daily) = reloaded.snapshot("sess-2");
    assert!(daily.usd_spent >= 1.5);
    assert!(reloaded.check_budget(&budget_cfg, "sess-2").is_err());
}

#[test]
fn telemetry_redactor_strips_all_secret_classes() {
    let raw = "Authorization: Bearer sk-proj-1234567890abcdef x-api-key: sk-ant-api03-abcdefghijkl \
               wallet_key=ABCDEF-123456-GHIJKL proxy=http://u123:p456@127.0.0.1:9999 \
               jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456 \
               private_key=supersecretwgkey";
    let clean = redact_secrets(raw);
    assert!(!clean.contains("sk-proj-1234567890abcdef"));
    assert!(!clean.contains("sk-ant-api03-abcdefghijkl"));
    assert!(!clean.contains("ABCDEF-123456-GHIJKL"));
    assert!(!clean.contains("u123:p456"));
    assert!(!clean.contains("eyJhbGciOiJIUzI1NiJ9"));
    assert!(!clean.contains("supersecretwgkey"));
}
