use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ninerouter_rs::config::schema::AppConfig;
use ninerouter_rs::config::secrets::SecretsBundle;
use ninerouter_rs::config::{load_opencode_profile, load_pricing};
use ninerouter_rs::hma::manager::HmaManager;
use ninerouter_rs::providers::anthropic::AnthropicAdapter;
use ninerouter_rs::providers::openai::OpenAiAdapter;
use ninerouter_rs::providers::opencode::OpenCodeAdapter;
use ninerouter_rs::router::RouterEngine;
use ninerouter_rs::router::budget::BudgetTracker;
use ninerouter_rs::server::{AppState, build_app};
use ninerouter_rs::telemetry::TelemetryHub;
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tokio::sync::broadcast;
use tower::ServiceExt;

fn test_app(csrf: &str, require_local_key: bool) -> axum::Router {
    let dir = tempdir().unwrap().keep();
    let mut cfg = AppConfig::default();
    cfg.server.require_local_api_key = require_local_key;
    let secrets = SecretsBundle {
        local_api_key: Some("my-secret-local-key".to_string()),
        ..Default::default()
    };
    let config_arc = Arc::new(ArcSwap::from_pointee(cfg));
    let secrets_arc = Arc::new(ArcSwap::from_pointee(secrets));
    let hma = Arc::new(HmaManager::new(30).unwrap());
    let opencode = Arc::new(OpenCodeAdapter::new(load_opencode_profile(&dir).unwrap()));
    let openai = Arc::new(OpenAiAdapter::new(None));
    let anthropic = Arc::new(AnthropicAdapter::new(None));
    let budget = Arc::new(BudgetTracker::load(&dir, load_pricing().unwrap()));
    let telemetry = Arc::new(TelemetryHub::new(None));
    let router = Arc::new(RouterEngine::new(
        Arc::clone(&config_arc),
        Arc::clone(&secrets_arc),
        Arc::clone(&hma),
        opencode,
        openai,
        anthropic,
        Arc::clone(&budget),
        Arc::clone(&telemetry),
    ));
    let (sse_tx, _) = broadcast::channel(16);
    build_app(AppState {
        data_dir: dir,
        port: 20128,
        csrf_token: csrf.to_string(),
        started_at: Instant::now(),
        config: config_arc,
        secrets: secrets_arc,
        hma,
        router,
        budget,
        telemetry,
        sse_tx,
    })
}

#[tokio::test]
async fn csrf_and_origin_guard_blocks_cross_origin_and_missing_token() {
    let app = test_app("tok-123", false);

    // Missing CSRF token -> 403
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/rtk")
                .header("host", "127.0.0.1:20128")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"enabled":true,"caveman_level":"off","ponytail_level":"off","custom_prompt":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Cross-origin Origin header -> 403 even with valid CSRF token
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/rtk")
                .header("host", "127.0.0.1:20128")
                .header("origin", "https://evil.example")
                .header("x-9router-csrf", "tok-123")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"enabled":true,"caveman_level":"off","ponytail_level":"off","custom_prompt":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);

    // Valid loopback request -> 200
    let resp3 = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/rtk")
                .header("host", "127.0.0.1:20128")
                .header("origin", "http://127.0.0.1:20128")
                .header("x-9router-csrf", "tok-123")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"enabled":true,"caveman_level":"lite","ponytail_level":"full","custom_prompt":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
}

#[tokio::test]
async fn llm_routes_models_count_tokens_and_error_codes() {
    let app = test_app("tok-123", false);

    let models = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/models")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(models.status(), StatusCode::OK);

    let count = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages/count_tokens")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"model":"oc/big-pickle","messages":[{"role":"user","content":"hello world"}]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(count.status(), StatusCode::OK);

    // Unsupported OAuth provider -> 400
    let bad_provider = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"model":"kiro/claude-opus","messages":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_provider.status(), StatusCode::BAD_REQUEST);

    // Unknown unprefixed model -> 404
    let unknown = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"model":"totally-unknown-model","messages":[]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn strict_local_api_key_enforcement() {
    let app = test_app("tok-123", true);
    let unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/models")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    let ok = app
        .oneshot(
            Request::builder()
                .uri("/v1/models")
                .header("authorization", "Bearer my-secret-local-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}
