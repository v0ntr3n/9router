pub mod llm_routes;
pub mod mgmt_routes;
pub mod security;

use crate::config::schema::AppConfig;
use crate::config::secrets::SecretsBundle;
use crate::hma::manager::HmaManager;
use crate::router::RouterEngine;
use crate::router::budget::BudgetTracker;
use crate::telemetry::TelemetryHub;
use arc_swap::ArcSwap;
use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use rust_embed::Embed;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

#[derive(Embed)]
#[folder = "web/"]
struct WebAssets;

#[derive(Clone)]
pub struct AppState {
    pub data_dir: PathBuf,
    pub port: u16,
    pub csrf_token: String,
    pub started_at: Instant,
    pub config: Arc<ArcSwap<AppConfig>>,
    pub secrets: Arc<ArcSwap<SecretsBundle>>,
    pub hma: Arc<HmaManager>,
    pub router: Arc<RouterEngine>,
    pub budget: Arc<BudgetTracker>,
    pub telemetry: Arc<TelemetryHub>,
    pub sse_tx: broadcast::Sender<(String, String)>,
}

pub fn build_app(state: AppState) -> Router {
    let mgmt_mutations = Router::new()
        .route("/api/v1/config", put(mgmt_routes::put_config))
        .route("/api/v1/secrets", put(mgmt_routes::put_secrets))
        .route("/api/v1/hma/activate", post(mgmt_routes::post_hma_activate))
        .route("/api/v1/hma/start", post(mgmt_routes::post_hma_start))
        .route("/api/v1/hma/switch", post(mgmt_routes::post_hma_start))
        .route("/api/v1/hma/stop", post(mgmt_routes::post_hma_stop))
        .route("/api/v1/hma/check-ip", post(mgmt_routes::post_hma_check_ip))
        .route("/api/v1/rtk", put(mgmt_routes::put_rtk))
        .route("/api/v1/import", post(mgmt_routes::post_import))
        .route("/api/v1/log-level", put(mgmt_routes::put_log_level))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security::csrf_and_origin_guard,
        ));

    Router::new()
        .route("/", get(serve_index))
        .route("/app.js", get(serve_app_js))
        .route("/styles.css", get(serve_styles_css))
        .route("/health", get(mgmt_routes::get_health))
        .route("/api/v1/status", get(mgmt_routes::get_status))
        .route("/api/v1/config", get(mgmt_routes::get_config))
        .route("/api/v1/hma/countries", get(mgmt_routes::get_hma_countries))
        .route("/api/v1/diagnostics", get(mgmt_routes::get_diagnostics))
        .route("/api/v1/events", get(mgmt_routes::get_events_sse))
        .route("/v1/models", get(llm_routes::get_models))
        .route(
            "/v1/chat/completions",
            post(llm_routes::post_chat_completions),
        )
        .route("/v1/responses", post(llm_routes::post_responses))
        .route("/v1/messages", post(llm_routes::post_messages))
        .route(
            "/v1/messages/count_tokens",
            post(llm_routes::post_count_tokens),
        )
        .merge(mgmt_mutations)
        .with_state(state)
}

async fn serve_index(axum::extract::State(state): axum::extract::State<AppState>) -> Response {
    let raw = WebAssets::get("index.html")
        .map(|f| String::from_utf8_lossy(&f.data).into_owned())
        .unwrap_or_else(|| "<h1>9router-rs</h1>".to_string());
    let rendered = raw.replace("{{CSRF_TOKEN}}", &state.csrf_token);
    Html(rendered).into_response()
}

async fn serve_app_js() -> Response {
    match WebAssets::get("app.js") {
        Some(f) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/javascript; charset=utf-8"),
            )],
            f.data.into_owned(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve_styles_css() -> Response {
    match WebAssets::get("styles.css") {
        Some(f) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            )],
            f.data.into_owned(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
