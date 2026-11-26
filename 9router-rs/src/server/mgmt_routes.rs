use super::AppState;
use crate::config::import::import_legacy_defaults;
use crate::config::save_config;
use crate::config::schema::{AppConfig, RtkConfig};
use crate::config::secrets::save_secrets;
use crate::hma::client::HmaClient;
use crate::telemetry::BuildInfo;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::Stream;
use serde::Deserialize;
use serde_json::{Value, json};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

pub async fn get_health(State(state): State<AppState>) -> Json<Value> {
    let tunnel = state.hma.metrics();
    let cfg = state.config.load();
    let secrets = state.secrets.load();
    Json(json!({
        "ok": true,
        "tunnel": tunnel,
        "providers": {
            "opencode": if cfg.providers.opencode.enabled { "ready" } else { "disabled" },
            "openai": if !cfg.providers.openai.enabled { "disabled" } else if secrets.openai_api_key.is_some() { "configured" } else { "missing_key" },
            "anthropic": if !cfg.providers.anthropic.enabled { "disabled" } else if secrets.anthropic_api_key.is_some() { "configured" } else { "missing_key" },
        }
    }))
}

pub async fn get_status(State(state): State<AppState>) -> Json<Value> {
    let build = BuildInfo::current();
    let cfg = state.config.load();
    let secrets = state.secrets.load();
    let tunnel = state.hma.metrics();
    let (sess_usd, daily) = state.budget.snapshot("default-session");
    Json(json!({
        "version": build.version,
        "git_sha": build.git_sha,
        "uptime_secs": state.started_at.elapsed().as_secs(),
        "hma_activated": secrets.hma_activated(),
        "secrets": secrets.status(),
        "tunnel": tunnel,
        "rtk_stats": state.telemetry.rtk_stats(),
        "budget": {
            "session_usd": sess_usd,
            "daily_usd": daily.usd_spent,
            "daily_cap_usd": cfg.budget.daily_usd_cap,
            "date_utc": daily.date_utc,
        }
    }))
}

pub async fn get_config(State(state): State<AppState>) -> Json<AppConfig> {
    Json((*state.config.load_full()).clone())
}

pub async fn put_config(State(state): State<AppState>, Json(next): Json<AppConfig>) -> Response {
    if let Err(e) = next.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }
    if let Err(e) = save_config(&state.data_dir, &next) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }
    state.config.store(Arc::new(next.clone()));
    Json(next).into_response()
}

#[derive(Deserialize)]
pub struct SecretsUpdatePayload {
    pub openai_api_key: Option<String>,
    pub anthropic_api_key: Option<String>,
    pub local_api_key: Option<String>,
}

pub async fn put_secrets(
    State(state): State<AppState>,
    Json(payload): Json<SecretsUpdatePayload>,
) -> Response {
    let mut bundle = (*state.secrets.load_full()).clone();
    if let Some(k) = payload.openai_api_key {
        bundle.openai_api_key = if k.trim().is_empty() {
            None
        } else {
            Some(k.trim().to_string())
        };
    }
    if let Some(k) = payload.anthropic_api_key {
        bundle.anthropic_api_key = if k.trim().is_empty() {
            None
        } else {
            Some(k.trim().to_string())
        };
    }
    if let Some(k) = payload.local_api_key {
        bundle.local_api_key = if k.trim().is_empty() {
            None
        } else {
            Some(k.trim().to_string())
        };
    }
    if let Err(e) = save_secrets(&state.data_dir, &bundle) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }
    let status = bundle.status();
    state.secrets.store(Arc::new(bundle));
    Json(status).into_response()
}

#[derive(Deserialize)]
pub struct HmaActivatePayload {
    pub activation_code: String,
}

pub async fn post_hma_activate(
    State(state): State<AppState>,
    Json(payload): Json<HmaActivatePayload>,
) -> Response {
    let code = payload.activation_code.trim();
    if code.is_empty()
        || code.len() > 64
        || !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid HMA activation code format" })),
        )
            .into_response();
    }

    let mut bundle = (*state.secrets.load_full()).clone();
    let fingerprint = bundle
        .hma_device_fingerprint
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(HmaClient::generate_device_fingerprint);

    let lic = match state.hma.client().lookup_license(code).await {
        Ok(l) => l,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let reg = match state
        .hma
        .client()
        .associate_license(code, &lic.container_id, &fingerprint)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let masked_udid = if reg.device_udid.len() > 8 {
        format!(
            "{}...{}",
            &reg.device_udid[..4],
            &reg.device_udid[reg.device_udid.len() - 4..]
        )
    } else {
        "****".to_string()
    };

    bundle.hma_wallet_key = Some(code.to_string());
    bundle.hma_container_id = Some(lic.container_id);
    bundle.hma_device_fingerprint = Some(fingerprint);
    bundle.hma_device_udid = Some(reg.device_udid);
    bundle.hma_access_token = Some(reg.access_token);
    bundle.hma_refresh_token = Some(reg.refresh_token);

    if let Err(e) = save_secrets(&state.data_dir, &bundle) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }
    state.secrets.store(Arc::new(bundle));
    Json(json!({ "activated": true, "device_udid_masked": masked_udid })).into_response()
}

pub async fn get_hma_countries(State(state): State<AppState>) -> Response {
    let secrets = state.secrets.load();
    match state
        .hma
        .list_countries(secrets.hma_access_token.as_deref())
        .await
    {
        Ok(countries) => Json(json!({ "countries": countries })).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct HmaStartPayload {
    pub country: String,
    pub city: Option<String>,
}

pub async fn post_hma_start(
    State(state): State<AppState>,
    Json(payload): Json<HmaStartPayload>,
) -> Response {
    let secrets = state.secrets.load();
    let Some(ref token) = secrets.hma_access_token else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "HMA license is not activated" })),
        )
            .into_response();
    };
    match state
        .hma
        .start_or_switch(token, &payload.country, payload.city.as_deref())
        .await
    {
        Ok(metrics) => {
            let _ = state.sse_tx.send((
                "tunnel_status".to_string(),
                serde_json::to_string(&metrics).unwrap_or_default(),
            ));
            let exit_ip = metrics.exit_ip.clone().unwrap_or_default();
            Json(json!({ "tunnel": metrics, "exit_ip": exit_ip })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn post_hma_stop(State(state): State<AppState>) -> Json<Value> {
    state.hma.stop().await;
    let metrics = state.hma.metrics();
    let _ = state.sse_tx.send((
        "tunnel_status".to_string(),
        serde_json::to_string(&metrics).unwrap_or_default(),
    ));
    Json(json!({ "stopped": true }))
}

pub async fn post_hma_check_ip(State(state): State<AppState>) -> Response {
    match state.hma.check_active_exit_ip().await {
        Ok(ip) => Json(json!({ "exit_ip": ip })).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn put_rtk(State(state): State<AppState>, Json(rtk): Json<RtkConfig>) -> Response {
    let mut cfg = (*state.config.load_full()).clone();
    cfg.rtk = rtk;
    if let Err(e) = cfg.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }
    if let Err(e) = save_config(&state.data_dir, &cfg) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }
    let out = cfg.rtk.clone();
    state.config.store(Arc::new(cfg));
    Json(out).into_response()
}

#[derive(Deserialize)]
pub struct ImportPayload {
    pub overwrite: Option<bool>,
}

pub async fn post_import(
    State(state): State<AppState>,
    Json(payload): Json<ImportPayload>,
) -> Response {
    match import_legacy_defaults(&state.data_dir, payload.overwrite.unwrap_or(false)) {
        Ok(res) => {
            if let Ok(reloaded) = crate::config::secrets::load_secrets(&state.data_dir) {
                state.secrets.store(Arc::new(reloaded));
            }
            Json(res).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct LogLevelPayload {
    pub level: String,
}

pub async fn put_log_level(
    State(state): State<AppState>,
    Json(payload): Json<LogLevelPayload>,
) -> Response {
    match state.telemetry.set_log_level(payload.level.trim()) {
        Ok(()) => Json(json!({ "level": payload.level.trim() })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn get_diagnostics(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "build": BuildInfo::current(),
        "config": *state.config.load_full(),
        "secrets_status": state.secrets.load().status(),
        "tunnel": state.hma.metrics(),
        "rtk_stats": state.telemetry.rtk_stats(),
        "recent_requests": state.telemetry.recent_requests(),
        "recent_fallbacks": state.telemetry.recent_fallbacks(),
    }))
}

pub async fn get_events_sse(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.sse_tx.subscribe();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        let (name, data) = rx.recv().await.ok()?;
        let ev = Event::default().event(name).data(data);
        Some((Ok(ev), rx))
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
