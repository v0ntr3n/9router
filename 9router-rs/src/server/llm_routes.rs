use super::AppState;
use crate::providers::ProviderId;
use crate::router::budget::BudgetTracker;
use crate::rtk;
use crate::telemetry::RequestEventRecord;
use crate::translator::ir::WireFormat;
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::TryStreamExt;
use serde_json::{Value, json};
use std::time::Instant;
use uuid::Uuid;

#[allow(clippy::result_large_err)]
fn check_local_auth(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let cfg = state.config.load();
    if !cfg.server.require_local_api_key {
        return Ok(());
    }
    let secrets = state.secrets.load();
    let expected = secrets.local_api_key.as_deref().unwrap_or("").trim();
    if expected.is_empty() {
        return Ok(());
    }
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .unwrap_or("")
        .trim();
    if provided == expected {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"type": "unauthorized", "message": "Invalid local API key"}})),
        )
            .into_response())
    }
}

pub async fn get_models(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = check_local_auth(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    let mut data = Vec::new();
    for (model, owner) in &cfg.routing.unprefixed_model_map {
        let prefix = match owner.as_str() {
            "opencode" => "oc",
            "openai" => "openai",
            "anthropic" => "anthropic",
            other => other,
        };
        data.push(json!({
            "id": format!("{prefix}/{model}"),
            "object": "model",
            "owned_by": owner
        }));
    }
    Json(json!({ "object": "list", "data": data })).into_response()
}

pub async fn post_chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    handle_inference(state, headers, WireFormat::OpenAiChat, body).await
}

pub async fn post_responses(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    handle_inference(state, headers, WireFormat::OpenAiResponses, body).await
}

pub async fn post_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    handle_inference(state, headers, WireFormat::AnthropicMessages, body).await
}

pub async fn post_count_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(resp) = check_local_auth(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    let secrets = state.secrets.load();
    let raw_model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if let Ok(target) = crate::router::RouterEngine::resolve_target(&cfg, raw_model)
        && target.provider == ProviderId::Anthropic
        && let Some(ref key) = secrets.anthropic_api_key
    {
        let proxy_url = if cfg.providers.anthropic.use_hma {
            state.hma.active_proxy_url()
        } else {
            None
        };
        let mut forwarded = body.clone();
        forwarded["model"] = Value::String(target.upstream_model);
        if let Ok(val) = state
            .router
            .anthropic
            .count_tokens(&forwarded, key, proxy_url.as_deref())
            .await
        {
            return Json(val).into_response();
        }
    }

    let bytes = serde_json::to_vec(&body).map(|v| v.len()).unwrap_or(0);
    let est = BudgetTracker::estimate_tokens_from_bytes(bytes);
    Json(json!({ "input_tokens": est })).into_response()
}

async fn handle_inference(
    state: AppState,
    headers: HeaderMap,
    inbound_format: WireFormat,
    mut body: Value,
) -> Response {
    if let Err(resp) = check_local_auth(&state, &headers) {
        return resp;
    }

    let started = Instant::now();
    let request_id = Uuid::new_v4().to_string();
    let bypass_rtk = headers
        .get("x-9router-token-saver")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("off"));

    let cfg = state.config.load();
    let rtk_outcome = rtk::apply_pre_translate(&mut body, &cfg.rtk, bypass_rtk);
    if rtk_outcome.tokens_saved_est > 0 {
        state
            .telemetry
            .record_rtk_savings(rtk_outcome.tokens_saved_est);
        let stats = state.telemetry.rtk_stats();
        let _ = state.sse_tx.send((
            "rtk_stats".to_string(),
            serde_json::to_string(&stats).unwrap_or_default(),
        ));
    }

    let session_key = headers
        .get("x-opencode-session")
        .or_else(|| headers.get("x-session-id"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default-session")
        .to_string();

    match state
        .router
        .route_request(&request_id, inbound_format, body, &session_key)
        .await
    {
        Ok(routed) => {
            let ttft_ms = started.elapsed().as_millis() as u64;
            let ev = RequestEventRecord {
                ts_utc: chrono::Utc::now().to_rfc3339(),
                request_id: request_id.clone(),
                provider: routed.provider.as_str().to_string(),
                egress: routed.egress.clone(),
                status: routed.response.status,
                ttft_ms,
                tokens_in: 0,
                tokens_out: 0,
                fallback_count: routed.fallback_count,
            };
            state.telemetry.record_request(ev.clone());
            let _ = state.sse_tx.send((
                "request_event".to_string(),
                serde_json::to_string(&ev).unwrap_or_default(),
            ));

            let body_stream = routed.response.stream.map_err(std::io::Error::other);
            let mut resp = Response::builder()
                .status(StatusCode::from_u16(routed.response.status).unwrap_or(StatusCode::OK))
                .header("content-type", routed.response.content_type)
                .body(Body::from_stream(body_stream))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());

            let h = resp.headers_mut();
            if let Ok(v) = HeaderValue::from_str(&request_id) {
                h.insert(HeaderName::from_static("x-request-id"), v);
            }
            if let Ok(v) = HeaderValue::from_str(routed.provider.as_str()) {
                h.insert(HeaderName::from_static("x-router-provider"), v);
            }
            if let Ok(v) = HeaderValue::from_str(&routed.egress) {
                h.insert(HeaderName::from_static("x-router-egress"), v);
            }
            if let Ok(v) = HeaderValue::from_str(&routed.fallback_count.to_string()) {
                h.insert(HeaderName::from_static("x-router-fallback-count"), v);
            }
            resp
        }
        Err((status, err_type, msg)) => {
            let mut resp = (
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                Json(json!({ "error": { "type": err_type, "message": msg } })),
            )
                .into_response();
            if let Ok(v) = HeaderValue::from_str(&request_id) {
                resp.headers_mut()
                    .insert(HeaderName::from_static("x-request-id"), v);
            }
            resp
        }
    }
}
