use super::AppState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Validates `Host`, `Origin` (if present), and per-launch `X-9Router-CSRF` token on all mutating `/api/v1/*` routes.
pub async fn csrf_and_origin_guard(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let allowed_hosts = [
        format!("127.0.0.1:{}", state.port),
        format!("localhost:{}", state.port),
        "127.0.0.1".to_string(),
        "localhost".to_string(),
    ];

    if let Some(host) = req.headers().get("host").and_then(|v| v.to_str().ok())
        && !allowed_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host.trim()))
    {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Forbidden Host header"})),
        )
            .into_response();
    }

    if let Some(origin) = req.headers().get("origin").and_then(|v| v.to_str().ok()) {
        let allowed_origins = [
            format!("http://127.0.0.1:{}", state.port),
            format!("http://localhost:{}", state.port),
            "http://127.0.0.1".to_string(),
            "http://localhost".to_string(),
        ];
        if !allowed_origins
            .iter()
            .any(|o| o.eq_ignore_ascii_case(origin.trim()))
        {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": "Cross-origin mutation rejected"})),
            )
                .into_response();
        }
    }

    let csrf = req
        .headers()
        .get("x-9router-csrf")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if csrf != state.csrf_token {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Missing or invalid X-9Router-CSRF token"})),
        )
            .into_response();
    }

    next.run(req).await
}
