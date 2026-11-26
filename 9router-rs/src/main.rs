use arc_swap::ArcSwap;
use clap::Parser;
use ninerouter_rs::config::secrets::load_secrets;
use ninerouter_rs::config::{
    default_data_dir, load_config, load_opencode_profile, load_pricing,
};
use ninerouter_rs::hma::manager::HmaManager;
use ninerouter_rs::providers::anthropic::AnthropicAdapter;
use ninerouter_rs::providers::openai::OpenAiAdapter;
use ninerouter_rs::providers::opencode::OpenCodeAdapter;
use ninerouter_rs::router::RouterEngine;
use ninerouter_rs::router::budget::BudgetTracker;
use ninerouter_rs::server::{AppState, build_app};
use ninerouter_rs::telemetry::{init_tracing, install_panic_hook};
use rand::RngCore;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

#[derive(Parser, Debug)]
#[command(name = "9router-rs", version, about = "Pure-Rust 9Router Edition")]
struct Cli {
    #[arg(long, env = "NINEROUTER_PORT")]
    port: Option<u16>,

    #[arg(long, env = "NINEROUTER_BIND")]
    bind: Option<String>,

    #[arg(long, env = "NINEROUTER_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[arg(long, env = "NINEROUTER_LOG_LEVEL")]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.unwrap_or_else(default_data_dir);
    let _ = std::fs::create_dir_all(&data_dir);

    install_panic_hook(&data_dir);

    let mut cfg = load_config(&data_dir).unwrap_or_default();
    if let Some(p) = cli.port {
        cfg.server.port = p;
    }
    if let Some(b) = cli.bind {
        cfg.server.bind = b;
    }
    if let Some(lvl) = cli.log_level {
        cfg.logging.level = lvl;
    }

    let (telemetry, _log_guard) =
        init_tracing(&data_dir, &cfg.logging.level).expect("failed to initialize tracing");

    if cfg.server.bind != "127.0.0.1" && cfg.server.bind != "::1" && cfg.server.bind != "localhost"
    {
        tracing::warn!(
            bind = %cfg.server.bind,
            "Binding to a non-loopback interface exposes local LLM endpoints"
        );
    }

    let secrets = load_secrets(&data_dir).unwrap_or_default();
    let oc_profile = load_opencode_profile(&data_dir).expect("failed to load opencode profile");
    let pricing = load_pricing().expect("failed to load pricing table");

    let config_arc = Arc::new(ArcSwap::from_pointee(cfg.clone()));
    let secrets_arc = Arc::new(ArcSwap::from_pointee(secrets));
    let hma = Arc::new(
        HmaManager::new(cfg.fallback.hma_rotation_cooldown_secs)
            .expect("failed to initialize HMA manager"),
    );
    let opencode = Arc::new(OpenCodeAdapter::new(oc_profile));
    {
        let oc_ref = Arc::clone(&opencode);
        hma.set_on_ip_change(Arc::new(move |_new_ip| {
            oc_ref.on_hma_ip_changed();
        }));
    }
    let openai = Arc::new(OpenAiAdapter::new(None));
    let anthropic = Arc::new(AnthropicAdapter::new(None));
    let budget = Arc::new(BudgetTracker::load(&data_dir, pricing));

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

    let mut csrf_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut csrf_bytes);
    let csrf_token = hex::encode(csrf_bytes);
    let (sse_tx, _) = broadcast::channel(128);

    let state = AppState {
        data_dir,
        port: cfg.server.port,
        csrf_token,
        started_at: Instant::now(),
        config: config_arc,
        secrets: secrets_arc,
        hma: Arc::clone(&hma),
        router,
        budget,
        telemetry,
        sse_tx,
    };

    let addr: SocketAddr = format!("{}:{}", cfg.server.bind, cfg.server.port)
        .parse()
        .expect("invalid bind address");

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!(
                "error: port {} is already in use (is Node.js 9router running?). Pass --port <PORT> or stop the other process.",
                cfg.server.port
            );
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("error: failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    println!("9router-rs listening on http://{addr}");
    println!("  Web UI : http://{addr}/");
    println!("  API    : http://{addr}/v1");

    let app = build_app(state);
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Shutdown signal received; draining active streams (up to 30s)...");
    });

    if let Err(e) = server.await {
        tracing::error!("server error: {e}");
    }

    let _ = tokio::time::timeout(Duration::from_secs(30), hma.stop()).await;
}
