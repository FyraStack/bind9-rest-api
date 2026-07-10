use axum::Router;
use axum::extract::State;
use axum::routing::get;
use dns_update::{DnsUpdater, TsigAlgorithm};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use stable_eyre::Result;
use std::fs;
use std::sync::Arc;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

struct AppState {
    db_pool: Pool<Postgres>,
    dns_updater: DnsUpdater,
}

#[derive(Deserialize)]
struct Config {
    postgres_connection_url: String,
    port: String,
    dns: DNSConfig,
}

#[derive(Deserialize)]
struct DNSConfig {
    addr: String,
    key_name: String,
    key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init(Some("bind9-rest-api"))?;

    let config: Config = if let Ok(file) = fs::File::open("config.json") {
        serde_json::from_reader(file).expect("unable to parse config.json")
    } else {
        panic!("No config file found");
    };

    let shared_state = Arc::new(create_state_from_config(&config).await?);

    let app = Router::new()
        .route("/health", get(health))
        .with_state(shared_state);

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn create_state_from_config(config: &Config) -> Result<AppState> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.postgres_connection_url)
        .await?;

    let dns_client = DnsUpdater::new_rfc2136_tsig(
        &config.dns.addr,
        &config.dns.key_name,
        config.dns.key.clone(),
        TsigAlgorithm::HmacSha512,
    )
    .unwrap();

    Ok(AppState {
        db_pool: pool,
        dns_updater: dns_client,
    })
}

async fn health(State(state): State<Arc<AppState>>) {}

pub fn env_filter(debug_target: Option<&str>) -> EnvFilter {
    let env = std::env::var("ODOROBO_LOG").unwrap_or_else(|_| "".into());

    let base = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse_lossy(&env);

    #[cfg(debug_assertions)]
    let base = {
        let base = if let Some(debug_target) = debug_target {
            base.add_directive(format!("{debug_target}=trace").parse().unwrap())
        } else {
            base
        };

        base.add_directive(
            format!("{}=debug", env!("CARGO_PKG_NAME").replace('-', "_"))
                .parse()
                .unwrap(),
        )
    };

    base
}

pub fn init(debug_target: Option<&str>) -> Result<()> {
    stable_eyre::install()?;
    let fmt = tracing_subscriber::fmt().with_env_filter(env_filter(debug_target));
    #[cfg(debug_assertions)]
    let fmt = {
        fmt.pretty()
            .with_file(true)
            .with_line_number(true)
            .with_ansi(true)
    };

    fmt.init();

    Ok(())
}
