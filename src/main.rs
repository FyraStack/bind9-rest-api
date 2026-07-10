use std::sync::Arc;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

use stable_eyre::Result;

mod config;
mod db;
mod dns_client;
mod reconciler;
mod routes;

#[tokio::main]
async fn main() -> Result<()> {
    init(Some("bind9-rest-api"))?;

    let config = Arc::new(config::Config::from_file("config.json"));

    let db_pool = db::create_pool(&config.postgres_connection_url).await?;
    db::migrate(&db_pool).await?;

    let dns_client = dns_client::DnsClient::new(
        &config.dns.addr,
        &config.dns.key_name,
        config.dns.key.as_bytes().to_vec(),
        hickory_proto::rr::rdata::tsig::TsigAlgorithm::HmacSha512,
    )
    .map_err(|e| stable_eyre::Report::msg(e.to_string()))?;

    // Start background reconciler
    reconciler::spawn_reconciler(
        db_pool.clone(),
        dns_client.clone(),
        config.reconciler_interval_secs,
    );

    let state = routes::AppState {
        db: db_pool,
        dns: dns_client,
    };

    let app = routes::router(state);

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("Listening on {addr}");
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

pub fn env_filter(debug_target: Option<&str>) -> EnvFilter {
    let env = std::env::var("BIND9_REST_LOG").unwrap_or_else(|_| "".into());

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
