use stable_eyre::Result;
use std::time::Duration;

use sqlx::Pool;
use sqlx::Postgres;
use tracing::{info, warn};

use crate::db;
use crate::dns_client::DnsClient;

pub fn spawn_reconciler(db: Pool<Postgres>, dns: DnsClient, interval_secs: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            if let Err(e) = reconcile(&db, &dns).await {
                warn!("Reconciler error: {e}");
            }
        }
    });
}

async fn reconcile(db: &Pool<Postgres>, dns: &DnsClient) -> Result<()> {
    let records = db::all_records(db).await?;

    for record in &records {
        // Query BIND for the current PTR record at this name
        let bind_ptrs = dns.list_ptrs(&record.name).await?;

        // The expected target
        let expected = vec![record.ptr_target.clone()];

        if bind_ptrs != expected {
            info!(
                "Reconciling {} in zone {}: expected {:?}, found {:?}",
                record.name, record.zone, expected, bind_ptrs
            );

            dns.set_ptr(
                &record.name,
                record.ttl as u32,
                &record.ptr_target,
                &record.zone,
            )
            .await?;

            info!("Reconciled {} in zone {}", record.name, record.zone);
        }
    }

    Ok(())
}
