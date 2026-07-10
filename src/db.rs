use chrono::{DateTime, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DnsRecord {
    pub id: Uuid,
    pub zone: String,
    pub name: String,
    pub ptr_target: String,
    pub ttl: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create_pool(url: &str) -> Result<Pool<Postgres>, sqlx::Error> {
    PgPoolOptions::new().max_connections(5).connect(url).await
}

pub async fn migrate(pool: &Pool<Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dns_records (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            zone        TEXT NOT NULL,
            name        TEXT NOT NULL,
            ptr_target  TEXT NOT NULL,
            ttl         INTEGER NOT NULL DEFAULT 300,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (zone, name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn upsert_ptr(
    pool: &Pool<Postgres>,
    zone: &str,
    name: &str,
    ptr_target: &str,
    ttl: i32,
) -> Result<DnsRecord, sqlx::Error> {
    sqlx::query_as(
        r#"
        INSERT INTO dns_records (zone, name, ptr_target, ttl)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (zone, name)
        DO UPDATE SET ptr_target = $3, ttl = $4, updated_at = now()
        RETURNING id, zone, name, ptr_target, ttl, created_at, updated_at
        "#,
    )
    .bind(zone)
    .bind(name)
    .bind(ptr_target)
    .bind(ttl)
    .fetch_one(pool)
    .await
}

pub async fn delete_ptr(
    pool: &Pool<Postgres>,
    zone: &str,
    name: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM dns_records WHERE zone = $1 AND name = $2")
        .bind(zone)
        .bind(name)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_ptr(
    pool: &Pool<Postgres>,
    zone: &str,
    name: &str,
) -> Result<Option<DnsRecord>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, zone, name, ptr_target, ttl, created_at, updated_at FROM dns_records WHERE zone = $1 AND name = $2",
    )
    .bind(zone)
    .bind(name)
    .fetch_optional(pool)
    .await
}

pub async fn list_ptrs_in_zone(
    pool: &Pool<Postgres>,
    zone: &str,
) -> Result<Vec<DnsRecord>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, zone, name, ptr_target, ttl, created_at, updated_at FROM dns_records WHERE zone = $1 ORDER BY name",
    )
    .bind(zone)
    .fetch_all(pool)
    .await
}

pub async fn all_records(pool: &Pool<Postgres>) -> Result<Vec<DnsRecord>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, zone, name, ptr_target, ttl, created_at, updated_at FROM dns_records ORDER BY zone, name",
    )
    .fetch_all(pool)
    .await
}
