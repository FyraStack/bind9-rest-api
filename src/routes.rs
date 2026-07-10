use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::db::{self, DnsRecord};
use crate::dns_client::DnsClient;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::Pool<sqlx::Postgres>,
    pub dns: DnsClient,
}

pub fn router(state: AppState) -> Router {
    let shared = Arc::new(state);

    Router::new()
        .route("/health", get(health))
        .route("/zones/:zone/ptrs", get(list_ptrs))
        .route(
            "/zones/:zone/ptrs/:name",
            get(get_ptr).put(set_ptr).delete(delete_ptr),
        )
        .with_state(shared)
}

async fn health() -> &'static str {
    "ok"
}

// --- Request / response types ---

#[derive(Serialize)]
struct PtrResponse {
    zone: String,
    name: String,
    ptr_target: String,
    ttl: i32,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct SetPtrRequest {
    ptr_target: String,
    #[serde(default = "default_ttl")]
    ttl: i32,
}

fn default_ttl() -> i32 {
    300
}

fn to_response(record: &DnsRecord) -> PtrResponse {
    PtrResponse {
        zone: record.zone.clone(),
        name: record.name.clone(),
        ptr_target: record.ptr_target.clone(),
        ttl: record.ttl,
    }
}

// --- Handlers ---

async fn list_ptrs(
    State(state): State<Arc<AppState>>,
    Path(zone): Path<String>,
) -> Result<Json<Vec<PtrResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let records = db::list_ptrs_in_zone(&state.db, &zone)
        .await
        .map_err(|e| internal_error(e.to_string()))?;
    Ok(Json(records.iter().map(to_response).collect()))
}

async fn get_ptr(
    State(state): State<Arc<AppState>>,
    Path((zone, name)): Path<(String, String)>,
) -> Result<Json<PtrResponse>, (StatusCode, Json<ErrorResponse>)> {
    let record = db::get_ptr(&state.db, &zone, &name)
        .await
        .map_err(|e| internal_error(e.to_string()))?
        .ok_or_else(|| not_found("PTR record not found"))?;
    Ok(Json(to_response(&record)))
}

async fn set_ptr(
    State(state): State<Arc<AppState>>,
    Path((zone, name)): Path<(String, String)>,
    Json(body): Json<SetPtrRequest>,
) -> Result<Json<PtrResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate
    if body.ptr_target.is_empty() {
        return Err(bad_request("ptr_target must not be empty"));
    }
    if body.ttl < 0 {
        return Err(bad_request("ttl must be non-negative"));
    }

    // Write to DB first
    let record = db::upsert_ptr(&state.db, &zone, &name, &body.ptr_target, body.ttl)
        .await
        .map_err(|e| internal_error(e.to_string()))?;

    // Then sync to DNS server
    if let Err(e) = state
        .dns
        .set_ptr(&name, body.ttl as u32, &body.ptr_target, &zone)
        .await
    {
        // Rollback DB
        let _ = db::delete_ptr(&state.db, &zone, &name).await;
        return Err(dns_error(e.to_string()));
    }

    Ok(Json(to_response(&record)))
}

async fn delete_ptr(
    State(state): State<Arc<AppState>>,
    Path((zone, name)): Path<(String, String)>,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // Delete from DNS server first (so we don't leave orphan records if this fails)
    // If the record doesn't exist on the DNS server that's OK — deletion is idempotent
    let _ = state.dns.set_ptr(&name, 0, "", &zone).await;

    // Delete from DB
    let deleted = db::delete_ptr(&state.db, &zone, &name)
        .await
        .map_err(|e| internal_error(e.to_string()))?;

    if deleted {
        Ok(())
    } else {
        Err(not_found("PTR record not found"))
    }
}

// --- Error helpers ---

fn internal_error(msg: String) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: msg }),
    )
}

fn not_found(msg: &'static str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

fn bad_request(msg: &'static str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

fn dns_error(msg: String) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorResponse {
            error: format!("DNS update failed: {msg}"),
        }),
    )
}
