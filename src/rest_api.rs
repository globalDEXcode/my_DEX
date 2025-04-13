//////////////////////////////////////
/// my_dex/src/rest_api.rs
//////////////////////////////////////

use axum::{
    routing::{get, post},
    extract::{Path, State, Json},
    http::StatusCode,
    response::IntoResponse,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use crate::node_logic::{DexNode, OrderRequest};
use crate::error::DexError;
use crate::shard_logic::shard_manager::ShardManager;

#[derive(Clone)]
pub struct AppState {
    pub node: Arc<DexNode>,
    pub shard_manager: ShardManager,
}

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            message: None,
            data: Some(data),
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            success: false,
            message: Some(msg.to_string()),
            data: None,
        }
    }
}

// ==== Request/Response Models ====

#[derive(Deserialize)]
pub struct BalanceQuery {
    pub user_id: String,
    pub coin: String,
}

#[derive(Serialize)]
pub struct ShardInfoEntry {
    pub shard_id: u32,
    pub replicas: Vec<String>,
}

// ==== Endpoints ====

pub async fn ping() -> impl IntoResponse {
    (StatusCode::OK, Json(ApiResponse::success("pong")))
}

pub async fn place_order(
    State(state): State<AppState>,
    Json(req): Json<OrderRequest>,
) -> impl IntoResponse {
    if state.node.watchtower.is_banned(&req.user_id) {
        warn!("Gebannter Nutzer {} versucht Order zu platzieren", req.user_id);
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()> ::error("Zugriff verweigert: gesperrter Nutzer")),
        );
    }

    match state.node.place_order(req) {
        Ok(_) => (StatusCode::OK, Json(ApiResponse::success("Order akzeptiert"))),
        Err(e) => {
            warn!("Fehler bei Order: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()> ::error(&format!("{:?}", e))),
            )
        }
    }
}

pub async fn get_balance(
    State(state): State<AppState>,
    Json(req): Json<BalanceQuery>,
) -> impl IntoResponse {
    if state.node.watchtower.is_banned(&req.user_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()> ::error("Zugriff verweigert: gesperrter Nutzer")),
        );
    }

    let bal = state.node.user_get_free_balance(&req.user_id, &req.coin);
    (StatusCode::OK, Json(ApiResponse::success(bal)))
}

pub async fn get_all_shards(State(state): State<AppState>) -> impl IntoResponse {
    let shard_info = state.shard_manager.shard_info.lock().unwrap();
    let mut entries = vec![];

    for (shard_id, replicas) in &shard_info.shard_replicas {
        entries.push(ShardInfoEntry {
            shard_id: *shard_id,
            replicas: replicas.iter().map(|id| id.to_string()).collect(),
        });
    }

    (StatusCode::OK, Json(ApiResponse::success(entries)))
}

pub async fn get_single_shard(
    Path(shard_id): Path<u32>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let shard_info = state.shard_manager.shard_info.lock().unwrap();
    let replicas = shard_info
        .get_replicas(shard_id)
        .into_iter()
        .map(|id| id.to_string())
        .collect::<Vec<String>>();

    (StatusCode::OK, Json(ApiResponse::success(ShardInfoEntry {
        shard_id,
        replicas,
    })))
}

pub async fn force_replicate_shard(
    Path(shard_id): Path<u32>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.shard_manager.replicate_shard_to_new_node(shard_id) {
        Ok(_) => (
            StatusCode::OK,
            Json(ApiResponse::<()> ::success("Replikation angestoßen")),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()> ::error(&format!("Fehler: {:?}", e))),
        ),
    }
}

// ==== Router aufbauen ====

pub fn build_rest_api(state: AppState) -> Router {
    Router::new()
        .route("/api/ping", get(ping))
        .route("/api/place_order", post(place_order))
        .route("/api/get_balance", post(get_balance))
        .route("/api/shards", get(get_all_shards))
        .route("/api/shard/:id", get(get_single_shard))
        .route("/api/replicate_shard/:id", post(force_replicate_shard))
        .with_state(state)
}
