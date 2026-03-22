use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{delete, get, post};
use axum::Router;
use serde::{Deserialize, Serialize};

use crate::server::registry::TunnelRegistry;

#[derive(Deserialize)]
pub struct CreateTunnelReq {
    name: String,
}

#[derive(Serialize)]
pub struct CreateTunnelResp {
    name: String,
    token: String,
}

pub async fn serve(addr: String, registry: Arc<TunnelRegistry>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/tunnels", post(create_tunnel))
        .route("/tunnels", get(list_tunnels))
        .route("/tunnels/{name}", delete(delete_tunnel))
        .route("/tunnels/{name}/status", get(tunnel_status))
        .with_state(registry);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("tunnel api listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn create_tunnel(
    State(registry): State<Arc<TunnelRegistry>>,
    Json(body): Json<CreateTunnelReq>,
) -> (StatusCode, Json<CreateTunnelResp>) {
    let token = registry.create_tunnel(&body.name);
    (
        StatusCode::CREATED,
        Json(CreateTunnelResp {
            name: body.name,
            token,
        }),
    )
}

async fn list_tunnels(
    State(registry): State<Arc<TunnelRegistry>>,
) -> Json<Vec<crate::server::registry::TunnelInfo>> {
    Json(registry.list_tunnels())
}

async fn delete_tunnel(
    State(registry): State<Arc<TunnelRegistry>>,
    Path(name): Path<String>,
) -> StatusCode {
    if registry.revoke_tunnel(&name) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn tunnel_status(
    State(registry): State<Arc<TunnelRegistry>>,
    Path(name): Path<String>,
) -> Result<Json<crate::server::registry::TunnelStatus>, StatusCode> {
    registry
        .tunnel_status(&name)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
