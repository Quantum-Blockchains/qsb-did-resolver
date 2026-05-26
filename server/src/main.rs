use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use qsb_did_resolver_core::{
    document::{DidResolutionMetadata, DidResolutionResultHttp},
    resolver::{invalid_did_result, is_qsb_did, map_raw_to_resolution, not_found_result},
    rpc::RpcClient,
};
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "qsb-did-resolver-server")]
#[command(about = "Off-chain DID resolver HTTP server for did:qsb")]
struct Args {
    #[arg(
        long,
        env = "QSB_RESOLVER_LISTEN_ADDR",
        default_value = "127.0.0.1:8080"
    )]
    listen_addr: SocketAddr,
    #[arg(
        long,
        env = "QSB_NODE_RPC_URL",
        default_value = "http://127.0.0.1:9944"
    )]
    node_rpc_url: String,
    #[arg(long, env = "QSB_RPC_TIMEOUT_SECS", default_value_t = 10)]
    rpc_timeout_secs: u64,
}

#[derive(Clone)]
struct AppState {
    rpc: RpcClient,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let state = Arc::new(AppState {
        rpc: RpcClient::new(args.node_rpc_url.clone(), args.rpc_timeout_secs)?,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/1.0/identifiers/:did", get(resolve_did))
        .with_state(state);

    info!("qsb-did-resolver-server listening on {}", args.listen_addr);
    info!("using node RPC {}", args.node_rpc_url);
    axum::serve(
        tokio::net::TcpListener::bind(args.listen_addr).await?,
        app.into_make_service(),
    )
    .await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn resolve_did(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    if !is_qsb_did(&did) {
        return (
            StatusCode::BAD_REQUEST,
            Json(invalid_did_result().into_http()),
        )
            .into_response();
    }

    match state.rpc.did_by_string(&did).await {
        Ok(Some(details)) => {
            let resolved = map_raw_to_resolution(&did, details);
            (StatusCode::OK, Json(resolved.into_http())).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(not_found_result().into_http())).into_response(),
        Err(err) => {
            error!("resolver backend error: {:?}", err);
            let body = DidResolutionResultHttp {
                did_document: None,
                did_document_metadata: serde_json::json!({
                    "deactivated": false,
                    "versionId": 0
                }),
                did_resolution_metadata: serde_json::to_value(DidResolutionMetadata {
                    content_type: None,
                    error: Some(b"internalError".to_vec()),
                })
                .expect("serialize internal error"),
            };
            (StatusCode::BAD_GATEWAY, Json(body)).into_response()
        }
    }
}
