use std::net::SocketAddr;

use axum::{routing::get, Router};
use tower_http::services::ServeDir;
use tracing::info;

mod model;
mod ws;
mod scan;
mod export;
mod modules;
mod bruteforce;
mod bruteforce_manager;
mod reports;

use crate::reports::list_reports;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let app = Router::new()
        .route("/ws", get(ws::ws_handler))
        .route("/api/reports", get(list_reports))
        .nest_service("/results", tower_http::services::ServeDir::new("results"))
        .nest_service("/", ServeDir::new("static"));

    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    info!("Запуск на http://{addr}");

    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app,
    )
    .await
    .unwrap();
}
