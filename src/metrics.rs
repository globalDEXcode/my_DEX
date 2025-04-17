// my_dex/src/metrics.rs
//
// Prometheus-Client-Integration. 
// Startet einen HTTP-Server auf /metrics-Endpunkt.

use lazy_static::lazy_static;
use prometheus::{
    IntCounter, IntGauge, Registry, Encoder, TextEncoder,
    register_int_counter, register_int_gauge
};
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use std::net::SocketAddr;
use tracing::{info, error};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    pub static ref ORDER_COUNT: IntCounter = register_int_counter!(
        "dex_order_total",
        "Total number of Orders created"
    ).expect("Failed to register ORDER_COUNT");

    pub static ref ACTIVE_SWAPS: IntGauge = register_int_gauge!(
        "dex_active_swaps",
        "Number of active Atomic Swaps"
    ).expect("Failed to register ACTIVE_SWAPS");

    pub static ref DEX_NODE_STARTS: IntCounter = register_int_counter!(
        "dex_node_starts_total",
        "Wie oft ein Node-Prozess startete"
    ).expect("Failed to register DEX_NODE_STARTS");

    pub static ref CRDT_MERGE_COUNT: IntCounter = register_int_counter!(
        "dex_crdt_merge_total",
        "Wie oft CRDT-merge_remote aufgerufen wurde"
    ).expect("Failed to register CRDT_MERGE_COUNT");

    pub static ref HTLC_REDEEM_COUNT: IntCounter = register_int_counter!(
        "dex_htlc_redeem_total",
        "Anzahl Redeems in HTLC"
    ).expect("Failed to register HTLC_REDEEM_COUNT");

    pub static ref HTLC_REFUND_COUNT: IntCounter = register_int_counter!(
        "dex_htlc_refund_total",
        "Anzahl Refunds in HTLC"
    ).expect("Failed to register HTLC_REFUND_COUNT");

    pub static ref SWAP_SELLER_REDEEM_COUNT: IntCounter = register_int_counter!(
        "dex_swap_seller_redeem_total",
        "Wie oft Seller redeem auf AtomicSwap"
    ).expect("Failed to register SWAP_SELLER_REDEEM_COUNT");

    pub static ref SWAP_BUYER_REDEEM_COUNT: IntCounter = register_int_counter!(
        "dex_swap_buyer_redeem_total",
        "Wie oft Buyer redeem auf AtomicSwap"
    ).expect("Failed to register SWAP_BUYER_REDEEM_COUNT");

    pub static ref SWAP_REFUND_COUNT: IntCounter = register_int_counter!(
        "dex_swap_refund_total",
        "Wie oft AtomicSwap refund ausgeführt"
    ).expect("Failed to register SWAP_REFUND_COUNT");

    pub static ref PARTIAL_FILL_COUNT: IntCounter = register_int_counter!(
        "dex_partial_fill_total",
        "Wie oft eine Partial-Fill Operation ausgeführt wurde"
    ).expect("Failed to register PARTIAL_FILL_COUNT");
}

pub fn register_metrics() {
    let _ = REGISTRY.register(Box::new(ORDER_COUNT.clone()));
    let _ = REGISTRY.register(Box::new(ACTIVE_SWAPS.clone()));
    let _ = REGISTRY.register(Box::new(DEX_NODE_STARTS.clone()));
    let _ = REGISTRY.register(Box::new(CRDT_MERGE_COUNT.clone()));

    let _ = REGISTRY.register(Box::new(HTLC_REDEEM_COUNT.clone()));
    let _ = REGISTRY.register(Box::new(HTLC_REFUND_COUNT.clone()));
    let _ = REGISTRY.register(Box::new(SWAP_SELLER_REDEEM_COUNT.clone()));
    let _ = REGISTRY.register(Box::new(SWAP_BUYER_REDEEM_COUNT.clone()));
    let _ = REGISTRY.register(Box::new(SWAP_REFUND_COUNT.clone()));

    let _ = REGISTRY.register(Box::new(PARTIAL_FILL_COUNT.clone()));
}

pub async fn serve_metrics(addr: SocketAddr) {
    info!("Starting Prometheus metrics endpoint at {:?}", addr);

    let svc = make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(service_fn(|req: Request<Body>| async move {
            if req.uri().path() == "/metrics" {
                let metric_families = REGISTRY.gather();
                let mut buf = Vec::new();
                let encoder = TextEncoder::new();
                if let Err(e) = encoder.encode(&metric_families, &mut buf) {
                    error!("Fehler beim Codieren der Metriken: {:?}", e);
                    return Ok(Response::builder()
                        .status(500)
                        .body(Body::from("Fehler beim Codieren der Metriken"))
                        .unwrap());
                }
                Ok(Response::new(Body::from(buf)))
            } else {
                Ok(Response::builder().status(404).body(Body::from("Not Found")).unwrap())
            }
        }))
    });

    let server = Server::bind(&addr).serve(svc);
    if let Err(e) = server.await {
        error!("Metrics server error: {:?}", e);
    }
}
