//////////////////////////////////////////////////////////////////////
/// my_dex/src/metrics_tls.rs
//////////////////////////////////////////////////////////////////////

use std::{
    fs::File,
    io::{BufReader, Error as IoError},
    net::{SocketAddr, IpAddr},
    sync::Arc,
    time::{Duration, Instant},
    panic::AssertUnwindSafe,
};

use hyper::{
    Body, Request, Response, server::conn::Http, header::HeaderValue,
    service::{make_service_fn, service_fn},
};
use tokio::net::TcpListener;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        Certificate, PrivateKey, ServerConfig, RootCertStore,
        server::AllowAnyAuthenticatedClient,
    },
};
use tracing::{info, error, warn};
use crate::metrics::REGISTRY;
use crate::config_loader::NodeConfig;
use rcgen::generate_simple_self_signed;
use dashmap::DashMap;
use lazy_static::lazy_static;
use sha2::{Sha256, Digest};
use std::sync::OnceLock;
use std::panic::catch_unwind;

const MAX_REQUESTS_PER_MINUTE: u32 = 60;
const BURST_CAPACITY: u32 = 3;

static TOKEN: OnceLock<String> = OnceLock::new();

lazy_static! {
    static ref RATE_LIMITER: DashMap<IpAddr, (u32, Instant)> = DashMap::new();
}

pub fn init_metrics_token(config: &NodeConfig) {
    let token = config.metrics_token.clone().unwrap_or_else(|| "default_token_fallback_dev_only".to_string());
    TOKEN.set(token).expect("METRICS_TOKEN bereits gesetzt");
}

async fn handle_metrics(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    if req.uri().path() != "/metrics" {
        return Ok(Response::builder().status(404).body(Body::from("Not Found")).unwrap());
    }

    let remote_ip = req
        .extensions()
        .get::<SocketAddr>()
        .map(|addr| addr.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));

    let token_valid = req.headers().get("x-metrics-token").and_then(|val| val.to_str().ok()) == TOKEN.get().map(|s| s.as_str());
    if !token_valid {
        warn!("Zugriff verweigert: ungültiger Token von IP: {}", remote_ip);
        return Ok(Response::builder()
            .status(403)
            .body(Body::from("Forbidden: Ungültiger Token"))
            .unwrap());
    }

    let now = Instant::now();
    let (count, last_time) = RATE_LIMITER.entry(remote_ip).or_insert((0, now));
    if now.duration_since(*last_time) > Duration::from_secs(60) {
        *count = 1;
        *last_time = now;
    } else {
        if *count >= MAX_REQUESTS_PER_MINUTE {
            warn!("Rate Limit überschritten für IP: {}", remote_ip);
            return Ok(Response::builder()
                .status(429)
                .body(Body::from("Too Many Requests"))
                .unwrap());
        }
        *count += 1;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let metric_families = REGISTRY.gather();
        let mut buf = Vec::new();
        let encoder = prometheus::TextEncoder::new();
        if let Err(e) = encoder.encode(&metric_families, &mut buf) {
            error!("Fehler beim Codieren der Metriken: {}", e);
            return Response::builder()
                .status(500)
                .body(Body::from("Fehler beim Codieren der Metriken"))
                .unwrap();
        }
        Response::new(Body::from(buf))
    }));

    match result {
        Ok(resp) => Ok(resp),
        Err(_) => {
            error!("Panic in Metrikhandler abgefangen");
            Ok(Response::builder()
                .status(500)
                .body(Body::from("Interner Fehler beim Sammeln der Metriken"))
                .unwrap())
        }
    }
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, IoError> {
    let cert_file = BufReader::new(File::open(cert_path)?);
    let key_file = BufReader::new(File::open(key_path)?);

    let certs = rustls_pemfile::certs(cert_file)?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();

    let mut keys = rustls_pemfile::pkcs8_private_keys(key_file)?
        .into_iter()
        .map(PrivateKey)
        .collect::<Vec<_>>();

    if certs.is_empty() || keys.is_empty() {
        return Err(IoError::new(std::io::ErrorKind::InvalidInput, "Zertifikat oder Key leer"));
    }

    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|e| IoError::new(std::io::ErrorKind::InvalidData, format!("TLS-Konfiguration ungültig: {:?}", e)))
}

fn load_tls_config_with_mtls(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> Result<ServerConfig, IoError> {
    let cert_file = BufReader::new(File::open(cert_path)?);
    let key_file = BufReader::new(File::open(key_path)?);
    let ca_file = BufReader::new(File::open(client_ca_path)?);

    let certs = rustls_pemfile::certs(cert_file)?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();
    let mut keys = rustls_pemfile::pkcs8_private_keys(key_file)?
        .into_iter()
        .map(PrivateKey)
        .collect::<Vec<_>>();

    let client_certs = rustls_pemfile::certs(ca_file)?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();

    let mut client_root_store = RootCertStore::empty();
    for cert in &client_certs {
        client_root_store.add(cert).map_err(|_| {
            IoError::new(std::io::ErrorKind::InvalidInput, "Client-CA-Zertifikat ungültig")
        })?;
    }

    if certs.is_empty() || keys.is_empty() {
        return Err(IoError::new(std::io::ErrorKind::InvalidInput, "Zertifikat oder Key leer"));
    }

    ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(client_root_store)))
        .with_single_cert(certs, keys.remove(0))
        .map_err(|e| IoError::new(std::io::ErrorKind::InvalidData, format!("mTLS-Konfiguration ungültig: {:?}", e)))
}


fn generate_tls_config_in_memory() -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let cert = generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    let cert_chain = vec![Certificate(cert_der)];
    let key = PrivateKey(key_der);

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    Ok(config)
}


pub async fn serve_metrics_tls_generated(
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let tls_config = generate_tls_config_in_memory()?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(addr).await?;
    info!("TLS-Metrics-Server (rcgen) lauscht unter https://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let remote_addr = stream.peer_addr().ok();
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let service = make_service_fn(move |_| {
                        let remote_addr = remote_addr;
                        async move {
                            Ok::<_, hyper::Error>(service_fn(move |mut req| {
                                if let Some(addr) = remote_addr {
                                    req.extensions_mut().insert(addr);
                                }
                                handle_metrics(req)
                            }))
                        }
                    });

                    if let Err(err) = Http::new()
                        .serve_connection(tls_stream, service)
                        .await
                    {
                        error!("Fehler bei Verbindung: {}", err);
                    }
                }
                Err(e) => error!("TLS-Handshake fehlgeschlagen: {}", e),
            }
        });
    }
}

pub async fn serve_metrics_tls_mtls(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let tls_config = load_tls_config_with_mtls(cert_path, key_path, client_ca_path)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(addr).await?;
    info!("TLS-Metrics-Server (mTLS) lauscht unter https://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let remote_addr = stream.peer_addr().ok();
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let service = make_service_fn(move |_| {
                        let remote_addr = remote_addr;
                        async move {
                            Ok::<_, hyper::Error>(service_fn(move |mut req| {
                                if let Some(addr) = remote_addr {
                                    req.extensions_mut().insert(addr);
                                }
                                handle_metrics(req)
                            }))
                        }
                    });

                    if let Err(err) = Http::new()
                        .serve_connection(tls_stream, service)
                        .await
                    {
                        error!("Fehler bei Verbindung: {}", err);
                    }
                }
                Err(e) => error!("TLS-Handshake fehlgeschlagen: {}", e),
            }
        });
    }
}
