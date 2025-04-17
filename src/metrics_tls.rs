//////////////////////////////////////////////////////////////////////
/// my_dex/src/metrics_tls.rs
//////////////////////////////////////////////////////////////////////

use std::{fs::File, io::{BufReader, Error as IoError}, net::SocketAddr, sync::Arc};
use hyper::{Body, Request, Response, server::conn::Http, header::HeaderValue};
use hyper::service::{make_service_fn, service_fn};
use tokio::net::TcpListener;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{Certificate, PrivateKey, ServerConfig}
};
use tracing::{info, error};
use crate::metrics::REGISTRY;
use rcgen::generate_simple_self_signed;

const METRICS_TOKEN: &str = "supersecuremetricsaccesskey123";

/// Antwortet mit den Prometheus-Metriken, wenn Token im Header korrekt ist
async fn handle_metrics(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    if req.uri().path() != "/metrics" {
        return Ok(Response::builder().status(404).body(Body::from("Not Found")).unwrap());
    }

    match req.headers().get("x-metrics-token") {
        Some(token) if token == HeaderValue::from_static(METRICS_TOKEN) => {
            let metric_families = REGISTRY.gather();
            let mut buf = Vec::new();
            let encoder = prometheus::TextEncoder::new();
            if let Err(e) = encoder.encode(&metric_families, &mut buf) {
                error!("Fehler beim Codieren der Metriken: {:?}", e);
                return Ok(Response::builder()
                    .status(500)
                    .body(Body::from("Fehler beim Codieren der Metriken"))
                    .unwrap());
            }
            Ok(Response::new(Body::from(buf)))
        }
        _ => {
            error!("Zugriff verweigert: ungültiger oder fehlender Token bei /metrics");
            Ok(Response::builder()
                .status(403)
                .body(Body::from("Forbidden: Ungültiger Token"))
                .unwrap())
        }
    }
}

/// TLS-Konfiguration aus Zertifikatsdateien laden
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

/// Startet einen TLS-geschützten Prometheus-Metrics-Server mit Datei-Zertifikaten
pub async fn serve_metrics_tls(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str
) -> Result<(), Box<dyn std::error::Error>> {
    let tls_config = load_tls_config(cert_path, key_path)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(addr).await?;
    info!("TLS-Metrics-Server lauscht unter https://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let service = make_service_fn(|_| async {
                        Ok::<_, hyper::Error>(service_fn(handle_metrics))
                    });

                    if let Err(err) = Http::new()
                        .serve_connection(tls_stream, service)
                        .await
                    {
                        error!("Fehler bei Verbindung: {:?}", err);
                    }
                }
                Err(e) => error!("TLS-Handshake fehlgeschlagen: {:?}", e),
            }
        });
    }
}

/// Startet einen TLS-geschützten Prometheus-Metrics-Server mit dynamisch generiertem Zertifikat (rcgen)
pub async fn serve_metrics_tls_generated(
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    let certs = vec![Certificate(cert_der)];
    let key = PrivateKey(key_der);

    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(addr).await?;
    info!("TLS-Metrics-Server (rcgen) lauscht unter https://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let service = make_service_fn(|_| async {
                        Ok::<_, hyper::Error>(service_fn(handle_metrics))
                    });

                    if let Err(err) = Http::new()
                        .serve_connection(tls_stream, service)
                        .await
                    {
                        error!("Fehler bei Verbindung: {:?}", err);
                    }
                }
                Err(e) => error!("TLS-Handshake fehlgeschlagen: {:?}", e),
            }
        });
    }
}

