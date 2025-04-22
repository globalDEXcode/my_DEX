// my_dex/src/config_loader.rs
//
// Lädt die NodeConfig aus einer YAML-Datei, z. B. "config/node_config.yaml".
// Enthält Felder für DB-Retries, Merge-Retries, HSM/TPM (PKCS#11),
// NTP, STUN/TURN, TLS/mTLS-Konfiguration usw.
//

use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tracing::{info, instrument};
use crate::error::DexError;
use keyring::Keyring;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeConfig {
    // Basisfelder
    pub node_id: String,
    pub listen_addr: String,
    pub metrics_addr: String,
    pub jaeger_addr: String,
    pub atomic_swap_timeout_sec: u64,
    pub crdt_merge_interval_sec: u64,
    pub log_level: String,
    pub db_path: String,

    // DB-Retries
    pub db_max_retries: u32,
    pub db_backoff_sec: u64,

    // Merge-Retries
    pub merge_max_retries: u32,
    pub merge_backoff_sec: u64,

    // Noise/TLS
    pub use_noise: bool,

    // Identity / KeyStore
    pub keystore_path: String,
    pub keystore_pass: String,

    // Access Control
    pub allowed_node_pubkeys: Vec<String>,

    // Timeouts
    pub order_timeout_sec: u64,
    pub swap_timeout_sec: u64,

    // Shard-Count
    pub num_shards: u32,

    // Minimaler Amount für partial fill
    pub partial_fill_min_amount: f64,

    // HSM/TPM-Felder
    pub use_hardware: bool,
    pub pkcs11_lib_path: String,
    pub slot_id: u64,
    pub hsm_pin: String,

    // NEUE Felder: NTP / STUN / TURN
    #[serde(default)]
    pub ntp_servers: Vec<String>,

    #[serde(default)]
    pub stun_server: String,

    #[serde(default)]
    pub turn_server: String,

    #[serde(default)]
    pub turn_username: String,

    #[serde(default)]
    pub turn_password: String,

    // NEU: TLS / Metrics-Absicherung
    #[serde(default)]
    pub metrics_token: Option<String>,

    #[serde(default)]
    pub metrics_enable_tls: bool,

    #[serde(default)]
    pub metrics_require_mtls: bool,

    #[serde(default)]
    pub metrics_tls_cert_path: Option<String>,

    #[serde(default)]
    pub metrics_tls_key_path: Option<String>,

    #[serde(default)]
    pub metrics_tls_client_ca_path: Option<String>,
}

/// Lädt die Config aus einer YAML-Datei.
/// Beispiel-Aufruf:
///   let mut cfg = load_config("config/node_config.yaml")?;
#[instrument(name = "load_config", skip(path))]
pub fn load_config(path: &str) -> Result<NodeConfig> {
    // Datei einlesen
    let content = fs::read_to_string(path)
        .map_err(|e| DexError::Other(format!("Fehler beim Lesen der Config-Datei {}: {:?}", path, e)))?;

    // YAML -> NodeConfig
    let mut cfg: NodeConfig = serde_yaml::from_str(&content)
        .map_err(|e| DexError::Other(format!("YAML-Deserialization error: {:?}", e)))?;

    // Kurzes Logging
    info!("NodeConfig geladen => node_id={}, log_level={}, ntp_servers={:?}, stun_server={}, turn_server={}",
        cfg.node_id,
        cfg.log_level,
        cfg.ntp_servers,
        cfg.stun_server,
        cfg.turn_server
    );

    // Secrets aus OS-Keyring laden
    // Wir verwenden hier den aktuellen Wert von cfg.keystore_pass als Key
    let keystore_pass = Keyring::new("my-dex", &cfg.keystore_pass)
        .get_password()
        .map_err(|e| DexError::Other(format!("Fehler beim Auslesen des Keystore-PIN: {}", e)))?;
    cfg.keystore_pass = keystore_pass;

    let hsm_pin = Keyring::new("my-dex", &cfg.hsm_pin)
        .get_password()
        .map_err(|e| DexError::Other(format!("Fehler beim Auslesen des HSM-PIN: {}", e)))?;
    cfg.hsm_pin = hsm_pin;

    Ok(cfg)
}

/// Validiert kritische Felder in der Konfiguration.
pub fn validate_config(cfg: &NodeConfig) -> Result<(), String> {
    // node_id darf nicht leer sein
    if cfg.node_id.trim().is_empty() {
        return Err("Konfig-Fehler: node_id darf nicht leer sein.".into());
    }

    // IP:Port prüfen
    validate_socket_addr("listen_addr", &cfg.listen_addr)?;
    validate_socket_addr("metrics_addr", &cfg.metrics_addr)?;

    // Sicherstellen, dass beide Adressen nicht identisch sind
    if cfg.listen_addr == cfg.metrics_addr {
        return Err("Konfig-Fehler: 'listen_addr' und 'metrics_addr' dürfen nicht identisch sein.".into());
    }

    // TLS aktiv, aber kein Pfad
    if cfg.metrics_enable_tls {
        if let Some(cert_path) = &cfg.metrics_tls_cert_path {
            if !Path::new(cert_path).exists() {
                return Err(format!("TLS aktiviert, aber Zertifikat '{}' existiert nicht.", cert_path));
            }
        }

        if let Some(key_path) = &cfg.metrics_tls_key_path {
            if !Path::new(key_path).exists() {
                return Err(format!("TLS aktiviert, aber privater Schlüssel '{}' existiert nicht.", key_path));
            }
        }

        if cfg.metrics_require_mtls {
            if let Some(ca_path) = &cfg.metrics_tls_client_ca_path {
                if !Path::new(ca_path).exists() {
                    return Err(format!("mTLS aktiv, aber Client-CA '{}' existiert nicht.", ca_path));
                }
            } else {
                return Err("mTLS ist aktiv, aber 'metrics_tls_client_ca_path' fehlt.".into());
            }
        }
    }

    Ok(())
}

/// Prüft, ob ein gegebener String eine gültige Socket-Adresse (IP:Port) ist.
fn validate_socket_addr(field_name: &str, addr: &str) -> Result<(), String> {
    match addr.parse::<SocketAddr>() {
        Ok(socket) => {
            if socket.port() < 1024 {
                return Err(format!(
                    "Port für '{}' liegt unter 1024 ({}), bitte vermeiden!",
                    field_name, socket.port()
                ));
            }

            if is_sensitive_port(socket.port()) {
                return Err(format!(
                    "Port für '{}' ({}) ist als kritisch bekannt (z. B. SSH, SQL, Redis) und sollte vermieden werden.",
                    field_name, socket.port()
                ));
            }

            Ok(())
        }
        Err(_) => Err(format!(
            "Ungültige Socket-Adresse für '{}': {}",
            field_name, addr
        )),
    }
}

/// Gibt true zurück, wenn ein Port als sensibel bekannt ist.
fn is_sensitive_port(port: u16) -> bool {
    matches!(
        port,
        22    // SSH
        | 25   // SMTP
        | 80   // HTTP
        | 443  // HTTPS
        | 3306 // MySQL
        | 5432 // PostgreSQL
        | 6379 // Redis
    )
}

