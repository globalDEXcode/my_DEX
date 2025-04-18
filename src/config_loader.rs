// my_dex/src/config_loader.rs
//
// Lädt die NodeConfig aus einer YAML-Datei, z. B. "config/node_config.yaml".
// Enthält Felder für DB-Retries, Merge-Retries, HSM/TPM (PKCS#11),
// NTP, STUN/TURN, TLS/mTLS-Konfiguration usw.
//

use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::fs;
use tracing::{info, instrument};
use crate::error::DexError;

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
///   let cfg = load_config("config/node_config.yaml")?;
#[instrument(name = "load_config", skip(path))]
pub fn load_config(path: &str) -> Result<NodeConfig> {
    // Datei einlesen
    let content = fs::read_to_string(path)
        .map_err(|e| DexError::Other(format!("Fehler beim Lesen der Config-Datei {}: {:?}", path, e)))?;

    // YAML -> NodeConfig
    let cfg: NodeConfig = serde_yaml::from_str(&content)
        .map_err(|e| DexError::Other(format!("YAML-Deserialization error: {:?}", e)))?;

    // Kurzes Logging
    info!("NodeConfig geladen => node_id={}, log_level={}, ntp_servers={:?}, stun_server={}, turn_server={}",
        cfg.node_id,
        cfg.log_level,
        cfg.ntp_servers,
        cfg.stun_server,
        cfg.turn_server
    );

    Ok(cfg)
}

/// Validiert kritische Felder in der Konfiguration.
pub fn validate_config(cfg: &NodeConfig) -> Result<(), String> {
    // node_id darf nicht leer sein
    if cfg.node_id.trim().is_empty() {
        return Err("Konfig-Fehler: node_id darf nicht leer sein.".into());
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
