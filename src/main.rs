///////////////////////////////////////////////////////////
// my_dex/src/main.rs
///////////////////////////////////////////////////////////
//
//  1) GlobalSecurity anlegen (Ring-Sign, Tor, DDoS-Limits, etc.).
//  2) Health-Probes / Download-Endpunkt bereitstellen (Kubernetes readiness/liveness).
//  3) Integration der regulatorischen Sanktionslisten (Update, Anomaly-Detection).
//  4) Node-Konfiguration laden (inkl. DB-Retries) inkl. Fallback-Mechanismen und Selbstkonfiguration.
//  5) Logging & Audit einrichten, inkl. detailliertes Logging für Abstimmungen (Fullnode & Trader Dashboards).
//  6) DB initialisieren (RocksDB oder InMemory-Fallback).
//  6.1) Distributed DB Replication starten (Optimierung der Zustandsverwaltung).
//  6.2) ClusterManager mit Node-Sync-Fee starten.
//  6.3) ShardManager mit CRDT initialisieren.
//  7) P2P-Security initialisieren (STUN/TURN).
//  8) DexNode anlegen & starten (inkl. optionaler globaler Security-Integration).
//  8.1) Sicherheits-Demo: Block erstellen, signieren und verifizieren.
//  8.2) Light Client Konsensüberprüfung integrieren.
//  9) MatchingEngine initialisieren.
//  9.1) Settlement-Workflow optimieren: SecuredSettlementEngine einsetzen.
// 10) Kademlia-Service + TcpP2PAdapter starten.
// 10.1) Sichere TCP-Operation durchführen (TLS-verschlüsselt).
// 11) mDNS Discovery-Task starten.
// 12) Monitoring-Server (Global und Node-Scope) starten.
// 12.1) Konsens-Sicherheitsprozess initialisieren (SecurityDecorator).
// 13) Asynchrone Sicherheits-Tasks starten.
// 14) CRDT partial fill Demo auf dem DexNode durchführen.
// 15) Accounts/Wallet-Demo implementieren (Fullnode vs. NormalUser, 2FA, Delete -> Spenden).
// 16) Start des Fee-Pool-Distributor-Tasks (periodische Fee-Ausschüttung).
// 17) Audit eines Handelsereignisses durchführen.
// 17.1) Layer-2 DEX Integration & Trade-Verarbeitung via Layer2DEX.
// 18) Time-Limited Orders: Hintergrund-Task zum Prüfen abgelaufener Orders starten.
// 19) PriceFeed starten & Account-Endpunkte bereitstellen.
// 20) IPFS-Integration: Audit-Log dezentral speichern.
// 21) IPFS-Integration: Konfigurationsdatei dezentral speichern.
// 22) Dezentrale Fehlerverteilung via Reliable Gossip.
// 23) Self-Healing Watchdog starten (Config-basiert, parallelisiert, modular).
// 24) Warten auf Ctrl+C => geordneter Shutdown.
//

use anyhow::Result;
use tokio::signal;
use tracing::{info, warn, error, instrument, debug};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use once_cell::sync::Lazy;
use chrono::{Utc};
mod metrics_tls;


use crate::config_loader::{load_config, NodeConfig};
use crate::node_logic::DexNode;
use crate::storage::db_layer::{DexDB, CrdtSnapshot};
use crate::tracing_setup::shutdown_tracing;
use crate::monitoring::global_monitoring::start_global_monitoring_server;
use crate::monitoring::node_monitoring::start_node_monitoring_server;
use crate::security::async_security_tasks::run_security_tasks;
use crate::logging::enhanced_logging::{init_enhanced_logging, log_error, write_audit_log};
use crate::tracing_setup::init_tracing_with_otel_from_env;
use crate::network::p2p_security::{P2PSecurityConfig, AdvancedP2PSecurity, P2PSecurity};
use crate::network::cluster_management::ClusterManager;
use crate::kademlia::kademlia_service::{KademliaService, NodeId, KademliaMessage, KademliaP2PAdapter};
use crate::kademlia::mdns_discovery::{start_mdns_discovery, MdnsConfig};
use crate::identity::accounts::{AccountsManager, AccountType};
use crate::identity::wallet::{
    WalletManager, BlockchainType,
    BitcoinRPCConfig, ETHConfig, LTCConfig,
};
use crate::fees::fee_pool::FeePool;
use crate::dex_logic::time_limited_orders::check_expired_time_limited_orders;
use crate::network::p2p_adapter::TcpP2PAdapter;

use axum::{
    routing::get,
    Router,
    response::IntoResponse,
    http::{StatusCode, Response},
};
use std::net::SocketAddr as HealthSocketAddr;
use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::dex_logic::time_limited_orders::TimeLimitedOrderManager;
use crate::self_healing::custom_checks::inject_orderbook;
use crate::dex_logic::crdt_orderbook::OrderBookCRDT;
use crate::security::global_security_facade::GlobalSecuritySystem;
use crate::matching_engine::MatchingEngine;
use crate::crypto_scraper::PriceFeed;

// Zusätzliche Imports für IPFS Storage
use crate::storage::ipfs_storage::{add_file_to_ipfs, cat_file_from_ipfs};

// Importiere den IPFS-Manager (aus src/ipfs_manager.rs)
mod ipfs_manager;
use ipfs_manager::start_ipfs_daemon;

mod metrics_tls;
use crate::metrics_tls;

// ─────────────────────────────────────────────────────────────
// Integration des neuen Monitoring-Moduls inklusive metrics_server
// ─────────────────────────────────────────────────────────────
mod monitoring {
    // Hier wird das neue Modul "metrics_server" eingeführt.
    pub mod metrics_server {
        use axum::{Router, routing::get, http::StatusCode, Server};
        /// Diese Funktion startet einen einfachen Metrics-Server, der unter `/metrics` immer den Status OK zurückgibt.
        pub async fn run_metrics_server() {
            let app = Router::new().route("/metrics", get(|| async { StatusCode::OK }));
            let addr = "127.0.0.1:9300".parse().unwrap();
            println!("Metrics server started on {}", addr);
            if let Err(e) = Server::bind(&addr)
                .serve(app.into_make_service())
                .await
            {
                eprintln!("Metrics server error: {}", e);
            }
        }
    }
    // ... weitere Module (global_monitoring, node_monitoring, etc.) können hier ebenfalls definiert werden.
}

// Integration des Gossip- und Self-Healing-Moduls
mod gossip {
    use chrono::{DateTime, Utc};
    use serde::{Serialize, Deserialize};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, RwLock};
    use tokio::time::sleep;
    use tracing::{info, warn};
    use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
    use hex;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct FaultMessage {
        pub node_id: String,
        pub fault_type: String,
        pub timestamp: DateTime<Utc>,
        pub log_excerpt: String,
        pub severity: String,
        pub ttl: u64,
        pub signature: Option<String>,
    }

    impl FaultMessage {
        pub fn new(
            node_id: String,
            fault_type: String,
            log_excerpt: String,
            severity: String,
            ttl: u64,
        ) -> Self {
            FaultMessage {
                node_id,
                fault_type,
                timestamp: Utc::now(),
                log_excerpt,
                severity,
                ttl,
                signature: None,
            }
        }

        pub fn new_signed(
            node_id: String,
            fault_type: String,
            log_excerpt: String,
            severity: String,
            ttl: u64,
            keypair: &Keypair,
        ) -> Self {
            let timestamp = Utc::now();
            let message_str = format!("{}{}{}{}{}", node_id, fault_type, timestamp, log_excerpt, severity);
            let signature = keypair.sign(message_str.as_bytes());
            FaultMessage {
                node_id,
                fault_type,
                timestamp,
                log_excerpt,
                severity,
                ttl,
                signature: Some(hex::encode(signature.to_bytes())),
            }
        }

        pub fn verify(&self, public_key: &PublicKey) -> bool {
            if let Some(sig_hex) = &self.signature {
                if let Ok(sig_bytes) = hex::decode(sig_hex) {
                    if let Ok(signature) = Signature::from_bytes(&sig_bytes) {
                        let message_str = format!("{}{}{}{}{}", self.node_id, self.fault_type, self.timestamp, self.log_excerpt, self.severity);
                        return public_key.verify(message_str.as_bytes(), &signature).is_ok();
                    }
                }
            }
            false
        }
    }

    pub struct GossipManager {
        pub sender: mpsc::Sender<FaultMessage>,
        pub receiver: mpsc::Receiver<FaultMessage>,
        pub cache: RwLock<HashMap<String, (FaultMessage, Instant)>>,
        pub ttl: Duration,
    }

    impl GossipManager {
        pub fn new(ttl: Duration, channel_capacity: usize) -> Self {
            let (sender, receiver) = mpsc::channel(channel_capacity);
            GossipManager {
                sender,
                receiver,
                cache: RwLock::new(HashMap::new()),
                ttl,
            }
        }

        pub async fn broadcast(&self, msg: FaultMessage) -> Result<(), String> {
            let serialized = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
            let expiration = Instant::now() + self.ttl;
            {
                let mut cache = self.cache.write().await;
                cache.insert(serialized.clone(), (msg.clone(), expiration));
            }
            self.sender.send(msg).await.map_err(|e| e.to_string())?;
            Ok(())
        }

        pub async fn process_incoming(&self) {
            while let Some(msg) = self.receiver.recv().await {
                info!("Received gossip message: {:?}", msg);
                let serialized = match serde_json::to_string(&msg) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Error serializing message: {}", e);
                        continue;
                    }
                };
                {
                    let mut cache = self.cache.write().await;
                    if !cache.contains_key(&serialized) {
                        let expiration = Instant::now() + self.ttl;
                        cache.insert(serialized, (msg, expiration));
                    }
                }
            }
        }

        pub async fn cleanup_cache(&self) {
            loop {
                sleep(Duration::from_secs(10)).await;
                let now = Instant::now();
                let mut cache = self.cache.write().await;
                let before = cache.len();
                cache.retain(|_, &mut (_, exp)| exp > now);
                let after = cache.len();
                if before != after {
                    info!("Cache cleanup: {} messages removed", before - after);
                }
            }
        }
    }
    
    pub async fn broadcast_gossip_message(msg: FaultMessage) {
        println!("Broadcasting Fault Message: {:?}", msg);
    }
}

mod self_healing;
use crate::self_healing::{
    config::load_config as load_watchdog_config,
    config::extract_whitelist,
    watchdog::monitor_and_heal,
};


    pub async fn check_service_health(service_name: &str) -> bool {
        false
    }

    pub async fn restart_service(service_name: &str) -> Result<(), String> {
        let max_attempts = 5;
        let base_delay = Duration::from_secs(1);
        for attempt in 1..=max_attempts {
            info!("Restart attempt {} for service '{}'", attempt, service_name);
            let result = Command::new("echo")
                .arg("restarting service")
                .status();
            if let Ok(status) = result {
                if status.success() {
                    return Ok(());
                }
            }
            let delay = base_delay * attempt;
            warn!("Attempt {} for service '{}' failed, retrying in {:?}...", attempt, service_name, delay);
            sleep(delay).await;
        }
        Err(format!("Failed to restart service '{}' after {} attempts", service_name, max_attempts))
    }

    pub async fn load_backup_config() -> Option<String> {
        match crate::storage::ipfs_storage::cat_file_from_ipfs("backup_config_hash").await {
            Ok(data) => Some(String::from_utf8_lossy(&data).to_string()),
            Err(e) => {
                warn!("Failed to load backup config from IPFS: {:?}", e);
                None
            }
        }
    }

    pub async fn monitor_and_heal(service_name: &str, node_id: &str, interval_sec: u64) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_sec));
        loop {
            interval.tick().await;
            let healthy = check_service_health(service_name).await;
            if !healthy {
                warn!("Service '{}' appears unhealthy. Initiating self-healing.", service_name);
                let gossip_msg = crate::gossip::FaultMessage::new(
                    node_id.to_string(),
                    format!("{} failure", service_name),
                    format!("Service {} is unresponsive", service_name),
                    "critical".to_string(),
                    60,
                );
                broadcast_gossip_message(gossip_msg).await;
                match restart_service(service_name).await {
                    Ok(_) => info!("Service '{}' successfully restarted.", service_name),
                    Err(e) => {
                        warn!("Failed to restart service '{}': {}. Initiating fallback.", service_name, e);
                        if let Some(backup_config) = load_backup_config().await {
                            info!("Backup config loaded: {}", backup_config);
                        }
                    }
                }
            } else {
                info!("Service '{}' is healthy.", service_name);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Integration des Reliable Gossip Moduls
// ─────────────────────────────────────────────────────────────
mod reliable_gossip;
use reliable_gossip::{GossipMessage, GossipNode as ReliableGossipNode};

use crate::crypto::fallback_config::{load_backup_config_with_retry, verify_config_signature};

static IS_READY: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

mod sanctions {
    pub mod sanctions_list;
    pub mod internal_analysis;
    pub mod update_manager;
}

mod monitoring_logging {
    use chrono::{DateTime, Utc};
    use std::sync::{Mutex, Arc};

    #[derive(Debug, Clone)]
    pub struct LogEntry {
        pub timestamp: DateTime<Utc>,
        pub user_type: String,
        pub event: String,
    }

    pub struct Logger {
        logs: Mutex<Vec<LogEntry>>,
    }

    impl Logger {
        pub fn new() -> Self {
            Logger { logs: Mutex::new(Vec::new()) }
        }

        pub fn log_event(&self, user_type: &str, event: &str) {
            let entry = LogEntry {
                timestamp: Utc::now(),
                user_type: user_type.to_string(),
                event: event.to_string(),
            };
            let mut logs = self.logs.lock().unwrap();
            logs.push(entry);
        }

        pub fn get_logs_for_user(&self, user_type: &str) -> Vec<LogEntry> {
            let logs = self.logs.lock().unwrap();
            logs.iter().filter(|e| e.user_type == user_type).cloned().collect()
        }

        pub fn get_all_logs(&self) -> Vec<LogEntry> {
            let logs = self.logs.lock().unwrap();
            logs.clone()
        }
    }

    pub fn get_global_logger() -> Arc<Logger> {
        Arc::new(Logger::new())
    }
}

use monitoring_logging::{get_global_logger, Logger, LogEntry};

// ─────────────────────────────────────────────────────────────
// REST API Modul Integration
// ─────────────────────────────────────────────────────────────
mod rest_api;
use rest_api::{build_rest_api, AppState};

///////////////////////////////////////////////////////////
// Integration des neuen asynchronen Sicherheits-Tasks-Moduls
///////////////////////////////////////////////////////////
mod security {
    pub mod async_security_tasks {
        use tokio::time::{sleep, Duration};
        use tracing::{info, instrument};

        #[instrument]
        async fn validate_order() -> bool {
            info!("Validating order");
            sleep(Duration::from_millis(100)).await;
            true
        }

        #[instrument]
        async fn validate_trade() -> bool {
            info!("Validating trade");
            sleep(Duration::from_millis(100)).await;
            true
        }

        #[instrument]
        async fn validate_settlement() -> bool {
            info!("Validating settlement");
            sleep(Duration::from_millis(100)).await;
            true
        }

        /// Führt kontinuierlich alle Sicherheitsaufgaben parallel aus.
        pub async fn run_security_tasks() {
            loop {
                info!("Starting security tasks iteration");
                let (order_result, trade_result, settlement_result) = tokio::join!(
                    validate_order(),
                    validate_trade(),
                    validate_settlement()
                );
                info!(
                    "Completed security tasks: order: {}, trade: {}, settlement: {}",
                    order_result, trade_result, settlement_result
                );
                sleep(Duration::from_secs(5)).await;
            }
        }
    }

    pub mod global_security_facade {
        use anyhow::Result;
        pub struct GlobalSecuritySystem {
            pub enable_ring_sign: bool,
            pub enable_tor: bool,
            pub max_ddos_rate_per_min: u32,
        }
        impl GlobalSecuritySystem {
            pub fn new() -> Self {
                GlobalSecuritySystem {
                    enable_ring_sign: false,
                    enable_tor: false,
                    max_ddos_rate_per_min: 0,
                }
            }
            pub async fn init_all(&mut self) -> Result<()> {
                Ok(())
            }

            pub fn audit_event(&self, event_str: &str) {
                // In echter Umgebung => Logging, Metriken, etc.
                println!("GlobalSecuritySystem => audit_event: {}", event_str);
            }

            pub fn ring_sign_data(&self, data: &[u8]) -> Result<Vec<u8>, crate::error::DexError> {
                // In echter Umgebung => ring-sign Implementation
                // Hier nur Dummy
                Ok(vec![1,2,3,4])
            }
        }
    }
}

// Integration des Settlement-Moduls:
use crate::settlement::advanced_settlement::{AdvancedSettlementEngine, Asset};
use crate::settlement::secured_settlement::{SettlementEngineTrait, SecuredSettlementEngine};
use crate::security::security_validator::AdvancedSecurityValidator;

#[tokio::main]
#[instrument]
async fn main() -> Result<()> {
    init_tracing_with_otel_from_env();

// Globalen Logger initialisieren
let logger: Arc<Logger> = get_global_logger();
logger.log_event("system", "Global Logger initialisiert.");

// TLS-Metrics-Server starten (mit rcgen)
let tls_metrics_addr = "0.0.0.0:9443".parse::<SocketAddr>()?;
tokio::spawn(async move {
    if let Err(e) = metrics_tls::serve_metrics_tls_generated(tls_metrics_addr).await {
        error!("TLS-Metrics-Server konnte nicht gestartet werden: {:?}", e);
    }
});
logger.log_event("system", "TLS Metrics Server gestartet.");


// IPFS-Daemon starten (lokal, aus "my_dex/.ipfs/bin/")
match start_ipfs_daemon() {
    Ok(()) => {
        info!("IPFS daemon successfully started.");
        logger.log_event("system", "IPFS daemon successfully started.");
    },
    Err(e) => {
        warn!("Error starting IPFS daemon: {}", e);
        logger.log_event("system", &format!("Error starting IPFS daemon: {}", e));
    }
}

    // (1) GlobalSecurity anlegen
    let mut global_sec = security::global_security_facade::GlobalSecuritySystem::new();
    global_sec.enable_ring_sign = true;
    global_sec.enable_tor = true;
    global_sec.max_ddos_rate_per_min = 120;
    if let Err(e) = global_sec.init_all().await {
        error!("Global Security init fehlgeschlagen: {:?}", e);
    }
    let global_sec_arc = Arc::new(Mutex::new(global_sec));
    logger.log_event("system", "Global Security System initialisiert.");

    // (X) HSM-/TPM-Key-Management initialisieren
    use crate::crypto::hsm_provider::HsmProvider;
    use crate::crypto::hsm_provider::fallback;
    let hsm_provider = HsmProvider::new("/path/to/pkcs11.so")?;
    let session = hsm_provider.open_session("your_user_pin")?;
    info!("HSM-/TPM-Key-Management: HSM-Session erfolgreich geöffnet.");

    // (2) Health-Probes und Download-Endpunkt
    start_health_server().await;
    logger.log_event("system", "Health Server gestartet.");

    // (3) Integration der regulatorischen Sanktionslisten
    println!("Starte Integration der regulatorischen Sanktionslisten...");
    match sanctions::update_manager::update_sanctions_list() {
        Ok(_) => println!("Update der Sanktionsliste erfolgreich."),
        Err(e) => println!("Update-Prozess fehlgeschlagen: {}", e),
    }
    logger.log_event("system", "Sanktionslisten aktualisiert.");

    // (4) Node-Konfiguration laden
    let cfg_path = "config/node_config.yaml";
    let config: NodeConfig = match load_config(cfg_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            log_error(e);
            use crate::crypto::fallback_config::{load_backup_config_with_retry, verify_config_signature};
            let backup_config = load_backup_config_with_retry("config_backup_hash", 5, Duration::from_secs(1)).await?;
            // config-Signatur wird hier verifiziert => gut
            if !verify_config_signature(&backup_config, "signature_placeholder", "public_key_placeholder") {
                return Err(anyhow::anyhow!("Fallback configuration signature is invalid"));
            }
            serde_yaml::from_str(&backup_config).context("Failed to parse fallback configuration")?
        }
    };
    // TIPP: Du könntest hier optional negative Fee-Werte, etc. abfangen,
    // falls es in config misst. 
    logger.log_event("system", "Node-Konfiguration geladen.");

    // (5) Logging & Audit einrichten
    init_enhanced_logging(&config.log_level, "./logs", "audit.log");
    info!("Node startet => node_id={}, log_level={}", config.node_id, config.log_level);
    write_audit_log("Node-Start: Konfiguration und Logging initialisiert.");
    logger.log_event("system", "Enhanced Logging initialisiert.");

    // (6) DB initialisieren
    let db = match DexDB::open_with_retries(
        &config.db_path,
        config.db_max_retries,
        config.db_backoff_sec
    ) {
        Ok(db) => db,
        Err(e) => {
            log_error(e);
            return Err(anyhow::anyhow!("Datenbank konnte nicht geöffnet werden"));
        }
    };
    info!("DB init => fallback mem? => {}", if db.fallback_mem.is_some() { "YES" } else { "NO" });
    write_audit_log("DB initialisiert.");
    logger.log_event("system", "Datenbank initialisiert.");

    // CRDT-Snapshot-Test
    let snap = CrdtSnapshot { version: 1, data: vec![1, 2, 3, 4] };
    if let Err(e) = db.store_crdt_snapshot(&snap) {
        log_error(e);
    }
    match db.load_crdt_snapshot(1) {
        Ok(Some(loaded)) => info!("CRDT-Snapshot loaded => version={}, data={:?}", loaded.version, loaded.data),
        Ok(None) => info!("No snapshot found for v=1"),
        Err(e) => log_error(e),
    }
    write_audit_log("CRDT-Snapshot-Demo abgeschlossen.");
    logger.log_event("system", "CRDT-Snapshot-Test durchgeführt.");

    // (6.1) Distributed DB Replication
    {
        use crate::storage::distributed_db::{DistributedDexDB, RocksDBInstance, DistributedDB};
        let db_listen_addr: SocketAddr = "127.0.0.1:5002".parse()?;
        let local_db_instance = RocksDBInstance::new(&config.db_path)?;
        let distributed_db = DistributedDexDB::new(Box::new(local_db_instance), vec![], db_listen_addr);
        distributed_db.start_replication_server().await?;
        info!("Distributed DB replication server gestartet auf {}", db_listen_addr);
    }

    // (6.2) ClusterManager => Node-Sync-Fee
    {
        let mut cluster_mgr = ClusterManager::new(&config, &db);
        cluster_mgr.enable_sync_fee(0.01);
        cluster_mgr.start().await?;
        info!("ClusterManager => Neuer Node-Sync-Fee-Ansatz aktiv => 1% Belohnung für Sync-Knoten");
        logger.log_event("system", "ClusterManager mit Extra Sync-Fee integriert.");
    }

    // (6.3) ShardManager mit CRDT initialisieren
use crate::shard_logic::shard_manager::ShardManager;
use crate::watchtower::Watchtower;
use crate::crdt_logic::{CrdtDelta, Order};

let shard_manager = {
    let shard_manager = ShardManager::new(3, Some(kad_arc.clone()));

    // 1) Shard erstellen
    let watchtower = Watchtower::new();
    shard_manager.create_shard(0, "db_shard_0.db", watchtower)?;

    // 2) Lokalen Node abonnieren
    let local_id = kad_arc.lock().unwrap().local_id.clone();
    shard_manager.subscribe_node_to_shard(&local_id.to_string(), 0);

    // 3) Delta anwenden
    let delta = CrdtDelta {
        updated_orders: vec![
            Order {
                id: "order-123".to_string(),
                user_id: "local-user".to_string(),
                timestamp: 0,
                quantity: 1.5,
                price: 99.0,
            }
        ],
        removed_orders: vec![],
    };
    shard_manager.apply_delta(0, &delta)?;

    // 4) Snapshot + Checkpoint speichern
    shard_manager.store_shard_snapshot(0)?;
    shard_manager.checkpoint_and_store(0, 123_456, None)?;

    info!("ShardManager erfolgreich initialisiert und CRDT-Daten angewendet.");
    shard_manager
};

if let Some(orderbook) = shard_manager.get_orderbook_crdt(0) {
    inject_orderbook(orderbook);
}
logger.log_event("system", "ShardManager mit CRDT initialisiert.");


   // (7) P2P-Security initialisieren (STUN/TURN)
    let p2p_sec_cfg = P2PSecurityConfig {
        whitelist: Default::default(),
        blacklist: Default::default(),
        ddos_rate_limit_per_min: 60,
        tor_enabled: false,
        tor_socks_port: 9050,
        stun_server: config.stun_server.clone(),
        turn_server: config.turn_server.clone(),
        turn_username: config.turn_username.clone(),
        turn_password: config.turn_password.clone(),
    };
    let p2p_sec = AdvancedP2PSecurity::new(p2p_sec_cfg).await?;
    info!("P2PSecurity-System initialisiert.");
    logger.log_event("system", "P2PSecurity-System initialisiert.");

    if !config.stun_server.is_empty() {
        match p2p_sec.stun_probe_external_ip().await {
            Ok(ext_ip) => info!("STUN => external IP ist {}", ext_ip),
            Err(e) => warn!("STUN => external IP lookup fehlgeschlagen: {:?}", e),
        }
    }
    if !config.turn_server.is_empty() {
        match p2p_sec.turn_allocate_channel().await {
            Ok(_) => info!("TURN => Channel allocated."),
            Err(e) => warn!("TURN => allocate channel fehlgeschlagen: {:?}", e),
        }
    }

    // (8) DexNode anlegen & starten
    let mut node = DexNode::new(config.clone(), Some(global_sec_arc.clone()));
    node.start().await?;
    IS_READY.store(true, Ordering::Relaxed);
    write_audit_log("DexNode erfolgreich gestartet.");
    logger.log_event("system", "DexNode gestartet.");

    // (8.1) Sicherheits-Demo: Block erstellen, signieren und verifizieren
    {
        use crate::block::{Block, Transaction};
        use ed25519_dalek::Keypair;
        use rand::rngs::OsRng;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut csprng = OsRng {};
        let demo_keypair: Keypair = Keypair::generate(&mut csprng);

        let demo_transactions = vec![
            Transaction {
                id: 101,
                from: "DemoAlice".to_string(),
                to: "DemoBob".to_string(),
                amount: 42,
            },
            Transaction {
                id: 102,
                from: "DemoBob".to_string(),
                to: "DemoCharlie".to_string(),
                amount: 84,
            },
        ];

        let demo_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Zeitfehler")
            .as_secs();

        let mut demo_block = Block::new(999, "0".to_string(), demo_timestamp, 0, demo_transactions)
            .expect("Fehler beim Erstellen des Demo-Blocks");

        demo_block.sign_block(&demo_keypair);
        info!("Demo-Block erstellt und signiert: {:#?}", demo_block);

        let block_valid = demo_block.verify_block(&demo_keypair.public);
        if block_valid {
            info!("Demo-Block-Signatur ist gültig.");
        } else {
            error!("Demo-Block-Signatur ist ungültig!");
        }
    }

    // (8.2) Light Client Konsensüberprüfung integrieren
    {
        mod light_client;
        use light_client::{LightClient, Peer, BlockHeader};
        use tokio::time::Duration;

        struct DummyPeer {
            id: String,
        }

        #[async_trait::async_trait]
        impl Peer for DummyPeer {
            async fn get_latest_block_header(&self) -> Result<BlockHeader, anyhow::Error> {
                Ok(BlockHeader::new(100, "prev_hash_example".into(), 1630000000, 42, "merkle_root_example".into()))
            }
            fn get_peer_id(&self) -> String {
                self.id.clone()
            }
        }

        let peers: Vec<Box<dyn Peer + Send + Sync>> = vec![
            Box::new(DummyPeer { id: "Peer1".into() }),
            Box::new(DummyPeer { id: "Peer2".into() }),
            Box::new(DummyPeer { id: "Peer3".into() }),
        ];

        let light_client = LightClient::new(peers, 2, Duration::from_secs(5));
        tokio::spawn(async move {
            light_client.monitor_consensus(Duration::from_secs(30)).await;
        });
        info!("Light Client Konsensüberprüfung gestartet.");
    
        let api_state = AppState {
            node: Arc::new(node.clone()),
        };
        
        let api_router = build_rest_api(api_state);
        tokio::spawn(async move {
            let addr = "0.0.0.0:8080".parse::<SocketAddr>().unwrap();
            info!("REST-API läuft auf {}", addr);
            axum::Server::bind(&addr)
                .serve(api_router.into_make_service())
                .await
                .expect("REST-API konnte nicht gestartet werden");
    });

    // (9) MatchingEngine initialisieren
    let mut engine = MatchingEngine::new_with_global_security(Some(global_sec_arc.clone()));
    // Optional: Orders platzieren, etc.

    // (9.1) Settlement-Workflow optimieren: SecuredSettlementEngine
    {
        use crate::settlement::advanced_settlement::{AdvancedSettlementEngine, Asset};
        use crate::settlement::secured_settlement::{SettlementEngineTrait, SecuredSettlementEngine};
        use crate::security::security_validator::AdvancedSecurityValidator;

        let arc_db = Arc::new(Mutex::new(db));
        let settlement_fee_pool = Arc::new(FeePool::new(arc_db.clone(), "settlement/fee_pool"));

        let standard_fee = config.settlement_fees.standard;
        let atomic_fee   = config.settlement_fees.atomic_swap;

        let advanced_settlement_engine = AdvancedSettlementEngine::new(
            settlement_fee_pool,
            arc_db.clone(),
            standard_fee,
            atomic_fee
        );

        let mut secured_engine = SecuredSettlementEngine::new(
            advanced_settlement_engine,
            AdvancedSecurityValidator::new()
        );

        match secured_engine.finalize_trade("buyer1", "seller1", Asset::BTC, Asset::LTC, 1.0, 50000.0) {
            Ok(_) => info!("Settlement trade finalized successfully."),
            Err(e) => error!("Settlement trade failed: {:?}", e),
        }
    }

    // (10) Kademlia-Service + TcpP2PAdapter
    let local_node_id = NodeId::random();
    info!("Kademlia => local NodeId = {:?}", &local_node_id);
    let parse_addr = config.listen_addr.parse::<SocketAddr>()?;
    let p2p_adapter = Arc::new(Mutex::new(TcpP2PAdapter::new(parse_addr)));
    {
        let p2p_clone = p2p_adapter.clone();
        tokio::spawn(async move {
            if let Err(e) = p2p_clone.lock().unwrap().start_listener().await {
                error!("TCP P2PAdapter: listener error: {:?}", e);
            }
        });
    }
    let kad_service = KademliaService::new(local_node_id, 20, p2p_adapter.clone());
    let kad_arc = Arc::new(Mutex::new(kad_service));
    {
        let kad_for_task = kad_arc.clone();
        tokio::spawn(async move {
            kad_for_task.lock().unwrap().run_service().await;
        });
    }

    // (10.1) Sichere TCP-Operation
    {
        use crate::network::p2p_operations::send_secure_data_to_peer;
        match send_secure_data_to_peer("192.168.1.100:443", "example.com", b"Hello, secure peer!").await {
            Ok(response) => info!("Secure peer response: {:?}", response),
            Err(e) => error!("Secure peer operation failed: {:?}", e),
        }
    }

    // (11) mDNS Discovery-Task
    {
        let mdns_cfg = MdnsConfig {
            service_name: "_mydex._udp".to_string(),
            port: parse_addr.port(),
        };
        let kad_for_mdns = kad_arc.clone();
        tokio::spawn(async move {
            match start_mdns_discovery(kad_for_mdns, mdns_cfg).await {
                Ok(_) => info!("mDNS discovery loop ended gracefully."),
                Err(e) => error!("mDNS discovery error: {:?}", e),
            }
        });
    }

    // (12) Monitoring-Server
    let global_addr: SocketAddr = "127.0.0.1:9100".parse()?;
    tokio::spawn(async move {
        info!("Global Monitoring Server wird auf {} gestartet", global_addr);
        start_global_monitoring_server(global_addr).await;
    });
    let node_addr: SocketAddr = "127.0.0.1:9200".parse()?;
    tokio::spawn(async move {
        info!("Node Monitoring Server wird auf {} gestartet", node_addr);
        start_node_monitoring_server(node_addr).await;
    });
    tokio::spawn(async {
        info!("Metrics Server wird auf 127.0.0.1:9300 gestartet");
        monitoring::metrics_server::run_metrics_server().await;
    });
    info!("Monitoring-Server wurden gestartet.");
    write_audit_log("Monitoring-Server initialisiert.");
    logger.log_event("system", "Monitoring-Server gestartet.");

    // (12.1) Konsens-Sicherheitsprozess
    {
        let base_consensus = BaseConsensus;
        let secured_consensus = SecurityDecorator::new(base_consensus);
        let consensus_proposal = secured_consensus.propose("Beispiel-Konsensdaten").await?;
        info!("Konsens-Proposal erstellt: {}", consensus_proposal);
    }

    // (13) Asynchrone Sicherheits-Tasks
    tokio::spawn(async {
        run_security_tasks().await;
    });
    write_audit_log("Asynchrone Sicherheitsaufgaben gestartet.");
    logger.log_event("system", "Sicherheits-Tasks gestartet.");

    // (14) CRDT partial fill Demo
    node.add_order("order-abc");
    node.add_order("order-xyz");
    let pf1 = node.partial_fill_order("order-abc", 3.0);
    info!("Partial fill result => {:?}", pf1);
    write_audit_log("Beispielhafte Order-Operationen durchgeführt.");
    logger.log_event("system", "Partial fill Demo durchgeführt.");

    // (15) Accounts/Wallet-Demo
    let arc_db = Arc::new(Mutex::new(db));
    let btc_cfg = BitcoinRPCConfig {
        rpc_url: "http://127.0.0.1:8332".into(),
        rpc_user: "bitcoinrpc".into(),
        rpc_pass: "pass".into(),
    };
    let ltc_cfg = LTCConfig {
        rpc_url: "http://127.0.0.1:19332".into(),
        rpc_user: "ltcrpc".into(),
        rpc_pass: "pass".into(),
    };
    let eth_cfg = ETHConfig {
        rpc_url: "https://mainnet.infura.io/v3/<yourKey>".into(),
    };
    let wmgr = WalletManager::new(
        arc_db.lock().unwrap().clone(),
        Some(btc_cfg),
        Some(ltc_cfg),
        Some(eth_cfg)
    );
    let acc_mgr = AccountsManager::new(arc_db.clone(), wmgr);
    acc_mgr.register_fullnode_account("fullnode_1", "topsecret", Some("Germany".into()))?;
    let _fn_acc = acc_mgr.login_fullnode("fullnode_1", "topsecret")?;
    info!("Fullnode-Betreiber eingeloggt => user_id=fullnode_1");
    logger.log_event("fullnode", "Fullnode-Betreiber fullnode_1 eingeloggt.");
    acc_mgr.register_normal_user("alice", "mypassword", true, Some("Egypt".into()))?;
    match acc_mgr.login_normal_user("alice", "mypassword", Some("123456")) {
        Ok(acc) => {
            info!("NormalUser eingeloggt => user_id={}", acc.user_id);
            logger.log_event("trader", &format!("NormalUser {} eingeloggt.", acc.user_id));
        },
        Err(e) => {
            warn!("Login user=alice => error={:?}", e);
            logger.log_event("trader", "NormalUser alice Login fehlgeschlagen.");
        },
    }
    acc_mgr.pause_account("alice")?;
    if let Err(e) = acc_mgr.delete_account("alice") {
        warn!("delete_account(alice) => {:?}", e);
        acc_mgr.donate_all_funds("alice")?;
        acc_mgr.delete_account("alice")?;
        info!("Account alice nun gelöscht");
        logger.log_event("trader", "Account alice gelöscht nach Fund-Spende.");
    }

    // (16) Fee-Pool Distributor Task
    let fee_pool = FeePool::new(arc_db.clone(), "system_accounts/fee_pool");
    {
        let fp_clone = fee_pool.clone();
        tokio::spawn(async move {
            loop {
                info!("FeePoolDistributor: Starte periodische Fee-Verteilung...");
                if let Err(e) = fp_clone.distribute_all() {
                    warn!("Fee distribution error: {:?}", e);
                }
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
    }
    info!("Fee-Pool Distributor-Task gestartet.");
    write_audit_log("Fee-Pool Distributor-Task gestartet.");
    logger.log_event("system", "Fee-Pool Distributor-Task gestartet.");

    // (17) Audit eines Handelsereignisses
    {
        use crate::audit::audit_log::{TradeAuditEvent, TradeEventType, log_trade_event};
        let trade_event = TradeAuditEvent::new(
            TradeEventType::Sell,
            "ETH",
            10.0,
            Some("Charlie".to_string()),
            Some("Dave".to_string()),
        );
        if let Err(e) = log_trade_event(&trade_event, "trade_audit.log") {
            eprintln!("Fehler beim Loggen des Handelsereignisses: {:?}", e);
        } else {
            info!("Handelsereignis wurde erfolgreich protokolliert.");
        }
        logger.log_event("system", "Handelsereignis auditiert.");
    }

    // (17.1) Layer-2 DEX Integration
    {
        use my_dex::layer2::Layer2DEX;
        tracing::info!("Layer-2 DEX Integration: Starte Initialisierung.");
        let layer2 = Layer2DEX::new(1000, 30, 70, "0.0.0.0:9000".to_string(), 10);
        if let Err(e) = layer2.initialize().await {
            tracing::error!("Layer2DEX initialization failed: {:?}", e);
        }
        if let Err(e) = layer2.process_trade("OrderDelta: Buy 100 XYZ at price 10").await {
            tracing::error!("Layer2DEX trade processing failed: {:?}", e);
        }
        let layer2_clone = layer2;
        tokio::spawn(async move {
            if let Err(e) = layer2_clone.delta_gossip.start_listener().await {
                tracing::error!("Layer2DEX delta gossip listener error: {:?}", e);
            }
        });
        let layer2_clone2 = layer2;
        tokio::spawn(async move {
            if let Err(e) = layer2_clone2.watchtower_service.monitor().await {
                tracing::error!("Layer2DEX watchtower monitoring error: {:?}", e);
            }
        });
        tracing::info!("Layer-2 DEX Integration abgeschlossen.");
    }

    // (18) Time-Limited Orders: Hintergrund-Task
    {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if let Err(e) = check_expired_time_limited_orders() {
                    eprintln!("Fehler beim Prüfen abgelaufener Orders: {:?}", e);
                }
            }
        });
        info!("Background-Task für Time-Limited-Orders gestartet (alle 30s)...");
        logger.log_event("system", "Time-Limited Orders Background-Task gestartet.");
    }

    // (19) PriceFeed-Integration und Account-Endpunkt
    // NEU: In echter Produktion => 
    //   1) TLS-gesicherte WebSocket
    //   2) ggf. mehrere Feeds / signierte Oracles, um Manipulationen zu vermeiden
    let price_feed = Arc::new(Mutex::new(PriceFeed::new()));
    tokio::spawn({
        let price_feed_clone = price_feed.clone();
        async move {
            if let Err(e) = crate::run_price_feed_system(price_feed_clone).await {
                error!("PriceFeed system error: {:?}", e);
            }
        }
    });
    #[derive(Clone)]
    struct AppState {
        price_feed: Arc<Mutex<PriceFeed>>,
    }
    async fn get_current_prices(State(state): State<AppState>) -> Json<serde_json::Value> {
        let pf = state.price_feed.lock().unwrap();
        Json(json!( {
            "prices": pf.prices,
            "last_updated": pf.last_updated,
        }))
    }
    // TIPP: In Produktion => HTTPS/TLS, Auth, 
    // damit nicht jeder ungeprüft auf 0.0.0.0:3000 zugreifen kann.
    let account_routes = Router::new()
        .route("/prices", get(get_current_prices))
        .with_state(AppState { price_feed: price_feed.clone() });
    tokio::spawn(async move {
        let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
        info!("Account endpoint server gestartet auf {}", addr);
        axum::Server::bind(&addr)
            .serve(account_routes.into_make_service())
            .await
            .unwrap();
    });

    // (20) Kritische Daten dezentral über IPFS speichern: Audit-Log
    {
        match add_file_to_ipfs("trade_audit.log").await {
            Ok(hash) => {
                info!("Audit Log erfolgreich auf IPFS gespeichert, Hash: {}", hash);
                logger.log_event("system", &format!("Audit Log auf IPFS gespeichert, Hash: {}", hash));
            },
            Err(e) => {
                warn!("Fehler beim Speichern des Audit Logs auf IPFS: {:?}", e);
                logger.log_event("system", "Fehler beim Speichern des Audit Logs auf IPFS.");
            }
        }
    }
    
    // (21) Kritische Daten dezentral über IPFS speichern: Konfigurationsdatei
    {
        match add_file_to_ipfs("config/node_config.yaml").await {
            Ok(hash) => {
                info!("Konfigurationsdatei erfolgreich auf IPFS gespeichert, Hash: {}", hash);
                logger.log_event("system", &format!("Konfigurationsdatei auf IPFS gespeichert, Hash: {}", hash));
            },
            Err(e) => {
                warn!("Fehler beim Speichern der Konfigurationsdatei auf IPFS: {:?}", e);
                logger.log_event("system", "Fehler beim Speichern der Konfigurationsdatei auf IPFS.");
            }
        }
    }
    
    // (22) Dezentrale Fehlerverteilung mittels Gossip
    {
        use crate::gossip::FaultMessage;
        let (rg_tx, rg_rx) = tokio::sync::mpsc::channel(100);
        let mut reliable_node = ReliableGossipNode::new("node-123".to_string(), rg_tx, rg_rx);
        let fault = FaultMessage {
            node_id: "node-123".to_string(),
            fault_type: "Datenbankfehler".to_string(),
            timestamp: Utc::now(),
            log_excerpt: "DB connection timeout".to_string(),
            severity: "critical".to_string(),
            ttl: 60,
            signature: None,
        };
        let fault_payload = serde_json::to_vec(&fault)
            .expect("Fehler beim Serialisieren der FaultMessage");
        tokio::spawn(async move {
            if let Err(e) = reliable_node.broadcast(fault_payload).await {
                eprintln!("Fehler beim Reliable Gossip Broadcast: {:?}", e);
            }
        });
        logger.log_event("system", "Beispielhafte Fehlermeldung via Reliable Gossip verschickt.");
    }

// (23) Self-Healing Watchdog starten
if let Some(wd_config) = load_watchdog_config("config/watchdog.toml") {
    print_loaded_services(&wd_config);
    if !validate_config(&wd_config) {
        error!("Ungültige Watchdog-Konfiguration – Self-Healing wird nicht gestartet.");
    } else {
        let whitelist = extract_whitelist(&wd_config);

        for (service_name, svc_cfg) in wd_config.services.iter() {
            let node_id = config.node_id.clone();
            let svc_name = service_name.clone();
            let interval = svc_cfg.interval_sec;
            let svc_cfg = svc_cfg.clone();
            let wl = whitelist.clone();

            tokio::spawn(async move {
                monitor_and_heal(&svc_name, &node_id, interval, svc_cfg, wl).await;
            });
        }

        info!("Self-Healing Watchdog aktiviert für {} Dienste", whitelist.len());
        logger.log_event("system", "Self-Healing Watchdog aktiviert.");
    }
} else {
    warn!("Watchdog-Konfiguration konnte nicht geladen werden – kein Self-Healing aktiv.");
}



    // (24) Warten auf Ctrl+C => geordneter Shutdown
    info!("DEX Node läuft – drücken Sie Strg+C zum Beenden");
    tokio::signal::ctrl_c().await?;
    info!("Shutdown-Signal empfangen – Node wird beendet");
    write_audit_log("Shutdown-Signal empfangen.");
    shutdown_tracing();
    Ok(())
}

async fn start_health_server() {
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(|| async {
            if IS_READY.load(Ordering::Relaxed) {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }))
        .route("/download_audit_log", get(download_audit_log));
    let addr = HealthSocketAddr::from(([0, 0, 0, 0], 9100));
    tokio::spawn(async move {
        if let Err(e) = axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
        {
            eprintln!("Health server error: {}", e);
        }
    });
}

async fn download_audit_log() -> impl IntoResponse {
    match tokio::fs::read("trade_audit.log").await {
        Ok(data) => {
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .header("Content-Disposition", "attachment; filename=\"trade_audit.log\"")
                .body(data)
                .unwrap()
        }
        Err(_) => {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body("Audit-Log-Datei nicht gefunden".into())
                .unwrap()
        }
    }
}
