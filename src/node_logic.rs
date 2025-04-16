///////////////////////////////////////////////////////////
// my_dex/src/node_logic.rs
///////////////////////////////////////////////////////////
//
//  1) DexNode (Original-Implementierung)
//    - new(config: NodeConfig): Konstruktor
//    - start() (async): Start-Logik (NTP-Sync, NAT-Traversal)
//    - calc_fee_preview(amount: f64)
//    - place_order(req: OrderRequest)
//    - list_open_orders()
//    - execute_matching()
//    - user_get_free_balance(user_id, coin)
//    - user_deposit(user_id, coin, amount)
//    - partial_fill_order(order_id, fill_amount)
//    - get_time_offset()
//
//  2) DexNodeSnippet (aus Snippet, um GlobalSecurity einzubinden)
//    - new(config: NodeConfig, Option<Arc<Mutex<GlobalSecuritySystem>>>)
//    - snippet_start_node() (async)
//    - shutdown()
//
//  3) Time-Limited Orders (Integration-Beispiel)
//    - example_time_limited(): Legt Zeitbegrenzte Order an, partial_fill, check_expired, cancel
//
//  4) Interne Hilfsfunktionen für NAT & NTP (innerhalb DexNode)
//    - sync_ntp_time(): Ruft konfig. NTP-Server auf, errechnet Offset
//    - setup_nat_traversal(): Versucht UPnP-Port-Mapping via IGD
//
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::task;
use tracing::{info, debug, instrument, warn, error};

use crate::config_loader::NodeConfig;
use crate::crdt_logic::CrdtState;
use crate::metrics::ORDER_COUNT;
use crate::error::DexError;

// Ursprüngliches Security-System:
use crate::security::advanced_security::AdvancedSecuritySystem;

// Neu aus dem Snippet (GlobalSecuritySystem):
use crate::security::global_security_facade::GlobalSecuritySystem;

use crate::logging::enhanced_logging::{log_error, write_audit_log};

// Falls Sie eine Matching-Engine haben
use crate::matching_engine::{MatchingEngine, TradeResult};
// Falls Sie Settlement/Balance-Funktionen haben
use crate::settlement::advanced_settlement::SettlementEngineTrait;
// Falls Sie Fees berechnen wollen
use crate::fees::{calc_fee_distribution, FeeDistribution};

// NTP
use sntpc::{self, Error as SntpError};
use futures::future::join_all;

// NAT
use igd::aio::{search_gateway, AddPortError};
use igd::PortMappingProtocol;

////////////////////////////////////////////////////////////////////////////////
// Zusätzliche Strukturen: z. B. OrderSide, OrderRequest
////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
pub enum OrderSide {
    Buy,
    Sell,
}

#[derive(Clone, Debug)]
pub struct OrderRequest {
    pub user_id: String,
    pub coin_to_sell: String,
    pub coin_to_buy: String,
    pub amount: f64,
    pub price: f64,
    pub side: OrderSide,
    pub auth_token: Option<String>,
}

////////////////////////////////////////////////////////////////////////////////
// DexNode — Zusammenführung aus Original-Code + Snippet
////////////////////////////////////////////////////////////////////////////////
pub struct DexNode {
    // Konfiguration:
    pub config: NodeConfig,

    // CRDT-State => Orders, Partial-Fill
    pub state: Arc<Mutex<CrdtState>>,

    // Ursprüngliches Security-System (advanced):
    pub advanced_security: AdvancedSecuritySystem,

    // NEU: Optionales globales Sicherheitssystem aus dem Snippet
    pub global_security: Option<Arc<Mutex<GlobalSecuritySystem>>>,

    // Evtl. Matching-Engine
    pub matching_engine: Option<Arc<Mutex<MatchingEngine>>>,

    // SettlementEngine => lock_funds / release_funds
    pub settlement_engine: Option<Arc<Mutex<dyn SettlementEngineTrait + Send>>>,

    // Wallet/Balance – super simples InMemory-Fallback:
    pub balances: Arc<Mutex<std::collections::HashMap<(String, String), (f64, f64)>>>,
    
    // Zeit-Offset aus NTP
    pub ntp_time_offset: Arc<Mutex<Option<i64>>>,
}

impl DexNode {
    /// Konstruktor
    #[instrument(name="node_new", skip(config))]
    pub fn new(
        config: NodeConfig,
        global_sec: Option<Arc<Mutex<GlobalSecuritySystem>>>
    ) -> Self {
        info!("Creating DexNode with config: {:?}", config);

        // CRDT
        let st = CrdtState::default();

        // Altes Security-System
        let advanced_sec = AdvancedSecuritySystem::new()
            .expect("Failed to init advanced security system");

        DexNode {
            config,
            state: Arc::new(Mutex::new(st)),
            advanced_security: advanced_sec,
            global_security: global_sec,
            matching_engine: None,
            settlement_engine: None,
            balances: Arc::new(Mutex::new(std::collections::HashMap::new())),
            ntp_time_offset: Arc::new(Mutex::new(None)),
        }
    }

    /// Setze eine MatchingEngine
    pub fn set_matching_engine(&mut self, me: Arc<Mutex<MatchingEngine>>) {
        self.matching_engine = Some(me);
    }

    /// Setze eine SettlementEngine
    pub fn set_settlement_engine(&mut self, se: Arc<Mutex<dyn SettlementEngineTrait + Send>>) {
        self.settlement_engine = Some(se);
    }

    /// Start-Logik (async) => zusammengeführt mit Snippet-Code
    #[instrument(name="node_start", skip(self))]
    pub async fn start(&mut self) -> Result<()> {
        info!("Node {} is starting...", self.config.node_id);

            // 🔒 Absicherung: Nur starten, wenn use_noise aktiv ist
    if !self.config.use_noise {
        error!("Abbruch: Konfiguration use_noise=false => Unsichere Kommunikation!");
        return Err(anyhow::anyhow!("Unsichere Konfiguration: use_noise=false"));
    }

        // Integration aus Snippet: GlobalSecurity => audit_event
        if let Some(ref sec_arc) = self.global_security {
            let sec = sec_arc.lock().unwrap();
            sec.audit_event("DexNode startet NTP-Sync");
        }

        // parallele NTP + NAT
        let ntp_handle = tokio::spawn(self.sync_ntp_time());
        let nat_handle = tokio::spawn(self.setup_nat_traversal());

        let _ = ntp_handle.await?;
        let _ = nat_handle.await?;

        // ... weitere Gossip / CRDT / etc.
        Ok(())
    }

    /// Shutdown (aus Snippet => audit_event("DexNode shutdown"))
    pub fn shutdown(&mut self) {
        if let Some(ref sec_arc) = self.global_security {
            sec_arc.lock().unwrap().audit_event("DexNode shutdown");
        }
    }

    // ================  Trading / Order-Funktionen  ================
    pub fn calc_fee_preview(&self, amount: f64) -> f64 {
        let fee_percent = 0.001; // 0.1%
        amount * fee_percent
    }

    #[instrument(name="node_place_order", skip(self, req))]
    pub fn place_order(&self, req: OrderRequest) -> Result<(), DexError> {
        // 🚫 Banned-Prüfung (Watchtower)
        if let Some(global_sec) = &self.global_security {
            if global_sec.lock().unwrap().is_banned(&req.user_id) {
                return Err(DexError::Other(format!(
                    "User {} ist vom Netzwerk gesperrt", req.user_id
                )));
            }
        }

        // 1) check free
        let mut bals = self.balances.lock().unwrap();
        let bal_key = (req.user_id.clone(), req.coin_to_sell.clone());
        let (free, locked) = bals.entry(bal_key.clone()).or_insert((0.0, 0.0));
        if *free < req.amount {
            return Err(DexError::Other(format!(
                "Not enough free balance for user={} coin={}",
                req.user_id, req.coin_to_sell
            )));
        }

        // 2) lock
        *free -= req.amount;
        *locked += req.amount;
        drop(bals); // unlock

        // 3) CRDT => addLocalOrder
        let mut st = self.state.lock().unwrap();
        let local_order_id = format!("{}_{}", req.coin_to_sell, req.coin_to_buy);

        st.add_local_order(
            &self.config.node_id,
            &local_order_id,
            &req.user_id,
            req.amount,
            req.price,
        )?;

        ORDER_COUNT.inc();
        info!(
            "place_order => user={} side={:?} amt={} price={} coin_s={}, coin_b={}",
            req.user_id, req.side, req.amount, req.price, req.coin_to_sell, req.coin_to_buy
        );
        write_audit_log(&format!(
            "User {} placed order => side={:?}, amt={}",
            req.user_id, req.side, req.amount
        ));
        Ok(())
    }

    #[instrument(name="node_list_orders", skip(self))]
    pub fn list_open_orders(&self) -> Vec<String> {
        let st = self.state.lock().unwrap();
        let visible = st.visible_orders();
        visible.iter().map(|o| o.id.clone()).collect()
    }

    #[instrument(name="node_execute_matching", skip(self))]
    pub fn execute_matching(&self) -> Result<(), DexError> {
        if let Some(me) = &self.matching_engine {
            let trades: Vec<TradeResult> = me.lock().unwrap().match_orders();
            if let Some(se) = &self.settlement_engine {
                for tr in trades {
                    // settlement => se.lock().unwrap().finalize_trade(...)
                }
            }
        } else {
            warn!("No matching_engine => skip");
        }
        Ok(())
    }

    pub fn user_get_free_balance(&self, user_id: &str, coin: &str) -> f64 {
        let bals = self.balances.lock().unwrap();
        let key = (user_id.to_string(), coin.to_string());
        let (free, _) = bals.get(&key).cloned().unwrap_or((0.0, 0.0));
        free
    }

    pub fn user_deposit(&self, user_id: &str, coin: &str, amount: f64) {
        let mut bals = self.balances.lock().unwrap();
        let key = (user_id.to_string(), coin.to_string());
        let entry = bals.entry(key).or_insert((0.0, 0.0));
        entry.0 += amount;
        info!("User {} => deposit {} {}", user_id, amount, coin);
    }

    #[instrument(name="node_partial_fill", skip(self))]
    pub fn partial_fill_order(&self, order_id: &str, fill_amount: f64) -> Result<(), DexError> {
        let min_fill = self.config.partial_fill_min_amount;
        let mut st = self.state.lock().unwrap();
        st.partial_fill(&self.config.node_id, order_id, fill_amount, min_fill)
    }

    // ================  NAT + NTP  ================
    #[instrument(name="sync_ntp_time", skip(self))]
    async fn sync_ntp_time(&self) -> Result<()> {
        if self.config.ntp_servers.is_empty() {
            info!("No NTP servers configured => skipping NTP sync");
            return Ok(());
        }
        info!("Starting NTP sync => servers = {:?}", self.config.ntp_servers);
    
        let futures_list = self.config.ntp_servers.iter()
            .map(|server_addr| async move {
                let opts = sntpc::Options::default().with_timeout(Duration::from_secs(3));
                let res = sntpc::get_time(server_addr, opts).await;
                (server_addr.clone(), res)
            })
            .collect::<Vec<_>>();
    
        let results = futures::future::join_all(futures_list).await;
        let mut offsets = vec![];
    
        for (srv, res) in results {
            match res {
                Ok(ntp_ts) => {
                    debug!("NTP server={} => got={:?}", srv, ntp_ts);
                    let system_now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let offset = (ntp_ts.sec as i64) - system_now;
                    offsets.push(offset);
                }
                Err(e) => {
                    warn!("NTP server={} => error={:?}", srv, e);
                }
            }
        }
    
        if offsets.is_empty() {
            warn!("All NTP queries failed => no offset update");
            return Ok(());
        }
    
        offsets.sort_unstable();
        let mid = offsets.len() / 2;
        let median_offset = offsets[mid];
    
        // Sicherheitsprüfung: Nur kleine Abweichung zulassen (z. B. max ±10 Sekunden)
        let max_allowed_offset = 10; // Sekunden
    
        if median_offset.abs() > max_allowed_offset {
            warn!(
                "NTP-Zeitabweichung zu groß ({}s > {}s) – mögliche Zeitmanipulation oder unsichere Quelle!",
                median_offset,
                max_allowed_offset
            );
    
            // Optional: Node-Abbruch erzwingen
            // return Err(anyhow::anyhow!(
            //     "Unsichere Zeitquelle: NTP-Zeitabweichung {}s > erlaubt {}s",
            //     median_offset,
            //     max_allowed_offset
            // ));
        }
    
        // Offset speichern
        {
            let mut off_lock = self.ntp_time_offset.lock().unwrap();
            *off_lock = Some(median_offset);
        }
    
        info!("NTP => akzeptierter Offset = {}s", median_offset);
        Ok(())
    }


    #[instrument(name="setup_nat_traversal", skip(self))]
    async fn setup_nat_traversal(&self) -> Result<()> {
        if self.config.stun_server.is_empty() && self.config.turn_server.is_empty() {
            debug!("No stun/turn set => skipping NAT traversal");
            return Ok(());
        }
        info!("Trying NAT-UPnP => searching gateway...");
        match search_gateway(Default::default()).await {
            Ok(gw) => {
                let local_addr = self.config.listen_addr.parse::<SocketAddr>()
                    .unwrap_or_else(|_| "127.0.0.1:9000".parse().unwrap());
                let local_port = local_addr.port();
                let external_port = local_port;
                let desc = "my_dex node NAT mapping";

                match gw.add_port(
                    PortMappingProtocol::TCP,
                    external_port,
                    "127.0.0.1",
                    local_port,
                    3600,
                    desc
                ).await {
                    Ok(_) => {
                        info!("NAT => UPnP port mapping created: external={} => local={}",
                            external_port, local_port
                        );
                    }
                    Err(e) => match e {
                        AddPortError::PortInUse => {
                            warn!("UPnP: Port already mapped or in use");
                        }
                        _ => {
                            warn!("UPnP add_port error: {:?}", e);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("No IGD gateway found => error={:?}", e);
            }
        }
        Ok(())
    }

    pub fn get_time_offset(&self) -> Option<i64> {
        *self.ntp_time_offset.lock().unwrap()
    }
}

// Beispiel für Time-Limited Orders (Integration)
use crate::dex_logic::time_limited_orders::{TimeLimitedOrderManager, OrderSide as TLOOrderSide};

fn example_time_limited() {
    let mut manager = TimeLimitedOrderManager::new();

    manager.place_time_limited_order(
        "orderABC",
        "alice",
        TLOOrderSide::Sell,
        1.0,      // quantity
        80000.0,  // price
        86400,    // 1 Tag
        2
    ).unwrap();

    manager.partial_fill("orderABC", 0.20).unwrap();

    manager.check_expired_orders().unwrap();

    manager.cancel_order("orderABC").unwrap();
}
