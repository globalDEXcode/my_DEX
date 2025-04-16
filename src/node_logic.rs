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

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::task;
use tracing::{info, debug, instrument, warn, error};

use crate::config_loader::NodeConfig;
use crate::crdt_logic::CrdtState;
use crate::metrics::ORDER_COUNT;
use crate::error::DexError;

use crate::security::advanced_security::AdvancedSecuritySystem;
use crate::security::global_security_facade::GlobalSecuritySystem;

use crate::logging::enhanced_logging::{log_error, write_audit_log};
use crate::matching_engine::{MatchingEngine, TradeResult};
use crate::settlement::advanced_settlement::SettlementEngineTrait;
use crate::fees::{calc_fee_distribution, FeeDistribution};

use sntpc::{self, Error as SntpError};
use futures::future::join_all;

use igd::aio::{search_gateway, AddPortError};
use igd::PortMappingProtocol;

fn lock_or_err<T>(m: &Mutex<T>, label: &str) -> Result<MutexGuard<'_, T>, DexError> {
    m.lock().map_err(|_| DexError::Other(format!("Lock fehlgeschlagen: {}", label)))
}

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

pub struct DexNode {
    pub config: NodeConfig,
    pub state: Arc<Mutex<CrdtState>>,
    pub advanced_security: AdvancedSecuritySystem,
    pub global_security: Option<Arc<Mutex<GlobalSecuritySystem>>>,
    pub matching_engine: Option<Arc<Mutex<MatchingEngine>>>,
    pub settlement_engine: Option<Arc<Mutex<dyn SettlementEngineTrait + Send>>>,
    pub balances: Arc<Mutex<std::collections::HashMap<(String, String), (f64, f64)>>>,
    pub ntp_time_offset: Arc<Mutex<Option<i64>>>,
}

impl DexNode {
    #[instrument(name="node_new", skip(config))]
    pub fn new(
        config: NodeConfig,
        global_sec: Option<Arc<Mutex<GlobalSecuritySystem>>>
    ) -> Self {
        info!("Creating DexNode with config: {:?}", config);
        let st = CrdtState::default();
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

    pub fn set_matching_engine(&mut self, me: Arc<Mutex<MatchingEngine>>) {
        self.matching_engine = Some(me);
    }

    pub fn set_settlement_engine(&mut self, se: Arc<Mutex<dyn SettlementEngineTrait + Send>>) {
        self.settlement_engine = Some(se);
    }

    #[instrument(name="node_start", skip(self))]
    pub async fn start(&mut self) -> Result<()> {
        info!("Node {} is starting...", self.config.node_id);

        if !self.config.use_noise {
            error!("Abbruch: Konfiguration use_noise=false => Unsichere Kommunikation!");
            return Err(anyhow::anyhow!("Unsichere Konfiguration: use_noise=false"));
        }

        if let Some(ref sec_arc) = self.global_security {
            let sec = lock_or_err(sec_arc, "global_security")?;
            sec.audit_event("DexNode startet NTP-Sync");
        }

        let ntp_handle = tokio::spawn(self.sync_ntp_time());
        let nat_handle = tokio::spawn(self.setup_nat_traversal());

        let _ = ntp_handle.await?;
        let _ = nat_handle.await?;

        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(ref sec_arc) = self.global_security {
            if let Ok(sec) = sec_arc.lock() {
                sec.audit_event("DexNode shutdown");
            }
        }
    }

    pub fn calc_fee_preview(&self, amount: f64) -> f64 {
        let fee_percent = 0.001;
        amount * fee_percent
    }

    #[instrument(name="node_place_order", skip(self, req))]
    pub fn place_order(&self, req: OrderRequest) -> Result<(), DexError> {
        if let Some(global_sec) = &self.global_security {
            let sec = lock_or_err(global_sec, "global_security")?;
            if sec.is_banned(&req.user_id) {
                return Err(DexError::Other(format!(
                    "User {} ist vom Netzwerk gesperrt", req.user_id
                )));
            }
        }

        let mut bals = lock_or_err(&self.balances, "balances")?;
        let bal_key = (req.user_id.clone(), req.coin_to_sell.clone());
        let (free, locked) = bals.entry(bal_key.clone()).or_insert((0.0, 0.0));
        if *free < req.amount {
            return Err(DexError::Other(format!(
                "Not enough free balance for user={} coin={}",
                req.user_id, req.coin_to_sell
            )));
        }

        *free -= req.amount;
        *locked += req.amount;
        drop(bals);

        let mut st = lock_or_err(&self.state, "state")?;
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
}

#[instrument(name="node_list_orders", skip(self))]
pub fn list_open_orders(&self) -> Vec<String> {
    let st = lock_or_err(&self.state, "state")
        .ok() // bei Fehler leere Liste
        .map(|s| s.visible_orders())
        .unwrap_or_default();
    st.iter().map(|o| o.id.clone()).collect()
}

#[instrument(name="node_execute_matching", skip(self))]
pub fn execute_matching(&self) -> Result<(), DexError> {
    if let Some(me) = &self.matching_engine {
        let trades = me.lock()
            .map_err(|_| DexError::Other("Zugriff auf matching_engine fehlgeschlagen".into()))?
            .match_orders();

        if let Some(se) = &self.settlement_engine {
            for _tr in trades {
                // TODO: finalize_trade(...), aktuell nicht implementiert
            }
        }
    } else {
        warn!("No matching_engine => skip");
    }
    Ok(())
}

pub fn user_get_free_balance(&self, user_id: &str, coin: &str) -> f64 {
    let bals = lock_or_err(&self.balances, "balances").ok();
    let key = (user_id.to_string(), coin.to_string());
    bals.and_then(|b| b.get(&key).cloned()).map(|(free, _)| free).unwrap_or(0.0)
}

pub fn user_deposit(&self, user_id: &str, coin: &str, amount: f64) {
    if let Ok(mut bals) = lock_or_err(&self.balances, "balances") {
        let key = (user_id.to_string(), coin.to_string());
        let entry = bals.entry(key).or_insert((0.0, 0.0));
        entry.0 += amount;
        info!("User {} => deposit {} {}", user_id, amount, coin);
    } else {
        warn!("Deposit fehlgeschlagen: balances nicht verfügbar");
    }
}

#[instrument(name="node_partial_fill", skip(self))]
pub fn partial_fill_order(&self, order_id: &str, fill_amount: f64) -> Result<(), DexError> {
    let min_fill = self.config.partial_fill_min_amount;
    let mut st = lock_or_err(&self.state, "state")?;
    st.partial_fill(&self.config.node_id, order_id, fill_amount, min_fill)
}

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

    let results = join_all(futures_list).await;
    let mut offsets = vec![];

    for (srv, res) in results {
        match res {
            Ok(ntp_ts) => {
                debug!("NTP server={} => got={:?}", srv, ntp_ts);
                let system_now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| anyhow::anyhow!("Systemzeitfehler: {:?}", e))?
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

    let max_allowed_offset = 10;

    if median_offset.abs() > max_allowed_offset {
        warn!(
            "NTP-Zeitabweichung zu groß ({}s > {}s) – mögliche Zeitmanipulation oder unsichere Quelle!",
            median_offset,
            max_allowed_offset
        );
        // Optional: return Err(...)
    }

    let mut off_lock = self.ntp_time_offset.lock()
        .map_err(|_| anyhow::anyhow!("Zugriff auf NTP-Offset fehlgeschlagen"))?;
    *off_lock = Some(median_offset);

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
            let local_addr: SocketAddr = self.config.listen_addr.parse()
                .map_err(|e| anyhow::anyhow!("Ungültige listen_addr: {}", e))?;
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
                          external_port, local_port);
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
    lock_or_err(&self.ntp_time_offset, "ntp_time_offset")
        .ok()
        .map(|guard| *guard)
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
