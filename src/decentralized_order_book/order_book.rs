///////////////////////////////////////////////////////////
// my_dex/src/decentralized_order_book/order_book.rs
///////////////////////////////////////////////////////////

use std::collections::HashMap;
use crate::decentralized_order_book::order::{Order, OrderStatus, OrderSide, OrderType};
use crate::decentralized_order_book::conflict_resolution::ConflictResolution;

/// Neue Definitionen für die delta-basierte Synchronisation

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum OrderDelta {
    Add(Order),
    Remove { order_id: String, timestamp: i64 },
}

/// Ein sehr vereinfachtes CRDT-Orderbuch mit Delta-Synchronisation:
/// - Speichert Orders in einer HashMap<String, Order>.
/// - Enthält optional einen Sender für Delta-Updates.
#[derive(Debug, Clone)]
pub struct CrdtOrderBook {
    orders: HashMap<String, Order>,
    // Optionaler Sender, um Delta-Updates zu verbreiten.
    delta_sender: Option<tokio::sync::mpsc::UnboundedSender<OrderDelta>>,
}

impl CrdtOrderBook {
    pub fn new() -> Self {
        Self {
            orders: HashMap::new(),
            delta_sender: None,
        }
    }

    /// Setzt den Delta-Sender, der zur Verbreitung von Order-Deltas genutzt wird.
    pub fn set_delta_sender(&mut self, sender: tokio::sync::mpsc::UnboundedSender<OrderDelta>) {
        self.delta_sender = Some(sender);
    }

    /// Naive Merge (z. B. Timestamp-basiert).
    pub fn merge(&mut self, other: &CrdtOrderBook) {
        for (id, other_ord) in &other.orders {
            match self.orders.get(id) {
                None => {
                    // Sicherheitscheck: Signatur valide?
                    if other_ord.verify_signature() {
                        self.orders.insert(id.clone(), other_ord.clone());
                    }
                },
                Some(local_ord) => {
                    if other_ord.timestamp > local_ord.timestamp {
                        if other_ord.verify_signature() {
                            self.orders.insert(id.clone(), other_ord.clone());
                        }
                    }
                }
            }
        }
    }

    /// Liefert alle Orders zurück (auch bereits gefüllte oder stornierte).
    /// Das Filtern übernimmt der Aufrufer (z. B. im Matching).
    pub fn all_visible_orders(&self) -> Vec<Order> {
        self.orders.values().cloned().collect()
    }

    /// Fügt eine Order ein (oder überschreibt sie) und sendet ein entsprechendes Delta-Update.
    pub fn add_order(&mut self, order: Order) {
        // Prüfen, ob signiert
        if !order.verify_signature() {
            println!("Warn: add_order() => ungültige Order-Signatur => abgelehnt, ID={}", order.id);
            return;
        }

        self.orders.insert(order.id.clone(), order.clone());
        if let Some(sender) = &self.delta_sender {
            if let Err(e) = sender.send(OrderDelta::Add(order)) {
                println!("Failed to send delta update for add_order: {:?}", e);
            }
        }
    }

    /// Entfernt eine gegebene Order (falls vorhanden) und sendet ein entsprechendes Delta-Update.
    pub fn remove_order(&mut self, order: &Order) {
        self.orders.remove(&order.id);
        let timestamp = chrono::Utc::now().timestamp();
        if let Some(sender) = &self.delta_sender {
            if let Err(e) = sender.send(OrderDelta::Remove { order_id: order.id.clone(), timestamp }) {
                println!("Failed to send delta update for remove_order: {:?}", e);
            }
        }
    }

    /// Wendet ein Delta-Update auf das OrderBook an.
    pub fn apply_delta(&mut self, delta: OrderDelta) {
        match delta {
            OrderDelta::Add(order) => {
                if order.verify_signature() {
                    self.orders.insert(order.id.clone(), order);
                }
            },
            OrderDelta::Remove { order_id, timestamp: _ } => {
                self.orders.remove(&order_id);
            },
        }
    }
}

/// Dieses Struct verwaltet das CRDT-OrderBook und führt das Matching
/// (ohne Settlement/Escrow-Logik).
pub struct OrderBook {
    pub book: CrdtOrderBook,
    pub node_id: String,
    pub last_price: Option<f64>,
    pub conflict_resolver: ConflictResolution,
}

impl OrderBook {
    /// Konstruktor (keine Settlement-Übergabe, da Variante B).
    pub fn new(node_id: &str) -> Self {
        Self {
            book: CrdtOrderBook::new(),
            node_id: node_id.to_string(),
            last_price: None,
            conflict_resolver: ConflictResolution::new(),
        }
    }

    /// Merge zwei CRDT-Bücher.
    pub fn merge_with_crdt(&mut self, other: &CrdtOrderBook) {
        self.book.merge(other);
    }

    /// Fügt eine Order ins Orderbuch ein.
    /// (Escrow/Sperrungen passieren in exchange.rs, nicht hier.)
    pub fn add_order(&mut self, mut ord: Order) {
        if !self.conflict_resolver.track_order_changes(&ord.id) {
            println!("🚨 Order {} wurde zu oft geändert. Abgelehnt!", ord.id);
            return;
        }

        // Stop-Orders => bei Erreichen last_price => Market.
        if let OrderType::Stop(px) = ord.order_type {
            if let Some(lp) = self.last_price {
                if (ord.side == OrderSide::Buy && lp >= px)
                    || (ord.side == OrderSide::Sell && lp <= px)
                {
                    println!("Stop-Order {} => Market", ord.id);
                    ord.order_type = OrderType::Market;
                }
            }
        }

        self.book.add_order(ord);
    }

    /// Cancelt eine Order => Status=Cancelled (Guthabenfreigabe in exchange).
    pub fn cancel_order(&mut self, order_id: &str) {
        let all = self.book.all_visible_orders();
        if let Some(o) = all.iter().find(|x| x.id == order_id) {
            if matches!(o.status, OrderStatus::Filled | OrderStatus::Cancelled) {
                println!("Order {} ist bereits Filled/Cancelled.", order_id);
                return;
            }
            let mut cpy = o.clone();
            cpy.cancel();
            self.book.remove_order(o);
            self.book.add_order(cpy);
        } else {
            println!("Order {} nicht gefunden", order_id);
        }
    }

    /// Führt das reine Matching aus (Buy vs. Sell) und gibt
    /// `(buy_id, sell_id, fill_amount)` zurück.
    /// => Settlement-Finalisierung findet in exchange.rs statt.
    pub fn match_orders(&mut self) -> Vec<(String, String, f64)> {
        let all = self.book.all_visible_orders();
        // Filtern von Storniert/Gefüllt.
        let (mut buys, mut sells): (Vec<_>, Vec<_>) = all
            .into_iter()
            .filter(|o| !matches!(o.status, OrderStatus::Cancelled | OrderStatus::Filled))
            .partition(|o| o.side == OrderSide::Buy);

        // Sortieren.
        ConflictResolution::prioritize_orders(&mut buys);
        ConflictResolution::prioritize_orders(&mut sells);

        let mut trades = Vec::new();
        for buy in &mut buys {
            let needed = buy.remaining_quantity();
            if needed <= 0.0 {
                continue;
            }
            for sell in &mut sells {
                if sell.remaining_quantity() <= 0.0 {
                    continue;
                }
                if !self.price_match_ok(buy, sell) {
                    continue;
                }
                let fill_amt = needed.min(sell.remaining_quantity());
                trades.push((buy.id.clone(), sell.id.clone(), fill_amt));
                if (needed - fill_amt) <= 0.0 {
                    break;
                }
            }
        }

        trades
    }

    /// Füllt eine Order um fill_amt (nach erfolgreicher Settlement-Finalisierung).
    pub fn fill_order(&mut self, order_id: &str, fill_amt: f64) {
        let all = self.book.all_visible_orders();
        if let Some(o) = all.iter().find(|x| x.id == order_id) {
            if matches!(o.status, OrderStatus::Filled | OrderStatus::Cancelled) {
                return;
            }
            let mut cpy = o.clone();
            cpy.fill(fill_amt);
            self.book.remove_order(o);
            self.book.add_order(cpy);
        }
    }

    /// Simplest Price Check => Buy >= Sell?
    fn price_match_ok(&self, buy: &Order, sell: &Order) -> bool {
        let bpx = match buy.order_type {
            OrderType::Market => f64::MAX,
            OrderType::Limit(px) | OrderType::Stop(px) => px,
        };
        let spx = match sell.order_type {
            OrderType::Market => 0.0,
            OrderType::Limit(px) | OrderType::Stop(px) => px,
        };
        bpx >= spx
    }
}

/// Delta-basierte Synchronisation des OrderBooks via Lightning-Gossip-Protokoll.
/// In einer produktionsreifen Implementierung würde diese Funktion
/// Netzwerkkommunikation, Verschlüsselung und Delta-Kodierung beinhalten.
pub async fn delta_gossip_synchronizer(
    mut delta_receiver: tokio::sync::mpsc::UnboundedReceiver<OrderDelta>,
    order_book: Arc<tokio::sync::Mutex<CrdtOrderBook>>,
) {
    use tracing::info;
    while let Some(delta) = delta_receiver.recv().await {
        info!("Delta synchronizer received delta: {:?}", delta);
        let mut ob = order_book.lock().await;
        ob.apply_delta(delta);
    }
}

/// Erzeugt einen neuen OrderBook-Wrapper mit integriertem Delta-Synchronisierungsmechanismus.
/// Gibt den OrderBook-Wrapper und den UnboundedReceiver für Delta-Updates zurück.
pub fn create_order_book_with_delta(node_id: &str) -> (OrderBook, tokio::sync::mpsc::UnboundedReceiver<OrderDelta>) {
    use tokio::sync::mpsc::unbounded_channel;
    let (tx, rx) = unbounded_channel();
    let mut crdt_book = CrdtOrderBook::new();
    crdt_book.set_delta_sender(tx);
    let order_book = OrderBook {
        book: crdt_book,
        node_id: node_id.to_string(),
        last_price: None,
        conflict_resolver: ConflictResolution::new(),
    };
    (order_book, rx)
}
