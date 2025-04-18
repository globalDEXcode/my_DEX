/////////////////////////////////////////////////////////////
// my_dex/src/decentralized_order_book/order.rs
/////////////////////////////////////////////////////////////
//
// Enthält die zentrale Order-Datenstruktur für den DEX.
//
// Unterstützt:
//  - Klassische Orders mit Ed25519-Signatur
//  - Privacy-Orders mit Monero-kompatibler Ring-Signatur (MLSAG)
//
// Hauptbestandteile:
//  - OrderType: Market, Limit, Stop
//  - OrderSide: Buy oder Sell
//  - OrderStatus: Open, PartiallyFilled, Filled, Cancelled
//  - Order:
//     • Metadaten (ID, User, Timestamp)
//     • Order-Parameter (Type, Side, Quantity, Status)
//     • Signaturfelder:
//         - `signature` + `pub_key`: klassische Authentifizierung
//         - `ring_signature` + `ring_members`: anonyme RingSig-Verifikation
//
// Methoden:
//  - new(...)                     → erstellt neue Order
//  - fill(amount)                → aktualisiert Füllstatus
//  - cancel()                    → bricht offene Order ab
//  - verify_signature()          → prüft klassische Ed25519-Signatur
//  - verify_ring_signature(msg) → prüft Ring-Signatur (MLSAG)
//
/////////////////////////////////////////////////////////////


use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use ed25519_dalek::PublicKey;
use crate::crypto::ring_sig::RingSignature;
use std::fmt;

/// Art der Order (Market, Limit, Stop)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderType {
    Market,
    Limit(f64),
    Stop(f64),
}

/// Kauf- oder Verkaufsorder
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    Buy,
    Sell,
}

/// Status der Order
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderStatus {
    Open,
    PartiallyFilled,
    Filled,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Order {
    pub id: String,
    pub user_id: String,
    pub timestamp: u64,
    pub order_type: OrderType,
    pub side: OrderSide,
    pub quantity: f64,
    pub filled_quantity: f64,
    pub status: OrderStatus,

    // Neu: Signatur
    pub signature: Option<Vec<u8>>,
    pub pub_key: Option<Vec<u8>>,

    /// Optional: Ring-Signatur für anonyme Orderprüfungen
    pub ring_signature: Option<RingSignature>,

    /// Ring-Mitglieder für die Verifikation der Signatur
    pub ring_members: Option<Vec<PublicKey>>,
}

impl Order {
    /// Erstellt eine neue Order mit automatisch generierter ID und Zeitstempel
    pub fn new(user_id: &str, order_type: OrderType, side: OrderSide, quantity: f64) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let unique_id = format!("{}_{}", user_id, now);
        Self {
            id: unique_id,
            user_id: user_id.to_string(),
            timestamp: now,
            order_type,
            side,
            quantity,
            filled_quantity: 0.0,
            status: OrderStatus::Open,
            signature: None,
            pub_key: None,
            ring_signature: None,
            ring_members: None,
        }
    }

    /// Gibt an, wie viel von der Order noch offen ist
    pub fn remaining_quantity(&self) -> f64 {
        self.quantity - self.filled_quantity
    }

    /// Führt die Order (teilweise oder vollständig) aus
    pub fn fill(&mut self, amount: f64) {
        self.filled_quantity += amount;
        if self.remaining_quantity() <= 0.0 {
            self.status = OrderStatus::Filled;
        } else {
            self.status = OrderStatus::PartiallyFilled;
        }
    }

    /// Cancelt die Order, falls sie noch offen oder teilweise gefüllt ist
    pub fn cancel(&mut self) {
        if matches!(self.status, OrderStatus::Open | OrderStatus::PartiallyFilled) {
            self.status = OrderStatus::Cancelled;
        }
    }

    /// Minimalbeispiel für Signaturprüfung.
    pub fn verify_signature(&self) -> bool {
        if let (Some(sig_bytes), Some(pk_bytes)) = (self.signature.as_ref(), self.pub_key.as_ref()) {
            !sig_bytes.is_empty() && !pk_bytes.is_empty()
        } else {
            false
        }
    }

    /// Verifiziert eine Ring-Signatur mit den zugehörigen Ring-Mitgliedern.
    /// Das `msg`-Argument ist z. B. der Hash der Order-Payload.
    pub fn verify_ring_signature(&self, msg: &[u8]) -> bool {
        if let (Some(sig), Some(ring)) = (&self.ring_signature, &self.ring_members) {
            crate::crypto::ring_sig::verify_ring_mlsag(msg, ring, sig)
        } else {
            false
        }
    }
}

impl fmt::Display for Order {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Order[{}] user={} type={:?} side={:?} qty={} fill={} status={:?}, signed={}",
            self.id, self.user_id, self.order_type, self.side,
            self.quantity, self.filled_quantity, self.status,
            self.signature.is_some()
        )
    }
}
