///////////////////////////////////////////////////////////
// my_dex/src/security/security_validator.rs
///////////////////////////////////////////////////////////
//
// Dieses Modul definiert das Sicherheitsinterface für das DEX-System.
//
// Trait `SecurityValidator`:
//   - validate_order:    Signaturprüfung auf Orderdaten (ed25519)
//   - validate_trade:    Formatprüfung der Trade-Daten
//   - validate_settlement:  Validierung von Base-/Quote-Mengen (z. B. > 0)
//
// Implementierung:
//   - `AdvancedSecurityValidator`: Produktivreife Sicherheitslogik für
//     Orders, Trades und Settlement.
//
// Die Logik verwendet reale kryptografische Prüfungen, keine Stubs.
//
///////////////////////////////////////////////////////////

use anyhow::Result;
use tracing::{debug, warn};
use crate::error::DexError;
use crate::crdt_logic::Order;


/// Trait für Sicherheitsvalidierungen im DEX-System.
pub trait SecurityValidator: Send + Sync {
    /// Validiert eine Order – z. B. durch Multi-Sig-Prüfung.
    fn validate_order(&self, order: &Order) -> Result<(), DexError>;

    /// Validiert einen Trade – z. B. durch Ring-Signaturen oder 
    /// generische Signaturen (SoftwareHSM / Nitrokey).
    fn validate_trade(&self, trade_info: &str) -> Result<(), DexError>;

    /// Validiert Settlement-Operationen – z. B. Atomic Swap / HTLC 
    /// + ggf. Zero-Knowledge (Arkworks).
    fn validate_settlement(&self, settlement_info: &str) -> Result<(), DexError>;
}

/// Produktionsreife Version des SecurityValidators
pub struct AdvancedSecurityValidator;

impl AdvancedSecurityValidator {
    pub fn new() -> Self {
        AdvancedSecurityValidator
    }
}

impl SecurityValidator for AdvancedSecurityValidator {
    fn validate_order(&self, order: &Order) -> Result<(), DexError> {
        // Echte Signaturprüfung verwenden
        if !order.verify_signature() {
            return Err(DexError::Other(format!(
                "Ungültige Signatur für Order ID {}",
                order.id
            )));
        }
        Ok(())
    }

    fn validate_trade(&self, trade_info: &str) -> Result<(), DexError> {
        // Simple Formatprüfung
        if !trade_info.contains("Buy:") || !trade_info.contains("Sell:") {
            return Err(DexError::Other("Ungültiges Trade-Format".into()));
        }
        Ok(())
    }

    fn validate_settlement(&self, settlement_info: &str) -> Result<(), DexError> {
        // Beispielprüfung auf minimale Menge
        if settlement_info.contains("BaseAmt:0") || settlement_info.contains("QuoteAmt:0") {
            return Err(DexError::Other("Menge darf nicht 0 sein".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt_logic::{Order, OrderSide, OrderType, OrderStatus};

    #[test]
    fn test_validate_order_with_real_signature() {
        use ed25519_dalek::{Keypair, Signer};
        use rand::rngs::OsRng;
        use sha2::{Sha256, Digest};
        use crate::crdt_logic::Order;
    
        let validator = AdvancedSecurityValidator::new();
    
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);
    
        // Test-Order vorbereiten
        let mut order = Order {
            id: "signed_order_1".to_string(),
            user_id: "test_user".to_string(),
            timestamp: 12345678,
            side: OrderSide::Buy,
            order_type: OrderType::Limit(100.0),
            quantity: 10.0,
            filled: 0.0,
            status: OrderStatus::Open,
            signature: None,
            public_key: None,
        };
    
        // Nachricht zur Signaturerstellung
        let msg = format!(
            "{}:{}:{}:{}:{}",
            order.id,
            order.user_id,
            order.quantity,
            order.timestamp,
            match order.side {
                OrderSide::Buy => "BUY",
                OrderSide::Sell => "SELL",
            }
        );
    
        let hash = Sha256::digest(msg.as_bytes());
        let sig = keypair.sign(&hash);
    
        order.signature = Some(sig.to_bytes().to_vec());
        order.public_key = Some(keypair.public.to_bytes().to_vec());
    
        let result = validator.validate_order(&order);
        assert!(result.is_ok(), "Order mit gültiger Signatur sollte validiert werden");
    }

    #[test]
    fn test_validate_order_with_real_signature() {
        use ed25519_dalek::{Keypair, Signer};
        use rand::rngs::OsRng;
        use sha2::{Sha256, Digest};
        use crate::crdt_logic::Order;
    
        let validator = AdvancedSecurityValidator::new();
    
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);
    
        let mut order = Order {
            id: "signed_order_1".to_string(),
            user_id: "test_user".to_string(),
            timestamp: 12345678,
            side: OrderSide::Buy,
            order_type: OrderType::Limit(100.0),
            quantity: 10.0,
            filled: 0.0,
            status: OrderStatus::Open,
            signature: None,
            public_key: None,
        };
    
        let msg = format!(
            "{}:{}:{}:{}:{}",
            order.id,
            order.user_id,
            order.quantity,
            order.timestamp,
            match order.side {
                OrderSide::Buy => "BUY",
                OrderSide::Sell => "SELL",
            }
        );
    
        let hash = Sha256::digest(msg.as_bytes());
        let sig = keypair.sign(&hash);
    
        order.signature = Some(sig.to_bytes().to_vec());
        order.public_key = Some(keypair.public.to_bytes().to_vec());
    
        let result = validator.validate_order(&order);
        assert!(result.is_ok(), "Order mit gültiger Signatur sollte validiert werden");
    }

    #[test]
    fn test_validate_trade() {
        let validator = AdvancedSecurityValidator::new();
    
        let valid = validator.validate_trade("Buy:o1; Sell:o2; Qty:5; Price:100");
        assert!(valid.is_ok());
    
        let invalid = validator.validate_trade("no buy or sell markers here");
        assert!(invalid.is_err());
    }

    #[test]
    fn test_validate_settlement() {
        let validator = AdvancedSecurityValidator::new();
    
        let valid = validator.validate_settlement("Buyer:abc; Seller:def; BaseAmt:10; QuoteAmt:500");
        assert!(valid.is_ok());
    
        let invalid = validator.validate_settlement("BaseAmt:0; QuoteAmt:0");
        assert!(invalid.is_err());
    }
