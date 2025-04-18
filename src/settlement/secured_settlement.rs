///////////////////////////////////////////////////////////
// my_dex/src/settlement/secured_settlement.rs
///////////////////////////////////////////////////////////
//
// Dieses Modul implementiert einen Sicherheits-Wrapper für den Settlement-Prozess.
// Der Trait `SettlementEngineTrait` definiert das Interface für Trade-Abwicklung.
// Die `SecuredSettlementEngine` erweitert jede kompatible Engine um:
//
// - Sicherheitsvalidierung vor dem Abwickeln von Trades
// - Prüfung auf 0 oder negative Beträge (base / quote)
// - Klares Logging und Fehlerbehandlung bei ungültigen Settlements
//
///////////////////////////////////////////////////////////

use anyhow::Result;
use tracing::error;
use crate::error::DexError;
use crate::security::security_validator::{SecurityValidator, AdvancedSecurityValidator};

/// Trait, der die grundlegende Settlement-Funktionalität kapselt.
pub trait SettlementEngineTrait: Send + Sync {
    /// Finalisiert einen Trade (Settlement) zwischen Käufer und Verkäufer.
    /// Bei erfolgreicher Validierung werden die entsprechenden Gelder freigegeben.
    fn finalize_trade(
        &mut self,
        buyer: &str,
        seller: &str,
        base_asset: &str,
        quote_asset: &str,
        base_amount: f64,
        quote_amount: f64,
    ) -> Result<(), DexError>;
}

/// Basiseinfach implementierte Settlement-Engine (z.B. aus matching_engine.rs)
/// Die hier gezeigte Struktur entspricht der bestehenden SettlementEngine.
#[derive(Clone, Debug)]
pub struct SettlementEngine {
    // Benutzer-ID -> (Asset -> (free, locked))
    pub balances: std::collections::HashMap<String, std::collections::HashMap<String, (f64, f64)>>,
}

impl SettlementEngine {
    pub fn new() -> Self {
        Self {
            balances: std::collections::HashMap::new(),
        }
    }

    pub fn lock_funds(&mut self, user_id: &str, asset: &str, amount: f64) -> Result<(), DexError> {
        let user_balance = self.balances.entry(user_id.to_string()).or_insert_with(std::collections::HashMap::new);
        let entry = user_balance.entry(asset.to_string()).or_insert((0.0, 0.0));
        if entry.0 < amount {
            return Err(DexError::Other(format!("Nicht genügend Guthaben bei {}", user_id)));
        }
        entry.0 -= amount;
        entry.1 += amount;
        Ok(())
    }

    pub fn release_funds(&mut self, user_id: &str, asset: &str, amount: f64) -> Result<(), DexError> {
        let user_balance = self.balances.entry(user_id.to_string()).or_insert_with(std::collections::HashMap::new);
        let entry = user_balance.entry(asset.to_string()).or_insert((0.0, 0.0));
        if entry.1 < amount {
            return Err(DexError::Other(format!("Nicht genügend gesperrte Mittel bei {}", user_id)));
        }
        entry.1 -= amount;
        entry.0 += amount;
        Ok(())
    }
}

impl SettlementEngineTrait for SettlementEngine {
    fn finalize_trade(
        &mut self,
        buyer: &str,
        seller: &str,
        base_asset: &str,
        quote_asset: &str,
        base_amount: f64,
        quote_amount: f64,
    ) -> Result<(), DexError> {
        self.lock_funds(buyer, base_asset, base_amount)?;
        self.lock_funds(seller, quote_asset, quote_amount)?;
        self.release_funds(buyer, base_asset, base_amount)?;
        self.release_funds(seller, quote_asset, quote_amount)?;
        Ok(())
    }
}

/// SecuredSettlementEngine umschließt eine bestehende SettlementEngine (inner)
/// und einen Sicherheitsvalidator. Vor dem finalen Abschluss eines Settlements
/// wird der Validator aufgerufen, um die Sicherheitsbedingungen zu prüfen.
pub struct SecuredSettlementEngine<E: SettlementEngineTrait, S: SecurityValidator> {
    pub inner: E,
    pub validator: S,
}

impl<E: SettlementEngineTrait, S: SecurityValidator> SecuredSettlementEngine<E, S> {
    pub fn new(inner: E, validator: S) -> Self {
        Self { inner, validator }
    }
}

impl<E: SettlementEngineTrait, S: SecurityValidator> SettlementEngineTrait for SecuredSettlementEngine<E, S> {
    fn finalize_trade(
        &mut self,
        buyer: &str,
        seller: &str,
        base_asset: &str,
        quote_asset: &str,
        base_amount: f64,
        quote_amount: f64,
    ) -> Result<(), DexError> {
        // Neue Sicherheitsprüfung: Basiswerte dürfen nicht <= 0 sein
        if base_amount <= 0.0 || quote_amount <= 0.0 {
            return Err(DexError::Other("Abrechnung mit 0 oder negativen Beträgen nicht erlaubt".into()));
        }

        let settlement_info = format!(
            "Buyer:{}; Seller:{}; BaseAsset:{}; QuoteAsset:{}; BaseAmt:{}; QuoteAmt:{}",
            buyer, seller, base_asset, quote_asset, base_amount, quote_amount
        );

        match self.validator.validate_settlement(&settlement_info) {
            Ok(_) => {
                // Prüfung erfolgreich → weiterleiten an echte Engine
                self.inner.finalize_trade(buyer, seller, base_asset, quote_asset, base_amount, quote_amount)
            },
            Err(e) => {
                // Validierung fehlgeschlagen → blockieren und loggen
                error!("SecuredSettlementEngine: Sicherheitsprüfung fehlgeschlagen: {:?}", e);
                Err(DexError::Other("Sicherheitsprüfung für Settlement fehlgeschlagen".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::security_validator::AdvancedSecurityValidator;

    #[test]
    fn test_secured_settlement_finalize() {
        let base_engine = SettlementEngine::new();
        let validator = AdvancedSecurityValidator::new();
        let mut secured_engine = SecuredSettlementEngine::new(base_engine, validator);

        let result = secured_engine.finalize_trade("buyer", "seller", "BTC", "USDT", 1.0, 50000.0);
        assert!(result.is_ok(), "Settlement mit gültigen Beträgen sollte erfolgreich sein");
    }

    #[test]
    fn test_secured_settlement_rejects_invalid_amounts() {
        let base_engine = SettlementEngine::new();
        let validator = AdvancedSecurityValidator::new();
        let mut secured_engine = SecuredSettlementEngine::new(base_engine, validator);

        let result = secured_engine.finalize_trade("buyer", "seller", "BTC", "USDT", 0.0, 0.0);

        assert!(
            result.is_err(),
            "Settlement mit 0-Werten muss abgelehnt werden"
        );
    }
}
