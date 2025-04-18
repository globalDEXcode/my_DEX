///////////////////////////////////////////////////////////
// my_dex/src/lib.rs
///////////////////////////////////////////////////////////
//
// Definiert und re-exportiert deine Module für interne und
// externe Nutzung (z. B. durch Integrationstests unter /tests).
//
// Enthalten sind:
//  - dezentrale Order-Logik (CRDT, Fees, Orders, RingSig)
//  - Netzwerk & P2P-Adapter
//  - Matching, HTLC, Validator, Storage
//  - Monitoring, Identity, Config, Tracing
//
///////////////////////////////////////////////////////////

// Hauptmodule
pub mod distributed_dht;
pub mod kademlia;
pub mod crypto;

// Identity => Accounts, Wallets
pub mod identity {
    pub mod wallet;
    pub mod accounts;
}

// Sybil-Schutz, Protokoll, etc.
pub mod sybil;
pub mod protocol;

// Netzwerk-Komponenten inkl. TCP + P2P
pub mod network {
    pub mod tcp;
    pub mod noise;
    pub mod secure_channel;
    pub mod p2p_adapter; // NEU: echter P2P-TCP-Adapter
}

// Rate Limiting, Konsens, Noise, Secure Channel ...
pub mod rate_limiting;
pub mod consensus;
pub mod noise;
pub mod secure_channel;
pub mod p2p_order_matcher;

// Matching Engine (wichtig für Integrationstests)
pub mod matching_engine;

// Dezentralisierte Orderbuch-Logik (CRDT, Fees, usw.)
pub mod decentralized_order_book;

// Dex-spezifische Logik für Matching, TLO, Orders, Signaturen, HTLC
pub mod dex_logic {
    pub mod crdt_orderbook;
    pub mod limit_orderbook;
    pub mod orders;
    pub mod fees;
    pub mod htlc;
    pub mod sign_utils;
    pub mod time_limited_orders;
    // optional: gossip, fuzz_test, etc.
}

// Demo & Simulation (optional)
pub mod cross_chain_demo;
pub mod node_simulation;
pub mod limit_orderbook_demo;

// Logging, Metriken, Konfiguration
pub mod logging;
pub mod metrics;
pub mod tracing_setup;
pub mod config_loader;
pub mod node_logic;

// Speicher-Backends (z. B. RocksDB, IPFS, Sled)
pub mod storage {
    pub mod db_layer;
    pub mod replicated_db_layer;
}

// Fehler-Handling
pub mod error;

// Gebührenverwaltung (z. B. poolbasierte Auszahlung)
pub mod fees {
    pub mod fee_pool;
    // ggf. weitere Fees-Module
}

// Zusatztools: HLC (Hybrid Logical Clock), GeoIP, NTP
pub mod utils {
    pub mod hlc;
    pub mod geoip_and_ntp;
}
