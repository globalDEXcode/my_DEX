/////////////////////////////////////////////////////////////
// tests/ring_signature_test.rs
/////////////////////////////////////////////////////////////
//
// Integrationstest für Orders mit Ring-Signaturen (MLSAG).
// - Erzeugt Keyring
// - Signiert Nachricht mit sign_ring_mlsag
// - Fügt Order ins OrderBook ein
// - Erwartung: Gültige Order wird angenommen, ungültige nicht
//
/////////////////////////////////////////////////////////////

use my_dex::decentralized_order_book::order::{Order, OrderType, OrderSide};
use my_dex::decentralized_order_book::order_book::OrderBook;
use my_dex::crypto::ring_sig::{sign_ring_mlsag, RingSignature};
use ed25519_dalek::{Keypair, PublicKey};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;

#[test]
fn test_add_order_with_valid_ring_signature() {
    let mut rng = OsRng{};
    let keypair1 = Keypair::generate(&mut rng);
    let keypair2 = Keypair::generate(&mut rng);
    let keypair3 = Keypair::generate(&mut rng);

    let ring = vec![
        keypair1.public,
        keypair2.public,
        keypair3.public,
    ];
    let real_index = 1;
    let secret = keypair2.secret.clone();

    // Erzeuge Order
    let mut order = Order::new("user123", OrderType::Limit(100.0), OrderSide::Buy, 5.0);
    order.ring_members = Some(ring.clone());

    // Nachricht hashen
    let msg = format!(
        "{}:{}:{}:{}",
        order.id, order.user_id, order.timestamp, order.quantity
    );
    let hash = Sha256::digest(msg.as_bytes());

    // Signiere Ring
    let sig = sign_ring_mlsag(&hash, &ring, &secret, real_index).expect("Signatur fehlgeschlagen");
    order.ring_signature = Some(sig);

    // Erstelle OrderBook
    let mut ob = OrderBook::new("test-node");

    ob.add_order(order);
    assert_eq!(ob.book.all_visible_orders().len(), 1);
}

#[test]
fn test_add_order_with_invalid_signature() {
    let mut order = Order::new("user123", OrderType::Limit(100.0), OrderSide::Buy, 5.0);
    order.ring_signature = None; // keine g�ltige Signatur
    order.ring_members = None;

    let mut ob = OrderBook::new("test-node");
    ob.add_order(order); // sollte nicht eingef�gt werden

    assert_eq!(ob.book.all_visible_orders().len(), 0);
}
