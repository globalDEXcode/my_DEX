// my_dex/src/crypto/ring_sig.rs

//! Dieses Modul stellt eine Monero-kompatible Ring-Signatur-Implementierung bereit
//! auf Basis von MLSAG (Multilayered Linkable Spontaneous Anonymous Group Signature)
//! unter Verwendung von `curve25519-dalek`, `merlin` und optional `monero` für Kompatibilität.

use anyhow::{Result, anyhow};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};

/// Die Struktur einer vollständigen Ring-Signatur.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingSignature {
    pub c1: Scalar,
    pub responses: Vec<Scalar>,
    pub key_image: RistrettoPoint,
    pub public_keys: Vec<RistrettoPoint>,
}

/// Signiert eine Nachricht mithilfe eines Rings von Public Keys und einem echten Schlüssel (real_index).
pub fn sign_ring_mlsag(
    message: &[u8],
    ring: &[RistrettoPoint],
    secret: Scalar,
    real_index: usize,
) -> Result<RingSignature> {
    if real_index >= ring.len() {
        return Err(anyhow!("real_index liegt außerhalb des Rings"));
    }

    let mut rng = OsRng;
    let mut transcript = Transcript::new(b"MLSAG_RingSig");
    transcript.append_message(b"msg", message);

    // Generiere Key Image
    let key_image = &secret * &RistrettoPoint::hash_from_bytes::<sha2::Sha512>(b"key_image")
        .compress().to_bytes().into();

    // Initialisierung
    let n = ring.len();
    let mut responses = vec![Scalar::zero(); n];
    let mut cs = vec![Scalar::zero(); n];
    let mut alpha = Scalar::random(&mut rng);

    // Schritt 1: berechne erstes Commitment
    let L = &alpha * &RistrettoPoint::default();
    transcript.append_point(b"L", &L.compress());
    cs[(real_index + 1) % n] = Scalar::hash_from_bytes::<sha2::Sha512>(
        &transcript.challenge_bytes(b"c1")
    );

    // Schritt 2: Responses füllen
    for i in (real_index + 1)..(real_index + n) {
        let idx = i % n;
        responses[idx] = Scalar::random(&mut rng);
        let L_i = &responses[idx] * &RistrettoPoint::default()
            + &cs[idx] * &ring[idx];
        transcript.append_point(b"L", &L_i.compress());
        cs[(idx + 1) % n] = Scalar::hash_from_bytes::<sha2::Sha512>(
            &transcript.challenge_bytes(b"c_next")
        );
    }

    // Eigener Response-Wert
    responses[real_index] = alpha - cs[real_index] * secret;

    Ok(RingSignature {
        c1: cs[0],
        responses,
        key_image,
        public_keys: ring.to_vec(),
    })
}

/// Verifiziert eine Ring-Signatur.
pub fn verify_ring_mlsag(message: &[u8], sig: &RingSignature) -> bool {
    let n = sig.public_keys.len();
    if sig.responses.len() != n {
        return false;
    }

    let mut transcript = Transcript::new(b"MLSAG_RingSig");
    transcript.append_message(b"msg", message);
    let mut cs = vec![sig.c1];

    for i in 0..n {
        let L_i = &sig.responses[i] * &RistrettoPoint::default()
            + &cs[i] * &sig.public_keys[i];
        transcript.append_point(b"L", &L_i.compress());
        let c_next = Scalar::hash_from_bytes::<sha2::Sha512>(
            &transcript.challenge_bytes(b"c_next")
        );
        cs.push(c_next);
    }

    cs[0] == cs[n]
}
