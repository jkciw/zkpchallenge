use secp256k1::schnorr::Signature;
use secp256k1::{Message, Secp256k1, XOnlyPublicKey};
use crate::network::receive_proof;
use crate::confidential_tx::{verify_confidential_tx, ConfidentialTransaction};
use crate::prover::BulletproofResponse;
use tokio::net::TcpListener;
use serde_json;
use std::error::Error;

pub fn verify_bulletproof(response: &BulletproofResponse, expected_commitment: &XOnlyPublicKey) -> bool {
    response.response_commitment.serialize()[1..] == expected_commitment.serialize()
}

pub async fn verifier_main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Verifier: Listening on 127.0.0.1:8080...");

    // Wait for a transaction from the Prover.
    let tx_json = receive_proof(&listener).await?;
    println!("Verifier: Received a confidential transaction");

    // Deserialize the received JSON into a tuple (ConfidentialTransaction, Vec<u8>).
    let (tx, schnorr_sig_bytes): (ConfidentialTransaction, Vec<u8>) =
        serde_json::from_str(&tx_json).map_err(|e| format!("Failed to deserialize: {}", e))?;

    let schnorr_sig = Signature::from_slice(&schnorr_sig_bytes)
        .map_err(|_| "Invalid Schnorr signature format")?;

    let secp = Secp256k1::new();
    let tx_bytes = serde_json::to_vec(&tx)?;
    let tx_hash = Message::from_hashed_data::<secp256k1::hashes::sha256::Hash>(&tx_bytes);
    let sender_pk = XOnlyPublicKey::from_slice(&tx.sender)
        .map_err(|_| "Invalid sender public key format")?;
        
    let is_valid_tx = verify_confidential_tx(&tx);
    let is_valid_sig = secp.verify_schnorr(&schnorr_sig, &tx_hash, &sender_pk).is_ok();

    println!("Verifier: Transaction Valid? {}", is_valid_tx);
    println!("Verifier: Schnorr Signature Valid? {}", is_valid_sig);

    if is_valid_tx && is_valid_sig {
        println!("Verifier: Confidential Transaction is VALID!");
    } else {
        println!("Verifier: Invalid transaction or signature.");
    }

    Ok(())
}
