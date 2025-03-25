use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use crate::{commitment::generate_pedersen_commitment, prover::BulletproofResponse};
use crate::prover::respond_to_challenge;
use crate::challenge::generate_challenge;
use crate::verifier::verify_bulletproof;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct ConfidentialTransaction {
    pub sender: Vec<u8>,  // Convert PublicKey to bytes
    pub receiver: Vec<u8>,  // Convert PublicKey to bytes
    pub amount_commitment: Vec<u8>,  // Convert PublicKey to bytes
    pub proof: Vec<u8>,  // Serialize Bulletproof proof data
}

/// Convert PublicKey to bytes
fn public_key_to_bytes(pk: &PublicKey) -> Vec<u8> {
    pk.serialize().to_vec()
}

/// Convert bytes to PublicKey
fn bytes_to_public_key(bytes: &[u8]) -> PublicKey {
    PublicKey::from_slice(bytes).expect("Invalid PublicKey bytes")
}

/// Create a confidential transaction with Bulletproofs
pub fn create_confidential_tx(sender_sk: &SecretKey, receiver_pk: &PublicKey, amount: u64) -> ConfidentialTransaction {
    let secp = Secp256k1::new();

    // Generate a Pedersen commitment for the amount
    let commitment = generate_pedersen_commitment(amount);

    // Generate a range proof for the commitment
    let mut rng = OsRng;
    let challenge = generate_challenge(&mut rng).expect("Failed to generate Bulletproof Challenge");
    let commitment = commitment.unwrap_or_else(|e| panic!("Commitment generation failed: {}", e));
    let proof = respond_to_challenge(&vec![commitment.commitment], &challenge);


    ConfidentialTransaction {
        sender: public_key_to_bytes(&PublicKey::from_secret_key(&secp, sender_sk)),
        receiver: public_key_to_bytes(receiver_pk),
        amount_commitment: public_key_to_bytes(&commitment.commitment),
        proof: proof.response_commitment.serialize().to_vec(),
    }
}

/// Verify the confidential transaction
pub fn verify_confidential_tx(tx: &ConfidentialTransaction) -> bool {
    let secp = Secp256k1::new();

    // Convert bytes back to PublicKey
    let proof_commitment = bytes_to_public_key(&tx.proof);
    let amount_commitment = bytes_to_public_key(&tx.amount_commitment);

    let response = BulletproofResponse {
        response_commitment: proof_commitment,
        response_challenge: secp256k1::SecretKey::new(&mut rand::thread_rng()),
    };

    let (amount_commitment_xonly, _) = amount_commitment.x_only_public_key();

    let is_valid = verify_bulletproof(&response, &amount_commitment_xonly);

    is_valid
}

