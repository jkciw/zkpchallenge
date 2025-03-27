use secp256k1::{PublicKey, Secp256k1, SecretKey};
use crate::{commitment::generate_pedersen_commitment, prover::BulletproofResponse};
use crate::prover::respond_to_challenge;
use crate::challenge::generate_challenge;
use crate::verifier::verify_bulletproof;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct ConfidentialTransaction {
    pub sender: Vec<u8>,         // Serialized sender public key (XOnly)
    pub receiver: Vec<u8>,       // Serialized receiver public key
    pub amount_commitment: Vec<u8>, // Serialized Pedersen commitment
    pub proof: Vec<u8>,          // Serialized Bulletproof proof data
}

/// Convert PublicKey to bytes
fn public_key_to_bytes(pk: &PublicKey) -> Vec<u8> {
    pk.serialize().to_vec()
}

/// Convert bytes to PublicKey
fn bytes_to_public_key(bytes: &[u8]) -> PublicKey {
    PublicKey::from_slice(bytes).expect("Invalid PublicKey bytes")
}

/// In reality, this should include all public data relevant to the proof.
/// For now we use a single Pedersen commitment.
pub fn build_transcript(commitments: &[PublicKey]) -> Vec<u8> {
    let mut transcript = Vec::new();
    for commitment in commitments {
        transcript.extend_from_slice(&commitment.serialize());
    }
    transcript
}

pub fn create_confidential_tx(
    sender_sk: &SecretKey,
    receiver_pk: &PublicKey,
    amount: u64,
) -> ConfidentialTransaction {
    let secp = Secp256k1::new();

    let commitment_result = generate_pedersen_commitment(amount);
    let commitment = commitment_result.unwrap_or_else(|e| panic!("Commitment generation failed: {}", e));

    let transcript = build_transcript(&[commitment.commitment]);

    let challenge = generate_challenge(&transcript)
        .expect("Failed to generate challenge from transcript");
    
    // In reality, this again would be a detailed proof; here it's a simplified/dummy response.
    let proof = respond_to_challenge(&vec![commitment.commitment], &challenge);

    ConfidentialTransaction {
        sender: public_key_to_bytes(&PublicKey::from_secret_key(&secp, sender_sk)),
        receiver: public_key_to_bytes(receiver_pk),
        amount_commitment: public_key_to_bytes(&commitment.commitment),
        proof: proof.response_commitment.serialize().to_vec(),
    }
}

pub fn verify_confidential_tx(tx: &ConfidentialTransaction) -> bool {
    let secp = Secp256k1::new();

    let proof_commitment = bytes_to_public_key(&tx.proof);
    let amount_commitment = bytes_to_public_key(&tx.amount_commitment);

    let response = BulletproofResponse {
        response_commitment: proof_commitment,
        response_challenge: secp256k1::SecretKey::new(&mut rand::thread_rng()),
    };

    let (amount_commitment_xonly, _) = amount_commitment.x_only_public_key();

    verify_bulletproof(&response, &amount_commitment_xonly)
}