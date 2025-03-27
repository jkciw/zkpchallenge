use secp256k1::SecretKey;
use sha2::{Sha256, Digest};
use std::error::Error;

#[derive(Debug)]
pub struct BulletproofChallenge {
    pub challenge: SecretKey,
}

/// Generate a Bulletproof Challenge using the Fiat–Shamir heuristic.
pub fn generate_challenge(transcript: &[u8]) -> Result<BulletproofChallenge, Box<dyn Error>> {
    let hash = Sha256::digest(transcript);
    let challenge = SecretKey::from_slice(&hash)
        .map_err(|e| format!("Challenge generation from transcript failed: {}", e))?;
    
    Ok(BulletproofChallenge { challenge })
}
