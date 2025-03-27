use secp256k1::SecretKey;
use sha2::{Sha256, Digest};
use std::error::Error;

/// In reality, the challenge is derived from a transcript of all the commitments
/// and additional context using the Fiat–Shamir heuristic.
#[derive(Debug)]
pub struct BulletproofChallenge {
    pub challenge: SecretKey,
}

pub fn generate_challenge(transcript: &[u8]) -> Result<BulletproofChallenge, Box<dyn Error>> {
    let domain_sep = b"BulletproofChallengeDomainSep";
    let mut hasher = Sha256::new();
    hasher.update(domain_sep);
    hasher.update(transcript);
    let hash = hasher.finalize();
    let challenge = SecretKey::from_slice(&hash)
        .map_err(|e| format!("Challenge generation failed: {}", e))?;
    
    Ok(BulletproofChallenge { challenge })
}
