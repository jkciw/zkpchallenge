use secp256k1::SecretKey;
use rand::rngs::OsRng;
use rand::RngCore;
use std::error::Error;

/// Struct representing a Bulletproof Challenge.
pub struct BulletproofChallenge {
    pub challenge: SecretKey,
}

/// Generates a Bulletproof Challenge.
pub fn generate_challenge(rng: &mut OsRng) -> Result<BulletproofChallenge, Box<dyn Error>> {
    let mut challenge_bytes = [0u8; 32];
    rng.fill_bytes(&mut challenge_bytes);

    let challenge = SecretKey::from_slice(&challenge_bytes)
        .map_err(|e| format!("Challenge generation failed: {}", e))?;

    Ok(BulletproofChallenge { challenge })
}
