use secp256k1::{Secp256k1, SecretKey, PublicKey, All};
use rand::rngs::OsRng;
use rand::RngCore;
use std::error::Error;

/// Struct representing a Pedersen Commitment.
pub struct PedersenCommitment {
    pub value: u64,
    pub blinding: SecretKey,
    pub commitment: PublicKey,
}

/// Generates a blinding factor (secret key).
fn generate_blinding_factor() -> Result<SecretKey, Box<dyn Error>> {
    let mut rng = OsRng;
    let mut blinding_bytes = [0u8; 32];
    rng.fill_bytes(&mut blinding_bytes);
    
    SecretKey::from_slice(&blinding_bytes).map_err(|e| format!("Blinding factor error: {}", e).into())
}

/// Generates a commitment using the blinding factor.
fn generate_commitment(secp: &Secp256k1<All>, blinding: &SecretKey) -> Result<PublicKey, Box<dyn Error>> {
    let generator_h = PublicKey::from_secret_key(secp, blinding);
    let generator_g = PublicKey::from_secret_key(secp, &SecretKey::from_slice(&[2; 32]).unwrap());

    let commitment = generator_g.combine(&generator_h)
        .map_err(|_| "Failed to generate Pedersen Commitment")?;

    Ok(commitment)
}

/// Generates a Pedersen Commitment for a given value.
pub fn generate_pedersen_commitment(value: u64) -> Result<PedersenCommitment, Box<dyn Error>> {
    let secp = Secp256k1::new();

    let blinding = generate_blinding_factor()?;
    let commitment = generate_commitment(&secp, &blinding)?;

    debug_assert!(commitment.serialize().len() == 33, "Invalid commitment generated!");


    Ok(PedersenCommitment {
        value,
        blinding,
        commitment,
    })
}
