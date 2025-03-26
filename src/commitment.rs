use secp256k1::{Secp256k1, SecretKey, PublicKey, All, Scalar};
use secp256k1::hashes::{sha256, Hash};
use rand::rngs::OsRng;
use rand::RngCore;
use std::error::Error;

pub struct PedersenCommitment {
    pub value: u64,
    pub blinding: SecretKey,
    pub commitment: PublicKey,
}

fn get_generator_h(secp: &Secp256k1<All>, generator_g: &PublicKey) -> Result<PublicKey, Box<dyn Error>> {
    let hash = sha256::Hash::hash(&generator_g.serialize());
    let h_sk = SecretKey::from_slice(&hash.to_byte_array())?;
    let generator_h = PublicKey::from_secret_key(secp, &h_sk);
    Ok(generator_h)
}

fn scalar_from_u64(value: u64) -> Result<SecretKey, Box<dyn Error>> {
    // u64 to 8 little-endian bytes and pad the rest with zeros
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    let sk = SecretKey::from_slice(&bytes)?;
    Ok(sk)
}

fn generate_commitment(secp: &Secp256k1<All>, value: u64, blinding: &SecretKey) -> Result<PublicKey, Box<dyn Error>> {
    let a_sk = scalar_from_u64(value)?;
    
    let secret_g = SecretKey::from_slice(&[1; 32])?;
    let generator_g = PublicKey::from_secret_key(secp, &secret_g);

    // independent generator from G.
    let generator_h = get_generator_h(secp, &generator_g)?;
    
    let a_g = generator_g.mul_tweak(secp, &a_sk.into())?;
    
    let blinding_scalar = Scalar::from_be_bytes(blinding.secret_bytes()).map_err(|_| "Invalid scalar")?;
    let r_h = generator_h.mul_tweak(secp, &blinding_scalar)?;
    
    let commitment = a_g.combine(&r_h)?;
    
    Ok(commitment)
}

pub fn generate_pedersen_commitment(value: u64) -> Result<PedersenCommitment, Box<dyn Error>> {
    let secp = Secp256k1::new();
    
    let mut rng = OsRng;
    let mut blinding_bytes = [0u8; 32];
    rng.fill_bytes(&mut blinding_bytes);
    let blinding = SecretKey::from_slice(&blinding_bytes)?;
    
    let commitment = generate_commitment(&secp, value, &blinding)?;
    
    Ok(PedersenCommitment {
        value,
        blinding,
        commitment,
    })
}
