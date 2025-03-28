use secp256k1::{Secp256k1, SecretKey, PublicKey, All, Scalar};
use secp256k1::hashes::{sha256, Hash};
use rand::rngs::OsRng;
use rand::RngCore;
use std::error::Error;

#[allow(dead_code)]
pub struct PedersenCommitment {
    pub value: u64,
    pub blinding: SecretKey,
    pub commitment: PublicKey,
}

fn get_generator_h(secp: &Secp256k1<All>, generator_g: &PublicKey) -> Result<PublicKey, Box<dyn Error>> {
    let hash = sha256::Hash::hash(&generator_g.serialize());
    let h_scalar = Scalar::from_be_bytes(hash.to_byte_array()).map_err(|_| "Invalid scalar for H")?;
    let generator_h = generator_g.mul_tweak(secp, &h_scalar.into())?;
    Ok(generator_h)
}

fn scalar_from_u64(value: u64) -> Result<Scalar, Box<dyn Error>> {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes()); // or to_be_bytes(), but be consistent!
    let scalar = Scalar::from_be_bytes(bytes).map_err(|_| "Invalid scalar")?;
    Ok(scalar)
}

fn generate_commitment(secp: &Secp256k1<All>, value: u64, blinding: &SecretKey) -> Result<PublicKey, Box<dyn Error>> {
    let value_scalar = scalar_from_u64(value)?;
    
    let secret_g = SecretKey::from_slice(&[1; 32])?;
    let generator_g = PublicKey::from_secret_key(secp, &secret_g);

    let generator_h = get_generator_h(secp, &generator_g)?;
    
    let a_g = generator_g.mul_tweak(secp, &value_scalar)?; //THIS IS: aG

    let blinding_scalar = Scalar::from_be_bytes(blinding.secret_bytes()).map_err(|_| "Invalid blinding scalar")?;
    let r_h = generator_h.mul_tweak(secp, &blinding_scalar)?; //THIS IS: rH
    
    //TODO Implement commitment : aG + rH
    let commitment = generator_g.clone(); 

    
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