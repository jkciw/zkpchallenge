use secp256k1::{PublicKey, Secp256k1};
use std::error::Error;

pub fn compute_inner_product_commitment(bit_commitments: &[PublicKey]) -> Result<PublicKey, Box<dyn Error>> {
    let secp = Secp256k1::new();

    if bit_commitments.is_empty() {
        return Err("Error: Cannot compute inner product on an empty list.".into());
    }

    let mut result = bit_commitments[0];

    for commitment in bit_commitments.iter().skip(1) {
        result = result.combine(commitment)
            .map_err(|_| "Error: Failed to combine commitments")?;
    }

    Ok(result)
}
