use secp256k1::PublicKey;
use std::error::Error;

pub fn compute_inner_product_commitment(bit_commitments: &[PublicKey]) -> Result<PublicKey, Box<dyn Error>> {
    if bit_commitments.is_empty() {
        return Err("Error: Cannot compute inner product on an empty list.".into());
    }

    let mut result = bit_commitments[0];

    // Recursively sum result with the next commitment
    // Mathematical representation: result = commitment[0] + commitment[1] + ... + commitment[n]
    for commitment in bit_commitments.iter().skip(1) {
        result = result.clone() //TODO: Combine the current result with the next commitment
        
        // Mathematical representaiton: result = result + commitment
        // NOTE: Final result also needs to handle possible errors.
    }

    Ok(result)
}
