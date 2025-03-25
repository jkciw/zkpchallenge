use secp256k1::{PublicKey};

pub fn compute_inner_product_commitment(bit_commitments: &[PublicKey]) -> PublicKey {
    let secp = secp256k1::Secp256k1::new();
    let mut result = bit_commitments[0];

    for commitment in bit_commitments.iter().skip(1) {
        result = result.combine(commitment).expect("Failed to sum commitments");
    }

    result
}
