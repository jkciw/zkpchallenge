mod commitment;
mod prover;
mod verifier;
mod challenge;
mod confidential_tx;
mod inner_product;
mod network;

use std::env;
use tokio::runtime::Runtime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Expect two arguments: mode ("prover" or "verifier") and an address (e.g., "192.168.1.100:8080")
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: cargo run -- <prover | verifier> <address:port>");
        std::process::exit(1);
    }

    let mode = &args[1];
    let address = &args[2];

    let runtime = Runtime::new()?;
    match mode.as_str() {
        "prover" => {
            println!("Starting Prover... sending to {}", address);
            runtime.block_on(prover::prover_main(address))?;
        }
        "verifier" => {
            println!("Starting Verifier... listening on {}", address);
            runtime.block_on(verifier::verifier_main(address))?;
        }
        _ => {
            eprintln!("Invalid mode. Use 'prover' or 'verifier'.");
            std::process::exit(1);
        }
    }

    Ok(())
}
