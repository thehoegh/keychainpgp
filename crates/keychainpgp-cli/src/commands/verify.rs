use std::io::{self, Read};

use anyhow::{Context, Result};
use keychainpgp_core::{CryptoEngine, SequoiaEngine};
use keychainpgp_keys::Keyring;

pub fn run(signer: &str) -> Result<()> {
    let engine = SequoiaEngine::new();
    let keyring = Keyring::open_default()?;

    // Find the signer's public key by fingerprint or email
    let signer_records = keyring.search_keys(signer)?;
    let signer_record = signer_records
        .first()
        .with_context(|| format!("no key found matching '{signer}'"))?;

    // Read signed data from stdin (limit to 64 MB to prevent memory exhaustion)
    const MAX_INPUT: u64 = 64 * 1024 * 1024;
    let mut signed_data = Vec::new();
    io::stdin()
        .take(MAX_INPUT)
        .read_to_end(&mut signed_data)
        .context("failed to read from stdin")?;

    let public_key = engine
        .export_public_key_text(&signer_record.pgp_data)
        .context("failed to export signer public key")?;

    match engine.verify(&signed_data, public_key.as_bytes()) {
        Ok(result) => {
            if result.valid {
                let name = signer_record.name.as_deref().unwrap_or("(unknown)");
                eprintln!("Good signature from {name}");
                if let Some(fp) = &result.signer_fingerprint {
                    eprintln!("Fingerprint: {fp}");
                }
            } else {
                eprintln!("BAD signature: verification failed");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Verification error: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}
