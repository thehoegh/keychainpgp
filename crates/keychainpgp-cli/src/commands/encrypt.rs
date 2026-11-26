use std::io::{self, Read, Write};

use anyhow::{Context, Result};
use keychainpgp_core::{CryptoEngine, SequoiaEngine};
use keychainpgp_keys::Keyring;

pub fn run(engine: &SequoiaEngine, recipient_fingerprints: &[String]) -> Result<()> {
    let keyring = Keyring::open_default()?;

    // Look up recipient public keys (by fingerprint or name/email search)
    let mut recipient_keys = Vec::new();
    for query in recipient_fingerprints {
        // Try exact fingerprint first
        if let Some(record) = keyring.get_key(query)? {
            recipient_keys.push(public_key(&engine, &record.pgp_data, query)?);
            continue;
        }

        // Fall back to search
        let results = keyring.search_keys(query)?;
        match results.len() {
            0 => anyhow::bail!("no key found matching '{query}'"),
            1 => {
                let record = results.into_iter().next().unwrap();
                recipient_keys.push(public_key(&engine, &record.pgp_data, query)?);
            }
            n => {
                eprintln!("Ambiguous recipient '{query}' matched {n} keys:");
                for r in &results {
                    let name = r.name.as_deref().unwrap_or("(no name)");
                    let email = r
                        .email
                        .as_deref()
                        .map(|e| format!(" <{e}>"))
                        .unwrap_or_default();
                    eprintln!("  {} {name}{email}", &r.fingerprint[..16]);
                }
                anyhow::bail!("specify a more precise recipient (use full fingerprint)");
            }
        }
    }

    // Read plaintext from stdin (limit to 64 MB to prevent memory exhaustion)
    const MAX_INPUT: u64 = 64 * 1024 * 1024;
    let mut plaintext = Vec::new();
    io::stdin()
        .take(MAX_INPUT)
        .read_to_end(&mut plaintext)
        .context("failed to read from stdin")?;

    if plaintext.is_empty() {
        anyhow::bail!("no input data (stdin was empty)");
    }

    // Encrypt
    let ciphertext = engine.encrypt(&plaintext, &recipient_keys)?;

    // Write to stdout
    io::stdout()
        .write_all(&ciphertext)
        .context("failed to write to stdout")?;

    eprintln!(
        "Encrypted for {} recipient(s).",
        recipient_fingerprints.len()
    );

    Ok(())
}

fn public_key(engine: &SequoiaEngine, pgp_data: &[u8], query: &str) -> Result<Vec<u8>> {
    let public_key = engine
        .export_public_key_text(pgp_data)
        .with_context(|| format!("failed to export public key for {query}"))?;
    Ok(public_key.into_bytes())
}
