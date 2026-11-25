//! Key import functionality.

use keychainpgp_core::armor;

use crate::error::{Error, Result};

/// The result of parsing imported key data.
#[derive(Debug)]
pub struct ImportedKey {
    /// Raw key bytes (ASCII-armored or binary).
    pub data: Vec<u8>,
    /// Whether this is a public or private key.
    pub is_secret: bool,
}

/// Parse raw bytes and determine if they contain valid PGP key material.
///
/// A file that contains both a public key block and a private key block
/// returns each block separately. The public key's bytes do not include the
/// private key block.
pub fn parse_import(data: &[u8]) -> Result<Vec<ImportedKey>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Err(Error::InvalidKey {
            reason: "data does not contain a recognized PGP key block".into(),
        });
    };

    let mut keys = Vec::new();
    let public_keys = armor::public_key_blocks(text);
    let private_keys = armor::private_key_blocks(text);
    if !public_keys.is_empty() {
        keys.push(ImportedKey {
            data: public_keys.into_bytes(),
            is_secret: false,
        });
    }
    if !private_keys.is_empty() {
        keys.push(ImportedKey {
            data: private_keys.into_bytes(),
            is_secret: true,
        });
    }
    if keys.is_empty() {
        return Err(Error::InvalidKey {
            reason: "data does not contain a recognized PGP key block".into(),
        });
    }

    Ok(keys)
}

/// Read key data from a file path.
pub fn read_key_file(path: &std::path::Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_file_does_not_keep_the_private_block_in_the_public_key() {
        let data = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nsecret\n-----END PGP PRIVATE KEY BLOCK-----\n";
        let keys = parse_import(data).unwrap();
        assert_eq!(keys.len(), 2);
        assert!(!keys[0].is_secret);
        let public_key = String::from_utf8(keys[0].data.clone()).unwrap();
        assert!(public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));
        assert!(!public_key.contains("PRIVATE KEY BLOCK"));
        assert!(keys[1].is_secret);
        assert!(String::from_utf8_lossy(&keys[1].data).contains("PRIVATE KEY BLOCK"));
    }
}
