//! Key export functionality.

use keychainpgp_core::SequoiaEngine;

use crate::error::Result;
use crate::storage::KeyRecord;

/// Export a public key as ASCII-armored text.
///
/// A private key block stored after the public key is not included.
pub fn export_public_key(record: &KeyRecord) -> Result<String> {
    SequoiaEngine::new()
        .export_public_key_text(&record.pgp_data)
        .map_err(Into::into)
}
