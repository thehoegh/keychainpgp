/// Checks whether the given bytes contain an ASCII-armored PGP message.
#[must_use]
pub fn is_pgp_message(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    text.contains("-----BEGIN PGP MESSAGE-----")
}

/// Checks whether the given bytes contain an ASCII-armored PGP public key block.
#[must_use]
pub fn is_pgp_public_key(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    text.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")
}

/// Checks whether the given bytes contain an ASCII-armored PGP private key block.
#[must_use]
pub fn is_pgp_private_key(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----")
}

/// Checks whether the given bytes contain a cleartext-signed PGP message.
#[must_use]
pub fn is_cleartext_signed(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    text.contains("-----BEGIN PGP SIGNED MESSAGE-----")
}

/// Checks whether the given bytes contain any recognized PGP ASCII armor.
#[must_use]
pub fn is_pgp_armored(data: &[u8]) -> bool {
    is_pgp_message(data)
        || is_pgp_public_key(data)
        || is_pgp_private_key(data)
        || is_cleartext_signed(data)
}

/// The type of PGP block detected in the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgpBlockKind {
    Message,
    PublicKey,
    PrivateKey,
    Signature,
    SignedMessage,
}

/// Public and private ASCII-armor blocks taken from one key file.
///
/// A file can start with a public key block and continue with a private key
/// block. Callers that want a public key must use `public_keys` rather than
/// the original text: a prefix check still sees the public header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlockSplit {
    /// Complete public key blocks, in their original armor.
    pub public_keys: String,
    /// Private key blocks, including a block that has no matching END line.
    pub private_keys: String,
}

const PUBLIC_KEY_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PUBLIC_KEY_END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
const PRIVATE_KEY_BEGIN: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
const PRIVATE_KEY_END: &str = "-----END PGP PRIVATE KEY BLOCK-----";

/// Split ASCII-armored public and private key blocks.
///
/// An unclosed private key block is kept in [`KeyBlockSplit::private_keys`] so
/// it cannot be treated as part of the public key. An unclosed public key
/// block is dropped.
#[must_use]
pub fn split_key_blocks(text: &str) -> KeyBlockSplit {
    let mut public_keys = String::new();
    let mut private_keys = String::new();
    let mut current = String::new();
    let mut mode = KeyBlockMode::Outside;

    for line in lines_with_endings(text) {
        let label = armor_label(line);
        match mode {
            KeyBlockMode::Outside => {
                if label == PUBLIC_KEY_BEGIN {
                    mode = KeyBlockMode::Public;
                    current.push_str(line);
                } else if label == PRIVATE_KEY_BEGIN {
                    mode = KeyBlockMode::Private;
                    current.push_str(line);
                }
            }
            KeyBlockMode::Public => {
                current.push_str(line);
                if label == PUBLIC_KEY_END {
                    push_block(&mut public_keys, &mut current);
                    mode = KeyBlockMode::Outside;
                }
            }
            KeyBlockMode::Private => {
                current.push_str(line);
                if label == PRIVATE_KEY_END {
                    push_block(&mut private_keys, &mut current);
                    mode = KeyBlockMode::Outside;
                }
            }
        }
    }

    // A missing END line would otherwise leave the rest of the file, including
    // a private key, attached to the public block.
    if mode == KeyBlockMode::Private && !current.is_empty() {
        push_block(&mut private_keys, &mut current);
    }

    KeyBlockSplit {
        public_keys,
        private_keys,
    }
}

/// Complete public key blocks from `text`.
#[must_use]
pub fn public_key_blocks(text: &str) -> String {
    split_key_blocks(text).public_keys
}

/// Private key blocks from `text`, including an unclosed private key block.
#[must_use]
pub fn private_key_blocks(text: &str) -> String {
    split_key_blocks(text).private_keys
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyBlockMode {
    Outside,
    Public,
    Private,
}

fn armor_label(line: &str) -> &str {
    line.trim_end_matches(['\n', '\r']).trim()
}

fn lines_with_endings(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        if let Some(index) = rest.find('\n') {
            let (line, tail) = rest.split_at(index + 1);
            rest = tail;
            Some(line)
        } else {
            let line = rest;
            rest = "";
            Some(line)
        }
    })
}

fn push_block(output: &mut String, current: &mut String) {
    if current.is_empty() {
        return;
    }
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    output.push_str(current);
    current.clear();
}

/// Detect what kind of PGP block is present in the given data.
#[must_use]
pub fn detect_pgp_block(data: &[u8]) -> Option<PgpBlockKind> {
    let text = String::from_utf8_lossy(data);
    // Check cleartext signed first — it contains both SIGNED MESSAGE and SIGNATURE headers
    if text.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
        Some(PgpBlockKind::SignedMessage)
    } else if text.contains("-----BEGIN PGP MESSAGE-----") {
        Some(PgpBlockKind::Message)
    } else if text.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
        Some(PgpBlockKind::PublicKey)
    } else if text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        Some(PgpBlockKind::PrivateKey)
    } else if text.contains("-----BEGIN PGP SIGNATURE-----") {
        Some(PgpBlockKind::Signature)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pgp_message() {
        let data = b"-----BEGIN PGP MESSAGE-----\ndata\n-----END PGP MESSAGE-----";
        assert!(is_pgp_message(data));
        assert_eq!(detect_pgp_block(data), Some(PgpBlockKind::Message));
    }

    #[test]
    fn test_detect_pgp_public_key() {
        let data =
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ndata\n-----END PGP PUBLIC KEY BLOCK-----";
        assert!(is_pgp_public_key(data));
        assert_eq!(detect_pgp_block(data), Some(PgpBlockKind::PublicKey));
    }

    #[test]
    fn test_plain_text_not_detected() {
        let data = b"Hello, this is just plain text.";
        assert!(!is_pgp_armored(data));
        assert_eq!(detect_pgp_block(data), None);
    }

    fn sample_public() -> &'static str {
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n"
    }

    fn sample_private() -> &'static str {
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nsecret\n-----END PGP PRIVATE KEY BLOCK-----\n"
    }

    #[test]
    fn public_block_is_preserved_exactly() {
        let public_key = sample_public();
        assert_eq!(public_key_blocks(public_key), public_key);
        assert!(private_key_blocks(public_key).is_empty());
    }

    #[test]
    fn public_block_followed_by_private_block_is_split() {
        let combined = format!("{}{}", sample_public(), sample_private());
        // A prefix or "contains public header" check still sees a public key.
        assert!(is_pgp_public_key(combined.as_bytes()));
        assert!(
            combined
                .trim_start()
                .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        );
        assert!(is_pgp_private_key(combined.as_bytes()));

        assert_eq!(public_key_blocks(&combined), sample_public());
        assert_eq!(private_key_blocks(&combined), sample_private());
        assert!(!public_key_blocks(&combined).contains("PRIVATE KEY BLOCK"));
    }

    #[test]
    fn private_block_before_public_block_is_split() {
        let combined = format!("{}{}", sample_private(), sample_public());
        assert_eq!(public_key_blocks(&combined), sample_public());
        assert_eq!(private_key_blocks(&combined), sample_private());
    }

    #[test]
    fn unclosed_private_block_is_not_returned_as_public() {
        let text = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret without end";
        let public_key = public_key_blocks(text);
        assert!(public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));
        assert!(!public_key.contains("PRIVATE"));
        assert!(!public_key.contains("secret"));
        assert!(private_key_blocks(text).contains("secret without end"));
    }

    #[test]
    fn crlf_key_blocks_are_split() {
        let public_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nabc\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n";
        let private_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\r\nsecret\r\n-----END PGP PRIVATE KEY BLOCK-----\r\n";
        let combined = format!("{public_key}{private_key}");
        assert_eq!(public_key_blocks(&combined), public_key);
        assert_eq!(private_key_blocks(&combined), private_key);
    }
}
