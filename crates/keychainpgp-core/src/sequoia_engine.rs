use std::io::Write;
use std::sync::{PoisonError, RwLock};

use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::parse::stream::*;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::Marshal;
use sequoia_openpgp::serialize::stream::*;
use sequoia_openpgp::types::{KeyFlags, PublicKeyAlgorithm};

use secrecy::ExposeSecret;

use crate::armor;
use crate::engine::CryptoEngine;
use crate::error::{Error, Result};
use crate::types::{
    ArmorHeaders, CertInfo, Fingerprint, GeneratedKeyPair, KeyAlgorithm, KeyCapability,
    KeyGenOptions, SubkeyInfo, UserId, VerifyResult,
};

/// Sequoia-PGP backed implementation of [`CryptoEngine`].
pub struct SequoiaEngine {
    policy: StandardPolicy<'static>,
    armor_headers: RwLock<ArmorHeaders>,
}

impl SequoiaEngine {
    /// Create a new `SequoiaEngine` with the standard policy and no armor headers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: StandardPolicy::new(),
            armor_headers: RwLock::new(ArmorHeaders::default()),
        }
    }

    /// Create a new `SequoiaEngine` that emits the given armor headers.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArmorHeader`] if the headers fail validation.
    pub fn with_armor_headers(headers: ArmorHeaders) -> Result<Self> {
        let engine = Self::new();
        engine.set_armor_headers(headers)?;
        Ok(engine)
    }

    /// Replace the armor headers emitted in PGP output.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArmorHeader`] if the headers fail validation;
    /// the previous headers are kept.
    pub fn set_armor_headers(&self, headers: ArmorHeaders) -> Result<()> {
        headers.validate()?;
        *self
            .armor_headers
            .write()
            .unwrap_or_else(PoisonError::into_inner) = headers;
        Ok(())
    }

    /// Create an armor writer with the configured headers.
    fn armor_writer<'a, W: Write + Send + Sync + 'a>(
        &self,
        output: &'a mut W,
        kind: sequoia_openpgp::armor::Kind,
    ) -> std::result::Result<sequoia_openpgp::armor::Writer<&'a mut W>, std::io::Error> {
        self.armor_writer_for_cert(output, kind, None)
    }

    /// Create an armor writer with the configured headers, adding the user ID
    /// and fingerprint of `cert` when key info headers are enabled.
    fn armor_writer_for_cert<'a, W: Write + Send + Sync + 'a>(
        &self,
        output: &'a mut W,
        kind: sequoia_openpgp::armor::Kind,
        cert: Option<&Cert>,
    ) -> std::result::Result<sequoia_openpgp::armor::Writer<&'a mut W>, std::io::Error> {
        let config = self
            .armor_headers
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let mut headers: Vec<(&str, String)> = Vec::new();
        if config.version {
            headers.push((
                "Version",
                concat!("KeychainPGP ", env!("CARGO_PKG_VERSION")).into(),
            ));
        }
        if let Some(comment) = &config.comment {
            headers.push(("Comment", comment.clone()));
        }
        if let Some(cert) = cert.filter(|_| config.key_info) {
            let uid = cert.userids().next().map(|u| u.userid().to_string());
            if let Some(uid) = uid.filter(|u| !u.chars().any(char::is_control)) {
                headers.push(("Comment", uid));
            }
            headers.push(("Fingerprint", cert.fingerprint().to_hex()));
        }
        sequoia_openpgp::armor::Writer::with_headers(output, kind, headers)
    }

    /// Parse decrypted backup bytes into individual certificates.
    ///
    /// Returns a list of `(public_key_armored, secret_key_armored, CertInfo)` for
    /// each certificate found in the data.
    #[allow(clippy::type_complexity)]
    pub fn parse_backup_certs(&self, data: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>, CertInfo)>> {
        use sequoia_openpgp::cert::CertParser;

        let certs: Vec<Cert> = CertParser::from_bytes(data)
            .map_err(|e| Error::InvalidArmor {
                reason: format!("failed to parse backup keys: {e}"),
            })?
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err(Error::InvalidArmor {
                reason: "no valid keys found in the decrypted backup".into(),
            });
        }

        let mut results = Vec::new();
        for cert in &certs {
            // Serialize public key
            let mut public_bytes = Vec::new();
            {
                let mut writer = self
                    .armor_writer_for_cert(
                        &mut public_bytes,
                        sequoia_openpgp::armor::Kind::PublicKey,
                        Some(cert),
                    )
                    .map_err(|e| Error::InvalidArmor {
                        reason: format!("serialization error: {e}"),
                    })?;
                cert.serialize(&mut writer)
                    .map_err(|e| Error::InvalidArmor {
                        reason: format!("serialization error: {e}"),
                    })?;
                writer.finalize().map_err(|e| Error::InvalidArmor {
                    reason: format!("serialization error: {e}"),
                })?;
            }

            // Serialize secret key (TSK)
            let mut secret_bytes = Vec::new();
            {
                let mut writer = self
                    .armor_writer(&mut secret_bytes, sequoia_openpgp::armor::Kind::SecretKey)
                    .map_err(|e| Error::InvalidArmor {
                        reason: format!("serialization error: {e}"),
                    })?;
                cert.as_tsk()
                    .serialize(&mut writer)
                    .map_err(|e| Error::InvalidArmor {
                        reason: format!("serialization error: {e}"),
                    })?;
                writer.finalize().map_err(|e| Error::InvalidArmor {
                    reason: format!("serialization error: {e}"),
                })?;
            }

            // Inspect metadata — use secret_bytes so has_secret_key is correct
            let info = self.inspect_key(&secret_bytes)?;
            results.push((public_bytes, secret_bytes, info));
        }

        Ok(results)
    }

    /// Decrypt a symmetrically-encrypted PGP message (SKESK) using a password.
    ///
    /// Used to decrypt OpenKeychain backup files. The structure is:
    /// `SKESK → SEIP → CompressedData → Literal Data → cert bytes`.
    /// We use low-level PacketParser to walk into each container layer
    /// and extract the Literal Data body containing the key material.
    pub fn decrypt_skesk(&self, ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
        use sequoia_openpgp::crypto::Password;

        // Build password variants: digits-only, with dashes, with spaces, and raw input.
        // OpenKeychain may use different formats depending on the version.
        let digits_only: String = password.chars().filter(|c| c.is_ascii_digit()).collect();
        let with_dashes: String = digits_only
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("-");
        let with_spaces: String = digits_only
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" ");

        let mut passwords = vec![
            Password::from(digits_only.as_bytes()),
            Password::from(with_dashes.as_bytes()),
            Password::from(with_spaces.as_bytes()),
        ];
        if password != digits_only && password != with_dashes && password != with_spaces {
            passwords.push(Password::from(password.as_bytes()));
        }

        // Try each password variant with a fresh PacketParser.
        // SKESK with esk=None always derives a key (can't fail at SKESK level),
        // so the real check is whether the derived key decrypts the SEIP correctly.
        for pw in &passwords {
            match Self::try_decrypt_skesk_with_password(ciphertext, pw) {
                Ok(data) if !data.is_empty() => return Ok(data),
                _ => continue,
            }
        }

        Err(Error::Decryption {
            reason: "incorrect transfer code or not a valid backup".into(),
        })
    }

    /// Try decrypting SKESK-encrypted data with a single password.
    ///
    /// Uses PacketParser with `recurse()` to walk into the SEIP and
    /// CompressedData containers, letting Sequoia handle both decryption
    /// and decompression transparently through its streaming pipeline.
    fn try_decrypt_skesk_with_password(
        ciphertext: &[u8],
        password: &sequoia_openpgp::crypto::Password,
    ) -> Result<Vec<u8>> {
        use sequoia_openpgp::Packet;
        use sequoia_openpgp::parse::{PacketParser, PacketParserResult};

        let mut ppr = PacketParser::from_bytes(ciphertext).map_err(|e| Error::Decryption {
            reason: format!("invalid data: {e}"),
        })?;
        let mut session_key = None;
        let mut output = Vec::new();
        let mut inside_encrypted = false;

        while let PacketParserResult::Some(mut pp) = ppr {
            match &pp.packet {
                Packet::SKESK(skesk) => {
                    if let Ok((algo, sk)) = skesk.decrypt(password) {
                        session_key = Some((algo, sk));
                    }
                    ppr = pp
                        .next()
                        .map_err(|e| Error::Decryption {
                            reason: format!("parse error: {e}"),
                        })?
                        .1;
                }
                Packet::SEIP(_) => {
                    if let Some((algo, ref sk)) = session_key {
                        pp.decrypt(algo, sk).map_err(|e| Error::Decryption {
                            reason: format!("wrong key: {e}"),
                        })?;
                        inside_encrypted = true;
                        // Recurse INTO the decrypted container
                        ppr = pp
                            .recurse()
                            .map_err(|e| Error::Decryption {
                                reason: format!("parse error: {e}"),
                            })?
                            .1;
                    } else {
                        return Err(Error::Decryption {
                            reason: "no SKESK packet found".into(),
                        });
                    }
                }
                Packet::CompressedData(_) if inside_encrypted => {
                    // Recurse INTO the compressed container (Sequoia decompresses)
                    ppr = pp
                        .recurse()
                        .map_err(|e| Error::Decryption {
                            reason: format!("decompress error: {e}"),
                        })?
                        .1;
                }
                #[allow(deprecated)]
                Packet::MDC(_) => {
                    ppr = pp
                        .next()
                        .map_err(|e| Error::Decryption {
                            reason: format!("parse error: {e}"),
                        })?
                        .1;
                }
                Packet::Literal(_) if inside_encrypted => {
                    // Literal Data packet: extract just the body (cert bytes),
                    // not the Literal wrapper (format/filename/date).
                    pp.buffer_unread_content().map_err(|e| Error::Decryption {
                        reason: format!("read error: {e}"),
                    })?;
                    let (pkt, next_ppr) = pp.next().map_err(|e| Error::Decryption {
                        reason: format!("parse error: {e}"),
                    })?;
                    if let Packet::Literal(lit) = pkt {
                        output.extend_from_slice(lit.body());
                    }
                    ppr = next_ppr;
                }
                _ if inside_encrypted => {
                    // Other cert packets: buffer body and serialize as-is
                    pp.buffer_unread_content().map_err(|e| Error::Decryption {
                        reason: format!("read error: {e}"),
                    })?;
                    let (pkt, next_ppr) = pp.next().map_err(|e| Error::Decryption {
                        reason: format!("parse error: {e}"),
                    })?;
                    pkt.serialize(&mut output).map_err(|e| Error::Decryption {
                        reason: format!("serialize error: {e}"),
                    })?;
                    ppr = next_ppr;
                }
                _ => {
                    ppr = pp
                        .next()
                        .map_err(|e| Error::Decryption {
                            reason: format!("parse error: {e}"),
                        })?
                        .1;
                }
            }
        }

        if !inside_encrypted {
            return Err(Error::Decryption {
                reason: "no encrypted data found".into(),
            });
        }

        Ok(output)
    }
}

impl Default for SequoiaEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a Sequoia User ID component value into our UserId type.
fn parse_user_id(uid: &sequoia_openpgp::packet::UserID) -> UserId {
    // Sequoia gives us the raw User ID string, typically "Name <email>"
    let raw = String::from_utf8_lossy(uid.value()).to_string();

    // Try to extract email from angle brackets
    if let (Some(open), Some(close)) = (raw.rfind('<'), raw.rfind('>'))
        && open < close
    {
        let email = raw[open + 1..close].trim().to_string();
        let name = raw[..open].trim().to_string();
        return UserId {
            name: if name.is_empty() { None } else { Some(name) },
            email: if email.is_empty() { None } else { Some(email) },
        };
    }

    // If no angle brackets, check if it looks like an email
    if raw.contains('@') {
        UserId {
            name: None,
            email: Some(raw.trim().to_string()),
        }
    } else {
        UserId {
            name: Some(raw.trim().to_string()),
            email: None,
        }
    }
}

/// Map a Sequoia `PublicKeyAlgorithm` to our `KeyAlgorithm`.
fn map_algorithm(algo: PublicKeyAlgorithm, key_size: Option<usize>) -> KeyAlgorithm {
    match algo {
        PublicKeyAlgorithm::EdDSA => KeyAlgorithm::Ed25519,
        PublicKeyAlgorithm::RSAEncryptSign => KeyAlgorithm::Rsa(key_size.unwrap_or(4096) as u32),
        // ECDH/ECDSA with Curve25519 are part of the Ed25519 suite
        PublicKeyAlgorithm::ECDH | PublicKeyAlgorithm::ECDSA => KeyAlgorithm::Ed25519,
        _ => KeyAlgorithm::Ed25519,
    }
}

impl CryptoEngine for SequoiaEngine {
    fn generate_key_pair(&self, options: KeyGenOptions) -> Result<GeneratedKeyPair> {
        let user_id = options.user_id.to_openpgp_string();

        let mut builder = match options.algorithm {
            KeyAlgorithm::Ed25519 => CertBuilder::new()
                .add_userid(user_id)
                .set_cipher_suite(CipherSuite::Cv25519)
                .add_signing_subkey()
                .add_subkey(
                    KeyFlags::empty().set_transport_encryption(),
                    options.expiration,
                    None,
                ),
            KeyAlgorithm::Rsa(bits) => {
                let suite = match bits {
                    3072 => CipherSuite::RSA3k,
                    _ => CipherSuite::RSA4k,
                };
                CertBuilder::new()
                    .add_userid(user_id)
                    .set_cipher_suite(suite)
                    .add_signing_subkey()
                    .add_subkey(
                        KeyFlags::empty().set_transport_encryption(),
                        options.expiration,
                        None,
                    )
            }
        };

        if let Some(expiration) = options.expiration {
            builder = builder.set_validity_period(expiration);
        }

        if let Some(ref passphrase) = options.passphrase {
            builder = builder.set_password(Some(sequoia_openpgp::crypto::Password::from(
                passphrase.expose_secret().as_slice(),
            )));
        }

        let (cert, revocation) = builder.generate().map_err(|e| Error::KeyGeneration {
            reason: e.to_string(),
        })?;

        let fingerprint = Fingerprint::new(cert.fingerprint().to_hex());

        // Serialize public key (certificate)
        let mut public_key = Vec::new();
        {
            let mut writer = self
                .armor_writer_for_cert(
                    &mut public_key,
                    sequoia_openpgp::armor::Kind::PublicKey,
                    Some(&cert),
                )
                .map_err(|e| Error::KeyGeneration {
                    reason: format!("armor error: {e}"),
                })?;
            cert.serialize(&mut writer)
                .map_err(|e| Error::KeyGeneration {
                    reason: format!("serialize error: {e}"),
                })?;
            writer.finalize().map_err(|e| Error::KeyGeneration {
                reason: format!("finalize error: {e}"),
            })?;
        }

        // Serialize secret key
        let mut secret_key_bytes = Vec::new();
        {
            let mut writer = self
                .armor_writer(
                    &mut secret_key_bytes,
                    sequoia_openpgp::armor::Kind::SecretKey,
                )
                .map_err(|e| Error::KeyGeneration {
                    reason: format!("armor error: {e}"),
                })?;
            cert.as_tsk()
                .serialize(&mut writer)
                .map_err(|e| Error::KeyGeneration {
                    reason: format!("serialize error: {e}"),
                })?;
            writer.finalize().map_err(|e| Error::KeyGeneration {
                reason: format!("finalize error: {e}"),
            })?;
        }

        // Serialize revocation certificate (as a full revoked certificate)
        let mut revocation_cert = Vec::new();
        {
            let mut writer = self
                .armor_writer(
                    &mut revocation_cert,
                    sequoia_openpgp::armor::Kind::PublicKey,
                )
                .map_err(|e| Error::KeyGeneration {
                    reason: format!("armor error: {e}"),
                })?;

            // Merge revocation signature into the cert to create a full revoked certificate.
            // This is more widely compatible than a standalone signature packet.
            let (revoked_cert, _) = cert
                .clone()
                .insert_packets(vec![sequoia_openpgp::Packet::from(revocation)])
                .map_err(|e| Error::KeyGeneration {
                    reason: format!("failed to merge revocation: {e}"),
                })?;

            revoked_cert
                .serialize(&mut writer)
                .map_err(|e| Error::KeyGeneration {
                    reason: format!("revocation cert serialize error: {e}"),
                })?;
            writer.finalize().map_err(|e| Error::KeyGeneration {
                reason: format!("finalize error: {e}"),
            })?;
        }

        Ok(GeneratedKeyPair {
            public_key,
            secret_key: secrecy::SecretBox::new(Box::new(secret_key_bytes)),
            fingerprint,
            revocation_cert,
        })
    }

    fn encrypt(&self, plaintext: &[u8], recipient_keys: &[Vec<u8>]) -> Result<Vec<u8>> {
        if recipient_keys.is_empty() {
            return Err(Error::NoRecipients);
        }

        let certs: Vec<Cert> = recipient_keys
            .iter()
            .map(|key| {
                Cert::from_bytes(key).map_err(|e| Error::Encryption {
                    reason: format!("invalid recipient key: {e}"),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let mut recipients: Vec<Recipient> = Vec::new();
        for cert in &certs {
            let valid_cert =
                cert.with_policy(&self.policy, None)
                    .map_err(|e| Error::Encryption {
                        reason: format!("key policy check failed: {e}"),
                    })?;

            for key in valid_cert
                .keys()
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
                .for_storage_encryption()
            {
                recipients.push(key.into());
            }
        }

        if recipients.is_empty() {
            return Err(Error::Encryption {
                reason: "no valid encryption-capable subkeys found".into(),
            });
        }

        let mut output = Vec::new();
        {
            let mut armored_writer = self
                .armor_writer(&mut output, sequoia_openpgp::armor::Kind::Message)
                .map_err(|e| Error::Encryption {
                    reason: format!("armor error: {e}"),
                })?;

            let message = Message::new(&mut armored_writer);
            let message = Encryptor::for_recipients(message, recipients)
                .build()
                .map_err(|e| Error::Encryption {
                    reason: format!("encryptor error: {e}"),
                })?;
            let mut message =
                LiteralWriter::new(message)
                    .build()
                    .map_err(|e| Error::Encryption {
                        reason: format!("literal writer error: {e}"),
                    })?;

            message
                .write_all(plaintext)
                .map_err(|e| Error::Encryption {
                    reason: format!("write error: {e}"),
                })?;
            message.finalize().map_err(|e| Error::Encryption {
                reason: format!("finalize error: {e}"),
            })?;

            armored_writer.finalize().map_err(|e| Error::Encryption {
                reason: format!("armor finalize error: {e}"),
            })?;
        }

        Ok(output)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        secret_key: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let cert = Cert::from_bytes(secret_key).map_err(|e| Error::Decryption {
            reason: format!("invalid secret key: {e}"),
        })?;

        let helper = DecryptHelper {
            policy: &self.policy,
            cert,
            passphrase,
        };

        let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
            .map_err(|e| Error::Decryption {
                reason: format!("invalid ciphertext: {e}"),
            })?
            .with_policy(&self.policy, None, helper)
            .map_err(|e| Error::Decryption {
                reason: format!("decryption failed: {e}"),
            })?;

        let mut plaintext = Vec::new();
        std::io::copy(&mut decryptor, &mut plaintext).map_err(|e| Error::Decryption {
            reason: format!("read error: {e}"),
        })?;

        Ok(plaintext)
    }

    fn sign(&self, data: &[u8], secret_key: &[u8], passphrase: Option<&[u8]>) -> Result<Vec<u8>> {
        let cert = Cert::from_bytes(secret_key).map_err(|e| Error::Signing {
            reason: format!("invalid secret key: {e}"),
        })?;

        let valid_cert = cert
            .with_policy(&self.policy, None)
            .map_err(|e| Error::Signing {
                reason: format!("key policy check failed: {e}"),
            })?;

        // Find a signing-capable secret key
        let mut keypair = None;

        // Try unencrypted secret keys first
        if let Some(ka) = valid_cert
            .keys()
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .unencrypted_secret()
            .next()
        {
            keypair = Some(
                ka.key()
                    .clone()
                    .into_keypair()
                    .map_err(|e| Error::Signing {
                        reason: format!("keypair conversion failed: {e}"),
                    })?,
            );
        }

        // Try with passphrase
        if keypair.is_none()
            && let Some(passphrase) = passphrase
        {
            let password = sequoia_openpgp::crypto::Password::from(passphrase);
            for ka in valid_cert
                .keys()
                .supported()
                .alive()
                .revoked(false)
                .for_signing()
                .secret()
            {
                let key = ka.key().clone();
                if let Ok(decrypted) = key.decrypt_secret(&password)
                    && let Ok(kp) = decrypted.into_keypair()
                {
                    keypair = Some(kp);
                    break;
                }
            }
        }

        let signer_keypair = keypair.ok_or_else(|| Error::Signing {
            reason: "no signing-capable secret key found".into(),
        })?;

        let mut output = Vec::new();
        {
            let mut armored_writer = self
                .armor_writer(&mut output, sequoia_openpgp::armor::Kind::Message)
                .map_err(|e| Error::Signing {
                    reason: format!("armor error: {e}"),
                })?;

            let message = Message::new(&mut armored_writer);
            let message = Signer::new(message, signer_keypair)
                .map_err(|e| Error::Signing {
                    reason: format!("signer error: {e}"),
                })?
                .build()
                .map_err(|e| Error::Signing {
                    reason: format!("signer error: {e}"),
                })?;
            let mut message = LiteralWriter::new(message)
                .build()
                .map_err(|e| Error::Signing {
                    reason: format!("literal writer error: {e}"),
                })?;

            message.write_all(data).map_err(|e| Error::Signing {
                reason: format!("write error: {e}"),
            })?;
            message.finalize().map_err(|e| Error::Signing {
                reason: format!("finalize error: {e}"),
            })?;

            armored_writer.finalize().map_err(|e| Error::Signing {
                reason: format!("armor finalize error: {e}"),
            })?;
        }

        Ok(output)
    }

    fn verify(&self, signed_data: &[u8], signer_key: &[u8]) -> Result<VerifyResult> {
        let signer_cert = Cert::from_bytes(signer_key).map_err(|e| Error::VerificationFailed {
            reason: format!("invalid signer key: {e}"),
        })?;

        let signer_fp = signer_cert.fingerprint().to_hex();

        let helper = VerifyHelper {
            policy: &self.policy,
            cert: signer_cert,
            result: None,
        };

        let mut verifier = VerifierBuilder::from_bytes(signed_data)
            .map_err(|e| Error::VerificationFailed {
                reason: format!("invalid signed data: {e}"),
            })?
            .with_policy(&self.policy, None, helper)
            .map_err(|e| Error::VerificationFailed {
                reason: format!("verification setup failed: {e}"),
            })?;

        // Consume the verified content
        let mut content = Vec::new();
        std::io::copy(&mut verifier, &mut content).map_err(|e| Error::VerificationFailed {
            reason: format!("read error: {e}"),
        })?;

        let helper = verifier.into_helper();

        Ok(helper.result.unwrap_or(VerifyResult {
            valid: false,
            signer_fingerprint: Some(signer_fp),
        }))
    }

    fn inspect_key(&self, key_data: &[u8]) -> Result<CertInfo> {
        use sequoia_openpgp::cert::CertParser;

        // Use CertParser to handle both single certs and keyrings
        let cert = CertParser::from_bytes(key_data)
            .map_err(|e| Error::InvalidArmor {
                reason: e.to_string(),
            })?
            .next()
            .ok_or_else(|| Error::InvalidArmor {
                reason: "no certificate found".into(),
            })?
            .map_err(|e| Error::InvalidArmor {
                reason: e.to_string(),
            })?;

        let fingerprint = Fingerprint::new(cert.fingerprint().to_hex());

        // Extract User IDs
        let user_ids: Vec<UserId> = cert
            .userids()
            .map(|uid| parse_user_id(uid.userid()))
            .collect();

        // Determine algorithm from primary key
        let pk = cert.primary_key().key();
        let pk_algo = pk.pk_algo();
        let key_size = pk.mpis().bits();
        let algorithm = map_algorithm(pk_algo, key_size);

        // Creation time
        let created_at = {
            let ct = pk.creation_time();
            chrono::DateTime::<chrono::Utc>::from(ct).to_rfc3339()
        };

        // Expiration time
        let expires_at = cert
            .with_policy(&self.policy, None)
            .ok()
            .and_then(|valid_cert| valid_cert.primary_key().key_expiration_time())
            .map(|et| chrono::DateTime::<chrono::Utc>::from(et).to_rfc3339());

        // Check for secret key material
        let has_secret_key = cert.is_tsk();

        let is_revoked = cert
            .with_policy(&self.policy, None)
            .ok()
            .map(|valid_cert| {
                valid_cert.primary_key().revocation_status()
                    != sequoia_openpgp::types::RevocationStatus::NotAsFarAsWeKnow
            })
            .unwrap_or(false);

        // Extract subkey information
        let subkeys = cert
            .with_policy(&self.policy, None)
            .ok()
            .map(|valid_cert| {
                valid_cert
                    .keys()
                    .subkeys()
                    .map(|ka| {
                        let key = ka.key();
                        let sk_fp = key.fingerprint().to_hex();
                        let sk_algo = key.pk_algo();
                        let sk_size = key.mpis().bits();
                        let sk_algorithm = map_algorithm(sk_algo, sk_size);
                        let sk_created = {
                            let ct = key.creation_time();
                            chrono::DateTime::<chrono::Utc>::from(ct).to_rfc3339()
                        };
                        let sk_expires = ka
                            .key_expiration_time()
                            .map(|et| chrono::DateTime::<chrono::Utc>::from(et).to_rfc3339());

                        let mut capabilities = Vec::new();
                        if ka.for_signing() {
                            capabilities.push(KeyCapability::Sign);
                        }
                        if ka.for_transport_encryption() || ka.for_storage_encryption() {
                            capabilities.push(KeyCapability::Encrypt);
                        }
                        if ka.for_certification() {
                            capabilities.push(KeyCapability::Certify);
                        }
                        if ka.for_authentication() {
                            capabilities.push(KeyCapability::Authenticate);
                        }

                        let is_revoked = is_revoked
                            || (ka.revocation_status()
                                != sequoia_openpgp::types::RevocationStatus::NotAsFarAsWeKnow);

                        SubkeyInfo {
                            fingerprint: sk_fp,
                            algorithm: sk_algorithm.to_string(),
                            created_at: sk_created,
                            expires_at: sk_expires,
                            capabilities,
                            is_revoked,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(CertInfo {
            fingerprint,
            user_ids,
            algorithm,
            created_at,
            expires_at,
            has_secret_key,
            is_revoked,
            subkeys,
        })
    }

    fn encrypt_symmetric(&self, plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
        use sequoia_openpgp::crypto::Password;

        let mut output = Vec::new();
        {
            let message = Message::new(&mut output);
            let encryptor = Encryptor::with_passwords(message, Some(Password::from(passphrase)))
                .build()
                .map_err(|e| Error::Encryption {
                    reason: e.to_string(),
                })?;

            let mut literal =
                LiteralWriter::new(encryptor)
                    .build()
                    .map_err(|e| Error::Encryption {
                        reason: e.to_string(),
                    })?;
            literal
                .write_all(plaintext)
                .map_err(|e| Error::Encryption {
                    reason: e.to_string(),
                })?;
            literal.finalize().map_err(|e| Error::Encryption {
                reason: e.to_string(),
            })?;
        }

        Ok(output)
    }

    fn armor_key(&self, key_data: &[u8]) -> Result<String> {
        let cert = Cert::from_bytes(key_data).map_err(|e| Error::InvalidArmor {
            reason: e.to_string(),
        })?;

        let mut armored = Vec::new();
        let kind = if cert.is_tsk() {
            sequoia_openpgp::armor::Kind::SecretKey
        } else {
            sequoia_openpgp::armor::Kind::PublicKey
        };

        {
            let mut writer =
                self.armor_writer(&mut armored, kind)
                    .map_err(|e| Error::InvalidArmor {
                        reason: e.to_string(),
                    })?;
            cert.serialize(&mut writer)
                .map_err(|e| Error::InvalidArmor {
                    reason: e.to_string(),
                })?;
        }

        String::from_utf8(armored).map_err(|e| Error::InvalidArmor {
            reason: format!("Internal UTF-8 error: {e}"),
        })
    }
}

/// Public key bytes from an import, with secret material kept separate.
///
/// `pgp_data` is safe to store and export as a public key. `secret_key` is
/// set when the input contained a private key block or secret packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedKeyMaterial {
    /// ASCII-armored public key. Does not contain a private key block.
    pub pgp_data: Vec<u8>,
    /// Armored secret key, when the import included secret material.
    pub secret_key: Option<Vec<u8>>,
}

impl SequoiaEngine {
    /// Return public-key armor for `pgp_data`.
    ///
    /// ASCII-armored public key material is returned unchanged when it has a
    /// public key block, no private key block, and no secret packets. A
    /// following private key block is removed. Binary OpenPGP keys, and secret
    /// keys with no separate public block, are re-armored as a public
    /// certificate. Binary packet bytes are never passed through lossy UTF-8
    /// conversion.
    pub fn export_public_key_text(&self, pgp_data: &[u8]) -> Result<String> {
        let text = std::str::from_utf8(pgp_data).ok();
        let public_blocks = text.map(armor::public_key_blocks).unwrap_or_default();
        let private_header = text.is_some_and(|_| armor::is_pgp_private_key(pgp_data));
        let secret_packets = self
            .read_certs(pgp_data)
            .unwrap_or_default()
            .iter()
            .any(|cert| cert.is_tsk());
        if let Some(text) = text
            && !public_blocks.is_empty()
            && !private_header
            && !secret_packets
        {
            return Ok(text.to_owned());
        }

        let bytes = self.public_only_bytes(pgp_data, &public_blocks)?;
        String::from_utf8(bytes).map_err(|e| Error::InvalidArmor {
            reason: format!("public key is not valid UTF-8: {e}"),
        })
    }

    /// Split imported armor into public key bytes and an optional secret key.
    ///
    /// The public half never includes a private key block. A file that starts
    /// with a public key and continues with a private key still reports the
    /// secret half, even though parsing only the first certificate does not.
    pub fn split_imported_key(&self, key_data: &[u8]) -> Result<ImportedKeyMaterial> {
        let text = std::str::from_utf8(key_data).unwrap_or("");
        let private_blocks = armor::private_key_blocks(text);
        let public_blocks = armor::public_key_blocks(text);
        let certs = self.read_certs(key_data).unwrap_or_default();
        let secret_packets = certs.iter().any(|cert| cert.is_tsk());
        let has_secret = secret_packets || !private_blocks.is_empty();

        if !has_secret {
            return Ok(ImportedKeyMaterial {
                pgp_data: key_data.to_vec(),
                secret_key: None,
            });
        }

        let pgp_data = self.public_only_bytes(key_data, &public_blocks)?;
        let secret_key = if !private_blocks.is_empty() {
            private_blocks.into_bytes()
        } else {
            key_data.to_vec()
        };
        Ok(ImportedKeyMaterial {
            pgp_data,
            secret_key: Some(secret_key),
        })
    }

    fn read_certs(&self, data: &[u8]) -> Result<Vec<Cert>> {
        use sequoia_openpgp::cert::CertParser;

        let certs = CertParser::from_bytes(data)
            .map_err(|e| Error::InvalidArmor {
                reason: e.to_string(),
            })?
            .filter_map(std::result::Result::ok)
            .collect();
        Ok(certs)
    }

    /// Armor `certs` as public keys. Secret packets are omitted.
    fn armor_public_certs(&self, certs: &[Cert]) -> Result<String> {
        if certs.is_empty() {
            return Err(Error::InvalidArmor {
                reason: "no certificate found".into(),
            });
        }

        let mut armored = String::new();
        for cert in certs {
            if !armored.is_empty() && !armored.ends_with('\n') {
                armored.push('\n');
            }
            let mut buffer = Vec::new();
            {
                let mut writer = self
                    .armor_writer(&mut buffer, sequoia_openpgp::armor::Kind::PublicKey)
                    .map_err(|e| Error::InvalidArmor {
                        reason: format!("armor error: {e}"),
                    })?;
                cert.serialize(&mut writer)
                    .map_err(|e| Error::InvalidArmor {
                        reason: format!("serialize error: {e}"),
                    })?;
                writer.finalize().map_err(|e| Error::InvalidArmor {
                    reason: format!("armor finalize error: {e}"),
                })?;
            }
            let text = String::from_utf8(buffer).map_err(|e| Error::InvalidArmor {
                reason: format!("public key is not valid UTF-8: {e}"),
            })?;
            armored.push_str(&text);
        }
        Ok(armored)
    }

    fn public_only_bytes(&self, original: &[u8], public_blocks: &str) -> Result<Vec<u8>> {
        if !public_blocks.is_empty() && !armor::is_pgp_private_key(public_blocks.as_bytes()) {
            let contains_secret = self
                .read_certs(public_blocks.as_bytes())
                .map(|parsed| parsed.iter().any(|cert| cert.is_tsk()))
                .unwrap_or(false);
            if !contains_secret {
                return Ok(public_blocks.as_bytes().to_vec());
            }
        }

        let certs = self.read_certs(original)?;
        let armored = self.armor_public_certs(&certs)?;
        if armor::is_pgp_private_key(armored.as_bytes()) {
            return Err(Error::InvalidArmor {
                reason: "refusing to export a private key block as a public key".into(),
            });
        }
        Ok(armored.into_bytes())
    }
}

/// Helper struct for the Sequoia decryption streaming API.
struct DecryptHelper<'a> {
    policy: &'a StandardPolicy<'static>,
    cert: Cert,
    passphrase: Option<&'a [u8]>,
}

impl VerificationHelper for DecryptHelper<'_> {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        // NOTE: During decryption, we intentionally do not verify signatures
        // because the signer's certificate is not available in this context.
        // Signature verification should be performed separately via the
        // `verify()` method after decryption, using the signer's public key.
        //
        // We iterate the structure to acknowledge any signatures present,
        // but do not treat unverifiable signatures as errors.
        for layer in structure {
            match layer {
                MessageLayer::SignatureGroup { .. }
                | MessageLayer::Compression { .. }
                | MessageLayer::Encryption { .. } => {}
            }
        }
        Ok(())
    }
}

impl DecryptionHelper for DecryptHelper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[sequoia_openpgp::packet::PKESK],
        _skesks: &[sequoia_openpgp::packet::SKESK],
        sym_algo: Option<sequoia_openpgp::types::SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(
            Option<sequoia_openpgp::types::SymmetricAlgorithm>,
            &SessionKey,
        ) -> bool,
    ) -> sequoia_openpgp::Result<Option<Cert>> {
        let valid_cert = self.cert.with_policy(self.policy, None)?;

        // Try unencrypted secret keys first
        for ka in valid_cert
            .keys()
            .supported()
            .unencrypted_secret()
            .for_transport_encryption()
            .for_storage_encryption()
        {
            let mut keypair = ka.key().clone().into_keypair()?;
            for pkesk in pkesks {
                if pkesk
                    .decrypt(&mut keypair, sym_algo)
                    .map(|(algo, sk)| decrypt(algo, &sk))
                    .unwrap_or(false)
                {
                    return Ok(None);
                }
            }
        }

        // Try with passphrase-decrypted keys
        if let Some(passphrase) = self.passphrase {
            let password = sequoia_openpgp::crypto::Password::from(passphrase);

            for ka in valid_cert
                .keys()
                .supported()
                .secret()
                .for_transport_encryption()
                .for_storage_encryption()
            {
                let key = ka.key().clone();
                if let Ok(decrypted) = key.decrypt_secret(&password)
                    && let Ok(mut keypair) = decrypted.into_keypair()
                {
                    for pkesk in pkesks {
                        if pkesk
                            .decrypt(&mut keypair, sym_algo)
                            .map(|(algo, sk)| decrypt(algo, &sk))
                            .unwrap_or(false)
                        {
                            return Ok(None);
                        }
                    }
                }
            }
        }

        Err(
            sequoia_openpgp::Error::MissingSessionKey("no suitable decryption key found".into())
                .into(),
        )
    }
}

/// Helper struct for the Sequoia signature verification streaming API.
struct VerifyHelper<'a> {
    #[allow(dead_code)]
    policy: &'a StandardPolicy<'static>,
    cert: Cert,
    result: Option<VerifyResult>,
}

impl VerificationHelper for VerifyHelper<'_> {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                if let Some(GoodChecksum { ka, .. }) = results.iter().flatten().next() {
                    self.result = Some(VerifyResult {
                        valid: true,
                        signer_fingerprint: Some(ka.cert().fingerprint().to_hex()),
                    });
                    return Ok(());
                }
                // No good signature found
                self.result = Some(VerifyResult {
                    valid: false,
                    signer_fingerprint: Some(self.cert.fingerprint().to_hex()),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{KeyGenOptions, UserId};

    /// Return the armor header lines between the BEGIN line and the blank separator.
    fn armor_header_lines(armored: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(armored)
            .lines()
            .skip(1)
            .take_while(|l| !l.is_empty())
            .map(String::from)
            .collect()
    }

    #[test]
    fn test_armor_headers_default_to_none() {
        let engine = SequoiaEngine::new();
        let key_pair = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new("A", "a@example.com")))
            .unwrap();
        let ciphertext = engine
            .encrypt(b"hi", std::slice::from_ref(&key_pair.public_key))
            .unwrap();

        assert!(armor_header_lines(&key_pair.public_key).is_empty());
        assert!(armor_header_lines(&ciphertext).is_empty());
    }

    #[test]
    fn test_armor_headers_custom_comment_and_version() {
        let engine = SequoiaEngine::with_armor_headers(ArmorHeaders {
            version: true,
            comment: Some("Sent from my laptop".into()),
            key_info: false,
        })
        .unwrap();
        let key_pair = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new("A", "a@example.com")))
            .unwrap();
        let ciphertext = engine
            .encrypt(b"hi", std::slice::from_ref(&key_pair.public_key))
            .unwrap();

        assert_eq!(
            armor_header_lines(&ciphertext),
            vec![
                concat!("Version: KeychainPGP ", env!("CARGO_PKG_VERSION")).to_string(),
                "Comment: Sent from my laptop".to_string(),
            ]
        );
    }

    #[test]
    fn test_armor_headers_key_info_only_on_public_keys() {
        let engine = SequoiaEngine::with_armor_headers(ArmorHeaders {
            key_info: true,
            ..ArmorHeaders::default()
        })
        .unwrap();
        let key_pair = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new("A", "a@example.com")))
            .unwrap();
        let ciphertext = engine
            .encrypt(b"hi", std::slice::from_ref(&key_pair.public_key))
            .unwrap();

        assert_eq!(
            armor_header_lines(&key_pair.public_key),
            vec![
                "Comment: A <a@example.com>".to_string(),
                format!("Fingerprint: {}", key_pair.fingerprint.0),
            ]
        );
        assert!(armor_header_lines(&ciphertext).is_empty());
    }

    #[test]
    fn test_armor_headers_reject_unsafe_comments() {
        let engine = SequoiaEngine::new();
        for comment in [
            "line\nVersion: injected",
            "carriage\rreturn",
            "   ",
            &"x".repeat(crate::types::MAX_ARMOR_COMMENT_LEN + 1),
        ] {
            let result = engine.set_armor_headers(ArmorHeaders {
                comment: Some(comment.to_string()),
                ..ArmorHeaders::default()
            });
            assert!(
                matches!(result, Err(Error::InvalidArmorHeader { .. })),
                "accepted {comment:?}"
            );
        }
        let key_pair = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new("A", "a@example.com")))
            .unwrap();
        assert!(armor_header_lines(&key_pair.public_key).is_empty());
    }

    #[test]
    fn test_generate_ed25519_key_pair() {
        let engine = SequoiaEngine::new();
        let options = KeyGenOptions::new(UserId::new("Test User", "test@example.com"));
        let result = engine.generate_key_pair(options);
        assert!(result.is_ok());

        let key_pair = result.unwrap();
        assert!(!key_pair.public_key.is_empty());
        assert!(!key_pair.fingerprint.0.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let engine = SequoiaEngine::new();

        let options = KeyGenOptions::new(UserId::new("Recipient", "recipient@example.com"));
        let key_pair = engine.generate_key_pair(options).unwrap();

        let plaintext = b"Hello, this is a secret message!";
        let ciphertext = engine
            .encrypt(plaintext, std::slice::from_ref(&key_pair.public_key))
            .unwrap();

        assert!(!ciphertext.is_empty());
        assert!(String::from_utf8_lossy(&ciphertext).contains("BEGIN PGP MESSAGE"));

        let decrypted = engine
            .decrypt(&ciphertext, key_pair.secret_key.expose_secret(), None)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_multiple_recipients() {
        let engine = SequoiaEngine::new();

        let kp1 = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Alice",
                "alice@example.com",
            )))
            .unwrap();
        let kp2 = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new("Bob", "bob@example.com")))
            .unwrap();

        let plaintext = b"Message for both Alice and Bob";
        let ciphertext = engine
            .encrypt(plaintext, &[kp1.public_key.clone(), kp2.public_key.clone()])
            .unwrap();

        // Both recipients should be able to decrypt
        let dec1 = engine
            .decrypt(&ciphertext, kp1.secret_key.expose_secret(), None)
            .unwrap();
        assert_eq!(dec1, plaintext);

        let dec2 = engine
            .decrypt(&ciphertext, kp2.secret_key.expose_secret(), None)
            .unwrap();
        assert_eq!(dec2, plaintext);
    }

    #[test]
    fn test_encrypt_no_recipients_fails() {
        let engine = SequoiaEngine::new();
        let result = engine.encrypt(b"hello", &[]);
        assert!(matches!(result, Err(Error::NoRecipients)));
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let engine = SequoiaEngine::new();

        let sender = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Sender",
                "sender@example.com",
            )))
            .unwrap();
        let wrong = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Wrong",
                "wrong@example.com",
            )))
            .unwrap();

        let ciphertext = engine
            .encrypt(b"secret", std::slice::from_ref(&sender.public_key))
            .unwrap();

        let result = engine.decrypt(&ciphertext, wrong.secret_key.expose_secret(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_and_verify() {
        let engine = SequoiaEngine::new();

        let kp = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Signer",
                "signer@example.com",
            )))
            .unwrap();

        let data = b"This message is signed by me.";
        let signed = engine
            .sign(data, kp.secret_key.expose_secret(), None)
            .unwrap();

        assert!(!signed.is_empty());
        assert!(String::from_utf8_lossy(&signed).contains("BEGIN PGP MESSAGE"));

        let result = engine.verify(&signed, &kp.public_key).unwrap();
        assert!(result.valid);
        assert!(result.signer_fingerprint.is_some());
    }

    #[test]
    fn test_verify_tampered_fails() {
        let engine = SequoiaEngine::new();

        let kp = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Signer",
                "signer@example.com",
            )))
            .unwrap();
        let wrong = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Other",
                "other@example.com",
            )))
            .unwrap();

        let signed = engine
            .sign(b"authentic", kp.secret_key.expose_secret(), None)
            .unwrap();

        // Verify with the wrong key should show invalid
        let result = engine.verify(&signed, &wrong.public_key);
        // This either errors out or returns valid=false
        if let Ok(r) = result {
            assert!(!r.valid);
        }
    }

    #[test]
    fn test_inspect_key() {
        let engine = SequoiaEngine::new();

        let kp = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Alice Johnson",
                "alice@example.com",
            )))
            .unwrap();

        // Inspect public key
        let info = engine.inspect_key(&kp.public_key).unwrap();
        assert_eq!(info.fingerprint.0, kp.fingerprint.0);
        assert_eq!(info.name(), Some("Alice Johnson"));
        assert_eq!(info.email(), Some("alice@example.com"));
        assert!(!info.has_secret_key);
        assert!(!info.created_at.is_empty());

        // Inspect secret key
        let secret_info = engine.inspect_key(kp.secret_key.expose_secret()).unwrap();
        assert!(secret_info.has_secret_key);
        assert_eq!(secret_info.fingerprint.0, kp.fingerprint.0);
    }

    #[test]
    fn test_inspect_key_extracts_expiration() {
        let engine = SequoiaEngine::new();

        let kp = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Expiry Test",
                "exp@test.com",
            )))
            .unwrap();

        let info = engine.inspect_key(&kp.public_key).unwrap();
        // Default key gen has 2-year expiration
        assert!(info.expires_at.is_some());
    }

    #[test]
    fn test_key_fingerprint() {
        let engine = SequoiaEngine::new();
        let options = KeyGenOptions::new(UserId::new("Test", "test@test.com"));
        let key_pair = engine.generate_key_pair(options).unwrap();

        let info = engine.inspect_key(&key_pair.public_key).unwrap();
        assert_eq!(info.fingerprint.0, key_pair.fingerprint.0);
    }

    #[test]
    fn test_decrypt_skesk_round_trip() {
        use sequoia_openpgp::crypto::Password;
        use sequoia_openpgp::serialize::stream::{Encryptor, Message};

        let engine = SequoiaEngine::new();
        let password = "123456789012345678901234567890123456";

        // Generate a test cert to use as backup payload
        let options = KeyGenOptions::new(UserId::new("Backup Test", "backup@test.com"));
        let key_pair = engine.generate_key_pair(options).unwrap();
        let cert = Cert::from_bytes(&key_pair.public_key).unwrap();
        let cert_binary = {
            let mut buf = Vec::new();
            cert.as_tsk().serialize(&mut buf).unwrap();
            buf
        };

        // Create a SKESK-encrypted message with raw cert data (no LiteralWriter),
        // mimicking OpenKeychain's backup format.
        let mut ciphertext = Vec::new();
        {
            let message = Message::new(&mut ciphertext);
            let mut encryptor =
                Encryptor::with_passwords(message, Some(Password::from(password.as_bytes())))
                    .build()
                    .unwrap();
            encryptor.write_all(&cert_binary).unwrap();
            encryptor.finalize().unwrap();
        }

        // Decrypt and verify the cert data round-trips correctly
        let decrypted = engine.decrypt_skesk(&ciphertext, password).unwrap();
        let certs = engine.parse_backup_certs(&decrypted).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].2.fingerprint.0, key_pair.fingerprint.0);
    }

    #[test]
    fn test_decrypt_openkeychain_backup() {
        let engine = SequoiaEngine::new();
        let backup_data = include_bytes!("../testdata/export_openkeychain.sec.pgp");
        let transfer_code = "6306-7060-1630-4222-8547-1679-5977-5194-8485";

        // Decrypt the SKESK-encrypted backup
        let decrypted = engine
            .decrypt_skesk(backup_data, transfer_code)
            .expect("decryption should succeed with the correct transfer code");
        assert!(!decrypted.is_empty(), "decrypted data should not be empty");

        // Parse certs from decrypted data
        let certs = engine
            .parse_backup_certs(&decrypted)
            .expect("should parse at least one cert from the backup");
        assert!(!certs.is_empty(), "should find at least one key");

        // Each cert should have a fingerprint
        for (public_bytes, secret_bytes, info) in &certs {
            assert!(!info.fingerprint.0.is_empty());
            assert!(!public_bytes.is_empty());
            assert!(!secret_bytes.is_empty());
        }
    }

    #[test]
    fn test_decrypt_skesk_wrong_password() {
        use sequoia_openpgp::crypto::Password;
        use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};

        let engine = SequoiaEngine::new();

        let mut ciphertext = Vec::new();
        {
            let message = Message::new(&mut ciphertext);
            let message = Encryptor::with_passwords(
                message,
                Some(Password::from("correct-password".as_bytes())),
            )
            .build()
            .unwrap();
            let mut writer = LiteralWriter::new(message).build().unwrap();
            writer.write_all(b"secret").unwrap();
            writer.finalize().unwrap();
        }

        let result = engine.decrypt_skesk(&ciphertext, "wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_symmetric_round_trip() {
        let engine = SequoiaEngine::new();
        let plaintext = b"Hello from KeychainPGP sync!";
        let passphrase = b"test-passphrase-1234";

        let encrypted = engine
            .encrypt_symmetric(plaintext, passphrase)
            .expect("symmetric encryption should succeed");
        assert!(!encrypted.is_empty());

        let decrypted = engine
            .decrypt_skesk(&encrypted, "test-passphrase-1234")
            .expect("decryption should succeed with same passphrase");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn export_strips_a_private_key_block_that_follows_the_public_key() {
        use secrecy::ExposeSecret;

        let engine = SequoiaEngine::new();
        let key_pair = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Combined",
                "combined@example.com",
            )))
            .unwrap();
        let public_key = String::from_utf8(key_pair.public_key.clone()).unwrap();
        let secret_key = String::from_utf8(key_pair.secret_key.expose_secret().clone()).unwrap();
        assert!(public_key.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(secret_key.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));

        let combined = format!("{public_key}\n{secret_key}");
        // The first certificate is the public block, so inspection does not
        // report the private key that follows it.
        let inspected = engine.inspect_key(combined.as_bytes()).unwrap();
        assert!(!inspected.has_secret_key);
        assert_eq!(inspected.fingerprint.0, key_pair.fingerprint.0);

        let exported = engine.export_public_key_text(combined.as_bytes()).unwrap();
        assert!(exported.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(!exported.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assert!(!exported.contains("PRIVATE KEY"));

        let material = engine.split_imported_key(combined.as_bytes()).unwrap();
        let stored = String::from_utf8(material.pgp_data.clone()).unwrap();
        assert!(!stored.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assert!(stored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        let secret = String::from_utf8(material.secret_key.unwrap()).unwrap();
        assert!(secret.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assert!(!secret.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        let ciphertext = engine.encrypt(b"hello", &[material.pgp_data]).unwrap();
        let decrypted = engine
            .decrypt(&ciphertext, secret.as_bytes(), None)
            .unwrap();
        assert_eq!(decrypted, b"hello");
    }

    #[test]
    fn export_of_a_public_key_is_unchanged() {
        let engine = SequoiaEngine::new();
        let key_pair = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Public Only",
                "public@example.com",
            )))
            .unwrap();
        let exported = engine.export_public_key_text(&key_pair.public_key).unwrap();
        assert_eq!(exported.as_bytes(), key_pair.public_key.as_slice());
    }

    #[test]
    fn export_of_a_binary_public_key_is_rearmored() {
        use sequoia_openpgp::serialize::MarshalInto;

        let engine = SequoiaEngine::new();
        let key_pair = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Binary Public",
                "binary@example.com",
            )))
            .unwrap();
        let cert = Cert::from_bytes(&key_pair.public_key).unwrap();
        let binary = cert.to_vec().unwrap();
        assert!(
            std::str::from_utf8(&binary).is_err() || !armor::is_pgp_public_key(&binary),
            "fixture should be a binary certificate, not ASCII armor"
        );

        let exported = engine.export_public_key_text(&binary).unwrap();
        assert!(exported.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(
            !exported.contains('\u{FFFD}'),
            "binary packet bytes must not be replaced with U+FFFD"
        );
        let info = engine.inspect_key(exported.as_bytes()).unwrap();
        assert_eq!(info.fingerprint.0, key_pair.fingerprint.0);
        assert!(!info.has_secret_key);

        let ciphertext = engine
            .encrypt(b"hello", &[exported.clone().into_bytes()])
            .unwrap();
        let decrypted = engine
            .decrypt(&ciphertext, key_pair.secret_key.expose_secret(), None)
            .unwrap();
        assert_eq!(decrypted, b"hello");

        let signed = engine
            .sign(b"signed", key_pair.secret_key.expose_secret(), None)
            .unwrap();
        let verified = engine.verify(&signed, exported.as_bytes()).unwrap();
        assert!(verified.valid);
    }

    #[test]
    fn export_of_a_secret_key_is_a_public_certificate() {
        use secrecy::ExposeSecret;

        let engine = SequoiaEngine::new();
        let key_pair = engine
            .generate_key_pair(KeyGenOptions::new(UserId::new(
                "Secret Only",
                "secret@example.com",
            )))
            .unwrap();
        let exported = engine
            .export_public_key_text(key_pair.secret_key.expose_secret())
            .unwrap();
        assert!(exported.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(!exported.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        let info = engine.inspect_key(exported.as_bytes()).unwrap();
        assert!(!info.has_secret_key);
        assert_eq!(info.fingerprint.0, key_pair.fingerprint.0);
    }
}
