//! Loading private keys and producing TLS handshake signatures.

use std::{fmt::Formatter, sync::Arc};

use rustls::{
    Error, SignatureAlgorithm, SignatureScheme,
    pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer},
    sign::{Signer, SigningKey},
};

use crate::secure_random;

#[derive(Debug)]
pub(crate) struct BotanKeyProvider;

impl rustls::crypto::KeyProvider for BotanKeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        any_supported_type(&key_der)
    }
}

/// Parse a given `PrivateKeyDer` as any supported key type (RSA, ECDSA P-256/P-384, Ed25519)
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    let key = match der {
        PrivateKeyDer::Pkcs8(pkcs8) => botan::Privkey::load_der(pkcs8.secret_pkcs8_der())
            .map_err(|e| Error::General(format!("failed to parse PKCS#8 private key: {e}")))?,
        PrivateKeyDer::Pkcs1(pkcs1) => botan::Privkey::load_rsa_pkcs1(pkcs1.secret_pkcs1_der())
            .map_err(|e| Error::General(format!("failed to parse PKCS#1 RSA private key: {e}")))?,
        PrivateKeyDer::Sec1(sec1) => {
            return Err(Error::General(
                "SEC1 EC private keys are no longer supported directly; \
                convert to PKCS#8 before loading"
                    .into(),
            ));
        }
        _ => return Err(Error::General("unsupported private key encoding".into())),
    };

    let algo = key
        .algo_name()
        .map_err(|e| Error::General(format!("cannot determine key algorithm: {e}")))?;
    let pubkey = key
        .pubkey()
        .map_err(|e| Error::General(format!("cannot extract public key: {e}")))?;

    let kind = match algo.as_str() {
        "RSA" => KeyKind::Rsa,
        "ECDSA" => {
            // Uncompressed SEC1 point
            // We need to differentiase between P256 and P384
            match pubkey.ec_public_point().map(|p| p.len()) {
                // 65 bytes: 1 + 2 * fieldsize (32 bytes, 256 bits)
                Ok(65) => KeyKind::EcdsaP256,
                // 97 bytes: 1 + 2 * fieldsize (48 bytes, 384 bits)
                Ok(97) => KeyKind::EcdsaP384,
                _ => {
                    return Err(Error::General(
                        "unsupported ECDSA curve (expected either P-256 or P-384)".into(),
                    ));
                }
            }
        }
        "Ed25519" => KeyKind::Ed25519,
        other => {
            return Err(Error::General(format!(
                "unsupported private key algorithm {other}"
            )));
        }
    };

    let spki = pubkey
        .der_encode()
        .map_err(|e| Error::General(format!("cannot encode SubjectPublicKeyInfo: {e}")))?;

    Ok(Arc::new(BotanSigningKey {
        key: Arc::new(key),
        kind,
        spki,
    }))
}

#[derive(Clone, Copy, Debug)]
enum KeyKind {
    Rsa,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
}

struct BotanSigningKey {
    key: Arc<botan::Privkey>,
    kind: KeyKind,
    /// Cached SPKI (SubjectPublicKeyInfo) so rustls can check the key matches the certificate.
    spki: Vec<u8>,
}

impl SigningKey for BotanSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let ours: &[SignatureScheme] = match self.kind {
            // Order of preference of RSA schemes that are offered.
            KeyKind::Rsa => &[
                // PSS is required by TLS 1.3
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                // PKCS#1 required by TLS 1.2
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA256,
            ],
            KeyKind::EcdsaP256 => &[SignatureScheme::ECDSA_NISTP256_SHA256],
            KeyKind::EcdsaP384 => &[SignatureScheme::ECDSA_NISTP384_SHA384],
            KeyKind::Ed25519 => &[SignatureScheme::ED25519],
        };

        ours.iter()
            .find(|scheme| offered.contains(scheme))
            .map(|&scheme| {
                Box::new(BotanSigner {
                    key: self.key.clone(),
                    scheme,
                }) as Box<dyn Signer>
            })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(&self.spki[..]))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.kind {
            KeyKind::Rsa => SignatureAlgorithm::RSA,
            KeyKind::EcdsaP256 | KeyKind::EcdsaP384 => SignatureAlgorithm::ECDSA,
            KeyKind::Ed25519 => SignatureAlgorithm::ED25519,
        }
    }
}

impl std::fmt::Debug for BotanSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BotanSigningKey")
            .field("kind", &self.kind)
            .finish()
    }
}

struct BotanSigner {
    key: Arc<botan::Privkey>,
    scheme: SignatureScheme,
}

impl Signer for BotanSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // padding name, and flag which signals if signature needs DER encoding
        let (padding, der) = match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => ("PKCS1v15(SHA-256)", false),
            SignatureScheme::RSA_PKCS1_SHA384 => ("PKCS1v15(SHA-384)", false),
            SignatureScheme::RSA_PKCS1_SHA512 => ("PKCS1v15(SHA-512)", false),
            SignatureScheme::RSA_PSS_SHA256 => ("PSS(SHA-256)", false),
            SignatureScheme::RSA_PSS_SHA384 => ("PSS(SHA-384)", false),
            SignatureScheme::RSA_PSS_SHA512 => ("PSS(SHA-512)", false),
            SignatureScheme::ECDSA_NISTP256_SHA256 => ("EMSA1(SHA-256)", true),
            SignatureScheme::ECDSA_NISTP384_SHA384 => ("EMSA1(SHA-384)", true),
            SignatureScheme::ED25519 => ("Pure", false),
            _ => return Err(Error::General("unsupported signature scheme".into())),
        };

        let mut signer = match der {
            true => botan::Signer::new_with_der_formatted_signatures(&self.key, padding),
            false => botan::Signer::new(&self.key, padding),
        }
        .map_err(|e| Error::General(format!("botan signer init failed: {e}")))?;

        signer
            .update(message)
            .map_err(|e| Error::General(format!("signing failed: {e}")))?;
        secure_random::do_with_thread_local_rng(|rng| {
            signer
                .finish(rng)
                .map_err(|e| Error::General(format!("signing failed: {e}")))
        })
        .map_err(|e| Error::General(format!("Error getting randomness")))?
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl std::fmt::Debug for BotanSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BotanSigner")
            .field("scheme", &self.scheme)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

    fn pkcs8_der(algo: &str, params: &str) -> Vec<u8> {
        let mut rng = botan::RandomNumberGenerator::new().unwrap();
        let key = botan::Privkey::create(algo, params, &mut rng).unwrap();
        key.der_encode().unwrap()
    }

    #[test]
    fn loads_supported_key_types() {
        for (algo, params) in [
            ("RSA", "2048"),
            ("ECDSA", "secp256r1"),
            ("ECDSA", "secp384r1"),
            ("Ed25519", ""),
        ] {
            let der = pkcs8_der(algo, params);
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der));
            any_supported_type(&key)
                .unwrap_or_else(|e| panic!("failed to load {algo} {params}: {e:?}"));
        }
    }

    #[test]
    fn rejects_sec1_ec_keys() {
        let key = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(vec![0u8; 32]));
        assert!(any_supported_type(&key).is_err());
    }

    #[test]
    fn rejects_garbage_pkcs8() {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0u8; 16]));
        assert!(any_supported_type(&key).is_err());
    }

    /// Full round trip, sign and verify using botan
    #[test]
    fn sign_and_verify_round_trip() {
        // (algo, params, scheme rustls would offer for this key type)
        let cases = [
            ("RSA", "2048", SignatureScheme::RSA_PSS_SHA256),
            ("RSA", "2048", SignatureScheme::RSA_PKCS1_SHA256),
            ("ECDSA", "secp256r1", SignatureScheme::ECDSA_NISTP256_SHA256),
            ("ECDSA", "secp384r1", SignatureScheme::ECDSA_NISTP384_SHA384),
            ("Ed25519", "", SignatureScheme::ED25519),
        ];

        let message = b"the quick brown fox jumps over the lazy dog";

        for (algo, params, scheme) in cases {
            let der = pkcs8_der(algo, params);
            let signing_key =
                any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
                    .unwrap_or_else(|e| panic!("load {algo} {params}: {e:?}"));

            let signer = signing_key
                .choose_scheme(&[scheme])
                .unwrap_or_else(|| panic!("{algo} did not offer {scheme:?}"));
            assert_eq!(signer.scheme(), scheme);

            let signature = signer
                .sign(message)
                .unwrap_or_else(|e| panic!("sign {algo} {scheme:?}: {e:?}"));

            // verify with Botan
            let spki = signing_key.public_key().expect("SPKI available");
            let pubkey = botan::Pubkey::load_der(spki.as_ref()).expect("load SPKI");
            let (padding, der_sig) = match scheme {
                SignatureScheme::RSA_PKCS1_SHA256 => ("PKCS1v15(SHA-256)", false),
                SignatureScheme::RSA_PKCS1_SHA384 => ("PKCS1v15(SHA-384)", false),
                SignatureScheme::RSA_PKCS1_SHA512 => ("PKCS1v15(SHA-512)", false),
                SignatureScheme::RSA_PSS_SHA256 => ("PSS(SHA-256)", false),
                SignatureScheme::RSA_PSS_SHA384 => ("PSS(SHA-384)", false),
                SignatureScheme::RSA_PSS_SHA512 => ("PSS(SHA-512)", false),
                SignatureScheme::ECDSA_NISTP256_SHA256 => ("EMSA1(SHA-256)", true),
                SignatureScheme::ECDSA_NISTP384_SHA384 => ("EMSA1(SHA-384)", true),
                SignatureScheme::ED25519 => ("Pure", false),
                other => panic!("no verify params for {other:?}"),
            };
            let mut verifier = if der_sig {
                botan::Verifier::new_with_der_formatted_signatures(&pubkey, padding)
            } else {
                botan::Verifier::new(&pubkey, padding)
            }
            .expect("verifier init");
            verifier.update(message).expect("verifier update");
            assert!(
                verifier.finish(&signature).expect("verify finish"),
                "signature did not verify for {algo} {scheme:?}"
            );

            // tampered message should fail verification
            let mut bad = message.to_vec();
            bad[0] ^= 0xff;
            let mut verifier = if der_sig {
                botan::Verifier::new_with_der_formatted_signatures(&pubkey, padding)
            } else {
                botan::Verifier::new(&pubkey, padding)
            }
            .expect("verifier init");
            verifier.update(&bad).expect("verifier update");
            assert!(
                !verifier.finish(&signature).expect("verify finish"),
                "tampered message unexpectedly verified for {algo} {scheme:?}"
            );
        }
    }
}
