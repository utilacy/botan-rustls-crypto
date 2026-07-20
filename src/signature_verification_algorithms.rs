use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{
        AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
        SubjectPublicKeyInfoDer, alg_id,
    },
    sign::public_key_to_spki,
};

#[derive(Debug)]
struct BotanVerify {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    padding: &'static str,
    /// X.509 and TLS carry ECDSA signatures DER-encoded; RSA and Ed25519
    /// signatures are raw.
    der_signature: bool,
}

impl SignatureVerificationAlgorithm for BotanVerify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let spki: SubjectPublicKeyInfoDer<'static> =
            public_key_to_spki(&self.public_key_alg_id, public_key);
        let key: botan::Pubkey =
            botan::Pubkey::load_der(spki.as_ref()).map_err(|_| InvalidSignature)?;

        let mut verifier: botan::Verifier = match self.der_signature {
            true => botan::Verifier::new_with_der_formatted_signatures(&key, self.padding),
            false => botan::Verifier::new(&key, self.padding),
        }
        .map_err(|_| InvalidSignature)?;
        verifier.update(message).map_err(|_| InvalidSignature)?;
        match verifier.finish(signature) {
            Ok(true) => Ok(()),
            _ => Err(InvalidSignature),
        }
    }
}

/// All signature algorithms this provider can verify, plus the mapping
/// from TLSs `SignatureScheme` to the concrete algorithm that satisfy it
pub static ALL_VERIFICATION_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

pub static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    padding: "PKCS1v15(SHA-256)",
    der_signature: false,
};

pub static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    padding: "PKCS1v15(SHA-384)",
    der_signature: false,
};

pub static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    padding: "PKCS1v15(SHA-512)",
    der_signature: false,
};

// We are deliberately being lenient about which certificate tag we accept (because that's what everyone does),
// and we are relying on Botans defaults for a couple of PSS parameters instead of setting them ourselves

pub static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    padding: "PSS(SHA-256)",
    der_signature: false,
};

pub static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    padding: "PSS(SHA-384)",
    der_signature: false,
};

pub static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    padding: "PSS(SHA-512)",
    der_signature: false,
};

pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    padding: "EMSA1(SHA-256)",
    der_signature: true,
};

pub static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    padding: "EMSA1(SHA-384)",
    der_signature: true,
};

pub static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    padding: "EMSA1(SHA-256)",
    der_signature: true,
};

pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    padding: "EMSA1(SHA-384)",
    der_signature: true,
};

pub static ED25519: &dyn SignatureVerificationAlgorithm = &BotanVerify {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
    padding: "Pure",
    der_signature: false,
};
