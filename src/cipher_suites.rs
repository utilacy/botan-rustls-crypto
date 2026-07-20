use botan::Cipher;
use rustls::{
    CipherSuite, CipherSuiteCommon, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite,
    Tls13CipherSuite,
    crypto::{KeyExchangeAlgorithm, tls12::PrfUsingHmac, tls13::HkdfUsingHmac},
};

use crate::{
    botan_aead::{BotanCipher, Tls12Aead, Tls13Aead},
    botan_hash, botan_hmac,
};

/// rustls for `confidentiality_limit`:
/// For AES-GCM implementations, this should be set to 2**24
const AES_GCM_CONF_LIMIT: u64 = 1 << 24;

pub(crate) static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &botan_hash::SHA384,
            confidentiality_limit: AES_GCM_CONF_LIMIT,
        },
        hkdf_provider: &HkdfUsingHmac(&botan_hmac::BotanHmac::HmacSha384),
        aead_alg: &Tls13Aead(BotanCipher::Aes256Gcm),
        quic: None,
    });

pub(crate) static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &botan_hash::SHA256,
            confidentiality_limit: AES_GCM_CONF_LIMIT,
        },
        hkdf_provider: &HkdfUsingHmac(&botan_hmac::BotanHmac::HmacSha256),
        aead_alg: &Tls13Aead(BotanCipher::Aes128Gcm),
        quic: None,
    });

static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &botan_hash::SHA384,
            confidentiality_limit: AES_GCM_CONF_LIMIT,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &Tls12Aead(BotanCipher::Aes256Gcm),
        prf_provider: &PrfUsingHmac(&botan_hmac::BotanHmac::HmacSha384),
    });

pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &botan_hash::SHA256,
            confidentiality_limit: AES_GCM_CONF_LIMIT,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &Tls12Aead(BotanCipher::Aes128Gcm),
        prf_provider: &PrfUsingHmac(&botan_hmac::BotanHmac::HmacSha256),
    });
