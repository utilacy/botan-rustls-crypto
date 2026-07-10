use botan::Cipher;
use rustls::{
    CipherSuite, CipherSuiteCommon, SupportedCipherSuite, Tls13CipherSuite,
    crypto::tls13::HkdfUsingHmac,
};

use crate::{
    botan_aead::{BotanCipher, Tls13Aead},
    botan_hash, botan_hmac,
};

// rustls: For AES-GCM implementations, this should be set to 2**24
const AES_GCM_CONF_LIMIT: u64 = 1 << 24;

pub(crate) static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &botan_hash::SHA384,
            confidentiality_limit: AES_GCM_CONF_LIMIT,
        },
        hkdf_provider: &HkdfUsingHmac(&botan_hmac::HMAC_SHA384),
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
        hkdf_provider: &HkdfUsingHmac(&botan_hmac::HMAC_SHA256),
        aead_alg: &Tls13Aead(BotanCipher::Aes128Gcm),
        quic: None,
    });
