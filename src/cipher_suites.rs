use rustls::{
    CipherSuite, CipherSuiteCommon, SupportedCipherSuite, Tls13CipherSuite,
    crypto::tls13::HkdfUsingHmac,
};

use crate::{
    botan_aead::{BotanCipher, Tls13Aead},
    botan_hash, botan_hmac,
};

pub(crate) static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &botan_hash::SHA384,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &HkdfUsingHmac(&botan_hmac::HMAC_SHA384),
        aead_alg: &Tls13Aead(BotanCipher::Aes256Gcm),
        quic: None,
    });
