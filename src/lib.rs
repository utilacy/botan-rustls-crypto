#![allow(unused)]

mod botan_aead;
mod botan_hash;
mod botan_hmac;
mod cipher_suites;

use rustls::{CipherSuite, SupportedCipherSuite, crypto::CryptoProvider};

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: supported_cipher_suites(),
        kx_groups: todo!(),
        signature_verification_algorithms: todo!(),
        secure_random: todo!(),
        key_provider: todo!(),
    }
}

fn supported_cipher_suites() -> Vec<SupportedCipherSuite> {
    static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
        // TLS 1.3
        cipher_suites::TLS13_AES_256_GCM_SHA384,
        cipher_suites::TLS13_AES_128_GCM_SHA256,
        // CipherSuite::TLS13_AES_128_GCM_SHA256,
        // CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        // // TLS 1.2
        // CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        // CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        // CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        // CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        // CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        // CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    ALL_CIPHER_SUITES.to_vec()
}

#[cfg(test)]
mod tests {
    use crate::provider;

    #[test]
    fn test_it() {
        // provider();
    }
}
