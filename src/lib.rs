#![allow(unused)]
#![doc = include_str!("../README.md")]

mod botan_aead;
mod botan_hash;
mod botan_hmac;
mod cipher_suites;
mod key_provider;
mod kx_groups;
mod secure_random;
mod signature_verification_algorithms;

use rustls::{CipherSuite, SupportedCipherSuite, crypto::CryptoProvider};

use crate::key_provider::BotanKeyProvider;
use crate::kx_groups::{ALL_KX_GROUPS, SECP256R1, SECP384R1, X25519};
use crate::secure_random::BotanRandom;

/// Returns a rustls [`CryptoProvider`] whose cryptography is entirely backed by
/// the Botan library.
///
/// Pass it to a rustls config builder to run TLS through Botan instead of the
/// default backend:
///
/// ```ignore
/// let config = rustls::ServerConfig::builder_with_provider(
///         std::sync::Arc::new(botan_crypto_provider::provider()),
///     )
///     .with_safe_default_protocol_versions()
///     .unwrap()
///     .with_no_client_auth()
///     .with_single_cert(certs, key)
///     .unwrap();
/// ```
///
/// See the crate level documentation for the full list of supported algorithms.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: supported_cipher_suites(),
        kx_groups: ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms:
            signature_verification_algorithms::ALL_VERIFICATION_ALGORITHMS,
        secure_random: &BotanRandom,
        key_provider: &BotanKeyProvider,
    }
}

fn supported_cipher_suites() -> Vec<SupportedCipherSuite> {
    static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
        // TLS 1.3
        cipher_suites::TLS13_AES_256_GCM_SHA384,
        cipher_suites::TLS13_AES_128_GCM_SHA256,
        // TLS 1.2
        cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        // TODO implement bindings to chacha20
    ];
    ALL_CIPHER_SUITES.to_vec()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, Stream,
    };

    use crate::provider;

    #[test]
    fn create_provider() {
        provider();
    }

    /// End-to-end smoke test for the whole Botan provider
    ///
    /// A rustls server whose `CryptoProvider` is entirely our Botan-backed
    /// implementation performs a real TLS handshake over a loopback socket with
    /// a stock rustls client running the reference `ring` provider
    #[test]
    fn end_to_end_handshake_with_standard_client() {
        // Self-signed ECDSA P-256 cert for "localhost"
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der: CertificateDer<'static> = signed.cert.der().clone();
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signed.signing_key.serialize_der()));

        // Server config backed by our Botan provider.
        let server_config = ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        let server_config = Arc::new(server_config);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        // get the address on the localhost (port is dynamically selected)
        let addr = listener.local_addr().unwrap();

        // spawn the server
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut conn = ServerConnection::new(server_config).unwrap();
            {
                let mut tls = Stream::new(&mut conn, &mut sock);
                let mut req = [0u8; 5];
                tls.read_exact(&mut req).unwrap();
                assert_eq!(&req, b"ping\n");
                tls.write_all(b"pong\n").unwrap();
                tls.flush().unwrap();
            }
            (
                conn.protocol_version(),
                conn.negotiated_cipher_suite().map(|s| s.suite()),
            )
        });

        // standard client: rustls stock ring provider
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();

        let server_name = ServerName::try_from("localhost").unwrap();
        let mut conn = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
        let mut sock = TcpStream::connect(addr).unwrap();
        {
            let mut tls = Stream::new(&mut conn, &mut sock);
            tls.write_all(b"ping\n").unwrap();
            tls.flush().unwrap();
            let mut reply = [0u8; 5];
            tls.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"pong\n");
        }

        let (version, suite) = server.join().unwrap();
        assert!(version.is_some());
        assert!(suite.is_some());
    }
}
