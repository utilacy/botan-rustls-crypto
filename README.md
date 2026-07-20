# botan-crypto-provider

A [rustls](https://github.com/rustls/rustls) `CryptoProvider` backed entirely by
the [Botan](https://botan.randombit.net/) cryptography library (via the
[`botan`](https://crates.io/crates/botan) FFI bindings). It lets a rustls client
or server run its TLS handshake and record protection through Botan instead of
the default *ring* / *aws-lc-rs* backends.

```rust,ignore
let config = rustls::ServerConfig::builder_with_provider(
        std::sync::Arc::new(botan_crypto_provider::provider()),
    )
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
```

## What is provided

The single entry point is `provider() -> rustls::crypto::CryptoProvider`, wiring
Botan into every slot rustls needs:

| Feature | Implementation | Comment |
|------|----------------|---------|
| TLS versions | TLS 1.3 and TLS 1.2 | |
| Cipher suites | `TLS13_AES_128_GCM_SHA256`, `TLS13_AES_256_GCM_SHA384` | AES-GCM AEAD |
| | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | TLS 1.2, ECDSA |
| Key exchange | X25519, secp256r1 (P-256), secp384r1 (P-384) | ECDH / X25519 |
| Record AEAD | AES-128/256-GCM | TLS 1.3 and TLS 1.2 framing |
| Hashes | SHA-256, SHA-384 | transcript + HKDF |
| HMAC / KDF | HMAC-SHA256, HMAC-SHA384 | HKDF (TLS 1.3) and PRF (TLS 1.2) |
| Signing | RSA (PKCS#1 & PSS), ECDSA P-256/P-384, Ed25519 | server/client handshake signatures |
| Signature verification | matching WebPKI algorithm set | certificate & handshake verification |
| Private keys | PKCS#8 and PKCS#1 DER | SEC1 keys must be converted to PKCS#8 |
| RNG | Botan system RNG | thread-local, used for signing and key generation |

Not yet implemented: ChaCha20-Poly1305, and direct SEC1 EC key loading.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Disclaimer of warranty

This software is provided "as is", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and noninfringement. In no event shall the authors or
copyright holders be liable for any claim, damages, or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. It is experimental and has not been audited; do not use it in
production without an independent security review.

This project is an independent, unofficial integration and is **not affiliated
with, endorsed by, or sponsored by** the Botan project or its authors. "Botan"
is the property of its respective owners and is used here only to describe the
underlying library this crate binds to.
