use botan::CipherDirection;
use rustls::{
    ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion,
    crypto::cipher::{
        AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
        Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
        UnsupportedOperationError, make_tls13_aad,
    },
};

/// All AEADs use 16-byte authentication tags
const TAG_LEN: usize = 16;

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + TAG_LEN;

/// Longest allowed TLS plaintext fragment (RFC 5246 §6.2.1: 2^14).
const MAX_FRAGMENT_LEN: usize = 16384;

/// A bridge implementation, implementing `Tls13AeadAlgorithm` for a botan provided stream cipher
pub(crate) struct Tls13Aead(pub(crate) BotanCipher);

impl Tls13AeadAlgorithm for Tls13Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Crypter {
            cipher: self.0.cipher(CipherDirection::Encrypt, key.as_ref()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Crypter {
            cipher: self.0.cipher(CipherDirection::Decrypt, key.as_ref()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match self.0 {
            BotanCipher::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            BotanCipher::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum BotanCipher {
    Aes128Gcm,
    Aes256Gcm,
}

impl BotanCipher {
    /// Names of cipher that need to match what is expected from `botan::Cipher::new`
    fn botan_name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128/GCM",
            Self::Aes256Gcm => "AES-256/GCM",
        }
    }

    /// Length of the keys used in the cipher
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    /// A keyed cipher, reused for every record on the connection
    fn cipher(self, direction: CipherDirection, key: &[u8]) -> botan::Cipher {
        if key.len() != self.key_len() {
            // The key length should be guaranteed by rustls, so failures here can only be
            // programming errors.
            panic!(
                "Unexpected, provided keylength {} does not match expected keylength {}.
                should be guaranateed by rustls.",
                key.len(),
                self.key_len()
            )
        }
        let mut cipher =
            botan::Cipher::new(self.botan_name(), direction).expect("botan provides this AEAD");
        cipher.set_key(key).expect("key of length key_len()");
        cipher
    }
}

/// One-shot AEAD encrypt
/// Returns ciphertext||tag
fn oneshot_encrypt(
    cipher: &mut botan::Cipher,
    nonce: &[u8],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, Error> {
    cipher
        .set_associated_data(aad)
        .and_then(|()| cipher.process(nonce, plain))
        .map_err(|_| Error::EncryptError)
}

/// One-shot AEAD decrypt of ciphertext||tag
/// Checks tag, then returns the plaintext
fn oneshot_decrypt(
    cipher: &mut botan::Cipher,
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, Error> {
    cipher
        .set_associated_data(aad)
        .and_then(|()| cipher.process(nonce, ct))
        .map_err(|_| Error::DecryptError)
}

/// Bridge between rustls `MessageEncryptor` and `MessageDecryptor` for botan provided cipher
struct Tls13Crypter {
    cipher: botan::Cipher,
    iv: Iv,
}

impl MessageEncrypter for Tls13Crypter {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        // TLS 1.3 specific: plaintext = content || real content type
        let mut plain = Vec::with_capacity(m.payload.len() + 1);
        m.payload.copy_to_vec(&mut plain);
        plain.extend_from_slice(&m.typ.to_array());

        let expected_ct_len = self.encrypted_payload_len(m.payload.len());
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(expected_ct_len);
        let ct = oneshot_encrypt(&mut self.cipher, &nonce, &aad, &plain)?;
        debug_assert_eq!(ct.len(), expected_ct_len);

        // create a rustls `OutboundOpagueMessage` from ct:
        let mut payload = PrefixedPayload::with_capacity(expected_ct_len);
        payload.extend_from_slice(&ct);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // TLS 1.3 records carry the legacy version (RFC 8446 5.1).
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Tls13Crypter {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        if m.payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }

        let nonce: [u8; 12] = Nonce::new(&self.iv, seq).0;
        let aad: [u8; 5] = make_tls13_aad(m.payload.len());
        let plain: Vec<u8> = oneshot_decrypt(&mut self.cipher, &nonce, &aad, &m.payload)?;

        // copy plain into `InboundPlainMessage`
        let payload = &mut m.payload;
        payload[..plain.len()].copy_from_slice(&plain);
        payload.truncate(plain.len());
        m.into_tls13_unpadded_message()
    }
}
