use rustls::crypto::hmac::{Hmac, Key, Tag};
use zeroize::Zeroizing;

pub(crate) static HMAC_SHA256: BotanHmac = BotanHmac {
    name: "HMAC(SHA-256)",
    output_len: 32,
};

pub(crate) static HMAC_SHA384: BotanHmac = BotanHmac {
    name: "HMAC(SHA-384)",
    output_len: 48,
};

/// [`Hmac`] backed by Botan's HMAC.
pub(crate) struct BotanHmac {
    name: &'static str,
    output_len: usize,
}

impl Hmac for BotanHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(BotanHmacKey {
            name: self.name,
            key: Zeroizing::new(key.to_vec()),
            output_len: self.output_len,
        })
    }

    fn hash_output_len(&self) -> usize {
        self.output_len
    }
}

/// The key is kept as bytes and a fresh Botan MAC object is created per
/// signature: HMAC setup costs two compression function calls, which is
/// negligible for the handful of PRF/HKDF invocations per handshake, and it
/// keeps this type lock-free despite `sign_concat` taking `&self`.
struct BotanHmacKey {
    name: &'static str,
    key: Zeroizing<Vec<u8>>,
    output_len: usize,
}

impl Key for BotanHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut mac = botan::MsgAuthCode::new(self.name).expect("botan provides HMAC");
        mac.set_key(&self.key).expect("HMAC accepts any key length");
        mac.update(first).expect("hmac update");
        for d in middle {
            mac.update(d).expect("hmac update");
        }
        mac.update(last).expect("hmac update");
        Tag::new(&mac.finish().expect("hmac finish"))
    }

    fn tag_len(&self) -> usize {
        self.output_len
    }
}
