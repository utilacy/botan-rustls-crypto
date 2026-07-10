use rustls::crypto::hmac::{Hmac, Key, Tag};
use zeroize::Zeroizing;

#[derive(Copy, Clone, Debug)]
pub(crate) enum BotanHmac {
    HmacSha256,
    HmacSha384,
}

impl BotanHmac {
    #[inline(always)]
    fn name(self) -> &'static str {
        match self {
            // needs to match what botan expects
            BotanHmac::HmacSha256 => "HMAC(SHA-256)",
            BotanHmac::HmacSha384 => "HMAC(SHA-384)",
        }
    }
    #[inline(always)]
    fn output_len(self) -> usize {
        match self {
            BotanHmac::HmacSha256 => 32,
            BotanHmac::HmacSha384 => 48,
        }
    }
}

impl Hmac for BotanHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(BotanHmacKey {
            hmac: *self,
            key: Zeroizing::new(key.to_vec()),
        })
    }

    fn hash_output_len(&self) -> usize {
        self.output_len()
    }
}

/// The key is kept as bytes and a fresh Botan MAC object is created per
/// signature: HMAC setup costs two compression function calls, which is
/// negligible for the handful of PRF/HKDF invocations per handshake, and it
/// keeps this type lock-free despite `sign_concat` taking `&self`.
struct BotanHmacKey {
    hmac: BotanHmac,
    key: Zeroizing<Vec<u8>>,
}

impl Key for BotanHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut mac = botan::MsgAuthCode::new(self.hmac.name())
            .expect("unexpected botan should provide HMAC");
        mac.set_key(&self.key).expect("HMAC accepts any key length");
        mac.update(first)
            .expect("unexpected error: hmac update first");
        for d in middle {
            mac.update(d).expect("unexpected error: hmac update middle");
        }
        mac.update(last)
            .expect("unexpected error: hmac update last");
        Tag::new(&mac.finish().expect("unexpected error: hmac finish"))
    }

    fn tag_len(&self) -> usize {
        self.hmac.output_len()
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::hmac::{Hmac, Tag};

    use crate::botan_hmac::BotanHmac;

    #[test]
    fn test_hmac() {
        let hmac = BotanHmac::HmacSha256;
        let key = [1u8; 10];
        let hmac_keyed = hmac.with_key(key.as_ref());
        let tag: Tag = hmac_keyed.sign_concat(&[2; 12], &[&[3; 13], &[4; 14]], &[5; 15]);
        static EXPECTED: &'static [u8] = &[
            204, 111, 31, 19, 216, 229, 159, 82, 210, 79, 249, 110, 225, 37, 207, 215, 44, 237,
            239, 215, 57, 183, 181, 120, 202, 203, 13, 48, 209, 93, 1, 115,
        ];
        assert_eq!(tag.as_ref(), EXPECTED);
    }
}
