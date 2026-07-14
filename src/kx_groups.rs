use std::fmt::Debug;

use botan::Privkey;
use rustls::{
    Error::{self, PeerMisbehaved},
    NamedGroup,
    PeerMisbehaved::InvalidKeyShare,
    crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    // X25519, SECP256R1, SECP384R1
];

struct BotanKxGroup {
    name: NamedGroup,
    algo: &'static str,
    params: &'static str,
    /// Expected length of the wire encoding of public values
    /// - 32 bytes for X25519,
    /// - 65 bytes for secp256r1,
    /// - 67 bytes for secp384r1,
    /// (see: RFC 8446 - 4.2.8.2)
    pub_key_len: usize,
    nist: bool,
}

impl Debug for BotanKxGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.name.fmt(f)
    }
}

impl SupportedKxGroup for BotanKxGroup {
    fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, Error> {
        // first create ephemeral keys:
        let (priv_key, pub_key) = create_ephemeral_key(self.algo, self.params)?;

        Ok(Box::new(BotanActiveKeyExchange {
            name: self.name,
            pub_key_len: self.pub_key_len,
            nist: self.nist,
            priv_key,
            pub_key,
        }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        // it is recommended to implement this function to help the linker
        None
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

fn create_ephemeral_key(
    algo: &'static str,
    params: &'static str,
) -> Result<(Privkey, Vec<u8>), Error> {
    let mut rng = botan::RandomNumberGenerator::new().map_err(|_| Error::FailedToGetRandomBytes)?;
    let priv_key = botan::Privkey::create(algo, params, &mut rng)
        .map_err(|_| Error::FailedToGetRandomBytes)?;
    // botan exports keys in the exact encoding TLS expects
    let pub_key: Vec<u8> = priv_key
        .key_agreement_key()
        .map_err(|_| Error::FailedToGetRandomBytes)?;
    Ok((priv_key, pub_key))
}

struct BotanActiveKeyExchange {
    name: NamedGroup,
    pub_key_len: usize,
    nist: bool,
    priv_key: Privkey,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for BotanActiveKeyExchange {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, Error> {
        // rustls expects the unprocessed agreed value ("Raw" no salt -> no KDF)
        // thus we dont need to have a salt in the ka.agree call
        if peer_pub_key.len() != self.pub_key_len {
            return Err(PeerMisbehaved(InvalidKeyShare));
        }
        // TODO if nist, check the peers public key

        // "Raw" is the string botan expects when agreeing on unmodified values
        let mut secret: Vec<u8> = botan::KeyAgreement::new(&self.priv_key, "Raw")
            .and_then(|mut ka| ka.agree(0, peer_pub_key, &[]))
            .map_err(|_| PeerMisbehaved(InvalidKeyShare))?;

        // RFC 7748 - 6.1: abort if all-zero value:
        // The check for the all-zero value results from the fact that the
        // X25519 function produces that value if it operates on an input
        // corresponding to a point with small order, where the order divides
        // the cofactor of the curve (see Section 7).  The check may be
        // performed by ORing all the bytes together and checking whether the
        // result is zero, as this eliminates standard side-channels in software
        // implementations.
        static ZEROS: [u8; 32] = [0u8; 32];
        if !self.nist && bool::from(secret.ct_eq(&ZEROS)) {
            return Err(PeerMisbehaved(InvalidKeyShare));
        }
        let shared_secret = SharedSecret::from(secret.as_ref());
        secret.zeroize(); // destroy the key before returning
        Ok(shared_secret)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}
