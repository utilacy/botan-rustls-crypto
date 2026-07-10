use std::fmt::Debug;

use botan::Privkey;
use rustls::{
    Error, NamedGroup,
    crypto::{ActiveKeyExchange, SupportedKxGroup},
};

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
        todo!()
    }

    fn pub_key(&self) -> &[u8] {
        todo!()
    }

    fn group(&self) -> NamedGroup {
        todo!()
    }
}
