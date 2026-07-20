use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};

/// A rustls [`Hash`] implementation backed by a Botan hash function.
pub(crate) struct BotanHash {
    name: &'static str,
    alg: HashAlgorithm,
    output_len: usize,
}

pub(crate) static SHA384: BotanHash = BotanHash {
    name: "SHA-384",
    alg: HashAlgorithm::SHA384,
    output_len: 48, // 48 bytes is 384 bits
};

pub(crate) static SHA256: BotanHash = BotanHash {
    name: "SHA-256",
    alg: HashAlgorithm::SHA256,
    output_len: 32, // 32 bytes is 256 bits
};

impl Hash for BotanHash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(BotanHashContext(self.into()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        let mut botan_hash: botan::HashFunction = self.into();
        botan_hash.update(data).expect("hash update");
        Output::new(&botan_hash.finish().expect("hash finish"))
    }

    fn output_len(&self) -> usize {
        self.output_len
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.alg
    }

    fn fips(&self) -> bool {
        false // botan is not fips
    }
}

impl From<&BotanHash> for botan::HashFunction {
    fn from(value: &BotanHash) -> Self {
        botan::HashFunction::new(value.name)
            .unwrap_or_else(|_| panic!("Botan should provide hash function: {}", value.name))
    }
}

/// Incremental hash computation
/// This struct is simply a facade over the botan Hashfunction
struct BotanHashContext(botan::HashFunction);

impl Context for BotanHashContext {
    fn fork_finish(&self) -> Output {
        let mut fork = self.0.duplicate().expect("hash duplicate");
        Output::new(&fork.finish().expect("hash finish"))
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Self(self.0.duplicate().expect("hash duplicate")))
    }

    fn finish(mut self: Box<Self>) -> Output {
        Output::new(&self.0.finish().expect("hash finish"))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("hash update");
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::hash::{Hash, HashAlgorithm};

    #[test]
    fn test_sha256() {
        assert_eq!(super::SHA256.fips(), false);
        assert_eq!(super::SHA256.algorithm(), HashAlgorithm::SHA256);
        static EXPECTED: &[u8] = &[
            159, 100, 167, 71, 225, 185, 127, 19, 31, 171, 182, 180, 71, 41, 108, 155, 111, 2, 1,
            231, 159, 179, 197, 53, 110, 108, 119, 232, 155, 106, 128, 106,
        ];
        assert_eq!(super::SHA256.hash(&[1, 2, 3, 4]).as_ref(), EXPECTED);
    }

    #[test]
    fn test_sha384() {
        assert_eq!(super::SHA384.fips(), false);
        assert_eq!(super::SHA384.algorithm(), HashAlgorithm::SHA384);
        static EXPECTED: &[u8] = &[
            90, 102, 125, 98, 67, 10, 140, 37, 62, 186, 228, 51, 51, 57, 4, 220, 110, 29, 65, 220,
            220, 71, 151, 4, 119, 49, 89, 185, 5, 163, 173, 130, 210, 186, 215, 118, 45, 129, 163,
            102, 204, 70, 251, 178, 226, 50, 127, 92,
        ];
        assert_eq!(super::SHA384.hash(&[1, 2, 3, 4]).as_ref(), EXPECTED);
    }
}
