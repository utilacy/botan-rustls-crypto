use std::cell::RefCell;

use botan::RandomNumberGenerator;
use rustls::crypto::{GetRandomFailed, SecureRandom};

/// [`SecureRandom`] implementation backed by Botan's userspace RNG.
/// Instances cached in threadlocal storage
#[derive(Debug)]
pub(crate) struct BotanRandom;

thread_local! {
    static THREAD_RNG: RefCell<Option<RandomNumberGenerator>> = const { RefCell::new(None) };
}

pub(crate) fn do_with_thread_local_rng<F, R>(f: F) -> Result<R, GetRandomFailed>
where
    F: FnOnce(&mut RandomNumberGenerator) -> R,
{
    THREAD_RNG.with_borrow_mut(|rng_handle| {
        if rng_handle.is_none() {
            *rng_handle = Some(RandomNumberGenerator::new().map_err(|_| GetRandomFailed)?);
        }
        let rng: &mut RandomNumberGenerator = rng_handle.as_mut().unwrap();
        Ok(f(rng))
    })
}

impl SecureRandom for BotanRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        do_with_thread_local_rng(|rng| rng.fill(buf).map_err(|_| GetRandomFailed))?
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::SecureRandom;

    use super::BotanRandom;

    #[test]
    fn smoke_test_rng() {
        let mut buf = [0u8; 64];
        BotanRandom.fill(&mut buf).unwrap();

        // did nothing
        assert!(buf.iter().any(|&b| b != 0), "RNG returned all zeros");

        // returns constant byte
        let first = buf[0];
        assert!(
            buf.iter().any(|&b| b != first),
            "RNG returned constant byte"
        );

        // Two independent calls should not produce the same randomness
        let mut buf2 = [0u8; 64];
        BotanRandom.fill(&mut buf2).unwrap();
        assert_ne!(buf, buf2, "two RNG fills produced identical output");
    }
}
