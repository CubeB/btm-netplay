//! A small random number source from std only: SplitMix64 seeded from the per-process
//! random keys of [`std::collections::hash_map::RandomState`] and the clock. Good enough for
//! session ids, claim tokens, STUN transaction ids and the game seed; not for secrets.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

/// SplitMix64.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// A generator with a fresh random seed.
    pub fn from_entropy() -> Self {
        let mut h = RandomState::new().build_hasher();
        if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            h.write_u128(d.as_nanos());
        }
        h.write_u32(std::process::id());
        Self(h.finish())
    }

    /// A generator with a fixed seed (tests, reproducible demos).
    pub fn seeded(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (0 when `n` is 0).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            for (b, r) in chunk.iter_mut().zip(v) {
                *b = r;
            }
        }
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }
}
