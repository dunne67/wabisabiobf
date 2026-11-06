use std::time::{SystemTime, UNIX_EPOCH};

/// Fast deterministic SplitMix64 PRNG used for per-build polymorphic VM generation.
#[derive(Debug, Clone)]
pub struct Prng {
    state: u64,
}

impl Prng {
    pub fn from_seed(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    pub fn from_entropy(extra_hash: u64) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xCAFE_BABE_DEAD_BEEF);
        let pid = std::process::id() as u64;
        let seed = nanos
            .wrapping_mul(0xBF58_476D_1CE4_E5B9)
            ^ pid.rotate_left(17)
            ^ extra_hash;
        Self::from_seed(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_usize(&mut self, bound: usize) -> usize {
        debug_assert!(bound > 0);
        (self.next_u64() % (bound as u64)) as usize
    }

    pub fn next_u8_range(&mut self, lo: u8, hi_inclusive: u8) -> u8 {
        let span = (hi_inclusive - lo) as usize + 1;
        lo + self.next_usize(span) as u8
    }

    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.next_usize(i + 1);
            slice.swap(i, j);
        }
    }
}
