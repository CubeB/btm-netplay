//! A toy deterministic engine for the demo and the tests: a state of 64 `u32`s mixed by
//! every player's command bytes with a fixed hash. It can be told to report a wrong hash
//! at one tick, to test desync detection.

use crate::types::{Engine, PlayerId, Tick};

/// Number of state words.
pub const WORDS: usize = 64;

fn mix(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x7FEB_352D);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846C_A68B);
    x ^ (x >> 16)
}

/// The toy engine.
#[derive(Clone, Debug)]
pub struct ToyEngine {
    state: [u32; WORDS],
    tick: Tick,
    corrupt_at: Option<Tick>,
    history: Vec<u32>,
    commands_seen: u64,
}

impl Default for ToyEngine {
    fn default() -> Self {
        Self::new(0)
    }
}

impl ToyEngine {
    /// A fresh state derived from the agreed simulation seed.
    pub fn new(seed: u64) -> Self {
        let mut state = [0u32; WORDS];
        let mut s = mix(seed as u32 ^ mix((seed >> 32) as u32));
        for w in &mut state {
            s = mix(s.wrapping_add(0x9E37_79B9));
            *w = s;
        }
        Self {
            state,
            tick: Tick(0),
            corrupt_at: None,
            history: Vec::new(),
            commands_seen: 0,
        }
    }

    /// Report a wrong hash after tick `t` (desync testing).
    pub fn corrupt_at(mut self, t: Option<Tick>) -> Self {
        self.corrupt_at = t;
        self
    }

    /// The last tick run.
    pub fn tick(&self) -> Tick {
        self.tick
    }

    /// The hash reported after each tick, index 0 = tick 1.
    pub fn history(&self) -> &[u32] {
        &self.history
    }

    /// The hash reported after tick `t`.
    pub fn hash_at(&self, t: Tick) -> Option<u32> {
        let i = usize::try_from(t.0).ok()?.checked_sub(1)?;
        self.history.get(i).copied()
    }

    /// Non-empty command sets applied so far.
    pub fn commands_seen(&self) -> u64 {
        self.commands_seen
    }

    fn true_hash(&self) -> u32 {
        let mut h: u32 = 0x811C_9DC5;
        for w in &self.state {
            for b in w.to_le_bytes() {
                h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
            }
        }
        h
    }
}

impl Engine for ToyEngine {
    fn step(&mut self, tick: Tick, commands: &[(PlayerId, Vec<u8>)]) {
        self.tick = tick;
        for (p, set) in commands {
            if !set.is_empty() {
                self.commands_seen += 1;
            }
            for (i, b) in set.iter().enumerate() {
                let idx = (usize::from(p.0) * 7 + i + tick.0 as usize) % WORDS;
                if let Some(w) = self.state.get_mut(idx) {
                    *w = mix(*w ^ u32::from(*b) ^ (u32::from(p.0) << 8) ^ ((i as u32) << 16));
                }
            }
        }
        let t = mix(tick.0);
        for (i, w) in self.state.iter_mut().enumerate() {
            if (i as u32 + tick.0).is_multiple_of(8) {
                *w = mix(w.wrapping_add(t));
            }
        }
        let h = self.state_hash();
        self.history.push(h);
    }

    fn state_hash(&self) -> u32 {
        let h = self.true_hash();
        if self.corrupt_at == Some(self.tick) {
            h ^ 0xDEAD_BEEF
        } else {
            h
        }
    }

    /// A fresh state from the seed; a chosen corrupt tick is kept.
    fn load(&mut self, seed: u64) -> bool {
        *self = Self::new(seed).corrupt_at(self.corrupt_at);
        true
    }

    fn dump(&self) -> String {
        let words: Vec<String> = self.state.iter().map(u32::to_string).collect();
        format!(
            "{{\"tick\":{},\"hash\":{},\"state\":[{}]}}",
            self.tick.0,
            self.true_hash(),
            words.join(",")
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_input_sensitive() {
        let mut a = ToyEngine::new(7);
        let mut b = ToyEngine::new(7);
        let mut c = ToyEngine::new(7);
        for t in 1..=50 {
            let cmds = vec![(PlayerId(1), vec![t as u8, 3]), (PlayerId(0), vec![])];
            a.step(Tick(t), &cmds);
            b.step(Tick(t), &cmds);
            let other = vec![(PlayerId(1), vec![t as u8, 4]), (PlayerId(0), vec![])];
            c.step(Tick(t), if t == 20 { &other } else { &cmds });
        }
        assert_eq!(a.history(), b.history());
        assert_ne!(a.state_hash(), c.state_hash());
        assert_eq!(a.hash_at(Tick(50)), Some(a.state_hash()));
    }

    #[test]
    fn corrupts_only_the_chosen_tick() {
        let mut a = ToyEngine::new(1);
        let mut b = ToyEngine::new(1).corrupt_at(Some(Tick(3)));
        for t in 1..=5 {
            a.step(Tick(t), &[]);
            b.step(Tick(t), &[]);
        }
        assert_eq!(a.hash_at(Tick(2)), b.hash_at(Tick(2)));
        assert_ne!(a.hash_at(Tick(3)), b.hash_at(Tick(3)));
        assert_eq!(a.hash_at(Tick(4)), b.hash_at(Tick(4)));
    }
}
