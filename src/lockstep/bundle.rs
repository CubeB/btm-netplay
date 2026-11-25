//! The command log and the rejoin catch-up bundle (5.6 step 7).
//!
//! The log keeps every tick's non-empty sets per player. A bundle is the log cut
//! at the speaker's scene time; the game setup header (seed, seats) is the
//! session's business and travels separately.

use crate::types::{PlayerId, Tick};
use crate::wire::{Reader, WireError, Writer, MAX_SEATS};

/// The log stops recording (and rejoin is refused) past this many bytes of sets.
pub const MAX_LOG_BYTES: usize = 64 << 20;

const BUNDLE_MAGIC: &[u8; 4] = b"BTMR";
const BUNDLE_VERSION: u8 = 1;

/// One recorded tick: its non-empty sets in player order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedTick {
    pub tick: Tick,
    pub sets: Vec<(PlayerId, Vec<u8>)>,
}

/// A finished recording of ticks 1..=`last_tick`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Bundle {
    pub last_tick: Tick,
    /// Ticks with at least one non-empty set, ascending.
    pub ticks: Vec<RecordedTick>,
}

impl Bundle {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        for b in BUNDLE_MAGIC {
            w.u8(*b);
        }
        w.u8(BUNDLE_VERSION);
        w.varint(u64::from(self.last_tick.0));
        w.varint(self.ticks.len() as u64);
        for t in &self.ticks {
            w.varint(u64::from(t.tick.0));
            w.varint(t.sets.len() as u64);
            for (p, s) in &t.sets {
                w.u8(p.0);
                w.bytes(s);
            }
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Bundle, WireError> {
        let mut r = Reader::new(bytes);
        for b in BUNDLE_MAGIC {
            if r.u8()? != *b {
                return Err(WireError::BadValue("bundle magic"));
            }
        }
        let v = r.u8()?;
        if v != BUNDLE_VERSION {
            return Err(WireError::BadVersion(v));
        }
        let last_tick = Tick(r.u32v("last tick")?);
        let n = r.count(2)?;
        let mut ticks = Vec::with_capacity(n);
        let mut prev = 0u32;
        for _ in 0..n {
            let tick = r.u32v("tick")?;
            if tick <= prev || tick > last_tick.0 {
                return Err(WireError::BadValue("tick order"));
            }
            prev = tick;
            let m = r.count(2)?;
            let mut sets = Vec::with_capacity(m);
            for _ in 0..m {
                let p = r.u8()?;
                if p >= MAX_SEATS {
                    return Err(WireError::BadValue("seat"));
                }
                sets.push((PlayerId(p), r.bytes()?.to_vec()));
            }
            ticks.push(RecordedTick {
                tick: Tick(tick),
                sets,
            });
        }
        Ok(Bundle { last_tick, ticks })
    }
}

/// The in-memory command log, bounded by [`MAX_LOG_BYTES`].
#[derive(Clone, Debug, Default)]
pub struct CommandLog {
    ticks: Vec<RecordedTick>,
    bytes: usize,
    overflowed: bool,
}

impl CommandLog {
    /// Records one tick's sets (the empty ones are skipped).
    pub fn record(&mut self, tick: Tick, sets: &[(PlayerId, Vec<u8>)]) {
        if self.overflowed {
            return;
        }
        let kept: Vec<(PlayerId, Vec<u8>)> = sets
            .iter()
            .filter(|(_, s)| !s.is_empty())
            .cloned()
            .collect();
        if kept.is_empty() {
            return;
        }
        self.bytes += kept.iter().map(|(_, s)| s.len() + 8).sum::<usize>();
        if self.bytes > MAX_LOG_BYTES {
            self.overflowed = true;
            self.ticks = Vec::new();
            return;
        }
        let mut kept = kept;
        kept.sort_by_key(|(p, _)| *p);
        self.ticks.push(RecordedTick { tick, sets: kept });
    }

    /// False once the cap was hit.
    pub fn usable(&self) -> bool {
        !self.overflowed
    }

    /// The bundle of ticks 1..=`last`.
    pub fn cut(&self, last: Tick) -> Bundle {
        Bundle {
            last_tick: last,
            ticks: self
                .ticks
                .iter()
                .filter(|t| t.tick <= last)
                .cloned()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn bundle_round_trip() {
        let mut log = CommandLog::default();
        log.record(Tick(1), &[(PlayerId(1), vec![]), (PlayerId(0), vec![1])]);
        log.record(Tick(2), &[(PlayerId(1), vec![])]);
        log.record(
            Tick(5),
            &[(PlayerId(3), vec![2, 3]), (PlayerId(1), vec![4])],
        );
        let b = log.cut(Tick(7));
        assert_eq!(b.ticks.len(), 2);
        assert_eq!(b.ticks[1].sets[0].0, PlayerId(1));
        let e = b.encode();
        assert_eq!(Bundle::decode(&e).unwrap(), b);
        for n in 0..e.len() {
            assert!(Bundle::decode(&e[..n]).is_err());
        }
    }
}
