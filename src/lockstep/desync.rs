//! Desync detection (section 4): per-source hash queues compared tick by tick.

use std::collections::{BTreeMap, VecDeque};

use crate::types::{PlayerId, Tick};
use crate::wire::MAX_BUFFERED;

/// A detected desync. Every peer names the same `tick`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Desync {
    /// The first diverging tick, T.
    pub tick: Tick,
    /// This peer, P.
    pub local: PlayerId,
    /// Local scene time when noticed, N (>= T).
    pub noticed_at: Tick,
    /// Every participating source's hash at T, in player order.
    pub hashes: Vec<(PlayerId, u32)>,
    /// The engine's state dump at N (4.4 `state`).
    pub dump: String,
}

impl Desync {
    /// The dump file name, `<prefix>-desync-tick<T>-player<P>.json` (4.4).
    pub fn file_name(&self, prefix: &str) -> String {
        format!(
            "{prefix}-desync-tick{}-player{}.json",
            self.tick.0, self.local.0
        )
    }

    /// The text of the fatal error box (4.3). `dump_path` is where the caller wrote
    /// the dump, or None if it could not be written.
    pub fn report(&self, dump_path: Option<&str>) -> String {
        let mut s = format!(
            "Desync detected.\n\nThe simulation diverged from the other players at tick {}.\n\
             This peer is player {}, and noticed at tick {}.\n\n",
            self.tick.0, self.local.0, self.noticed_at.0
        );
        for (p, h) in &self.hashes {
            s.push_str(&format!("  player {}  0x{h:08x}", p.0));
            if *p == self.local {
                s.push_str("  (this peer)");
            }
            s.push('\n');
        }
        s.push('\n');
        match dump_path {
            Some(path) => {
                s.push_str("A state dump for a bug report was written to:\n  ");
                s.push_str(path);
                s.push_str(
                    "\n\nEvery peer writes one naming the same tick. A report wants them all.\n",
                );
            }
            None => s.push_str("A state dump could not be written; see the log.\n"),
        }
        s
    }

    /// The dump file's JSON (4.4). `self.dump` is embedded as `state` verbatim if
    /// it is a JSON value (starts with `{` or `[`), otherwise as a string.
    pub fn dump_json(&self, build: &str, commit: &str, build_identity: &str) -> String {
        let hashes: Vec<String> = self
            .hashes
            .iter()
            .map(|(p, h)| format!("{{\"player\":{},\"hash\":{h}}}", p.0))
            .collect();
        let trimmed = self.dump.trim_start();
        let state = if trimmed.starts_with('{') || trimmed.starts_with('[') {
            self.dump.clone()
        } else {
            json_string(&self.dump)
        };
        format!(
            "{{\"desync\":{{\"firstDivergentTick\":{},\"localPlayer\":{},\"detectedAtTick\":{},\
             \"hashes\":[{}],\"build\":{},\"commit\":{},\"buildIdentity\":{}}},\"state\":{}}}",
            self.tick.0,
            self.local.0,
            self.noticed_at.0,
            hashes.join(","),
            json_string(build),
            json_string(commit),
            json_string(build_identity),
            state
        )
    }
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Clone, Debug)]
struct Source {
    /// First tick this source participates in.
    first: u32,
    /// Tick of the queue's front.
    next: u32,
    queue: VecDeque<u32>,
}

/// The hash comparison of 4.2.
#[derive(Clone, Debug)]
pub struct HashCompare {
    sources: BTreeMap<PlayerId, Source>,
    tick: u32,
    found: Option<(Tick, Vec<(PlayerId, u32)>)>,
}

impl Default for HashCompare {
    fn default() -> Self {
        Self::new()
    }
}

impl HashCompare {
    pub fn new() -> Self {
        HashCompare {
            sources: BTreeMap::new(),
            tick: 1,
            found: None,
        }
    }

    /// Registers (or re-registers) a source from tick `first`.
    pub fn add_source(&mut self, p: PlayerId, first: u32) {
        self.sources.insert(
            p,
            Source {
                first,
                next: first,
                queue: VecDeque::new(),
            },
        );
    }

    pub fn remove_source(&mut self, p: PlayerId) {
        self.sources.remove(&p);
    }

    pub fn is_source(&self, p: PlayerId) -> bool {
        self.sources.contains_key(&p)
    }

    /// Sets the comparison tick (a rejoining peer starts at R).
    pub fn start_at(&mut self, tick: u32) {
        self.tick = tick;
    }

    /// How many more hashes the source can queue (cap 900).
    pub fn room(&self, p: PlayerId) -> usize {
        self.sources
            .get(&p)
            .map_or(0, |s| MAX_BUFFERED.saturating_sub(s.queue.len()))
    }

    /// Queues the source's next hash. Returns false if not a source or full.
    pub fn push(&mut self, p: PlayerId, hash: u32) -> bool {
        match self.sources.get_mut(&p) {
            Some(s) if s.queue.len() < MAX_BUFFERED => {
                s.queue.push_back(hash);
                true
            }
            _ => false,
        }
    }

    /// The tick a source's next pushed hash belongs to.
    pub fn next_push_tick(&self, p: PlayerId) -> Option<u32> {
        self.sources
            .get(&p)
            .map(|s| s.next.saturating_add(s.queue.len() as u32))
    }

    /// Runs the comparison as far as it can. Sticky once a divergence is found.
    pub fn check(&mut self) -> Option<&(Tick, Vec<(PlayerId, u32)>)> {
        if self.found.is_some() {
            return self.found.as_ref();
        }
        loop {
            let c = self.tick;
            let participating: Vec<PlayerId> = self
                .sources
                .iter()
                .filter(|(_, s)| s.first <= c)
                .map(|(p, _)| *p)
                .collect();
            if participating.is_empty() {
                let f = self
                    .sources
                    .values()
                    .map(|s| s.first)
                    .filter(|&f| f > c)
                    .min()?;
                self.tick = f;
                continue;
            }
            let mut values = Vec::with_capacity(participating.len());
            for p in &participating {
                let s = self.sources.get_mut(p)?;
                while s.next < c && s.queue.pop_front().is_some() {
                    s.next += 1;
                }
                match s.queue.front() {
                    Some(&h) if s.next == c => values.push((*p, h)),
                    _ => return None,
                }
            }
            let first = values.first().map(|v| v.1);
            if values.iter().all(|v| Some(v.1) == first) {
                for p in &participating {
                    if let Some(s) = self.sources.get_mut(p) {
                        s.queue.pop_front();
                        s.next += 1;
                    }
                }
                self.tick = c.saturating_add(1);
            } else {
                self.found = Some((Tick(c), values));
                return self.found.as_ref();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_finds_first_divergence_and_is_sticky() {
        let mut h = HashCompare::new();
        h.add_source(PlayerId(0), 1);
        h.add_source(PlayerId(1), 1);
        h.add_source(PlayerId(2), 5);
        for t in 1..=6u32 {
            h.push(PlayerId(0), t);
            h.push(PlayerId(1), if t == 6 { 0 } else { t });
            if t >= 5 {
                h.push(PlayerId(2), t);
            }
        }
        let found = h.check().cloned();
        assert_eq!(
            found,
            Some((
                Tick(6),
                vec![(PlayerId(0), 6), (PlayerId(1), 0), (PlayerId(2), 6)]
            ))
        );
        h.push(PlayerId(0), 99);
        assert_eq!(h.check().map(|f| f.0), Some(Tick(6)));
    }

    #[test]
    fn report_text() {
        let d = Desync {
            tick: Tick(10),
            local: PlayerId(1),
            noticed_at: Tick(14),
            hashes: vec![(PlayerId(0), 0x1234_abcd), (PlayerId(1), 0x1234_abce)],
            dump: "{\"a\":1}".into(),
        };
        let r = d.report(Some("x.json"));
        assert!(r.contains("diverged from the other players at tick 10."));
        assert!(r.contains("This peer is player 1, and noticed at tick 14."));
        assert!(r.contains("  player 0  0x1234abcd\n"));
        assert!(r.contains("  player 1  0x1234abce  (this peer)\n"));
        assert!(d.report(None).contains("could not be written"));
        assert_eq!(d.file_name("btm"), "btm-desync-tick10-player1.json");
        assert!(d
            .dump_json("1.0", "abc", "id")
            .ends_with(",\"state\":{\"a\":1}}"));
    }
}
