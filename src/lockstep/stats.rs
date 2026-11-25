//! Network overlay metrics (section 6). Sampled whether or not shown.

use std::collections::VecDeque;
use std::time::Duration;

use crate::types::{Instant, PlayerId, Tick};

/// Overlay sample interval (8.6).
pub const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);
/// Samples kept per graph (8.6).
pub const SAMPLE_HISTORY: usize = 120;

/// The centred caption (1.5, 1.7, 5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caption {
    /// "WAITING FOR <names>", with "DROPPING IN n" if a countdown runs.
    Waiting {
        players: Vec<PlayerId>,
        dropping_in: Option<u32>,
    },
    /// "SLOWED FOR <names>".
    Slowed { players: Vec<PlayerId> },
}

/// One remote peer's overlay block.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerStats {
    pub player: PlayerId,
    pub name: String,
    pub dropped: bool,
    /// ms since any packet from them.
    pub quiet_ms: u32,
    /// Their projected scene time (projection capped at 200 ms) minus ours.
    pub tick_delta: i64,
    /// Own sets sent to them not yet acknowledged.
    pub unacked: usize,
    /// Smoothed RTT.
    pub rtt_ms: u32,
    /// Smoothed deviation ("jitter").
    pub jitter_ms: u32,
    /// Min and max smoothed RTT over the last 50 samples.
    pub rtt_min_max: Option<(u32, u32)>,
    /// "rtt >= N ms, no ack": set when acks have stopped (6).
    pub no_ack_bound_ms: Option<u32>,
    /// Their sets this machine holds ready to run.
    pub buffered: usize,
}

/// Worst values for one peer during one sample interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerSample {
    pub player: PlayerId,
    pub rtt_ms: u32,
    pub quiet_ms: u32,
    pub buffered: usize,
}

/// One 250 ms sample.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Sample {
    /// Ticks run during the interval.
    pub ticks: u32,
    /// ms spent stalled during the interval.
    pub stalled_ms: u32,
    pub peers: Vec<PeerSample>,
}

/// The overlay snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct Stats {
    pub tick: Tick,
    /// Ticks run per second over the last second of samples.
    pub ticks_per_s: f64,
    /// E = 30 x chosen speed.
    pub expected_ticks_per_s: f64,
    pub paused: bool,
    pub chosen_speed: u16,
    pub effective_speed: u16,
    pub capacity: u16,
    /// Order delay D (1.4) and D x 33 ms.
    pub order_delay: u32,
    pub order_delay_ms: u32,
    /// Worst smoothed RTT and deviation.
    pub rtt_ms: u32,
    pub jitter_ms: u32,
    /// Stalls of at least 33 ms, and the longest.
    pub stalls: u32,
    pub longest_stall_ms: u32,
    /// Total stalled time, short stalls included.
    pub stalled_total_ms: u64,
    /// Set while the current stall is at least 33 ms.
    pub stalled_ms: Option<u32>,
    /// Players with empty buffers at the last blocked attempt.
    pub waiting_for: Vec<PlayerId>,
    pub last_stall_waited_for: Vec<PlayerId>,
    pub no_remote_players: bool,
    /// Ticks discarded by the per-frame cap.
    pub lost_to_cap: u64,
    pub caption: Option<Caption>,
    pub peers: Vec<PeerStats>,
    /// Oldest first, at most 120.
    pub history: Vec<Sample>,
}

/// Accumulates the worst values of the current interval and keeps the history.
#[derive(Clone, Debug, Default)]
pub struct Sampler {
    started: Option<Instant>,
    current: Sample,
    history: VecDeque<Sample>,
}

impl Sampler {
    pub fn add_ticks(&mut self, n: u32) {
        self.current.ticks = self.current.ticks.saturating_add(n);
    }

    pub fn add_stalled(&mut self, d: Duration) {
        let ms = u32::try_from(d.as_millis()).unwrap_or(u32::MAX);
        self.current.stalled_ms = self.current.stalled_ms.saturating_add(ms);
    }

    pub fn observe_peer(&mut self, s: PeerSample) {
        match self.current.peers.iter_mut().find(|p| p.player == s.player) {
            Some(p) => {
                p.rtt_ms = p.rtt_ms.max(s.rtt_ms);
                p.quiet_ms = p.quiet_ms.max(s.quiet_ms);
                p.buffered = p.buffered.min(s.buffered);
            }
            None => self.current.peers.push(s),
        }
    }

    /// Closes intervals that have elapsed.
    pub fn roll(&mut self, now: Instant) {
        let Some(start) = self.started else {
            self.started = Some(now);
            return;
        };
        if now.0.saturating_sub(start.0) >= SAMPLE_INTERVAL {
            if self.history.len() >= SAMPLE_HISTORY {
                self.history.pop_front();
            }
            self.history.push_back(std::mem::take(&mut self.current));
            self.started = Some(
                Instant(start.0 + SAMPLE_INTERVAL)
                    .max(Instant(now.0.saturating_sub(SAMPLE_INTERVAL))),
            );
        }
    }

    pub fn history(&self) -> Vec<Sample> {
        self.history.iter().cloned().collect()
    }

    /// Ticks per second over the last four samples.
    pub fn ticks_per_s(&self) -> f64 {
        let n = self.history.len().min(4);
        if n == 0 {
            return 0.0;
        }
        let ticks: u32 = self.history.iter().rev().take(n).map(|s| s.ticks).sum();
        f64::from(ticks) / (n as f64 * SAMPLE_INTERVAL.as_secs_f64())
    }
}
