//! Punching (SPEC 2.5): while the lobby is up, the game socket sends a small fixed punch
//! datagram to every seated remote network peer every 400 ms. Both sides doing this
//! concurrently opens both routers.
//!
//! The state machine here is per remote endpoint: [`PunchState::Punching`] until a punch
//! datagram arrives from that endpoint's IP, then [`PunchState::Reachable`]. Punches keep
//! going after that (they keep the mapping alive until the game starts).

use std::time::Duration;

use super::{after, HeardSources};
use crate::types::{Endpoint, Instant, Outgoing};

/// Punch datagrams are sent this often.
pub const PUNCH_INTERVAL: Duration = Duration::from_millis(400);
/// At most this many targets, and this many remembered punch sources.
pub const MAX_PUNCH: usize = 16;

/// The fixed punch datagram. The first byte is outside ASCII and has top bits `10`, so it
/// is neither lobby text nor STUN nor a (CRC-suffixed) game datagram by shape.
pub const PUNCH_DATAGRAM: [u8; 7] = [0xB7, b'P', b'U', b'N', b'C', b'H', 1];

/// Whether a datagram received on the game socket is a punch.
pub fn is_punch(bytes: &[u8]) -> bool {
    bytes == PUNCH_DATAGRAM
}

/// Progress towards one remote peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PunchState {
    /// Sending punches, nothing heard back yet.
    Punching,
    /// A punch arrived from this peer's IP: direct traffic works.
    Reachable,
}

/// What [`Puncher`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PunchEvent {
    /// A punch arrived from a source not seen before (any source, seated or not).
    SourceHeard { from: Endpoint },
    /// `target` is now reachable directly: the first punch from its IP arrived from
    /// `from` ("<name> is reachable directly").
    Reachable { target: Endpoint, from: Endpoint },
}

#[derive(Clone, Copy, Debug)]
struct Target {
    addr: Endpoint,
    state: PunchState,
    sent: u32,
}

/// The punch scheduler and per-target state.
#[derive(Clone, Debug)]
pub struct Puncher {
    targets: Vec<Target>,
    next_send: Option<Instant>,
    sources: HeardSources,
}

impl Default for Puncher {
    fn default() -> Self {
        Self::new()
    }
}

impl Puncher {
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
            next_send: None,
            sources: HeardSources::new(MAX_PUNCH),
        }
    }

    /// Replace the target list with the game addresses of the seated remote network
    /// peers (duplicates dropped, at most [`MAX_PUNCH`]). Targets kept from before keep
    /// their state; if any target is new, the next [`Puncher::poll`] sends immediately.
    ///
    /// A new target whose IP was already heard punching is reachable at once; that is
    /// reported in the returned events.
    pub fn set_targets(&mut self, targets: &[Endpoint]) -> Vec<PunchEvent> {
        let mut list: Vec<Target> = Vec::new();
        let mut events = Vec::new();
        let mut any_new = false;
        for &addr in targets {
            if list.len() >= MAX_PUNCH || list.iter().any(|t| t.addr == addr) {
                continue;
            }
            if let Some(old) = self.targets.iter().find(|t| t.addr == addr) {
                list.push(*old);
                continue;
            }
            any_new = true;
            let heard = self
                .sources
                .as_slice()
                .iter()
                .find(|s| s.ip() == addr.ip())
                .copied();
            let state = match heard {
                Some(from) => {
                    events.push(PunchEvent::Reachable { target: addr, from });
                    PunchState::Reachable
                }
                None => PunchState::Punching,
            };
            list.push(Target {
                addr,
                state,
                sent: 0,
            });
        }
        self.targets = list;
        if any_new {
            self.next_send = None;
        }
        events
    }

    pub fn targets(&self) -> impl Iterator<Item = Endpoint> + '_ {
        self.targets.iter().map(|t| t.addr)
    }

    pub fn state(&self, target: Endpoint) -> Option<PunchState> {
        self.targets
            .iter()
            .find(|t| t.addr == target)
            .map(|t| t.state)
    }

    /// Whether `target` is reachable directly.
    pub fn is_reachable(&self, target: Endpoint) -> bool {
        self.state(target) == Some(PunchState::Reachable)
    }

    /// Punches sent to `target` so far.
    pub fn sent(&self, target: Endpoint) -> u32 {
        self.targets
            .iter()
            .find(|t| t.addr == target)
            .map_or(0, |t| t.sent)
    }

    /// Every punch source heard (up to 16), oldest first.
    pub fn sources(&self) -> &[Endpoint] {
        self.sources.as_slice()
    }

    /// When [`Puncher::poll`] next has something to send. `None` with no targets.
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.targets.is_empty() {
            return None;
        }
        Some(self.next_send.unwrap_or_default())
    }

    /// Send the punches that are due: all targets at once, then again every 400 ms.
    pub fn poll(&mut self, now: Instant, out: &mut Vec<Outgoing>) {
        if self.targets.is_empty() {
            return;
        }
        if self.next_send.is_some_and(|t| now < t) {
            return;
        }
        for t in &mut self.targets {
            out.push(Outgoing {
                to: t.addr,
                bytes: PUNCH_DATAGRAM.to_vec(),
            });
            t.sent = t.sent.saturating_add(1);
        }
        self.next_send = Some(after(now, PUNCH_INTERVAL));
    }

    /// Offer a datagram received on the game socket. Returns the events it caused; empty
    /// (and nothing recorded) if it is not a punch.
    pub fn handle(&mut self, from: Endpoint, bytes: &[u8]) -> Vec<PunchEvent> {
        let mut events = Vec::new();
        if !is_punch(bytes) {
            return events;
        }
        if self.sources.record(from) != super::Heard::Seen {
            events.push(PunchEvent::SourceHeard { from });
        }
        for t in &mut self.targets {
            if t.state == PunchState::Punching && t.addr.ip() == from.ip() {
                t.state = PunchState::Reachable;
                events.push(PunchEvent::Reachable {
                    target: t.addr,
                    from,
                });
            }
        }
        events
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
    }

    fn ms(n: u64) -> Instant {
        Instant(Duration::from_millis(n))
    }

    #[test]
    fn schedule_every_400ms() {
        let mut p = Puncher::new();
        let a = ep(1, 1, 1, 1, 1337);
        let b = ep(2, 2, 2, 2, 41000);
        assert_eq!(p.next_deadline(), None);
        p.set_targets(&[a, b]);
        assert_eq!(p.next_deadline(), Some(ms(0)));
        let mut out = Vec::new();
        p.poll(ms(1000), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].to, a);
        assert_eq!(out[0].bytes, PUNCH_DATAGRAM.to_vec());
        assert_eq!(out[1].to, b);
        assert_eq!(p.next_deadline(), Some(ms(1400)));
        out.clear();
        p.poll(ms(1399), &mut out);
        assert!(out.is_empty());
        p.poll(ms(1400), &mut out);
        assert_eq!(out.len(), 2);
        out.clear();
        p.poll(ms(1800), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(p.sent(a), 3);
        assert_eq!(p.sent(ep(9, 9, 9, 9, 9)), 0);
    }

    #[test]
    fn new_target_punches_at_once_and_old_state_kept() {
        let mut p = Puncher::new();
        let a = ep(1, 1, 1, 1, 1337);
        let b = ep(2, 2, 2, 2, 1337);
        p.set_targets(&[a]);
        let mut out = Vec::new();
        p.poll(ms(0), &mut out);
        p.handle(ep(1, 1, 1, 1, 999), &PUNCH_DATAGRAM);
        assert!(p.is_reachable(a));
        out.clear();
        p.set_targets(&[a, b]);
        p.poll(ms(100), &mut out);
        assert_eq!(out.len(), 2);
        assert!(p.is_reachable(a));
        assert_eq!(p.state(b), Some(PunchState::Punching));
        // Removing a target stops punching it.
        p.set_targets(&[b]);
        out.clear();
        p.poll(ms(500), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, b);
        assert_eq!(p.state(a), None);
    }

    #[test]
    fn reachable_by_ip_even_from_another_port() {
        let mut p = Puncher::new();
        let a = ep(1, 1, 1, 1, 1337);
        p.set_targets(&[a]);
        let from = ep(1, 1, 1, 1, 52000);
        let ev = p.handle(from, &PUNCH_DATAGRAM);
        assert_eq!(
            ev,
            vec![
                PunchEvent::SourceHeard { from },
                PunchEvent::Reachable { target: a, from }
            ]
        );
        // Announced once only.
        assert!(p.handle(from, &PUNCH_DATAGRAM).is_empty());
        assert!(p
            .handle(ep(1, 1, 1, 1, 52001), &PUNCH_DATAGRAM)
            .iter()
            .all(|e| matches!(e, PunchEvent::SourceHeard { .. })));
        // Punches keep flowing once reachable.
        let mut out = Vec::new();
        p.poll(ms(0), &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn stranger_and_non_punch_do_not_count() {
        let mut p = Puncher::new();
        let a = ep(1, 1, 1, 1, 1337);
        p.set_targets(&[a]);
        let ev = p.handle(ep(3, 3, 3, 3, 1), &PUNCH_DATAGRAM);
        assert_eq!(
            ev,
            vec![PunchEvent::SourceHeard {
                from: ep(3, 3, 3, 3, 1)
            }]
        );
        assert!(!p.is_reachable(a));
        assert!(p.handle(a, b"not a punch").is_empty());
        assert!(p.handle(a, &[]).is_empty());
        assert!(!p.is_reachable(a));
        assert_eq!(p.sources().len(), 1);
    }

    #[test]
    fn punch_heard_before_seating_is_reported_at_seating() {
        let mut p = Puncher::new();
        let from = ep(5, 5, 5, 5, 40000);
        p.handle(from, &PUNCH_DATAGRAM);
        let a = ep(5, 5, 5, 5, 40000);
        let ev = p.set_targets(&[a]);
        assert_eq!(ev, vec![PunchEvent::Reachable { target: a, from }]);
        assert!(p.is_reachable(a));
    }

    #[test]
    fn limits() {
        let mut p = Puncher::new();
        let targets: Vec<Endpoint> = (0..40).map(|i| ep(10, 0, 0, i, 1337)).collect();
        p.set_targets(&targets);
        assert_eq!(p.targets().count(), MAX_PUNCH);
        // Duplicates collapse.
        p.set_targets(&[targets[0], targets[0]]);
        assert_eq!(p.targets().count(), 1);
        for i in 0..40u8 {
            p.handle(ep(11, 0, 0, i, 1), &PUNCH_DATAGRAM);
        }
        assert_eq!(p.sources().len(), MAX_PUNCH);
    }

    #[test]
    fn fuzz_handle_never_panics() {
        let mut x: u64 = 0x1234_5678_9ABC_DEF1;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut p = Puncher::new();
        p.set_targets(&[ep(1, 1, 1, 1, 1)]);
        for _ in 0..5000 {
            let len = (next() % 12) as usize;
            let b: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = p.handle(ep(1, 1, 1, 1, 1), &b);
        }
        for n in 0..PUNCH_DATAGRAM.len() {
            assert!(!is_punch(&PUNCH_DATAGRAM[..n]));
        }
    }
}
