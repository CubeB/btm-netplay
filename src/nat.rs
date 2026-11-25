//! NAT traversal, punching and LAN discovery (SPEC 2.3 to 2.5, 2.7, 2.8, 2.10).
//!
//! Everything here is sans-IO: no sockets, no clock. The caller owns the sockets, passes
//! the current [`Instant`], hands in received datagrams with their source, and sends the
//! [`Outgoing`] datagrams it gets back from the socket the part says they belong to.
//! Randomness (STUN transaction ids) comes in as a closure.
//!
//! # Parts
//!
//! * [`stun`]: RFC 5389 Binding codec and [`stun::StunProbe`], the per-socket multi-server
//!   probe with settle, timeout, keepalive refresh and mapping classification.
//! * [`traversal`]: [`traversal::Traversal`], the two probes (discovery socket and game
//!   socket) combined into the idle / working / ready / failed status of 2.3, with the
//!   user-visible failure sentences and drift events (2.4).
//! * [`punch`]: [`punch::Puncher`], the 400 ms punch schedule and "reachable directly".
//! * [`lan`]: LAN announcements, probes, expiry, typed-address parsing and the host-name
//!   cache of 2.10.
//! * This module: the address rules of 2.8 ([`initial_peer_address`], [`PeerAddrBook`])
//!   and [`HeardSources`] ("every source address heard").
//!
//! # Boundary with `session`
//!
//! The host-approval flow (2.9) is owned by `session`. This crate part only supplies what
//! it needs:
//!
//! * [`HeardSources::record`] says whether a datagram on the discovery socket is the first
//!   from an IP (for "Hearing from a.b.c.d:p");
//! * [`punch::Puncher`] reports the first punch from a seated player's IP (for
//!   "<name> is reachable directly");
//! * [`traversal::Traversal`] reports the outside discovery endpoint, which `session`
//!   turns into an invite or reply code with [`crate::invite`], and tells it when that
//!   endpoint changed;
//! * [`lan::Announcer`] sends whatever announcement text `session` builds (3.1), to the
//!   broadcast, loopback and explicit targets, and answers probes; reply-code targets are
//!   added with [`lan::Announcer::add_target`].
//!
//! Pre-approval by reply code, claim tokens, seating and chat are not here.

pub mod lan;
pub mod punch;
pub mod stun;
pub mod traversal;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::types::{Endpoint, Instant, PlayerId};

/// Time `later` minus `earlier`, saturating at zero.
pub(crate) fn elapsed(later: Instant, earlier: Instant) -> Duration {
    later.0.saturating_sub(earlier.0)
}

/// `at` plus `d`.
pub(crate) fn after(at: Instant, d: Duration) -> Instant {
    Instant(at.0.saturating_add(d))
}

/// Whether we may send to this endpoint: a real unicast address and a non-zero port.
/// Used to reject addresses that STUN servers (or strangers) report.
pub fn is_sendable(ep: Endpoint) -> bool {
    let ip = ep.ip();
    ep.port() != 0 && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

/// Whether two addresses share their first two octets (IPv4 "same /16").
pub fn same_slash16(a: Ipv4Addr, b: Ipv4Addr) -> bool {
    let (a, b) = (a.octets(), b.octets());
    a[0] == b[0] && a[1] == b[1]
}

/// Where a peer is first believed to be (SPEC 2.8): the game address it announced if that
/// is in the same /16 as `lobby_source` (where its lobby datagrams came from); otherwise
/// the lobby source IP with `game_port` (the announced game port).
///
/// Whether to trust `announced` at all is the caller's rule (the host always does, a guest
/// only when it joined via a code); pass `None` when it should not.
pub fn initial_peer_address(
    announced: Option<Endpoint>,
    lobby_source: Endpoint,
    game_port: u16,
) -> Endpoint {
    match announced {
        Some(a) if same_slash16(*a.ip(), *lobby_source.ip()) => a,
        _ => SocketAddrV4::new(*lobby_source.ip(), game_port),
    }
}

/// What [`PeerAddrBook::observe`] decided about a datagram's source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// The source address is assigned to this seat.
    Known(PlayerId),
    /// The source was unknown but named a seat whose address is in the same /16, so the
    /// seat's address moved. Log once per move.
    Moved {
        seat: PlayerId,
        from: Endpoint,
        to: Endpoint,
    },
    /// Anything else from an unknown address: ignore silently.
    Ignored,
}

/// Seat to address table with the address-following rule of SPEC 2.8, shared by the load
/// handshake and the lockstep.
///
/// The caller must already have checked the datagram's integrity and parsed it; this is
/// not authentication. For a [`Observed::Known`] result the caller still compares the
/// datagram's claimed seat with the returned one ("must match the link").
#[derive(Clone, Debug, Default)]
pub struct PeerAddrBook {
    entries: Vec<(PlayerId, Endpoint)>,
}

impl PeerAddrBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign (or reassign) a seat's address.
    pub fn set(&mut self, seat: PlayerId, addr: Endpoint) {
        match self.entries.iter_mut().find(|(s, _)| *s == seat) {
            Some(entry) => entry.1 = addr,
            None => self.entries.push((seat, addr)),
        }
    }

    pub fn remove(&mut self, seat: PlayerId) {
        self.entries.retain(|(s, _)| *s != seat);
    }

    pub fn get(&self, seat: PlayerId) -> Option<Endpoint> {
        self.entries
            .iter()
            .find(|(s, _)| *s == seat)
            .map(|(_, a)| *a)
    }

    /// The seat whose address is exactly `addr`.
    pub fn seat_of(&self, addr: Endpoint) -> Option<PlayerId> {
        self.entries
            .iter()
            .find(|(_, a)| *a == addr)
            .map(|(s, _)| *s)
    }

    pub fn iter(&self) -> impl Iterator<Item = (PlayerId, Endpoint)> + '_ {
        self.entries.iter().copied()
    }

    /// Classify a datagram that passed integrity and parsing, from `source`, naming
    /// `claimed_seat` as its sender, and apply an address move if the rule allows one.
    pub fn observe(&mut self, source: Endpoint, claimed_seat: Option<PlayerId>) -> Observed {
        if let Some(seat) = self.seat_of(source) {
            return Observed::Known(seat);
        }
        let Some(seat) = claimed_seat else {
            return Observed::Ignored;
        };
        let Some(current) = self.get(seat) else {
            return Observed::Ignored;
        };
        if !same_slash16(*current.ip(), *source.ip()) {
            return Observed::Ignored;
        }
        self.set(seat, source);
        Observed::Moved {
            seat,
            from: current,
            to: source,
        }
    }
}

/// How new a heard source address was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Heard {
    /// First datagram from this IP: the moment to say "Hearing from a.b.c.d:p".
    NewIp,
    /// A known IP on a new port.
    NewEndpoint,
    /// Already recorded.
    Seen,
}

/// A bounded record of source addresses heard, oldest forgotten first (SPEC 2.10 keeps 32
/// for the discovery socket, 2.5 keeps 16 for punch sources).
#[derive(Clone, Debug)]
pub struct HeardSources {
    cap: usize,
    list: Vec<Endpoint>,
}

impl HeardSources {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            list: Vec::new(),
        }
    }

    pub fn record(&mut self, from: Endpoint) -> Heard {
        if self.list.contains(&from) {
            return Heard::Seen;
        }
        let new_ip = !self.list.iter().any(|e| e.ip() == from.ip());
        if self.list.len() >= self.cap {
            self.list.remove(0);
        }
        self.list.push(from);
        if new_ip {
            Heard::NewIp
        } else {
            Heard::NewEndpoint
        }
    }

    pub fn contains(&self, from: Endpoint) -> bool {
        self.list.contains(&from)
    }

    pub fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        self.list.iter().any(|e| *e.ip() == ip)
    }

    /// Sources in the order first heard (oldest first).
    pub fn as_slice(&self) -> &[Endpoint] {
        &self.list
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
    }

    #[test]
    fn sendable() {
        assert!(is_sendable(ep(8, 8, 8, 8, 1)));
        assert!(!is_sendable(ep(8, 8, 8, 8, 0)));
        assert!(!is_sendable(ep(0, 0, 0, 0, 5)));
        assert!(!is_sendable(ep(224, 1, 1, 1, 5)));
        assert!(!is_sendable(ep(255, 255, 255, 255, 5)));
    }

    #[test]
    fn slash16() {
        assert!(same_slash16(
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(10, 1, 200, 9)
        ));
        assert!(!same_slash16(
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(10, 2, 2, 3)
        ));
    }

    #[test]
    fn initial_address_rules() {
        let src = ep(100, 64, 1, 1, 1338);
        // Same /16: the announced game address wins, including its IP.
        let ann = ep(100, 64, 77, 5, 41000);
        assert_eq!(initial_peer_address(Some(ann), src, 1337), ann);
        // Different /16: source IP with the announced game port.
        let far = ep(100, 65, 77, 5, 41000);
        assert_eq!(
            initial_peer_address(Some(far), src, 1337),
            ep(100, 64, 1, 1, 1337)
        );
        // Nothing announced.
        assert_eq!(
            initial_peer_address(None, src, 6670),
            ep(100, 64, 1, 1, 6670)
        );
    }

    #[test]
    fn address_following() {
        let mut book = PeerAddrBook::new();
        book.set(PlayerId(0), ep(1, 1, 1, 1, 1337));
        book.set(PlayerId(1), ep(20, 30, 1, 1, 5000));
        // Known source.
        assert_eq!(
            book.observe(ep(1, 1, 1, 1, 1337), Some(PlayerId(0))),
            Observed::Known(PlayerId(0))
        );
        // Unknown, same /16 as seat 1: moves.
        let new = ep(20, 30, 9, 9, 6000);
        assert_eq!(
            book.observe(new, Some(PlayerId(1))),
            Observed::Moved {
                seat: PlayerId(1),
                from: ep(20, 30, 1, 1, 5000),
                to: new
            }
        );
        assert_eq!(book.get(PlayerId(1)), Some(new));
        assert_eq!(book.seat_of(new), Some(PlayerId(1)));
        // Unknown, different /16, no seat, or an unseated seat: ignored.
        assert_eq!(
            book.observe(ep(99, 99, 1, 1, 1), Some(PlayerId(1))),
            Observed::Ignored
        );
        assert_eq!(book.observe(ep(20, 30, 9, 8, 1), None), Observed::Ignored);
        assert_eq!(
            book.observe(ep(20, 30, 9, 8, 1), Some(PlayerId(5))),
            Observed::Ignored
        );
        book.remove(PlayerId(1));
        assert_eq!(book.get(PlayerId(1)), None);
    }

    #[test]
    fn heard_sources() {
        let mut h = HeardSources::new(2);
        assert_eq!(h.record(ep(1, 1, 1, 1, 10)), Heard::NewIp);
        assert_eq!(h.record(ep(1, 1, 1, 1, 10)), Heard::Seen);
        assert_eq!(h.record(ep(1, 1, 1, 1, 11)), Heard::NewEndpoint);
        // Capacity 2: the oldest is forgotten.
        assert_eq!(h.record(ep(2, 2, 2, 2, 1)), Heard::NewIp);
        assert_eq!(h.as_slice().len(), 2);
        assert!(!h.contains(ep(1, 1, 1, 1, 10)));
        assert!(h.contains_ip(Ipv4Addr::new(1, 1, 1, 1)));
    }
}
