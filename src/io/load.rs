//! The load handshake of SPEC 3.7 steps 4 and 5, sans-IO: every 100 ms each peer tells
//! every other peer "loading" or "ready" (naming its own seat), and waits until every
//! remote is ready, for at most 120 s. Address following (2.8) applies.

use std::fmt;
use std::time::Duration;

use crate::nat::{Observed, PeerAddrBook};
use crate::types::{Endpoint, Instant, Outgoing, PlayerId};
use crate::wire::{decode_datagram, encode_datagram, LoadStatus, Message};

/// Status messages go out this often (3.7, 8.6).
pub const LOAD_INTERVAL: Duration = Duration::from_millis(100);
/// The handshake gives up after this long (3.7, 8.6).
pub const LOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Something the handshake reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadEvent {
    /// A remote said it is ready (or is already running the lockstep).
    Ready(PlayerId),
    /// A seat's address moved (2.8). Logged once per move.
    Moved {
        seat: PlayerId,
        from: Endpoint,
        to: Endpoint,
    },
}

/// The handshake timed out; [`fmt::Display`] is the message of 3.7 step 5.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadTimeout {
    /// The remotes still not ready, with the address they were expected at.
    pub waiting_for: Vec<(PlayerId, Endpoint)>,
}

impl fmt::Display for LoadTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timed out waiting for other players to finish loading (")?;
        for (i, (p, e)) in self.waiting_for.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "player {} at {e}", p.0)?;
        }
        write!(
            f,
            "). They may have lost the connection, or the address may be wrong."
        )
    }
}

impl std::error::Error for LoadTimeout {}

/// One peer's load handshake.
#[derive(Clone, Debug)]
pub struct LoadHandshake {
    me: PlayerId,
    book: PeerAddrBook,
    ready: Vec<(PlayerId, bool)>,
    started: Instant,
    last_send: Option<Instant>,
    loaded: bool,
}

impl LoadHandshake {
    /// Start at `now` with the remote human seats and their game addresses.
    pub fn new(me: PlayerId, peers: &[(PlayerId, Endpoint)], now: Instant) -> Self {
        let mut book = PeerAddrBook::new();
        let mut ready = Vec::new();
        for &(p, e) in peers {
            if p != me && !ready.iter().any(|(q, _)| *q == p) {
                book.set(p, e);
                ready.push((p, false));
            }
        }
        Self {
            me,
            book,
            ready,
            started: now,
            last_send: None,
            loaded: false,
        }
    }

    /// This peer finished loading; its status becomes "ready".
    pub fn set_loaded(&mut self) {
        if !self.loaded {
            self.loaded = true;
            self.last_send = None;
        }
    }

    /// Where every remote is believed to be now (after address following).
    pub fn addresses(&self) -> &PeerAddrBook {
        &self.book
    }

    /// This peer is loaded and every remote is ready: start the lockstep.
    pub fn is_complete(&self) -> bool {
        self.loaded && self.ready.iter().all(|(_, r)| *r)
    }

    /// The remotes not ready yet, with their current addresses.
    pub fn waiting_for(&self) -> Vec<(PlayerId, Endpoint)> {
        self.ready
            .iter()
            .filter(|(_, r)| !*r)
            .filter_map(|(p, _)| self.book.get(*p).map(|e| (*p, e)))
            .collect()
    }

    /// When [`LoadHandshake::poll`] next has work.
    pub fn next_deadline(&self) -> Instant {
        match self.last_send {
            None => self.started,
            Some(t) => Instant(t.0.saturating_add(LOAD_INTERVAL)),
        }
    }

    /// Send the status when due. Fails once 120 s have passed without completing.
    pub fn poll(&mut self, now: Instant, out: &mut Vec<Outgoing>) -> Result<(), LoadTimeout> {
        if !self.is_complete() && now.0.saturating_sub(self.started.0) >= LOAD_TIMEOUT {
            return Err(LoadTimeout {
                waiting_for: self.waiting_for(),
            });
        }
        if self
            .last_send
            .is_some_and(|t| now < Instant(t.0 + LOAD_INTERVAL))
        {
            return Ok(());
        }
        self.last_send = Some(now);
        let msg = Message::LoadStatus(LoadStatus {
            sender: self.me,
            ready: self.loaded,
        });
        let Ok(bytes) = encode_datagram(&msg) else {
            return Ok(());
        };
        for (_, to) in self.book.iter() {
            out.push(Outgoing {
                to,
                bytes: bytes.clone(),
            });
        }
        Ok(())
    }

    /// Offer a datagram from the game socket. Anything that is not a valid game datagram
    /// from (or followable to) a remote seat is ignored.
    pub fn handle(&mut self, from: Endpoint, bytes: &[u8]) -> Vec<LoadEvent> {
        let mut events = Vec::new();
        let (sender, ready) = match decode_datagram(bytes) {
            Ok(Message::LoadStatus(s)) => (s.sender, s.ready),
            // A lockstep packet means the sender has already started (3.7 step 4).
            Ok(Message::Update(u)) => (u.sender, true),
            Err(_) => return events,
        };
        if sender == self.me {
            return events;
        }
        match self.book.observe(from, Some(sender)) {
            Observed::Known(seat) if seat == sender => {}
            Observed::Known(_) | Observed::Ignored => return events,
            Observed::Moved { seat, from, to } => {
                events.push(LoadEvent::Moved { seat, from, to });
            }
        }
        if ready {
            if let Some(entry) = self.ready.iter_mut().find(|(p, r)| *p == sender && !*r) {
                entry.1 = true;
                events.push(LoadEvent::Ready(sender));
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

    fn ep(port: u16) -> Endpoint {
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), port)
    }

    fn status(sender: u8, ready: bool) -> Vec<u8> {
        encode_datagram(&Message::LoadStatus(LoadStatus {
            sender: PlayerId(sender),
            ready,
        }))
        .unwrap()
    }

    #[test]
    fn completes_when_everyone_is_ready() {
        let t0 = Instant::default();
        let mut h = LoadHandshake::new(
            PlayerId(0),
            &[(PlayerId(1), ep(1)), (PlayerId(2), ep(2))],
            t0,
        );
        let mut out = Vec::new();
        h.poll(t0, &mut out).unwrap();
        assert_eq!(out.len(), 2);
        assert!(!h.is_complete());
        assert!(h.handle(ep(1), &status(1, false)).is_empty());
        assert_eq!(
            h.handle(ep(1), &status(1, true)),
            vec![LoadEvent::Ready(PlayerId(1))]
        );
        // A stranger naming seat 2 from another /16 is ignored.
        let stranger = SocketAddrV4::new(Ipv4Addr::new(99, 0, 0, 1), 2);
        assert!(h.handle(stranger, &status(2, true)).is_empty());
        // Same /16: the address follows.
        let moved = SocketAddrV4::new(Ipv4Addr::new(10, 0, 9, 9), 7);
        let ev = h.handle(moved, &status(2, true));
        assert_eq!(ev.len(), 2);
        assert_eq!(h.addresses().get(PlayerId(2)), Some(moved));
        assert!(!h.is_complete(), "not loaded yet");
        h.set_loaded();
        assert!(h.is_complete());
    }

    #[test]
    fn times_out_with_the_spec_message() {
        let t0 = Instant::default();
        let mut h = LoadHandshake::new(PlayerId(1), &[(PlayerId(0), ep(1337))], t0);
        h.set_loaded();
        let mut out = Vec::new();
        let err = h.poll(Instant(LOAD_TIMEOUT), &mut out).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Timed out waiting for other players to finish loading (player 0 at 10.0.0.1:1337). \
             They may have lost the connection, or the address may be wrong."
        );
    }

    #[test]
    fn resends_every_interval() {
        let t0 = Instant::default();
        let mut h = LoadHandshake::new(PlayerId(1), &[(PlayerId(0), ep(1))], t0);
        let mut out = Vec::new();
        h.poll(t0, &mut out).unwrap();
        h.poll(Instant(Duration::from_millis(50)), &mut out)
            .unwrap();
        assert_eq!(out.len(), 1);
        h.poll(Instant(LOAD_INTERVAL), &mut out).unwrap();
        assert_eq!(out.len(), 2);
    }
}
