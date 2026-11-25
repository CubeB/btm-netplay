//! The two STUN probes (discovery socket and game socket) combined into the traversal
//! status of SPEC 2.3, with keepalive and address-drift events (2.4) and symmetric NAT
//! detection (2.7).
//!
//! There is no `Idle` state here: "idle" is the caller holding no [`Traversal`].

use std::fmt;

use super::stun::{Mapping, ProbeEvent, ProbeState, StunProbe, TransactionId};
use crate::types::{Endpoint, Instant, Outgoing};

/// Which of our sockets a datagram belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socket {
    /// The discovery / lobby socket (UDP 1338 by default).
    Discovery,
    /// The game socket (UDP 1337 by default).
    Game,
}

/// A datagram to send from a given socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub socket: Socket,
    pub out: Outgoing,
}

/// Why traversal failed. [`TraversalFailure::message`] is the sentence shown to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraversalFailure {
    /// No server name resolved.
    NoServers,
    /// The game port could not be bound.
    PortInUse(u16),
    /// No server answered (on one or both sockets).
    NoReply,
    /// A socket's mapping depends on the destination (symmetric NAT).
    Symmetric,
    /// Anything else, with detail.
    Setup(String),
}

impl TraversalFailure {
    pub fn message(&self) -> String {
        match self {
            Self::NoServers => {
                "Cannot look up the address servers; is there an internet connection?".into()
            }
            Self::PortInUse(port) => {
                format!("UDP port {port} is in use; is another game running?")
            }
            Self::NoReply => {
                "No reply from the internet; UDP may be blocked on this connection.".into()
            }
            Self::Symmetric => {
                "This router gives each destination its own port, so direct play cannot work."
                    .into()
            }
            Self::Setup(detail) => format!("Internet connection setup failed: {detail}"),
        }
    }
}

impl fmt::Display for TraversalFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for TraversalFailure {}

/// Traversal status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Probing.
    Working,
    /// Both sockets' outside addresses are known.
    Ready {
        discovery: Endpoint,
        game: Endpoint,
    },
    Failed(TraversalFailure),
}

/// Something for `session` to act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraversalEvent {
    Ready {
        discovery: Endpoint,
        game: Endpoint,
    },
    Failed(TraversalFailure),
    /// A refresh found the discovery socket's outside endpoint moved: the invite (or reply)
    /// code must be regenerated.
    DiscoveryChanged(Endpoint),
    /// The game socket's outside endpoint moved: announce the new game address.
    GameChanged(Endpoint),
}

/// One probe per socket, plus the combined status.
#[derive(Clone, Debug)]
pub struct Traversal {
    discovery: StunProbe,
    game: StunProbe,
    status: Status,
}

impl Traversal {
    /// Start probing at `now` against already-resolved servers (the caller resolves the
    /// names off the UI thread and skips the ones that do not resolve).
    pub fn start(
        servers: &[Endpoint],
        now: Instant,
        rng: &mut dyn FnMut() -> TransactionId,
    ) -> Result<Self, TraversalFailure> {
        if servers.is_empty() {
            return Err(TraversalFailure::NoServers);
        }
        Ok(Self {
            discovery: StunProbe::new(servers, now, rng),
            game: StunProbe::new(servers, now, rng),
            status: Status::Working,
        })
    }

    pub fn status(&self) -> &Status {
        &self.status
    }

    /// The discovery socket's outside endpoint, once known. This is what an invite or
    /// reply code carries.
    pub fn discovery_endpoint(&self) -> Option<Endpoint> {
        match self.status {
            Status::Ready { discovery, .. } => Some(discovery),
            _ => None,
        }
    }

    pub fn game_endpoint(&self) -> Option<Endpoint> {
        match self.status {
            Status::Ready { game, .. } => Some(game),
            _ => None,
        }
    }

    /// The game port could not be bound. Takes precedence over any other failure that has
    /// not already been reported.
    pub fn game_port_in_use(&mut self, port: u16) -> Option<TraversalEvent> {
        if matches!(self.status, Status::Failed(_)) {
            return None;
        }
        let failure = TraversalFailure::PortInUse(port);
        self.status = Status::Failed(failure.clone());
        Some(TraversalEvent::Failed(failure))
    }

    /// The earliest time at which [`Traversal::poll`] has work.
    pub fn next_deadline(&self) -> Option<Instant> {
        if matches!(self.status, Status::Failed(_)) {
            return None;
        }
        match (self.discovery.next_deadline(), self.game.next_deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Advance time. Datagrams go into `sends`; status changes come back as events.
    pub fn poll(
        &mut self,
        now: Instant,
        rng: &mut dyn FnMut() -> TransactionId,
        sends: &mut Vec<Tx>,
    ) -> Vec<TraversalEvent> {
        let mut events = Vec::new();
        if matches!(self.status, Status::Failed(_)) {
            return events;
        }
        let mut out = Vec::new();
        let d = self.discovery.poll(now, rng, &mut out);
        sends.extend(out.drain(..).map(|o| Tx {
            socket: Socket::Discovery,
            out: o,
        }));
        let g = self.game.poll(now, rng, &mut out);
        sends.extend(out.drain(..).map(|o| Tx {
            socket: Socket::Game,
            out: o,
        }));
        self.absorb(Socket::Discovery, d, &mut events);
        self.absorb(Socket::Game, g, &mut events);
        events
    }

    /// Offer a datagram received on `socket`. `None` means it was not a STUN response to
    /// one of our requests and should be handled as something else.
    pub fn handle(
        &mut self,
        socket: Socket,
        now: Instant,
        from: Endpoint,
        bytes: &[u8],
    ) -> Option<Vec<TraversalEvent>> {
        let probe = match socket {
            Socket::Discovery => &mut self.discovery,
            Socket::Game => &mut self.game,
        };
        let handled = probe.handle(now, from, bytes);
        if !handled.accepted {
            return None;
        }
        let mut events = Vec::new();
        if !matches!(self.status, Status::Failed(_)) {
            self.absorb(socket, handled.event, &mut events);
        }
        Some(events)
    }

    fn absorb(
        &mut self,
        socket: Socket,
        event: Option<ProbeEvent>,
        events: &mut Vec<TraversalEvent>,
    ) {
        if let Some(ProbeEvent::Changed(r)) = event {
            // Drift after settling. Keep the stored status current.
            if let Status::Ready { discovery, game } = &mut self.status {
                match socket {
                    Socket::Discovery => {
                        *discovery = r.endpoint;
                        events.push(TraversalEvent::DiscoveryChanged(r.endpoint));
                    }
                    Socket::Game => {
                        *game = r.endpoint;
                        events.push(TraversalEvent::GameChanged(r.endpoint));
                    }
                }
            }
        }
        if self.status == Status::Working {
            if let Some(e) = self.evaluate() {
                events.push(e);
            }
        }
    }

    /// Failure precedence (port unavailable was handled at the call): no answer, then
    /// symmetric mapping.
    fn evaluate(&mut self) -> Option<TraversalEvent> {
        let (ds, gs) = (self.discovery.state(), self.game.state());
        if ds == ProbeState::Failed || gs == ProbeState::Failed {
            let f = TraversalFailure::NoReply;
            self.status = Status::Failed(f.clone());
            return Some(TraversalEvent::Failed(f));
        }
        if ds != ProbeState::Settled || gs != ProbeState::Settled {
            return None;
        }
        let (d, g) = (self.discovery.result()?, self.game.result()?);
        if d.mapping == Mapping::EndpointDependent || g.mapping == Mapping::EndpointDependent {
            let f = TraversalFailure::Symmetric;
            self.status = Status::Failed(f.clone());
            return Some(TraversalEvent::Failed(f));
        }
        self.status = Status::Ready {
            discovery: d.endpoint,
            game: g.endpoint,
        };
        Some(TraversalEvent::Ready {
            discovery: d.endpoint,
            game: g.endpoint,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::nat::stun::{looks_like_stun, MAGIC_COOKIE};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
    }

    fn ms(n: u64) -> Instant {
        Instant(Duration::from_millis(n))
    }

    struct Rng(u8);
    impl Rng {
        fn next(&mut self) -> TransactionId {
            self.0 = self.0.wrapping_add(1);
            [self.0; 12]
        }
    }

    fn reply(request: &[u8], mapped: Endpoint) -> Vec<u8> {
        assert!(looks_like_stun(request));
        let mut m = vec![0x01, 0x01, 0x00, 0x0c];
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&request[8..20]);
        m.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
        m.extend_from_slice(&(mapped.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        m.extend_from_slice(&(u32::from(*mapped.ip()) ^ MAGIC_COOKIE).to_be_bytes());
        m
    }

    fn servers() -> [Endpoint; 2] {
        [ep(74, 125, 1, 1, 19302), ep(162, 159, 1, 1, 3478)]
    }

    /// Answer every send with the endpoint chosen by `mapping(socket, server)`.
    fn answer_all(
        t: &mut Traversal,
        sends: &[Tx],
        now: Instant,
        mapping: &dyn Fn(Socket, Endpoint) -> Option<Endpoint>,
    ) -> Vec<TraversalEvent> {
        let mut events = Vec::new();
        for tx in sends {
            if let Some(m) = mapping(tx.socket, tx.out.to) {
                if let Some(e) = t.handle(tx.socket, now, tx.out.to, &reply(&tx.out.bytes, m)) {
                    events.extend(e);
                }
            }
        }
        events
    }

    #[test]
    fn no_servers() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let e = Traversal::start(&[], ms(0), &mut next).unwrap_err();
        assert_eq!(e, TraversalFailure::NoServers);
        assert!(e
            .message()
            .starts_with("Cannot look up the address servers"));
    }

    #[test]
    fn ready_when_both_sockets_known() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let mut t = Traversal::start(&servers(), ms(0), &mut next).unwrap();
        let mut sends = Vec::new();
        assert!(t.poll(ms(0), &mut next, &mut sends).is_empty());
        assert_eq!(sends.len(), 4);
        assert_eq!(sends.iter().filter(|s| s.socket == Socket::Game).count(), 2);
        let d = ep(203, 0, 113, 5, 40001);
        let g = ep(203, 0, 113, 5, 40002);
        let ev = answer_all(&mut t, &sends, ms(40), &|s, _| {
            Some(if s == Socket::Discovery { d } else { g })
        });
        assert_eq!(
            ev,
            vec![TraversalEvent::Ready {
                discovery: d,
                game: g
            }]
        );
        assert_eq!(
            t.status(),
            &Status::Ready {
                discovery: d,
                game: g
            }
        );
        assert_eq!(t.discovery_endpoint(), Some(d));
        assert_eq!(t.game_endpoint(), Some(g));
    }

    #[test]
    fn symmetric_nat_fails_with_message() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let mut t = Traversal::start(&servers(), ms(0), &mut next).unwrap();
        let mut sends = Vec::new();
        t.poll(ms(0), &mut next, &mut sends);
        let ev = answer_all(&mut t, &sends, ms(40), &|s, srv| {
            // Game socket gets a different port per destination.
            Some(if s == Socket::Discovery {
                ep(203, 0, 113, 5, 40001)
            } else {
                ep(203, 0, 113, 5, 50000 + srv.port() % 1000)
            })
        });
        assert_eq!(
            ev,
            vec![TraversalEvent::Failed(TraversalFailure::Symmetric)]
        );
        assert_eq!(
            TraversalFailure::Symmetric.to_string(),
            "This router gives each destination its own port, so direct play cannot work."
        );
        // Failed: no more sends.
        sends.clear();
        assert!(t.poll(ms(9000), &mut next, &mut sends).is_empty());
        assert!(sends.is_empty());
    }

    #[test]
    fn no_reply_after_timeout() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let mut t = Traversal::start(&servers(), ms(0), &mut next).unwrap();
        let mut sends = Vec::new();
        t.poll(ms(0), &mut next, &mut sends);
        assert!(t.poll(ms(3999), &mut next, &mut sends).is_empty());
        let ev = t.poll(ms(4000), &mut next, &mut sends);
        assert_eq!(ev, vec![TraversalEvent::Failed(TraversalFailure::NoReply)]);
        assert!(TraversalFailure::NoReply
            .message()
            .starts_with("No reply from the internet"));
    }

    #[test]
    fn one_socket_silent_is_no_reply() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let mut t = Traversal::start(&servers(), ms(0), &mut next).unwrap();
        let mut sends = Vec::new();
        t.poll(ms(0), &mut next, &mut sends);
        let ev = answer_all(&mut t, &sends, ms(40), &|s, _| {
            (s == Socket::Discovery).then(|| ep(203, 0, 113, 5, 40001))
        });
        assert!(ev.is_empty());
        let ev = t.poll(ms(4000), &mut next, &mut sends);
        assert_eq!(ev, vec![TraversalEvent::Failed(TraversalFailure::NoReply)]);
    }

    #[test]
    fn port_in_use_takes_precedence() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let mut t = Traversal::start(&servers(), ms(0), &mut next).unwrap();
        let ev = t.game_port_in_use(1337);
        assert_eq!(
            ev,
            Some(TraversalEvent::Failed(TraversalFailure::PortInUse(1337)))
        );
        assert_eq!(
            TraversalFailure::PortInUse(1337).message(),
            "UDP port 1337 is in use; is another game running?"
        );
        assert_eq!(t.game_port_in_use(1337), None);
        assert_eq!(t.next_deadline(), None);
    }

    #[test]
    fn drift_after_ready_is_reported() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let mut t = Traversal::start(&servers(), ms(0), &mut next).unwrap();
        let mut sends = Vec::new();
        t.poll(ms(0), &mut next, &mut sends);
        let d = ep(203, 0, 113, 5, 40001);
        let g = ep(203, 0, 113, 5, 40002);
        let pick = |s: Socket, _| Some(if s == Socket::Discovery { d } else { g });
        answer_all(&mut t, &sends, ms(40), &pick);
        // Keepalive: refresh after 4 s, both sockets, both servers.
        sends.clear();
        assert!(t.poll(ms(4039), &mut next, &mut sends).is_empty());
        assert!(sends.is_empty());
        assert_eq!(t.next_deadline(), Some(ms(4040)));
        t.poll(ms(4040), &mut next, &mut sends);
        assert_eq!(sends.len(), 4);
        // Discovery moved; game did not.
        let d2 = ep(203, 0, 113, 5, 41001);
        let ev = answer_all(&mut t, &sends, ms(4100), &|s, _| {
            Some(if s == Socket::Discovery { d2 } else { g })
        });
        assert_eq!(ev, vec![TraversalEvent::DiscoveryChanged(d2)]);
        assert_eq!(t.discovery_endpoint(), Some(d2));
        assert_eq!(t.game_endpoint(), Some(g));
    }

    #[test]
    fn non_stun_is_not_consumed() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let mut t = Traversal::start(&servers(), ms(0), &mut next).unwrap();
        assert!(t
            .handle(Socket::Discovery, ms(1), servers()[0], b"lobby text")
            .is_none());
    }
}
