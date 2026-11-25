//! A host and two guests on real localhost UDP sockets, in one process, from the lobby
//! through the load handshake to 300 ticks of lockstep with identical hashes: directly,
//! with every datagram going through an in-process relay, and mixed (one guest direct, one
//! that can only use the relay). And a guest that drops out and rejoins.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant as StdInstant};

use btm_netplay::io::toy::ToyEngine;
use btm_netplay::io::{
    Datagram, Event, Node, NodeConfig, Phase, Rng, Role, Socket, Stun, Transport, TransportError,
    TransportEvent, UdpTransport,
};
use btm_netplay::relay::{is_synthetic, RelayConfig, RelayLink, RelayServer};
use btm_netplay::session::SeatKind;
use btm_netplay::types::{Endpoint, Instant, Outgoing, PlayerId, Tick};

const TICKS: u32 = 300;

fn config(name: &str, drop_timeout: Duration) -> NodeConfig {
    let mut c = NodeConfig::new(name);
    c.bind_ip = Ipv4Addr::LOCALHOST;
    c.discovery_port = 0;
    c.game_port = 0;
    c.stun = Stun::Off;
    c.drop_timeout = drop_timeout;
    c
}

/// A relay server on a real socket, pumped by the test loop.
struct Relay {
    sock: UdpSocket,
    server: RelayServer,
    origin: StdInstant,
}

impl Relay {
    fn new() -> Self {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        sock.set_nonblocking(true).unwrap();
        let server = RelayServer::new(RelayConfig::default(), [7; 32]).unwrap();
        Self {
            sock,
            server,
            origin: StdInstant::now(),
        }
    }

    fn addr(&self) -> SocketAddrV4 {
        match self.sock.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            std::net::SocketAddr::V6(_) => panic!(),
        }
    }

    fn pump(&mut self) {
        let now = Instant(self.origin.elapsed());
        let mut buf = [0u8; 2048];
        let mut out: Vec<Outgoing> = Vec::new();
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((n, std::net::SocketAddr::V4(from))) => {
                    self.server.handle(now, from, &buf[..n], &mut out);
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(_) => break,
            }
        }
        self.server.poll(now);
        for o in out {
            let _ = self.sock.send_to(&o.bytes, o.to);
        }
    }
}

/// Real sockets, optionally cut off from every direct path: with `relay_only`, datagrams to
/// and from real addresses are dropped, so only the relay works (a symmetric NAT, say).
struct Filtered {
    inner: UdpTransport,
    relay_only: bool,
}

impl Transport for Filtered {
    fn local_port(&self, socket: Socket) -> Option<u16> {
        self.inner.local_port(socket)
    }

    fn send(&mut self, socket: Socket, out: &Outgoing) -> Result<(), TransportError> {
        if self.relay_only && !is_synthetic(out.to) {
            return Ok(());
        }
        self.inner.send(socket, out)
    }

    fn recv(&mut self, now: Instant) -> Result<Option<Datagram>, TransportError> {
        loop {
            match self.inner.recv(now)? {
                Some(d) if self.relay_only && !is_synthetic(d.from) => continue,
                other => return Ok(other),
            }
        }
    }

    fn rebind_game(&mut self) -> Result<(), TransportError> {
        self.inner.rebind_game()
    }

    fn close_discovery(&mut self) {
        self.inner.close_discovery();
    }

    fn poll(&mut self, now: Instant) -> Vec<TransportEvent> {
        self.inner.poll(now)
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.inner.next_deadline()
    }

    fn open_relay(&mut self, link: RelayLink) -> Result<(), TransportError> {
        self.inner.open_relay(link)
    }

    fn relay_link(&self) -> Option<&RelayLink> {
        self.inner.relay_link()
    }

    fn max_datagram_to(&self, to: Endpoint) -> usize {
        self.inner.max_datagram_to(to)
    }

    fn wait(&mut self, timeout: Duration) {
        self.inner.wait(timeout);
    }
}

fn node(cfg: NodeConfig, role: Role, relay_only: bool) -> Node<Filtered> {
    let inner =
        UdpTransport::bind(cfg.bind_ip, Some(cfg.discovery_port), Some(cfg.game_port)).unwrap();
    let t = Filtered { inner, relay_only };
    Node::with_transport(cfg, role, t, Rng::from_entropy()).unwrap()
}

struct Peer {
    name: &'static str,
    node: Node<Filtered>,
    engine: ToyEngine,
    rng: Rng,
    next_cmd: u32,
    log: Vec<String>,
}

impl Peer {
    fn new(name: &'static str, node: Node<Filtered>, seed: u64) -> Self {
        Peer {
            name,
            node,
            engine: ToyEngine::default(),
            rng: Rng::seeded(seed),
            next_cmd: 1,
            log: Vec::new(),
        }
    }

    fn pump(&mut self) {
        // The node loads the engine with the agreed seed itself (Engine::load).
        for e in self.node.pump(&mut self.engine) {
            if let Event::Ended(why) = &e {
                panic!("{} ended: {why}\nlog:\n{}", self.name, self.log.join("\n"));
            }
            self.log.push(e.to_string());
        }
        if self.node.phase() == Phase::Game {
            let t = self.node.scene_time().0;
            if t >= self.next_cmd {
                let len = 1 + self.rng.below(6) as usize;
                let mut cmd = vec![0u8; len];
                self.rng.fill(&mut cmd);
                self.node.submit_command(cmd).unwrap();
                self.next_cmd = t + 2 + self.rng.below(5) as u32;
            }
        }
    }
}

/// How a guest finds the host.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Via {
    /// The host's discovery address.
    Address,
    /// The host's relay code.
    RelayCode,
}

struct Guest {
    name: &'static str,
    via: Via,
    relay_only: bool,
}

/// A whole game: the host is `peers[0]`.
struct Game {
    relay: Option<Relay>,
    peers: Vec<Peer>,
    /// What each guest typed to join, in guest order.
    targets: Vec<String>,
    drop_timeout: Duration,
    started: bool,
    deadline: StdInstant,
    /// Before pressing start, also wait until host and guest 1 have punched each other.
    wait_direct: bool,
}

impl Game {
    fn new(relay: bool, guests: &[Guest], drop_timeout: Duration) -> Self {
        let mut relay = relay.then(Relay::new);
        let mut host_cfg = config("Host", drop_timeout);
        if let Some(r) = &relay {
            host_cfg.relay = Some(r.addr());
            host_cfg.relay_always = true;
        }
        let mut host = Peer::new("host", node(host_cfg, Role::Host, false), 1);
        let disc = SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            host.node.local_port(Socket::Discovery).unwrap(),
        );
        let deadline = StdInstant::now() + Duration::from_secs(60);
        // With a relay, the guests that need it join with the host's version-2 code.
        let code = relay.as_mut().map(|r| loop {
            assert!(
                StdInstant::now() < deadline,
                "no relay code: {:?}",
                host.log
            );
            r.pump();
            host.pump();
            if let Some(c) = host.node.relay_code() {
                break c.to_owned();
            }
            std::thread::sleep(Duration::from_millis(2));
        });
        let mut peers = vec![host];
        let mut targets = Vec::new();
        for (i, g) in guests.iter().enumerate() {
            let target = match g.via {
                Via::Address => disc.to_string(),
                Via::RelayCode => code.clone().unwrap(),
            };
            let cfg = config(g.name, drop_timeout);
            let n = node(cfg, Role::Join(target.clone()), g.relay_only);
            peers.push(Peer::new(g.name, n, 2 + i as u64));
            targets.push(target);
        }
        Self {
            relay,
            peers,
            targets,
            drop_timeout,
            started: false,
            deadline,
            wait_direct: false,
        }
    }

    fn logs(&self) -> String {
        self.peers
            .iter()
            .map(|p| format!("--- {}\n{}", p.name, p.log.join("\n")))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// One loop step: pump the relay and every peer, accept join requests, start when
    /// every guest is seated and ready.
    fn step(&mut self) {
        assert!(
            StdInstant::now() < self.deadline,
            "timed out; logs:\n{}",
            self.logs()
        );
        if let Some(r) = self.relay.as_mut() {
            r.pump();
        }
        for p in &mut self.peers {
            p.pump();
        }
        if self.started {
            return;
        }
        let guests = self.peers.len() - 1;
        let host = &mut self.peers[0].node;
        // A code-joined (here: relay-joined) guest asks for approval (2.9).
        if !host.pending_requests().is_empty() {
            host.accept(None);
        }
        let ready = host.host_lobby().is_some_and(|h| {
            let v = h.view();
            v.seats
                .iter()
                .filter(|s| s.kind == SeatKind::Network && s.ready)
                .count()
                == guests
                && (!self.wait_direct || v.paths.direct(0, 1))
        }) && host.start_blocker().is_none();
        if ready {
            host.start().unwrap();
            self.started = true;
        }
    }

    fn run_until(&mut self, mut done: impl FnMut(&Game) -> bool) {
        while !done(self) {
            self.step();
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn assert_same_hashes(&self, ticks: u32) {
        let reference = &self.peers[0].engine.history()[..ticks as usize];
        for p in &self.peers[1..] {
            assert_eq!(
                &p.engine.history()[..ticks as usize],
                reference,
                "{} diverged",
                p.name
            );
        }
    }
}

fn all_reached(ticks: u32) -> impl FnMut(&Game) -> bool {
    move |g| g.peers.iter().all(|p| p.engine.tick() >= Tick(ticks))
}

fn play(relay: bool) {
    let guests = [
        Guest {
            name: "Guest1",
            via: if relay { Via::RelayCode } else { Via::Address },
            relay_only: false,
        },
        Guest {
            name: "Guest2",
            via: if relay { Via::RelayCode } else { Via::Address },
            relay_only: false,
        },
    ];
    let mut game = Game::new(relay, &guests, Duration::from_secs(30));
    game.run_until(all_reached(TICKS));
    game.assert_same_hashes(TICKS);
    // Commands really flowed from every player.
    assert!(game.peers.iter().all(|p| p.engine.commands_seen() > 50));
    let host_log = game.peers[0].log.join("\n");
    assert!(host_log.contains("Guest1 has joined"), "{host_log}");
    // Relayed peers are heard at their synthetic endpoints 0.0.0.(k+1).
    let heard = if relay {
        "Hearing from 0.0.0.2"
    } else {
        "Hearing from 127.0.0.1"
    };
    assert!(host_log.contains(heard), "{host_log}");
    if let Some(r) = &game.relay {
        assert!(r.server.stats().forwarded > 500, "{:?}", r.server.stats());
        assert!(game.peers[0].node.transport().relay_link().is_some());
    }
}

#[test]
fn host_and_two_guests_play_300_ticks() {
    play(false);
}

#[test]
fn host_and_two_guests_play_300_ticks_through_a_relay() {
    play(true);
}

/// The game addresses one peer uses for the others.
fn peers_of(p: &Peer) -> Vec<(PlayerId, Endpoint)> {
    p.node.game_start().unwrap().peers.clone()
}

#[test]
fn a_direct_and_a_relay_only_guest_play_300_ticks() {
    let guests = [
        Guest {
            name: "Direct",
            via: Via::Address,
            relay_only: false,
        },
        Guest {
            name: "Relayed",
            via: Via::RelayCode,
            relay_only: true,
        },
    ];
    let mut game = Game::new(true, &guests, Duration::from_secs(30));
    game.wait_direct = true;
    game.run_until(all_reached(TICKS));
    game.assert_same_hashes(TICKS);
    assert!(game.peers.iter().all(|p| p.engine.commands_seen() > 50));

    // Host and the direct guest punched each other: direct. Every pair with the
    // relay-only guest goes through the relay, and both ends agree on it.
    let synthetic = |v: &[(PlayerId, Endpoint)], p: u8| {
        v.iter()
            .find(|(id, _)| *id == PlayerId(p))
            .map(|(_, e)| is_synthetic(*e))
            .unwrap()
    };
    let (host, direct, relayed) = (
        peers_of(&game.peers[0]),
        peers_of(&game.peers[1]),
        peers_of(&game.peers[2]),
    );
    assert!(
        !synthetic(&host, 1) && !synthetic(&direct, 0),
        "{host:?} {direct:?}"
    );
    assert!(
        synthetic(&host, 2) && synthetic(&relayed, 0),
        "{host:?} {relayed:?}"
    );
    assert!(
        synthetic(&direct, 2) && synthetic(&relayed, 1),
        "{direct:?} {relayed:?}"
    );
    let r = game.relay.as_ref().unwrap();
    assert!(r.server.stats().forwarded > 500, "{:?}", r.server.stats());
    assert!(game.peers[1].node.transport().relay_link().is_some());
}

#[test]
fn a_dropped_guest_rejoins_with_the_same_address_and_catches_up() {
    let guests = [
        Guest {
            name: "Guest1",
            via: Via::Address,
            relay_only: false,
        },
        Guest {
            name: "Guest2",
            via: Via::Address,
            relay_only: false,
        },
    ];
    let mut game = Game::new(false, &guests, Duration::from_secs(2));
    game.run_until(all_reached(100));
    // Guest 2's machine goes away: node, sockets and engine.
    drop(game.peers.remove(2));
    let cfg = config("Guest2", game.drop_timeout);
    let again = node(cfg, Role::Join(game.targets[1].clone()), false);
    game.peers.push(Peer::new("Guest2 again", again, 99));
    game.run_until(all_reached(400));
    game.assert_same_hashes(400);
    let log = |i: usize| {
        game.peers[i].log.join(
            "
",
        )
    };
    assert!(log(0).contains("Guest2 has left the game"), "{}", log(0));
    assert!(
        log(0).contains("Guest2 has rejoined the game"),
        "{}",
        log(0)
    );
    assert!(
        log(1).contains("Guest2 has rejoined the game"),
        "{}",
        log(1)
    );
    assert!(log(2).contains("Rejoined the game"), "{}", log(2));
    // The returning player's commands count again after the rejoin.
    assert!(game.peers[2].engine.commands_seen() > 50);
}

/// SPEC 2.6: a guest probes the host while its STUN probe is still waiting for an answer.
#[test]
fn a_guest_joins_while_its_stun_probe_is_still_out() {
    // A STUN server that never answers: the probe times out only after 4 s.
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let std::net::SocketAddr::V4(stun) = silent.local_addr().unwrap() else {
        panic!()
    };
    let wait = Duration::from_secs(30);
    let mut host = Peer::new("host", node(config("Host", wait), Role::Host, false), 1);
    let disc = SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        host.node.local_port(Socket::Discovery).unwrap(),
    );
    let mut cfg = config("Guest", wait);
    cfg.stun = Stun::Servers(vec![stun]);
    let mut guest = Peer::new("guest", node(cfg, Role::Join(disc.to_string()), false), 2);
    assert_eq!(guest.node.phase(), Phase::Lobby);
    let t0 = StdInstant::now();
    while guest.node.guest_lobby().and_then(|g| g.my_seat()).is_none() {
        assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", guest.log);
        host.pump();
        guest.pump();
        std::thread::sleep(Duration::from_millis(1));
    }
    // Seated before STUN could have settled: nothing has failed or answered yet.
    assert!(guest.node.reply_code().is_none());
    assert!(
        !guest
            .log
            .iter()
            .any(|l| l.contains("No reply from the internet")),
        "{:?}",
        guest.log
    );
}

/// A typed host name is looked up off the caller's thread: `Node::new` returns at once and
/// a later pump joins.
#[test]
fn a_guest_joins_by_host_name() {
    let wait = Duration::from_secs(30);
    let mut host = Peer::new("host", node(config("Host", wait), Role::Host, false), 1);
    let port = host.node.local_port(Socket::Discovery).unwrap();
    let target = format!("localhost:{port}");
    let mut guest = Peer::new(
        "guest",
        node(config("Guest", wait), Role::Join(target), false),
        2,
    );
    assert_eq!(guest.node.phase(), Phase::Traversal);
    let t0 = StdInstant::now();
    while guest.node.guest_lobby().and_then(|g| g.my_seat()).is_none() {
        assert!(t0.elapsed() < Duration::from_secs(20), "{:?}", guest.log);
        host.pump();
        guest.pump();
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        guest.log.iter().any(|l| l == "Looking up localhost..."),
        "{:?}",
        guest.log
    );
}
