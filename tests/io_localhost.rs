//! A host and two guests on real localhost UDP sockets, in one process, from the lobby
//! through the load handshake to 300 ticks of lockstep with identical hashes. Once
//! directly, once with every datagram going through an in-process relay.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant as StdInstant};

use btm_netplay::io::toy::ToyEngine;
use btm_netplay::io::{Event, Node, NodeConfig, Phase, Rng, Role, Socket, Stun, Transport};
use btm_netplay::relay::{RelayConfig, RelayServer};
use btm_netplay::session::SeatKind;
use btm_netplay::types::{Instant, Outgoing, Tick};

const TICKS: u32 = 300;

fn config(name: &str) -> NodeConfig {
    let mut c = NodeConfig::new(name);
    c.bind_ip = Ipv4Addr::LOCALHOST;
    c.discovery_port = 0;
    c.game_port = 0;
    c.stun = Stun::Off;
    c.drop_timeout = Duration::from_secs(30);
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

struct Peer {
    name: &'static str,
    node: Node,
    engine: ToyEngine,
    rng: Rng,
    next_cmd: u32,
    log: Vec<String>,
}

impl Peer {
    fn pump(&mut self) {
        for e in self.node.pump(&mut self.engine) {
            if let Event::Loading { seed, .. } = &e {
                self.engine = ToyEngine::new(*seed);
            }
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

fn peer(name: &'static str, node: Node, seed: u64) -> Peer {
    Peer {
        name,
        node,
        engine: ToyEngine::default(),
        rng: Rng::seeded(seed),
        next_cmd: 1,
        log: Vec::new(),
    }
}

fn run(mut host_cfg: NodeConfig, relay: Option<Relay>) {
    let mut relay = relay;
    if let Some(r) = &relay {
        host_cfg.relay = Some(r.addr());
        host_cfg.relay_always = true;
    }
    let mut host = peer("host", Node::new(host_cfg, Role::Host).unwrap(), 1);
    let disc = SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        host.node.local_port(Socket::Discovery).unwrap(),
    );
    // With a relay, the guests join with the host's version-2 code once it exists.
    let deadline = StdInstant::now() + Duration::from_secs(60);
    let target = if let Some(r) = relay.as_mut() {
        loop {
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
        }
    } else {
        disc.to_string()
    };
    let mut peers = vec![
        host,
        peer(
            "g1",
            Node::new(config("Guest1"), Role::Join(target.clone())).unwrap(),
            2,
        ),
        peer(
            "g2",
            Node::new(config("Guest2"), Role::Join(target)).unwrap(),
            3,
        ),
    ];
    let mut started = false;
    loop {
        assert!(
            StdInstant::now() < deadline,
            "timed out; logs:\n{:#?}",
            peers.iter().map(|p| &p.log).collect::<Vec<_>>()
        );
        if let Some(r) = relay.as_mut() {
            r.pump();
        }
        for p in &mut peers {
            p.pump();
        }
        // A code-joined (here: relay-joined) guest asks for approval (2.9).
        if !started && !peers[0].node.pending_requests().is_empty() {
            peers[0].node.accept(None);
        }
        if !started {
            let ready = peers[0].node.host_lobby().is_some_and(|h| {
                h.view()
                    .seats
                    .iter()
                    .filter(|s| s.kind == SeatKind::Network && s.ready)
                    .count()
                    == 2
            }) && peers[0].node.start_blocker().is_none();
            if ready {
                peers[0].node.start().unwrap();
                started = true;
            }
        }
        if peers.iter().all(|p| p.engine.tick() >= Tick(TICKS)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let reference = peers[0].engine.history()[..TICKS as usize].to_vec();
    for p in &peers[1..] {
        assert_eq!(
            &p.engine.history()[..TICKS as usize],
            &reference[..],
            "{} diverged",
            p.name
        );
    }
    // Commands really flowed from every player.
    assert!(peers.iter().all(|p| p.engine.commands_seen() > 50));
    let host_log = peers[0].log.join("\n");
    assert!(host_log.contains("Guest1 has joined"), "{host_log}");
    // Relayed peers are heard at their synthetic endpoints 0.0.0.(k+1).
    let heard = if relay.is_some() {
        "Hearing from 0.0.0.2"
    } else {
        "Hearing from 127.0.0.1"
    };
    assert!(host_log.contains(heard), "{host_log}");
    if let Some(r) = &relay {
        assert!(r.server.stats().forwarded > 500, "{:?}", r.server.stats());
        assert!(peers[0].node.transport().relay_link().is_some());
    }
}

#[test]
fn host_and_two_guests_play_300_ticks() {
    run(config("Host"), None);
}

#[test]
fn host_and_two_guests_play_300_ticks_through_a_relay() {
    run(config("Host"), Some(Relay::new()));
}
