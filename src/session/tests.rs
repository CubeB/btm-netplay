#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use super::codec::{
    self, encode_announce, encode_claim, encode_leave, encode_refuse, Announce, Claim, Leave, Msg,
    Refuse, RefuseReason,
};
use super::*;
use crate::types::Outgoing;

const BUILD: &[u8] = b"abc123def4567890";

fn ms(n: u64) -> Instant {
    Instant(Duration::from_millis(n))
}

fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
    SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
}

fn host_addr() -> Endpoint {
    ep(10, 0, 0, 1, DISCOVERY_PORT)
}

fn mesa() -> MapInfo {
    MapInfo {
        name: "Mesa".into(),
        identity: map_identity(b"desc", b"terrain"),
    }
}

fn mod_entry(id: &str, ver: &str, h: u8) -> ModEntry {
    ModEntry {
        id: id.into(),
        version: ver.into(),
        hash: [h; 32],
    }
}

fn host_cfg() -> HostConfig {
    HostConfig::new("Hosty", "Test game", BUILD, 0x1122_3344_5566_7788, [9; 32])
}

/// An in-memory network: the host, some guests, and a queue of datagrams in flight.
struct Net {
    now: Instant,
    host: HostLobby,
    host_events: Vec<HostEvent>,
    guests: Vec<G>,
    queue: VecDeque<(Endpoint, Endpoint, Vec<u8>)>,
    log: Vec<Vec<u8>>,
}

struct G {
    addr: Endpoint,
    lobby: GuestLobby,
    events: Vec<GuestEvent>,
    mute: bool,
}

impl G {
    fn failed(&self) -> Option<&JoinError> {
        self.events.iter().find_map(|e| match e {
            GuestEvent::Failed(j) => Some(j),
            _ => None,
        })
    }
    fn started(&self) -> Option<&GameStart> {
        self.events.iter().find_map(|e| match e {
            GuestEvent::Started(g) => Some(&**g),
            _ => None,
        })
    }
    fn seated(&self) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, GuestEvent::Seated(_)))
    }
}

impl Net {
    fn new(cfg: HostConfig) -> Self {
        let mut net = Self {
            now: ms(0),
            host: HostLobby::new(cfg, ms(0)).unwrap(),
            host_events: Vec::new(),
            guests: Vec::new(),
            queue: VecDeque::new(),
            log: Vec::new(),
        };
        net.host.set_map(ms(0), Some(mesa())).unwrap();
        net
    }

    fn guest_cfg(&self, name: &str) -> GuestConfig {
        let i = self.guests.len() as u8;
        let mut c = GuestConfig::new(name, BUILD, host_addr(), [i + 1; 16]);
        c.maps = vec![mesa()];
        c.colour = 5 + (i % 4);
        c
    }

    fn add(&mut self, name: &str) -> usize {
        let cfg = self.guest_cfg(name);
        self.add_cfg(cfg)
    }

    fn add_cfg(&mut self, cfg: GuestConfig) -> usize {
        let i = self.guests.len() as u8;
        let lobby = GuestLobby::new(cfg, self.now).unwrap();
        self.guests.push(G {
            addr: ep(10, 0, 0, 10 + i, DISCOVERY_PORT),
            lobby,
            events: Vec::new(),
            mute: false,
        });
        self.guests.len() - 1
    }

    fn route(&mut self, from: Endpoint, sends: Vec<Outgoing>) {
        for o in sends {
            self.log.push(o.bytes.clone());
            self.queue.push_back((o.to, from, o.bytes));
        }
    }

    fn host_step(&mut self, step: Step<HostEvent>) {
        self.host_events.extend(step.events);
        self.route(host_addr(), step.send);
    }

    fn guest_step(&mut self, i: usize, step: Step<GuestEvent>) {
        let addr = self.guests[i].addr;
        self.guests[i].events.extend(step.events);
        self.route(addr, step.send);
    }

    fn pump(&mut self) {
        let mut guard = 0;
        while let Some((to, from, bytes)) = self.queue.pop_front() {
            guard += 1;
            assert!(guard < 100_000, "datagram storm");
            if to == host_addr() {
                let s = self.host.on_datagram(self.now, from, &bytes);
                self.host_step(s);
            } else if to == ep(255, 255, 255, 255, DISCOVERY_PORT) {
                for i in 0..self.guests.len() {
                    if !self.guests[i].mute {
                        let s = self.guests[i].lobby.on_datagram(self.now, from, &bytes);
                        self.guest_step(i, s);
                    }
                }
            } else if let Some(i) = self.guests.iter().position(|g| g.addr == to) {
                if !self.guests[i].mute {
                    let s = self.guests[i].lobby.on_datagram(self.now, from, &bytes);
                    self.guest_step(i, s);
                }
            }
        }
    }

    /// Advance time in 50 ms steps, polling everyone and delivering everything.
    fn run(&mut self, millis: u64) {
        let end = self.now.0 + Duration::from_millis(millis);
        while self.now.0 < end {
            self.now = Instant(self.now.0 + Duration::from_millis(50));
            let s = self.host.poll(self.now);
            self.host_step(s);
            for i in 0..self.guests.len() {
                if !self.guests[i].mute {
                    let s = self.guests[i].lobby.poll(self.now);
                    self.guest_step(i, s);
                }
            }
            self.pump();
        }
    }

    fn run_until(&mut self, limit: u64, mut f: impl FnMut(&Net) -> bool) {
        let end = self.now.0 + Duration::from_millis(limit);
        while self.now.0 < end && !f(self) {
            self.run(50);
        }
    }

    fn deliver_to_host(&mut self, from: Endpoint, bytes: &[u8]) -> Step<HostEvent> {
        let s = self.host.on_datagram(self.now, from, bytes);
        self.host_events.extend(s.events.clone());
        s
    }

    fn host_saw(&self, f: impl Fn(&HostEvent) -> bool) -> bool {
        self.host_events.iter().any(f)
    }
}

fn base_claim(session: u64, token: u32, name: &str, seat: u8) -> Claim {
    Claim {
        build: BUILD.to_vec(),
        session,
        token,
        name: name.into(),
        seat,
        side: 0,
        colour: 6,
        team: -1,
        ready: false,
        epoch: None,
        game_port: GAME_PORT,
        game_addr: None,
        stun_addr: None,
        approval: false,
        chat: Vec::new(),
        proof: None,
        mods: ModSet::default(),
    }
}

fn send_claim(net: &mut Net, from: Endpoint, c: &Claim) -> Step<HostEvent> {
    let bytes = encode_claim(c).unwrap();
    let mut s = net.deliver_to_host(from, &bytes);
    s.events.retain(|e| !matches!(e, HostEvent::HearingFrom(_)));
    s
}

// ---------------------------------------------------------------------------------------

#[test]
fn full_lobby_host_plus_three_guests_to_game_start() {
    let mut net = Net::new(host_cfg());
    net.host.set_option(net.now, "difficulty", "hard").unwrap();
    net.host.set_computer(net.now, 9, "aggressive").unwrap();
    for n in ["Ann", "Bob", "Cy"] {
        net.add(n);
    }
    net.run_until(20_000, |n| n.guests.iter().all(G::seated));
    assert!(
        net.guests.iter().all(G::seated),
        "{:?}",
        net.guests[2].events
    );

    // Seats are distinct and hold the right guests; colours are unique.
    let seats = &net.host.view().seats;
    let mut names: Vec<_> = seats
        .iter()
        .filter(|s| s.kind == SeatKind::Network)
        .map(|s| s.name.clone())
        .collect();
    names.sort();
    assert_eq!(names, ["Ann", "Bob", "Cy"]);
    let mut colours: Vec<u8> = seats
        .iter()
        .filter(|s| s.kind != SeatKind::Open)
        .map(|s| s.colour)
        .collect();
    colours.sort();
    colours.dedup();
    assert_eq!(colours.len(), 5);

    net.run(2000); // everyone learns the final epoch before readying
                   // Not ready: Start is blocked.
    assert!(matches!(
        net.host.start(net.now, 1),
        Err(HostError::StartBlocked(StartBlocker::WaitingForReady(_)))
    ));
    for i in 0..3 {
        let s = net.guests[i].lobby.set_ready(net.now, true);
        net.guest_step(i, s);
    }
    net.run(1500);
    assert_eq!(net.host.start_blocker(), None);
    assert_eq!(net.host.help_line(), "Ready. Press Start.");

    // Chat works both ways.
    let s = net.guests[1].lobby.say(net.now, "hello room");
    net.guest_step(1, s);
    net.run(1500);
    let s = net.host.say(net.now, "welcome");
    net.host_step(s);
    net.run(1500);
    assert!(net.host_saw(
        |e| matches!(e, HostEvent::Chat(l) if l.text == "hello room" && l.from == "Bob")
    ));
    for g in &net.guests {
        let texts: Vec<_> = g
            .events
            .iter()
            .filter_map(|e| match e {
                GuestEvent::Chat(l) => Some(l.text.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(texts, ["hello room", "welcome"], "no duplicates");
    }

    let s = net.host.start(net.now, 0xfeed).unwrap();
    net.host_step(s);
    assert!(net.host_saw(|e| *e == HostEvent::Starting));
    assert_eq!(net.host.help_line(), "Starting game...");
    net.run(3500);

    let host_start = net
        .host_events
        .iter()
        .find_map(|e| match e {
            HostEvent::Started(g) => Some((**g).clone()),
            _ => None,
        })
        .expect("host started");
    assert_eq!(host_start.my_seat, PlayerId(0));
    assert_eq!(host_start.seed, 0xfeed);
    assert_eq!(host_start.map, mesa());
    assert_eq!(
        host_start.options,
        [("difficulty".to_owned(), "hard".to_owned())]
    );
    assert_eq!(host_start.peers.len(), 3);
    assert_eq!(host_start.computer_players(), [(PlayerId(9), "aggressive")]);
    assert_eq!(host_start.human_players().len(), 4);

    let mut my_seats = vec![0];
    for g in &net.guests {
        let gs = g.started().expect("guest started");
        assert_eq!(gs.seed, 0xfeed);
        assert_eq!(gs.options, host_start.options);
        assert_eq!(gs.map, host_start.map);
        assert_eq!(gs.session, host_start.session);
        assert_eq!(gs.peers.len(), 3);
        assert_eq!(gs.simulation_seed(), host_start.simulation_seed());
        // Everyone agrees on the guests' endpoints and the host's game address.
        for (id, e) in &host_start.peers {
            if *id != gs.my_seat {
                assert_eq!(gs.endpoint_of(*id), Some(*e));
            }
        }
        assert_eq!(
            gs.endpoint_of(PlayerId(0)),
            Some(ep(10, 0, 0, 1, GAME_PORT))
        );
        assert_eq!(gs.seats.len(), SEATS);
        for s in &host_start.seats {
            let t = &gs.seats[usize::from(s.index)];
            assert_eq!(
                (s.kind, &s.name, s.side, s.colour, s.team),
                (t.kind, &t.name, t.side, t.colour, t.team)
            );
        }
        my_seats.push(gs.my_seat.0);
    }
    my_seats.sort();
    assert_eq!(my_seats, [0, 1, 2, 3]);
    // After the start nothing is sent any more.
    assert!(net.host.poll(net.now).send.is_empty());
}

#[test]
fn build_mismatch_is_refused_with_the_right_message() {
    // Guest side: checked on the first announcement.
    let mut net = Net::new(host_cfg());
    let mut cfg = net.guest_cfg("Ann");
    cfg.build_id = b"ffff0000ffff0000-d".to_vec();
    net.add_cfg(cfg);
    net.run(1500);
    let e = net.guests[0].failed().unwrap().clone();
    assert_eq!(
        e.to_string(),
        "That game is version abc123de and this is ffff0000-d"
    );
    assert!(net.guests[0].lobby.is_closed());
    assert_eq!(net.host.view().seats[1].kind, SeatKind::Open);

    // Host side: a claim from a build that does not check (or an older one).
    let session = net.host.view().session;
    let mut c = base_claim(session, 77, "Dan", 1);
    c.build = b"deadbeefcafe".to_vec();
    let s = send_claim(&mut net, ep(10, 0, 0, 50, 1338), &c);
    assert_eq!(
        s.events,
        [HostEvent::BuildRefused {
            name: "Dan".into(),
            theirs: "deadbeef".into(),
            mine: "abc123de".into()
        }]
    );
    assert_eq!(
        s.events[0].to_string(),
        "Dan cannot join: it is version deadbeef\nThis is version abc123de"
    );
    let refuse = s
        .send
        .iter()
        .find_map(|o| match codec::decode(&o.bytes) {
            Ok(Msg::Refuse(r)) => Some(r),
            _ => None,
        })
        .unwrap();
    assert_eq!(refuse.reason, RefuseReason::Build);
    assert_eq!(refuse.token, 77);
    // Said once per token, but the refusal is repeated.
    let s = send_claim(&mut net, ep(10, 0, 0, 50, 1338), &c);
    assert!(s.events.is_empty());
    assert!(!s.send.is_empty());
    assert_eq!(net.host.view().seats[1].kind, SeatKind::Open);
    // An absent build id (an older build) is refused too.
    c.token = 78;
    c.build = Vec::new();
    let s = send_claim(&mut net, ep(10, 0, 0, 50, 1338), &c);
    assert_eq!(
        s.events[0].to_string(),
        "Dan cannot join: it is version an older version\nThis is version abc123de"
    );
}

#[test]
fn build_compatibility_rule() {
    assert!(build_compatible(b"", b"anything"));
    assert!(build_compatible(b"unknown", b""));
    assert!(!build_compatible(b"abc", b""));
    assert!(build_compatible(b"abc", b"unknown"));
    assert!(build_compatible(b"abc", b"abc"));
    assert!(!build_compatible(b"abc", b"abd"));
    assert!(!build_compatible(b"abc", b"abc-d"));
    assert_eq!(display_build(b"0123456789abcdef-d"), "01234567-d");
    assert_eq!(display_build(b"unknown"), "unknown");
    assert_eq!(display_build(b""), "an older version");
}

#[test]
fn mod_mismatch_names_exactly_the_mods_that_differ() {
    let host_mods = ModSet::new(
        [1; 32],
        vec![
            mod_entry("alpha", "1.0", 1),
            mod_entry("beta", "2.0", 2),
            mod_entry("gamma", "1.0", 3),
        ],
    )
    .unwrap();
    let guest_mods = ModSet::new(
        [2; 32],
        vec![
            mod_entry("alpha", "1.0", 1),
            mod_entry("beta", "2.0", 9),
            mod_entry("delta", "1", 4),
        ],
    )
    .unwrap();
    let mut hc = host_cfg();
    hc.mods = host_mods.clone();
    let mut net = Net::new(hc);
    let mut gc = net.guest_cfg("Ann");
    gc.mods = guest_mods;
    net.add_cfg(gc);
    net.run_until(5000, |n| n.guests[0].failed().is_some());

    let expected = ModDiff {
        entries: vec![
            ModDifference {
                id: "beta".into(),
                kind: ModDiffKind::Different,
            },
            ModDifference {
                id: "gamma".into(),
                kind: ModDiffKind::MissingFromGuest,
            },
            ModDifference {
                id: "delta".into(),
                kind: ModDiffKind::ExtraOnGuest,
            },
        ],
    };
    assert_eq!(
        net.guests[0].failed(),
        Some(&JoinError::ModMismatch(expected.clone()))
    );
    assert_eq!(
        net.guests[0].failed().unwrap().to_string(),
        "Your mods do not match the host's: beta (different version or contents), gamma (missing \
         from the guest), delta (not on the host)"
    );
    assert!(net.host_saw(
        |e| matches!(e, HostEvent::ModsRefused { name, diff } if name == "Ann" && *diff == expected)
    ));
    assert_eq!(net.host.view().seats[1].kind, SeatKind::Open);

    // The same set is accepted.
    net.add_cfg({
        let mut c = net.guest_cfg("Bob");
        c.mods = host_mods;
        c
    });
    net.run_until(5000, |n| n.guests[1].seated());
    assert!(net.guests[1].seated());
}

#[test]
fn password_is_checked_and_never_sent() {
    let mut hc = host_cfg();
    hc.password = Some("swordfish".into());
    let mut net = Net::new(hc);
    let mut wrong = net.guest_cfg("Wrong");
    wrong.password = Some("letmein".into());
    net.add_cfg(wrong);
    let none = net.guest_cfg("Nopw");
    net.add_cfg(none);
    let mut right = net.guest_cfg("Right");
    right.password = Some("swordfish".into());
    net.add_cfg(right);
    net.run_until(6000, |n| {
        n.guests[0].failed().is_some() && n.guests[2].seated()
    });

    assert_eq!(net.guests[0].failed(), Some(&JoinError::IncorrectPassword));
    assert_eq!(
        net.guests[0].failed().unwrap().to_string(),
        "Incorrect password"
    );
    assert_eq!(net.guests[1].failed(), Some(&JoinError::IncorrectPassword));
    assert!(net.guests[2].seated());
    assert!(net.host_saw(|e| matches!(e, HostEvent::PasswordRefused { name } if name == "Wrong")));
    assert_eq!(
        net.host
            .view()
            .seats
            .iter()
            .filter(|s| s.kind == SeatKind::Network)
            .count(),
        1
    );
    for d in &net.log {
        for needle in [&b"swordfish"[..], b"letmein"] {
            assert!(
                !d.windows(needle.len()).any(|w| w == needle),
                "password in the clear"
            );
        }
    }
    // A proof for another token or session does not verify.
    let ch = [3u8; 16];
    let a = password_proof("pw", 1, &ch, 5);
    assert_ne!(a, password_proof("pw", 1, &ch, 6));
    assert_ne!(a, password_proof("pw", 2, &ch, 5));
    assert_ne!(a, password_proof("pw2", 1, &ch, 5));
    assert_eq!(a, password_proof("pw", 1, &ch, 5));
}

#[test]
fn ten_seats_and_a_full_lobby() {
    let mut net = Net::new(host_cfg());
    for i in 0..9 {
        net.add(&format!("P{i}"));
    }
    net.run_until(60_000, |n| n.guests.iter().all(G::seated));
    assert!(net.guests.iter().all(G::seated));
    let mut seats: Vec<u8> = net
        .host
        .view()
        .seats
        .iter()
        .filter(|s| s.kind == SeatKind::Network)
        .map(|s| s.index)
        .collect();
    seats.sort();
    assert_eq!(seats, (1..10).collect::<Vec<u8>>());
    let mut colours: Vec<u8> = net.host.view().seats.iter().map(|s| s.colour).collect();
    colours.sort();
    colours.dedup();
    assert_eq!(colours.len(), 10, "ten distinct colours");

    // The eleventh peer finds the game full, on its first announcement.
    let late = net.add("Late");
    net.run_until(3000, |n| n.guests[late].failed().is_some());
    assert_eq!(net.guests[late].failed(), Some(&JoinError::GameFull));
    assert_eq!(
        net.guests[late].failed().unwrap().to_string(),
        "The game is full"
    );

    // A claim straight to the host (no announcement seen) is refused as full.
    let session = net.host.view().session;
    let s = send_claim(
        &mut net,
        ep(10, 0, 0, 99, 1338),
        &base_claim(session, 4242, "Raw", 3),
    );
    let r = s
        .send
        .iter()
        .find_map(|o| match codec::decode(&o.bytes) {
            Ok(Msg::Refuse(r)) => Some(r),
            _ => None,
        })
        .unwrap();
    assert_eq!(r.reason, RefuseReason::Full);
}

#[test]
fn leave_and_rejoin_of_a_seat() {
    let mut net = Net::new(host_cfg());
    net.add("Ann");
    net.add("Bob");
    net.add("Cy");
    net.run_until(20_000, |n| n.guests.iter().all(G::seated));
    let bob_seat = net.guests[1].lobby.my_seat().unwrap();

    // Bob leaves explicitly: the seat is open again at once.
    let s = net.guests[1].lobby.leave(net.now);
    net.guest_step(1, s);
    net.guests[1].mute = true;
    net.run(200);
    assert!(net.host_saw(
        |e| matches!(e, HostEvent::Left { name, seat } if name == "Bob" && *seat == bob_seat)
    ));
    assert_eq!(
        net.host.view().seats[usize::from(bob_seat.0)].kind,
        SeatKind::Open
    );
    assert_eq!(net.guests[1].lobby.status(), GuestStatus::Closed);

    // A newcomer takes the lowest open seat, which is Bob's.
    let dee = net.add("Dee");
    net.run_until(10_000, |n| n.guests[dee].seated());
    assert_eq!(net.guests[dee].lobby.my_seat(), Some(bob_seat));
    assert!(net.host_saw(
        |e| matches!(e, HostEvent::Joined { name, seat } if name == "Dee" && *seat == bob_seat)
    ));

    // Cy goes silent: the claim is forgotten after 3.5 s and the seat is freed.
    let cy_seat = net.guests[2].lobby.my_seat().unwrap();
    net.guests[2].mute = true;
    net.run(3000);
    assert_eq!(
        net.host.view().seats[usize::from(cy_seat.0)].kind,
        SeatKind::Network
    );
    net.run(1000);
    assert!(net.host_saw(|e| matches!(e, HostEvent::Left { name, .. } if name == "Cy")));
    assert_eq!(
        net.host.view().seats[usize::from(cy_seat.0)].kind,
        SeatKind::Open
    );

    // Cy comes back (the same peer, a late claim): it is seated again.
    net.guests[2].mute = false;
    net.run_until(10_000, |n| {
        n.host
            .view()
            .seats
            .iter()
            .any(|s| s.kind == SeatKind::Network && s.name == "Cy")
    });
    assert!(net
        .host
        .view()
        .seats
        .iter()
        .any(|s| s.kind == SeatKind::Network && s.name == "Cy"));
}

#[test]
fn removed_guest_cannot_come_back_with_the_same_token() {
    let mut net = Net::new(host_cfg());
    net.add("Ann");
    net.run_until(10_000, |n| n.guests[0].seated());
    let s = net.host.remove_seat(net.now, 1).unwrap();
    assert_eq!(s.events[0].to_string(), "Ann was removed");
    net.host_step(s);
    net.run(1500);
    assert_eq!(net.guests[0].failed(), Some(&JoinError::Removed));
    assert_eq!(
        net.guests[0].failed().unwrap().to_string(),
        "You were removed from the game"
    );
    assert_eq!(net.host.view().seats[1].kind, SeatKind::Open);
    assert!(matches!(
        net.host.remove_seat(net.now, 1),
        Err(HostError::SeatNotEditable(1))
    ));
    assert!(matches!(
        net.host.remove_seat(net.now, 12),
        Err(HostError::NoSuchSeat(12))
    ));
}

#[test]
fn ready_is_reset_when_the_setup_changes() {
    let mut net = Net::new(host_cfg());
    net.add("Ann");
    net.add("Bob");
    net.run_until(10_000, |n| n.guests.iter().all(G::seated));
    for i in 0..2 {
        let s = net.guests[i].lobby.set_ready(net.now, true);
        net.guest_step(i, s);
    }
    net.run(1500);
    let ready = |n: &Net| {
        n.host
            .view()
            .seats
            .iter()
            .filter(|s| s.kind == SeatKind::Network && s.ready)
            .count()
    };
    assert_eq!(ready(&net), 2);
    let epoch = net.host.view().epoch;

    // Names, chat and ready flags are not part of the fingerprint.
    let s = net.host.say(net.now, "chat is not setup");
    net.host_step(s);
    net.run(500);
    assert_eq!((ready(&net), net.host.view().epoch), (2, epoch));

    // A changed option clears every ready flag and bumps the epoch.
    let s = net.host.set_option(net.now, "mapping", "mapped").unwrap();
    net.host_step(s);
    assert_eq!(ready(&net), 0);
    assert_eq!(net.host.view().epoch, epoch + 1);
    net.run(1500);
    assert!(net.guests.iter().all(|g| !g.lobby.is_ready()));
    assert_eq!(net.guests[0].lobby.status(), GuestStatus::NotReady);
    // The same value again changes nothing.
    let s = net.host.set_option(net.now, "mapping", "mapped").unwrap();
    net.host_step(s);
    assert_eq!(net.host.view().epoch, epoch + 1);

    // A ready given under the old epoch is not believed.
    let session = net.host.view().session;
    let token = net.host.view().seats[1].token;
    let mut stale = base_claim(session, token, "Ann", 1);
    stale.ready = true;
    stale.epoch = Some(epoch);
    let (side, colour, team) = {
        let s = &net.host.view().seats[1];
        (s.side, s.colour, s.team)
    };
    stale.side = side;
    stale.colour = colour;
    stale.team = team;
    {
        let a = net.guests[0].addr;
        send_claim(&mut net, a, &stale);
    }
    assert!(!net.host.view().seats[1].ready);
    // Under the current epoch it is.
    stale.epoch = Some(epoch + 1);
    {
        let a = net.guests[0].addr;
        send_claim(&mut net, a, &stale);
    }
    assert!(net.host.view().seats[1].ready);
    // Changing the map, a seat or a computer also resets.
    let s = net.host.set_computer(net.now, 5, "sneaky").unwrap();
    net.host_step(s);
    assert!(!net.host.view().seats[1].ready);
    assert_eq!(net.host.view().epoch, epoch + 2);
    assert!(net.host.view().seats[5].ready, "computers are always ready");
    assert!(net.host.view().seats[0].ready, "the host is always ready");
    assert!(!net.host.view().seats[7].ready, "open seats never");
}

#[test]
fn guest_choice_is_applied_and_a_taken_colour_is_refused() {
    let mut net = Net::new(host_cfg());
    net.add("Ann");
    net.add("Bob");
    net.run_until(10_000, |n| n.guests.iter().all(G::seated));
    let ann = net.guests[0].lobby.my_seat().unwrap().0 as usize;
    let bob = net.guests[1].lobby.my_seat().unwrap().0 as usize;
    let bob_colour = net.host.view().seats[bob].colour;
    let free = (0..10u8)
        .find(|c| {
            net.host
                .view()
                .seats
                .iter()
                .all(|s| s.kind == SeatKind::Open || s.colour != *c)
        })
        .unwrap();

    let s = net.guests[0].lobby.set_choice(net.now, 2, free, 3);
    net.guest_step(0, s);
    assert_eq!(net.guests[0].lobby.choice(), (2, free, 3), "shown at once");
    net.run(1000);
    let seat = &net.host.view().seats[ann];
    assert_eq!((seat.side, seat.colour, seat.team), (2, free, 3));

    // Ann asks for Bob's colour: side and team apply, the colour does not, and after the hold
    // the host's word wins.
    let s = net.guests[0].lobby.set_choice(net.now, 1, bob_colour, 4);
    net.guest_step(0, s);
    net.run(1000);
    let seat = &net.host.view().seats[ann];
    assert_eq!((seat.side, seat.colour, seat.team), (1, free, 4));
    assert_eq!(net.guests[0].lobby.choice().1, bob_colour, "held for 2 s");
    net.run(2500);
    assert_eq!(net.guests[0].lobby.choice(), (1, free, 4));
    // Team is bounded to -1..=4.
    let s = net.host.set_seat_choice(net.now, 0, 0, 9, 4).unwrap();
    net.host_step(s);
    assert!(matches!(
        net.host.set_seat_choice(net.now, 0, 0, free, 0),
        Err(HostError::ColourTaken(_))
    ));
}

#[test]
fn approval_flow() {
    let mut hc = host_cfg();
    hc.require_approval = true;
    let mut net = Net::new(hc);
    assert!(net.host.view().approval_required);
    net.add("Bob");
    net.run(1500);
    assert!(
        net.host_saw(|e| matches!(e, HostEvent::HearingFrom(a) if *a == ep(10, 0, 0, 10, 1338)))
    );
    let hearing = net
        .host_events
        .iter()
        .filter(|e| matches!(e, HostEvent::HearingFrom(_)))
        .count();
    assert_eq!(hearing, 1, "once per IP");
    // One request, posted once, however many claims arrive.
    let reqs: Vec<_> = net
        .host_events
        .iter()
        .filter(|e| matches!(e, HostEvent::JoinRequest { .. }))
        .collect();
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].to_string(),
        "Bob wants to join. Click Accept or type /accept."
    );
    assert_eq!(net.host.pending_requests().len(), 1);
    assert_eq!(
        net.guests[0].lobby.status(),
        GuestStatus::WaitingForApproval
    );
    assert_eq!(
        net.guests[0].lobby.status().to_string(),
        "Waiting for the host to accept your join request..."
    );
    // The guest sees the real roster, without itself, and does not time out after 8 s.
    assert!(net.guests[0].lobby.view().unwrap().seats[1].kind == SeatKind::Open);
    net.run(12_000);
    assert!(net.guests[0].failed().is_none());
    assert_eq!(net.host.help_line(), "Waiting for another player to join");

    // Errors of /accept.
    let s = net.host.submit_line(net.now, "/accept Nobody");
    assert_eq!(
        s.events[0].to_string(),
        "No join request from that name is waiting."
    );
    // A second Bob: approval belongs to the token, not the name.
    net.add("bob");
    net.add("Cy");
    net.run(1500);
    assert_eq!(net.host.pending_requests().len(), 3);
    let tokens: Vec<u32> = net
        .host
        .pending_requests()
        .iter()
        .map(|p| p.token)
        .collect();
    let s = net.host.submit_line(net.now, "/accept CY");
    net.host_step(s);
    assert!(net.host_saw(|e| e.to_string() == "Accepted Cy's join request."));
    net.run(1500);
    assert!(net.guests[2].seated());
    assert!(!net.guests[0].seated() && !net.guests[1].seated());
    // Slash commands are not chat.
    assert!(!net.host_saw(|e| matches!(e, HostEvent::Chat(l) if l.text.contains("accept"))));
    // The button admits the oldest.
    let s = net.host.accept(net.now, None).unwrap();
    assert!(matches!(&s.events[0], HostEvent::Accepted { name } if name == "Bob"));
    net.host_step(s);
    net.run(1500);
    assert!(net.guests[0].seated());
    assert!(!net.guests[1].seated());
    assert_eq!(
        net.host
            .pending_requests()
            .iter()
            .map(|p| p.token)
            .collect::<Vec<_>>(),
        [tokens[1]]
    );
    // Accept by token.
    assert_eq!(
        net.host.accept_token(net.now, 12345).unwrap_err(),
        AcceptError::NoneWaiting
    );
    let s = net.host.accept_token(net.now, tokens[1]).unwrap();
    net.host_step(s);
    net.run(1500);
    assert!(net.guests[1].seated());
    // Nothing waiting now.
    let s = net.host.submit_line(net.now, "/accept");
    assert_eq!(s.events[0].to_string(), "No join requests are waiting.");

    // Not while launching.
    for i in 0..3 {
        let s = net.guests[i].lobby.set_ready(net.now, true);
        net.guest_step(i, s);
    }
    net.run(1500);
    let s = net.host.start(net.now, 5).unwrap();
    net.host_step(s);
    let s = net.host.submit_line(net.now, "/accept");
    assert_eq!(
        s.events[0].to_string(),
        "Cannot accept a join request while the game is starting."
    );
    assert!(matches!(
        net.host.set_option(net.now, "mapping", "mapped"),
        Err(HostError::AlreadyLaunching)
    ));
}

#[test]
fn refusing_a_request_tells_the_guest() {
    let mut hc = host_cfg();
    hc.require_approval = true;
    let mut net = Net::new(hc);
    net.add("Eve");
    net.run(1500);
    let token = net.host.pending_requests()[0].token;
    let s = net.host.refuse_token(net.now, token).unwrap();
    assert_eq!(s.events[0].to_string(), "Declined Eve's join request.");
    net.host_step(s);
    net.run(1500);
    assert_eq!(net.guests[0].failed(), Some(&JoinError::Declined));
    assert!(net.host.pending_requests().is_empty());
    assert_eq!(net.host.view().seats[1].kind, SeatKind::Open);
    // Even if the same token keeps claiming, it is not heard.
    let s = net.host.accept(net.now, None);
    assert_eq!(s.unwrap_err(), AcceptError::NoneWaiting);
}

#[test]
fn pre_approval_by_endpoint_skips_accept() {
    let mut hc = host_cfg();
    hc.require_approval = true;
    hc.game_addr = Some(ep(203, 0, 113, 5, 40000));
    let mut net = Net::new(hc);
    // A reply code naming the guest's source endpoint.
    let a = net.guests.len();
    assert_eq!(a, 0);
    let ann_addr = ep(10, 0, 0, 10, DISCOVERY_PORT);
    let s = net.host.pre_approve(net.now, ann_addr);
    assert_eq!(
        s.events[0].to_string(),
        "Reply code accepted (10.0.0.10:1338). Waiting for that player..."
    );
    net.host_step(s);
    net.add("Ann");
    net.run_until(5000, |n| n.guests[0].seated());
    assert!(net.guests[0].seated());
    assert!(
        !net.host_saw(|e| matches!(e, HostEvent::JoinRequest { .. })),
        "no /accept needed"
    );
    // Pre-approval is added to the announce-to list: it receives announcements.
    // And a code naming the host's own outside address is not usable.
    let s = net.host.pre_approve(net.now, ep(203, 0, 113, 5, 1338));
    assert_eq!(
        s.events[0].to_string(),
        "That code is on this router. It joins from the LAN list."
    );

    // Pre-approval by the announced STUN discovery address (a different source).
    let stun = ep(198, 51, 100, 7, 51000);
    net.host.pre_approve(net.now, stun);
    let session = net.host.view().session;
    let mut c = base_claim(session, 555, "Zed", 2);
    c.stun_addr = Some(stun);
    c.approval = true;
    let s = send_claim(&mut net, ep(10, 0, 0, 77, 1338), &c);
    assert!(s
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::Joined { name, .. } if name == "Zed")));
    assert!(!s
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::JoinRequest { .. })));
    // A different port is not the same endpoint.
    let mut c = base_claim(session, 556, "Yan", 3);
    c.stun_addr = Some(ep(198, 51, 100, 7, 51001));
    let s = send_claim(&mut net, ep(10, 0, 0, 78, 1338), &c);
    assert!(s
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::JoinRequest { .. })));
    // Pre-approving while a matching request waits seats it at once.
    let s = net.host.pre_approve(net.now, ep(10, 0, 0, 78, 1338));
    assert!(s
        .events
        .iter()
        .any(|e| matches!(e, HostEvent::Joined { name, .. } if name == "Yan")));
}

#[test]
fn approval_asked_by_the_guest_only() {
    // The lobby does not require approval, but a guest that came by invite code asks.
    let mut net = Net::new(host_cfg());
    let mut c = net.guest_cfg("Cat");
    c.approval = true;
    net.add_cfg(c);
    net.add("Lan");
    net.run(3000);
    assert!(
        net.guests[1].seated(),
        "LAN guests are seated automatically"
    );
    assert!(!net.guests[0].seated());
    assert_eq!(net.host.pending_requests().len(), 1);
    let s = net.host.accept(net.now, Some("cat")).unwrap();
    net.host_step(s);
    net.run(1500);
    assert!(net.guests[0].seated());
    // An approved token survives a lost seat: it is re-claimed under the same token.
}

#[test]
fn start_blockers_and_launch_window() {
    let mut net = Net::new(host_cfg());
    net.host.set_map(net.now, None).unwrap();
    assert_eq!(net.host.start_blocker(), Some(StartBlocker::NoMap));
    assert_eq!(net.host.help_line(), "Select a map");
    net.host.set_map(net.now, Some(mesa())).unwrap();
    assert_eq!(net.host.help_line(), "Waiting for another player to join");
    // A computer alone is not a network game.
    net.host.set_computer(net.now, 4, "x").unwrap();
    assert_eq!(
        net.host.start_blocker(),
        Some(StartBlocker::WaitingForPlayer)
    );
    net.add("Ann");
    net.run_until(5000, |n| n.guests[0].seated());
    assert_eq!(net.host.help_line(), "Waiting for Ann to be ready");
    let s = net.guests[0].lobby.set_ready(net.now, true);
    net.guest_step(0, s);
    net.run(1000);
    let t0 = net.now;
    let s = net.host.start(net.now, 9).unwrap();
    net.host_step(s);
    assert!(matches!(
        net.host.start(net.now, 9),
        Err(HostError::AlreadyLaunching)
    ));
    // The window is 2.5 s.
    net.run(2300);
    assert!(!net.host_saw(|e| matches!(e, HostEvent::Started(_))));
    net.run(300);
    assert!(net.host_saw(|e| matches!(e, HostEvent::Started(_))));
    assert!(net.now.0 - t0.0 >= LAUNCH_WINDOW);
    assert!(net.guests[0].started().is_some());
}

#[test]
fn late_claims_are_not_seated_while_launching() {
    let mut net = Net::new(host_cfg());
    net.add("Ann");
    net.run_until(5000, |n| n.guests[0].seated());
    let s = net.guests[0].lobby.set_ready(net.now, true);
    net.guest_step(0, s);
    net.run(800);
    let s = net.host.start(net.now, 1).unwrap();
    net.host_step(s);
    // A newcomer during the window is told the game has started.
    net.add("Late");
    net.run(1000);
    assert_eq!(net.guests[1].failed(), Some(&JoinError::AlreadyStarted));
    assert_eq!(
        net.guests[1].failed().unwrap().to_string(),
        "That game has already started"
    );
    assert_eq!(net.host.view().seats[2].kind, SeatKind::Open);
}

#[test]
fn map_checks() {
    // Missing map.
    let mut net = Net::new(host_cfg());
    let mut c = net.guest_cfg("Ann");
    c.maps = vec![];
    net.add_cfg(c);
    // Same name, other contents.
    let mut c = net.guest_cfg("Bob");
    c.maps = vec![MapInfo {
        name: "Mesa".into(),
        identity: "1-1-deadbeefdeadbeef".into(),
    }];
    net.add_cfg(c);
    // Unknown identity on our side is not checked.
    let mut c = net.guest_cfg("Cy");
    c.maps = vec![MapInfo {
        name: "Mesa".into(),
        identity: String::new(),
    }];
    net.add_cfg(c);
    net.run(3000);
    assert_eq!(
        net.guests[0].failed().unwrap().to_string(),
        "You do not have the map Mesa"
    );
    assert_eq!(
        net.guests[1].failed().unwrap().to_string(),
        "Your copy of the map Mesa is not the host's"
    );
    assert!(net.guests[2].seated());

    // The host changes to a map the guest lacks.
    let s = net
        .host
        .set_map(
            net.now,
            Some(MapInfo {
                name: "Delta".into(),
                identity: String::new(),
            }),
        )
        .unwrap();
    net.host_step(s);
    net.run(1500);
    assert_eq!(
        net.guests[2].failed(),
        Some(&JoinError::NoMap("Delta".into()))
    );
    net.run(4000);
    assert_eq!(
        net.host
            .view()
            .seats
            .iter()
            .filter(|s| s.kind == SeatKind::Network)
            .count(),
        0,
        "the guest told the host it left"
    );

    // A guest that is seated cannot load the map named at launch.
    assert_eq!(
        map_identity(b"ab", b"cde")
            .split('-')
            .take(2)
            .collect::<Vec<_>>(),
        ["2", "3"]
    );
    assert_eq!(map_identity(b"ab", b"cde").len(), 1 + 1 + 1 + 1 + 16);
    assert_ne!(
        map_identity(b"ab", b"cde"),
        map_identity(b"abc", b"de"),
        "separator byte"
    );
    assert_eq!(fnv1a(0xcbf2_9ce4_8422_2325, b"a"), 0xaf63_dc4c_8601_ec8c);
}

#[test]
fn lost_and_unreachable_host() {
    let mut net = Net::new(host_cfg());
    net.add("Ann");
    net.run_until(5000, |n| n.guests[0].seated());
    // The host goes quiet.
    net.guests[0].mute = false;
    for _ in 0..140 {
        net.now = Instant(net.now.0 + Duration::from_millis(50));
        let s = net.guests[0].lobby.poll(net.now);
        net.guest_step(0, s);
    }
    assert_eq!(net.guests[0].failed(), Some(&JoinError::HostLeft));
    assert_eq!(
        net.guests[0].failed().unwrap().to_string(),
        "The host has left"
    );

    // No host at all: after 8 s "The host did not answer".
    let mut lone =
        GuestLobby::new(GuestConfig::new("Bo", BUILD, host_addr(), [1; 16]), ms(0)).unwrap();
    let s = lone.poll(ms(0));
    assert_eq!(codec::decode(&s.send[0].bytes), Ok(Msg::Probe));
    assert_eq!(lone.status().to_string(), "Asking the host for a seat...");
    assert!(lone
        .poll(ms(7900))
        .events
        .iter()
        .all(|e| !matches!(e, GuestEvent::Failed(_))));
    let s = lone.poll(ms(8100));
    assert!(s
        .events
        .contains(&GuestEvent::Failed(JoinError::HostDidNotAnswer)));
    assert_eq!(
        JoinError::HostDidNotAnswer.to_string(),
        "The host did not answer"
    );
    assert!(matches!(
        GuestLobby::new(GuestConfig::new("  ", BUILD, host_addr(), [1; 16]), ms(0)),
        Err(JoinError::NameRequired)
    ));
    assert_eq!(
        JoinError::NameRequired.to_string(),
        "You must enter your name"
    );
    assert!(matches!(
        HostLobby::new(HostConfig::new("", "g", BUILD, 1, [0; 32]), ms(0)),
        Err(HostError::NameRequired)
    ));
    assert_eq!(
        HostLobby::new(HostConfig::new("h", " ", BUILD, 1, [0; 32]), ms(0))
            .err()
            .unwrap()
            .to_string(),
        "You must enter a game name"
    );
}

#[test]
fn announcements_are_ignored_from_strangers_and_other_sessions() {
    let mut net = Net::new(host_cfg());
    net.add("Ann");
    net.run_until(5000, |n| n.guests[0].seated());
    // A datagram from another IP, even a valid one, is ignored by the guest.
    let bytes = net
        .log
        .iter()
        .find(|b| matches!(codec::decode(b), Ok(Msg::Announce(_))))
        .unwrap()
        .clone();
    let s = net.guests[0]
        .lobby
        .on_datagram(net.now, ep(10, 9, 9, 9, 1338), &bytes);
    assert!(s.events.is_empty() && s.send.is_empty());
    // Another room's claim is ignored by the host.
    let s = send_claim(&mut net, ep(10, 0, 0, 60, 1338), &base_claim(1, 1, "X", 2));
    assert!(s.send.is_empty());
}

#[test]
fn probe_gets_an_announcement_rate_limited() {
    let mut net = Net::new(host_cfg());
    let probe = codec::encode_probe(BUILD);
    let from = ep(10, 0, 0, 40, 5555);
    let s = net.host.on_datagram(ms(1000), from, &probe);
    assert_eq!(s.send.len(), 1);
    assert_eq!(s.send[0].to, from);
    assert!(matches!(
        codec::decode(&s.send[0].bytes),
        Ok(Msg::Announce(_))
    ));
    let s = net.host.on_datagram(ms(1100), from, &probe);
    assert!(s.send.is_empty(), "at most once per 250 ms per prober");
    let s = net.host.on_datagram(ms(1300), from, &probe);
    assert_eq!(s.send.len(), 1);
}

#[test]
fn announcements_repeat_every_second_and_coalesce_changes() {
    let mut cfg = host_cfg();
    cfg.announce_targets = vec![ep(192, 0, 2, 9, 1338)];
    let mut host = HostLobby::new(cfg, ms(0)).unwrap();
    let s = host.poll(ms(0));
    let tos: Vec<_> = s.send.iter().map(|o| o.to).collect();
    assert_eq!(
        tos,
        [
            ep(255, 255, 255, 255, 1338),
            ep(127, 0, 0, 1, 1338),
            ep(192, 0, 2, 9, 1338)
        ]
    );
    assert!(host.poll(ms(500)).send.is_empty());
    assert_eq!(host.poll(ms(1000)).send.len(), 3);
    // A change goes out at once, but not more than once per 100 ms.
    host.set_option(ms(1010), "mapping", "mapped").unwrap();
    let s = host.poll(ms(1100));
    assert_eq!(s.send.len(), 3, "change sent");
    host.set_option(ms(1110), "mapping", "unmapped").unwrap();
    assert!(host.poll(ms(1150)).send.is_empty(), "coalesced");
    assert_eq!(host.poll(ms(1200)).send.len(), 3, "the latest state");
    // Identical re-advertising sends nothing extra.
    host.set_option(ms(1300), "mapping", "unmapped").unwrap();
    assert!(host.poll(ms(1400)).send.is_empty());
}

#[test]
fn reachable_directly_is_reported_once() {
    let mut net = Net::new(host_cfg());
    net.add("Ann");
    net.run_until(5000, |n| n.guests[0].seated());
    assert_eq!(net.host.note_punch(ep(10, 0, 0, 200, 1337)), None);
    let e = net.host.note_punch(ep(10, 0, 0, 10, 1337)).unwrap();
    assert_eq!(e.to_string(), "Ann is reachable directly");
    assert_eq!(net.host.note_punch(ep(10, 0, 0, 10, 1337)), None);
}

#[test]
fn nat_addresses_follow_the_16_rule() {
    // Same /16: the announced game address is believed.
    let src = ep(100, 64, 1, 2, 1338);
    assert_eq!(
        resolve_addr(src, Some(ep(100, 64, 9, 9, 40000)), 1337),
        ep(100, 64, 9, 9, 40000)
    );
    // Another /16: source IP plus the announced port.
    assert_eq!(
        resolve_addr(src, Some(ep(100, 65, 9, 9, 40000)), 1337),
        ep(100, 64, 1, 2, 1337)
    );
    assert_eq!(resolve_addr(src, None, 6670), ep(100, 64, 1, 2, 6670));

    // The host believes a guest's announced address.
    let mut host = HostLobby::new(host_cfg(), ms(0)).unwrap();
    let mut c = base_claim(host.view().session, 9, "Nat", 1);
    c.game_addr = Some(ep(100, 64, 9, 9, 40000));
    host.on_datagram(ms(10), src, &encode_claim(&c).unwrap());
    assert_eq!(host.view().seats[1].addr, Some(ep(100, 64, 9, 9, 40000)));
    // The mapping moved: the seat's address follows.
    c.game_addr = Some(ep(100, 64, 9, 9, 40001));
    host.on_datagram(ms(20), src, &encode_claim(&c).unwrap());
    assert_eq!(host.view().seats[1].addr, Some(ep(100, 64, 9, 9, 40001)));
}

#[test]
fn options_are_validated() {
    assert!(option_valid("difficulty", "hard"));
    assert!(!option_valid("difficulty", "nightmare"));
    assert!(option_valid("something_new", "whatever"));
    assert!(!option_valid("bad name", "x"));
    assert!(!option_valid("", "x"));
    assert!(!option_valid(&"n".repeat(33), "x"));
    assert!(!option_valid("a", &"v".repeat(65)));
    let mut host = HostLobby::new(host_cfg(), ms(0)).unwrap();
    assert_eq!(
        host.set_option(ms(0), "difficulty", "nightmare")
            .unwrap_err(),
        HostError::BadOption
    );
    for i in 0..MAX_OPTIONS {
        host.set_option(ms(0), &format!("opt{i}"), "v").unwrap();
    }
    assert_eq!(
        host.set_option(ms(0), "one_more", "v").unwrap_err(),
        HostError::TooManyOptions
    );
    // The community toggle.
    let mut host = HostLobby::new(host_cfg(), ms(0)).unwrap();
    host.submit_line(ms(0), "/community");
    assert_eq!(host.view().option("community"), Some("on"));
    host.submit_line(ms(0), "/community");
    assert_eq!(host.view().option("community"), Some("off"));
    let s = host.submit_line(ms(0), "/frobnicate now");
    assert_eq!(s.events[0].to_string(), "Unknown command: /frobnicate now");
    assert!(host.view().chat.is_empty());
}

// ---------------------------------------------------------------------------------------
// Encoding.

fn sample_announce() -> Announce {
    let mut seats: Vec<SeatInfo> = (0..10u8).map(SeatInfo::open).collect();
    seats[0].kind = SeatKind::Host;
    seats[0].name = "Hosty".into();
    seats[0].ready = true;
    seats[1] = SeatInfo {
        kind: SeatKind::Network,
        name: "Ann".into(),
        addr: Some(ep(1, 2, 3, 4, 5)),
        token: 99,
        ..SeatInfo::open(1)
    };
    seats[2] = SeatInfo {
        kind: SeatKind::Computer,
        personality: "rusher".into(),
        ..SeatInfo::open(2)
    };
    Announce {
        build: BUILD.to_vec(),
        session: 7,
        label: "label".into(),
        host_name: "Hosty".into(),
        game_port: 1337,
        map: Some(mesa()),
        challenge: Some([4; 16]),
        epoch: 12,
        launching: true,
        seed: 55,
        approval: true,
        seats,
        options: vec![("difficulty".into(), "easy".into())],
        chat: vec![ChatLine {
            seq: 3,
            from: "Ann".into(),
            text: "hi".into(),
        }],
        mods_hash: [8; 32],
    }
}

fn sample_claim() -> Claim {
    let mut c = base_claim(7, 1234, "Ann", 3);
    c.ready = true;
    c.epoch = Some(4);
    c.game_addr = Some(ep(1, 2, 3, 4, 5));
    c.stun_addr = Some(ep(6, 7, 8, 9, 10));
    c.approval = true;
    c.chat = vec![(1, "a".into()), (2, "b".into())];
    c.proof = Some([6; 32]);
    c.mods = ModSet::new([3; 32], vec![mod_entry("m", "1", 1)]).unwrap();
    c
}

#[test]
fn messages_round_trip() {
    let a = sample_announce();
    let bytes = encode_announce(&a).unwrap();
    assert!(bytes.len() <= MAX_LOBBY_DATAGRAM);
    assert_eq!(codec::decode(&bytes), Ok(Msg::Announce(a.clone())));
    let c = sample_claim();
    assert_eq!(codec::decode(&encode_claim(&c).unwrap()), Ok(Msg::Claim(c)));
    let r = Refuse {
        build: BUILD.to_vec(),
        session: 5,
        token: 6,
        reason: RefuseReason::Mods,
        diff: ModDiff {
            entries: vec![ModDifference {
                id: "x".into(),
                kind: ModDiffKind::Different,
            }],
        },
    };
    assert_eq!(codec::decode(&encode_refuse(&r)), Ok(Msg::Refuse(r)));
    let l = Leave {
        session: 1,
        token: 2,
    };
    assert_eq!(codec::decode(&encode_leave(BUILD, &l)), Ok(Msg::Leave(l)));
    assert_eq!(codec::decode(&codec::encode_probe(b"")), Ok(Msg::Probe));
    // Names are only carried for human seats.
    let mut a2 = a;
    a2.seats[2].name = "ghost".into();
    let Ok(Msg::Announce(back)) = codec::decode(&encode_announce(&a2).unwrap()) else {
        panic!("decode")
    };
    assert_eq!(back.seats[2].name, "");
}

#[test]
fn unknown_fields_and_versions() {
    let mut bytes = encode_announce(&sample_announce()).unwrap();
    // Unknown trailing fields are skipped.
    bytes.extend_from_slice(&[200, 3, 0, 1, 2, 3]);
    assert!(matches!(codec::decode(&bytes), Ok(Msg::Announce(_))));
    let mut bad = bytes.clone();
    bad[2] = 9;
    assert_eq!(codec::decode(&bad), Err(codec::DecodeError::BadVersion(9)));
    let mut bad = bytes.clone();
    bad[0] = b'X';
    assert_eq!(codec::decode(&bad), Err(codec::DecodeError::BadMagic));
    let mut bad = bytes;
    bad[3] = 77;
    assert_eq!(codec::decode(&bad), Err(codec::DecodeError::BadKind(77)));
    assert_eq!(
        codec::decode(&[0u8; 1501]),
        Err(codec::DecodeError::TooLong)
    );
    assert_eq!(codec::decode(&[]), Err(codec::DecodeError::Truncated));
    // Repeated options: the first wins.
    let mut a = sample_announce();
    a.options = vec![
        ("mapping".into(), "mapped".into()),
        ("mapping".into(), "unmapped".into()),
        ("bad name".into(), "x".into()),
    ];
    let Ok(Msg::Announce(back)) = codec::decode(&encode_announce(&a).unwrap()) else {
        panic!("decode")
    };
    assert_eq!(back.options, [("mapping".to_owned(), "mapped".to_owned())]);
}

#[test]
fn oversized_announcements_drop_chat_then_options() {
    let mut a = sample_announce();
    for s in &mut a.seats {
        s.kind = SeatKind::Network;
        s.name = "n".repeat(MAX_NAME);
        s.personality = "p".repeat(MAX_PERSONALITY);
        s.addr = Some(ep(9, 9, 9, 9, 9));
    }
    a.chat = (0..8)
        .map(|i| ChatLine {
            seq: i,
            from: "f".repeat(20),
            text: "t".repeat(80),
        })
        .collect();
    a.options = (0..32)
        .map(|i| {
            (
                format!("{:<32}", format!("o{i}")).replace(' ', "x"),
                "v".repeat(64),
            )
        })
        .collect();
    a.label = "l".repeat(100);
    a.map = Some(MapInfo {
        name: "m".repeat(200),
        identity: "i".repeat(200),
    });
    let bytes = encode_announce(&a).expect("fits after dropping");
    assert!(bytes.len() <= MAX_LOBBY_DATAGRAM);
    let Ok(Msg::Announce(back)) = codec::decode(&bytes) else {
        panic!("decode")
    };
    assert!(back.chat.is_empty(), "chat goes first");
    assert!(back.options.len() < 32, "then trailing options");
    assert_eq!(back.options, a.options[..back.options.len()]);
    assert_eq!(back.seats.len(), 10);

    // Only part of the chat when that is enough: the newest lines stay.
    let mut b = sample_announce();
    b.chat = (0..8)
        .map(|i| ChatLine {
            seq: i,
            from: "f".repeat(20),
            text: "t".repeat(80),
        })
        .collect();
    b.options = (0..32)
        .map(|i| (format!("opt{i}"), "v".repeat(40)))
        .collect();
    let bytes = encode_announce(&b).unwrap();
    let Ok(Msg::Announce(back)) = codec::decode(&bytes) else {
        panic!("decode")
    };
    assert!(bytes.len() <= MAX_LOBBY_DATAGRAM);
    assert!(back.options.len() == 32 || back.chat.is_empty());
    if let Some(last) = back.chat.last() {
        assert_eq!(last.seq, 7);
    }
}

#[test]
fn mod_set_bounds() {
    let many: Vec<ModEntry> = (0..=MAX_MODS)
        .map(|i| mod_entry(&format!("m{i}"), "1", 0))
        .collect();
    assert_eq!(
        ModSet::new([0; 32], many).unwrap_err(),
        ModSetError::TooMany
    );
    assert!(ModSet::new([0; 32], vec![mod_entry("", "1", 0)]).is_err());
    assert!(ModSet::new(
        [0; 32],
        vec![mod_entry(&"x".repeat(MAX_MOD_ID + 1), "1", 0)]
    )
    .is_err());
    assert!(ModSet::new([0; 32], vec![mod_entry("x", "1\n", 0)]).is_err());
    let full: Vec<ModEntry> = (0..MAX_MODS)
        .map(|i| mod_entry(&format!("{:x<24}", i), "123456789012", 1))
        .collect();
    let m = ModSet::new([1; 32], full).unwrap();
    let mut c = sample_claim();
    c.mods = m;
    c.name = "n".repeat(100);
    c.chat = (0..4).map(|i| (i, "c".repeat(100))).collect();
    let bytes = encode_claim(&c).unwrap();
    assert!(bytes.len() <= MAX_LOBBY_DATAGRAM, "{}", bytes.len());
    assert!(matches!(codec::decode(&bytes), Ok(Msg::Claim(_))));
    // Equal hashes mean equal sets.
    let a = ModSet::new([5; 32], vec![mod_entry("a", "1", 1)]).unwrap();
    assert_eq!(a.diff(&a.clone()), None);
    // Different hashes but identical lists: an empty list, still a refusal.
    let b = ModSet::new([6; 32], vec![mod_entry("a", "1", 1)]).unwrap();
    assert_eq!(a.diff(&b), Some(ModDiff::default()));
    assert_eq!(
        ModDiff::default().to_string(),
        "the mod sets differ (check mods and load order)"
    );
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn corpus() -> Vec<Vec<u8>> {
    let r = Refuse {
        build: BUILD.to_vec(),
        session: 5,
        token: 6,
        reason: RefuseReason::Mods,
        diff: ModDiff {
            entries: vec![ModDifference {
                id: "x".into(),
                kind: ModDiffKind::Different,
            }],
        },
    };
    vec![
        encode_announce(&sample_announce()).unwrap(),
        encode_claim(&sample_claim()).unwrap(),
        encode_refuse(&r),
        encode_leave(
            BUILD,
            &Leave {
                session: 1,
                token: 2,
            },
        ),
        codec::encode_probe(BUILD),
    ]
}

#[test]
fn decode_fuzz_never_panics() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    // Pure noise, with a valid-looking header half of the time.
    for i in 0..20_000 {
        let len = (rng.next() % 1600) as usize;
        let mut b: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        if i % 2 == 0 && b.len() > 5 {
            b[0] = b'B';
            b[1] = b'L';
            b[2] = 1;
            b[3] = 1 + (rng.next() % 5) as u8;
            b[4] = (rng.next() % 4) as u8;
        }
        let _ = codec::decode(&b);
    }
    // Every truncation of every valid message is handled.
    for m in corpus() {
        for n in 0..m.len() {
            let _ = codec::decode(&m[..n]);
        }
        assert!(codec::decode(&m).is_ok());
        // Single-byte corruption anywhere.
        for pos in 0..m.len() {
            for _ in 0..8 {
                let mut x = m.clone();
                x[pos] = rng.next() as u8;
                let _ = codec::decode(&x);
            }
        }
        // Bit flips and random splices.
        for _ in 0..2000 {
            let mut x = m.clone();
            for _ in 0..1 + rng.next() % 4 {
                let p = (rng.next() as usize) % x.len();
                x[p] ^= 1 << (rng.next() % 8);
            }
            let _ = codec::decode(&x);
        }
    }
}

#[test]
fn state_machines_survive_garbage() {
    let mut rng = Rng(0xDEAD_BEEF_1234_5678);
    let mut net = Net::new(host_cfg());
    net.add("Ann");
    net.run_until(5000, |n| n.guests[0].seated());
    let corpus = corpus();
    let from_host = host_addr();
    let from_other = ep(10, 0, 0, 33, 1338);
    for i in 0..30_000 {
        let mut b = if i % 3 == 0 {
            let len = (rng.next() % 300) as usize;
            (0..len).map(|_| rng.next() as u8).collect()
        } else {
            let mut m = corpus[(rng.next() as usize) % corpus.len()].clone();
            for _ in 0..rng.next() % 4 {
                let p = (rng.next() as usize) % m.len();
                m[p] = rng.next() as u8;
            }
            if rng.next().is_multiple_of(4) {
                let n = (rng.next() as usize) % m.len();
                m.truncate(n);
            }
            m
        };
        if b.len() > 1500 {
            b.truncate(1500);
        }
        net.now = Instant(net.now.0 + Duration::from_millis(7));
        let _ = net.host.on_datagram(net.now, from_other, &b);
        let _ = net.guests[0].lobby.on_datagram(net.now, from_host, &b);
        let _ = net.host.poll(net.now);
        let _ = net.guests[0].lobby.poll(net.now);
    }
    // And the lobby still has bounded state: the pending list and claims are capped.
    assert!(net.host.pending_requests().len() <= MAX_PENDING);
}

#[test]
fn pending_requests_are_bounded() {
    let mut hc = host_cfg();
    hc.require_approval = true;
    let mut host = HostLobby::new(hc, ms(0)).unwrap();
    let session = host.view().session;
    for i in 0..30u32 {
        let c = base_claim(session, 1000 + i, &format!("G{i}"), 1);
        host.on_datagram(
            ms(10),
            ep(10, 0, 1, i as u8, 1338),
            &encode_claim(&c).unwrap(),
        );
    }
    assert_eq!(host.pending_requests().len(), MAX_PENDING);
    // Requests that stop being heard expire.
    host.poll(ms(10_000));
    assert!(host.pending_requests().is_empty());
}

#[test]
fn texts_use_the_spec_wording() {
    let n = "Bob".to_owned();
    let cases: Vec<(String, &str)> = vec![
        (
            HostEvent::Joined {
                seat: PlayerId(1),
                name: n.clone(),
            }
            .to_string(),
            "Bob has joined",
        ),
        (
            HostEvent::Left {
                seat: PlayerId(1),
                name: n.clone(),
            }
            .to_string(),
            "Bob has left",
        ),
        (
            HostEvent::HearingFrom(ep(1, 2, 3, 4, 5)).to_string(),
            "Hearing from 1.2.3.4:5",
        ),
        (HostEvent::Starting.to_string(), "Starting game..."),
        (JoinError::GameFull.to_string(), "The game is full"),
        (JoinError::HostLeft.to_string(), "The host has left"),
        (
            JoinError::Removed.to_string(),
            "You were removed from the game",
        ),
        (
            JoinError::CouldNotLoadMap("M".into()).to_string(),
            "Could not load the map M",
        ),
        (
            JoinError::NoMap("M".into()).to_string(),
            "You do not have the map M",
        ),
        (
            JoinError::MapMismatch("M".into()).to_string(),
            "Your copy of the map M is not the host's",
        ),
        (
            JoinError::VersionMismatch {
                theirs: "X".into(),
                mine: "Y".into(),
            }
            .to_string(),
            "That game is version X and this is Y",
        ),
        (StartBlocker::NoMap.to_string(), "Select a map"),
        (
            GuestStatus::NotReady.to_string(),
            "Click the box beside your name when you are ready.",
        ),
        (
            GuestStatus::Ready.to_string(),
            "You are ready. Waiting for the host to start.",
        ),
        (
            HostError::GameNameRequired.to_string(),
            "You must enter a game name",
        ),
    ];
    for (got, want) in cases {
        assert_eq!(got, want);
    }
}

#[test]
fn game_start_helpers() {
    let mut net = Net::new(host_cfg());
    net.add("Ann");
    net.run_until(5000, |n| n.guests[0].seated());
    let s = net.guests[0].lobby.set_ready(net.now, true);
    net.guest_step(0, s);
    net.run(600);
    let s = net.host.start(net.now, 77).unwrap();
    net.host_step(s);
    net.run(3000);
    let gs = net.guests[0].started().unwrap().clone();
    let mut other = gs.clone();
    other.seats[0].name = "Someone else".into();
    assert_ne!(
        gs.simulation_seed(),
        other.simulation_seed(),
        "names feed the seed"
    );
    let mut other = gs.clone();
    other.seed = 78;
    assert_ne!(gs.simulation_seed(), other.simulation_seed());
    assert_eq!(gs.local_game_port, GAME_PORT);
    assert_eq!(gs.endpoint_of(PlayerId(5)), None);
    assert_eq!(net.guests[0].lobby.status(), GuestStatus::Starting);
}
