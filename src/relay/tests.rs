#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use super::code;
use super::*;
use crate::session::{
    GameStart, GuestConfig, GuestEvent, GuestLobby, HostConfig, HostEvent, HostLobby, MapInfo,
    Step, DISCOVERY_PORT, GAME_PORT,
};
use crate::types::Outgoing;

fn ms(n: u64) -> Instant {
    Instant(Duration::from_millis(n))
}

fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
    SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
}

const RELAY: Endpoint = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), DEFAULT_RELAY_PORT);

fn server(cfg: RelayConfig) -> RelayServer {
    RelayServer::new(cfg, [42; 32]).unwrap()
}

fn handle(s: &mut RelayServer, now: Instant, from: Endpoint, bytes: &[u8]) -> Vec<Outgoing> {
    let mut out = Vec::new();
    s.handle(now, from, bytes, &mut out);
    out
}

/// Allocate (or join) by hand, with the cookie round trip. Returns (room, secret, member).
fn hello(
    s: &mut RelayServer,
    now: Instant,
    from: Endpoint,
    join: Option<RoomId>,
) -> Result<(RoomId, u64, u8), RefuseReason> {
    let nonce = [from.ip().octets()[3], from.port() as u8, 1, 2, 3, 4, 5, 6];
    let frame = |cookie: Cookie| match join {
        None => ClientFrame::Allocate { nonce, cookie },
        Some(room) => ClientFrame::Join {
            nonce,
            cookie,
            room,
        },
    };
    let first = frame([0; 16]).encode().unwrap();
    let out = handle(s, now, from, &first);
    assert_eq!(out.len(), 1);
    assert!(
        out[0].bytes.len() <= first.len(),
        "challenge larger than hello"
    );
    let ServerFrame::Challenge { nonce: n, cookie } = decode_server(&out[0].bytes).unwrap() else {
        panic!("expected a challenge first");
    };
    assert_eq!(n, nonce);
    let out = handle(s, now, from, &frame(cookie).encode().unwrap());
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, from);
    match decode_server(&out[0].bytes).unwrap() {
        ServerFrame::Welcome {
            room,
            secret,
            member,
            ..
        } => Ok((room, secret, member)),
        ServerFrame::Refuse { reason, echo } => {
            assert_eq!(echo, nonce);
            Err(reason)
        }
        other => panic!("unexpected {other:?}"),
    }
}

fn data(room: RoomId, secret: u64, to: u8, payload: &[u8]) -> Vec<u8> {
    ClientFrame::Data {
        room,
        secret,
        to,
        src_port: 1338,
        dst_port: 1337,
        payload,
    }
    .encode()
    .unwrap()
}

fn host_addr() -> Endpoint {
    ep(198, 51, 100, 1, 40000)
}

fn guest_addr(i: u8) -> Endpoint {
    ep(192, 0, 2, 10 + i, 50000 + u16::from(i))
}

// ----- server ---------------------------------------------------------------------------

#[test]
fn allocate_needs_a_cookie_round_trip() {
    let mut s = server(RelayConfig::default());
    let hello0 = ClientFrame::Allocate {
        nonce: [1; 8],
        cookie: [0; 16],
    }
    .encode()
    .unwrap();
    let out = handle(&mut s, ms(0), host_addr(), &hello0);
    assert_eq!(s.room_count(), 0, "no state before the cookie comes back");
    let ServerFrame::Challenge { cookie, .. } = decode_server(&out[0].bytes).unwrap() else {
        panic!()
    };
    // The cookie does not work from another address, or with another nonce, or forged.
    let other = ep(198, 51, 100, 2, 40000);
    let with = |nonce, cookie| ClientFrame::Allocate { nonce, cookie }.encode().unwrap();
    for (from, bytes) in [
        (other, with([1; 8], cookie)),
        (host_addr(), with([2; 8], cookie)),
        (host_addr(), with([1; 8], [7; 16])),
    ] {
        let out = handle(&mut s, ms(10), from, &bytes);
        assert!(matches!(
            decode_server(&out[0].bytes),
            Ok(ServerFrame::Challenge { .. })
        ));
        assert_eq!(s.room_count(), 0);
    }
    // The real echo opens a room.
    let out = handle(&mut s, ms(20), host_addr(), &with([1; 8], cookie));
    let ServerFrame::Welcome {
        room,
        secret,
        member,
        members,
        max_payload,
        ..
    } = decode_server(&out[0].bytes).unwrap()
    else {
        panic!()
    };
    assert_ne!(room, 0);
    assert_ne!(secret, 0);
    assert_eq!((member, members, max_payload), (0, 1, 1400));
    assert_eq!(s.room_count(), 1);
    // A retransmitted hello (lost welcome) gets the same welcome, not a second room.
    let out = handle(&mut s, ms(30), host_addr(), &with([1; 8], [0; 16]));
    assert!(
        matches!(decode_server(&out[0].bytes), Ok(ServerFrame::Welcome { room: r, secret: x, .. }) if r == room && x == secret)
    );
    assert_eq!(s.room_count(), 1);
}

#[test]
fn cookies_expire_after_two_periods() {
    let mut s = server(RelayConfig::default());
    let nonce = [3; 8];
    let first = ClientFrame::Allocate {
        nonce,
        cookie: [0; 16],
    }
    .encode()
    .unwrap();
    let out = handle(&mut s, ms(1000), host_addr(), &first);
    let ServerFrame::Challenge { cookie, .. } = decode_server(&out[0].bytes).unwrap() else {
        panic!()
    };
    let again = ClientFrame::Allocate { nonce, cookie }.encode().unwrap();
    let out = handle(&mut s, ms(25_000), host_addr(), &again);
    assert!(matches!(
        decode_server(&out[0].bytes),
        Ok(ServerFrame::Challenge { .. })
    ));
    // Within the next period it still works.
    let out = handle(&mut s, ms(1000), host_addr(), &first);
    let ServerFrame::Challenge { cookie, .. } = decode_server(&out[0].bytes).unwrap() else {
        panic!()
    };
    let again = ClientFrame::Allocate { nonce, cookie }.encode().unwrap();
    let out = handle(&mut s, ms(15_000), host_addr(), &again);
    assert!(matches!(
        decode_server(&out[0].bytes),
        Ok(ServerFrame::Welcome { .. })
    ));
}

#[test]
fn join_and_forward_both_ways_unchanged() {
    let mut s = server(RelayConfig::default());
    let (room, hs, hm) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    let (r2, gs, gm) = hello(&mut s, ms(5), guest_addr(1), Some(room)).unwrap();
    assert_eq!((r2, hm, gm), (room, 0, 1));
    assert_eq!(s.members_of(room), Some(0b11));
    let payload: Vec<u8> = (0..=255u8).cycle().take(1400).collect();
    let out = handle(&mut s, ms(10), guest_addr(1), &data(room, gs, 0, &payload));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, host_addr());
    let ServerFrame::Deliver {
        secret,
        from,
        src_port,
        dst_port,
        payload: p,
    } = decode_server(&out[0].bytes).unwrap()
    else {
        panic!()
    };
    assert_eq!((secret, from, src_port, dst_port), (hs, 1, 1338, 1337));
    assert_eq!(p, &payload[..]);
    let out = handle(&mut s, ms(11), host_addr(), &data(room, hs, 1, b"back"));
    assert_eq!(out[0].to, guest_addr(1));
    assert!(
        matches!(decode_server(&out[0].bytes), Ok(ServerFrame::Deliver { secret, from: 0, payload: b"back", .. }) if secret == gs)
    );
    // To an absent member: a (rate-limited) refusal to the sender only.
    let out = handle(&mut s, ms(12), host_addr(), &data(room, hs, 5, b"x"));
    assert!(matches!(
        decode_server(&out[0].bytes),
        Ok(ServerFrame::Refuse {
            reason: RefuseReason::NoSuchMember,
            ..
        })
    ));
    let out = handle(&mut s, ms(13), host_addr(), &data(room, hs, 5, b"x"));
    assert!(
        out.is_empty(),
        "second refusal within the gap is suppressed"
    );
    // To itself: refused too.
    let out = handle(&mut s, ms(2000), host_addr(), &data(room, hs, 0, b"x"));
    assert!(matches!(
        decode_server(&out[0].bytes),
        Ok(ServerFrame::Refuse {
            reason: RefuseReason::NoSuchMember,
            ..
        })
    ));
    // Joining a room that does not exist is refused only after the cookie round trip.
    assert_eq!(
        hello(&mut s, ms(20), guest_addr(2), Some(room ^ 1)),
        Err(RefuseReason::NoSuchRoom)
    );
}

#[test]
fn member_limits() {
    let mut s = server(RelayConfig::default());
    let (room, _, _) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    for i in 1..10u8 {
        let (_, _, m) = hello(&mut s, ms(1), guest_addr(i), Some(room)).unwrap();
        assert_eq!(m, i);
    }
    assert_eq!(s.members_of(room), Some(0x3ff));
    assert_eq!(
        hello(&mut s, ms(2), guest_addr(10), Some(room)),
        Err(RefuseReason::RoomFull)
    );
    // A smaller configured limit.
    let mut s = server(RelayConfig {
        max_members: 3,
        ..RelayConfig::default()
    });
    let (room, _, _) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    hello(&mut s, ms(0), guest_addr(1), Some(room)).unwrap();
    hello(&mut s, ms(0), guest_addr(2), Some(room)).unwrap();
    assert_eq!(
        hello(&mut s, ms(0), guest_addr(3), Some(room)),
        Err(RefuseReason::RoomFull)
    );
    // A leaving member frees its index for the next joiner.
    assert!(RelayServer::new(
        RelayConfig {
            max_members: 11,
            ..RelayConfig::default()
        },
        [0; 32]
    )
    .is_err());
    assert!(RelayServer::new(
        RelayConfig {
            max_payload: 1401,
            ..RelayConfig::default()
        },
        [0; 32]
    )
    .is_err());
    assert!(RelayServer::new(
        RelayConfig {
            max_rooms: 0,
            ..RelayConfig::default()
        },
        [0; 32]
    )
    .is_err());
}

#[test]
fn room_limits() {
    let mut s = server(RelayConfig {
        max_rooms: 3,
        max_rooms_per_ip: 2,
        ..RelayConfig::default()
    });
    hello(&mut s, ms(0), ep(1, 1, 1, 1, 1), None).unwrap();
    hello(&mut s, ms(0), ep(1, 1, 1, 1, 2), None).unwrap();
    assert_eq!(
        hello(&mut s, ms(0), ep(1, 1, 1, 1, 3), None),
        Err(RefuseReason::TooManyRooms)
    );
    hello(&mut s, ms(0), ep(2, 2, 2, 2, 1), None).unwrap();
    assert_eq!(
        hello(&mut s, ms(0), ep(3, 3, 3, 3, 1), None),
        Err(RefuseReason::ServerFull)
    );
    assert_eq!(s.room_count(), 3);
}

#[test]
fn leave_frees_the_index_and_closes_empty_rooms() {
    let mut s = server(RelayConfig::default());
    let (room, hs, _) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    let (_, gs, _) = hello(&mut s, ms(0), guest_addr(1), Some(room)).unwrap();
    let leave = ClientFrame::Leave { room, secret: gs }.encode().unwrap();
    // Wrong address: ignored.
    handle(&mut s, ms(1), guest_addr(2), &leave);
    assert_eq!(s.members_of(room), Some(0b11));
    handle(&mut s, ms(1), guest_addr(1), &leave);
    assert_eq!(s.members_of(room), Some(0b01));
    let (_, _, m) = hello(&mut s, ms(2), guest_addr(3), Some(room)).unwrap();
    assert_eq!(m, 1);
    handle(
        &mut s,
        ms(3),
        host_addr(),
        &ClientFrame::Leave { room, secret: hs }.encode().unwrap(),
    );
    assert_eq!(s.room_count(), 1, "the guest is still there");
}

#[test]
fn rate_limit_packets_and_bytes() {
    let cfg = RelayConfig {
        member_packets_per_sec: 100,
        member_bytes_per_sec: 1_000_000,
        ..RelayConfig::default()
    };
    let mut s = server(cfg);
    let (room, hs, _) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    hello(&mut s, ms(0), guest_addr(1), Some(room)).unwrap();
    let frame = data(room, hs, 1, b"tick");
    let mut forwarded = 0;
    let mut refusals = 0;
    for _ in 0..150 {
        for o in handle(&mut s, ms(100), host_addr(), &frame) {
            match decode_server(&o.bytes).unwrap() {
                ServerFrame::Deliver { .. } => forwarded += 1,
                ServerFrame::Refuse {
                    reason: RefuseReason::RateLimited,
                    ..
                } => refusals += 1,
                other => panic!("{other:?}"),
            }
        }
    }
    assert_eq!(forwarded, 100, "one second's burst");
    assert_eq!(refusals, 1, "one refusal per gap");
    // Refills at the configured rate: 0.5 s later, 50 more.
    let mut more = 0;
    for _ in 0..100 {
        more += handle(&mut s, ms(600), host_addr(), &frame)
            .iter()
            .filter(|o| matches!(decode_server(&o.bytes), Ok(ServerFrame::Deliver { .. })))
            .count();
    }
    assert_eq!(more, 50);

    // Byte budget.
    let cfg = RelayConfig {
        member_packets_per_sec: 10_000,
        member_bytes_per_sec: 14_000,
        ..RelayConfig::default()
    };
    let mut s = server(cfg);
    let (room, hs, _) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    hello(&mut s, ms(0), guest_addr(1), Some(room)).unwrap();
    let big = data(room, hs, 1, &[0u8; 1400]);
    let n = (0..20)
        .flat_map(|_| handle(&mut s, ms(1), host_addr(), &big))
        .filter(|o| matches!(decode_server(&o.bytes), Ok(ServerFrame::Deliver { .. })))
        .count();
    assert_eq!(n, 10);
}

#[test]
fn oversized_payload_is_refused() {
    let mut s = server(RelayConfig {
        max_payload: 500,
        ..RelayConfig::default()
    });
    let (room, hs, _) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    hello(&mut s, ms(0), guest_addr(1), Some(room)).unwrap();
    let out = handle(&mut s, ms(1), host_addr(), &data(room, hs, 1, &[0u8; 501]));
    assert!(matches!(
        decode_server(&out[0].bytes),
        Ok(ServerFrame::Refuse {
            reason: RefuseReason::TooLarge,
            ..
        })
    ));
    assert_eq!(out.len(), 1);
    // Above the protocol limit the frame does not even decode.
    let mut raw = data(room, hs, 1, &[0u8; 1400]);
    raw.push(0);
    assert!(handle(&mut s, ms(2000), host_addr(), &raw).is_empty());
}

#[test]
fn idle_members_expire_and_empty_rooms_close() {
    let mut s = server(RelayConfig::default());
    let (room, hs, _) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    let (_, gs, _) = hello(&mut s, ms(0), guest_addr(1), Some(room)).unwrap();
    assert_eq!(s.next_deadline(), Some(ms(30_000)));
    // The host keeps pinging; the guest is silent.
    for t in (4000..=32_000).step_by(4000) {
        let ping = ClientFrame::Ping {
            room,
            secret: hs,
            id: t as u32,
            cookie: [0; 16],
        }
        .encode()
        .unwrap();
        let out = handle(&mut s, ms(t), host_addr(), &ping);
        assert!(matches!(
            decode_server(&out[0].bytes),
            Ok(ServerFrame::Pong { .. })
        ));
        s.poll(ms(t));
    }
    assert_eq!(s.members_of(room), Some(0b01));
    // The expired guest is told it is no longer a member, no larger than its ping.
    let ping = ClientFrame::Ping {
        room,
        secret: gs,
        id: 1,
        cookie: [0; 16],
    }
    .encode()
    .unwrap();
    let out = handle(&mut s, ms(32_001), guest_addr(1), &ping);
    assert!(out[0].bytes.len() <= ping.len());
    assert_eq!(
        decode_server(&out[0].bytes).unwrap(),
        ServerFrame::Refuse {
            echo: gs.to_be_bytes(),
            reason: RefuseReason::NotMember
        }
    );
    let ev = s.poll(ms(70_000));
    assert!(ev.contains(&ServerEvent::RoomClosed { room }));
    assert_eq!(s.room_count(), 0);
    assert_eq!(s.next_deadline(), None);
}

#[test]
fn spoofed_or_wrong_secrets_are_refused() {
    let mut s = server(RelayConfig::default());
    let (room, hs, _) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    let (_, gs, _) = hello(&mut s, ms(0), guest_addr(1), Some(room)).unwrap();
    let before = s.stats();
    // Wrong secret from the member's own address.
    assert!(handle(&mut s, ms(1), host_addr(), &data(room, hs ^ 1, 1, b"x")).is_empty());
    // The guest's secret, but sent as if from the host (or a stranger).
    assert!(handle(&mut s, ms(1), host_addr(), &data(room, gs, 0, b"x")).is_empty());
    assert!(handle(&mut s, ms(1), ep(6, 6, 6, 6, 6), &data(room, gs, 0, b"x")).is_empty());
    // Right secret, wrong room.
    assert!(handle(&mut s, ms(1), host_addr(), &data(room ^ 1, hs, 1, b"x")).is_empty());
    assert_eq!(s.stats().forwarded, before.forwarded);
    assert_eq!(s.stats().dropped, before.dropped + 4);
    // A forged welcome-retransmit: a join hello from a stranger for the room gets a
    // challenge, never a welcome with someone else's secret.
    let j = ClientFrame::Join {
        nonce: [0; 8],
        cookie: [0; 16],
        room,
    }
    .encode()
    .unwrap();
    let out = handle(&mut s, ms(1), ep(6, 6, 6, 6, 6), &j);
    assert!(matches!(
        decode_server(&out[0].bytes),
        Ok(ServerFrame::Challenge { .. })
    ));
}

#[test]
fn a_moved_member_is_rebound_only_after_a_cookie() {
    let mut s = server(RelayConfig::default());
    let (room, hs, _) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    let (_, gs, _) = hello(&mut s, ms(0), guest_addr(1), Some(room)).unwrap();
    let moved = ep(192, 0, 2, 11, 61000);
    // Data from the new address is not forwarded yet.
    assert!(handle(&mut s, ms(1), moved, &data(room, gs, 0, b"x")).is_empty());
    let ping = ClientFrame::Ping {
        room,
        secret: gs,
        id: 9,
        cookie: [0; 16],
    }
    .encode()
    .unwrap();
    let out = handle(&mut s, ms(2), moved, &ping);
    assert!(out[0].bytes.len() <= ping.len());
    let ServerFrame::Pong {
        cookie, members: 0, ..
    } = decode_server(&out[0].bytes).unwrap()
    else {
        panic!()
    };
    assert_ne!(cookie, [0; 16]);
    // The cookie is bound to the new address.
    let confirm = ClientFrame::Ping {
        room,
        secret: gs,
        id: 10,
        cookie,
    }
    .encode()
    .unwrap();
    let out = handle(&mut s, ms(3), ep(9, 9, 9, 9, 9), &confirm);
    assert!(matches!(
        decode_server(&out[0].bytes),
        Ok(ServerFrame::Pong { members: 0, .. })
    ));
    let mut out = Vec::new();
    let ev = s.handle(ms(3), moved, &confirm, &mut out);
    assert!(ev
        .iter()
        .any(|e| matches!(e, ServerEvent::MemberMoved { to, .. } if *to == moved)));
    assert!(matches!(
        decode_server(&out[0].bytes),
        Ok(ServerFrame::Pong { members: 0b11, .. })
    ));
    // Now forwarding works from the new address, and goes to it.
    assert_eq!(
        handle(&mut s, ms(4), moved, &data(room, gs, 0, b"x")).len(),
        1
    );
    let out = handle(&mut s, ms(4), host_addr(), &data(room, hs, 1, b"y"));
    assert_eq!(out[0].to, moved);
}

#[test]
fn never_sends_more_to_an_unverified_source_than_it_received() {
    let mut s = server(RelayConfig::default());
    let (room, hs, _) = hello(&mut s, ms(0), host_addr(), None).unwrap();
    let (_, gs, _) = hello(&mut s, ms(0), guest_addr(1), Some(room)).unwrap();
    let members = [host_addr(), guest_addr(1)];
    let mut x: u64 = 0xdead_beef_cafe_f00d;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let base = s.stats();
    for i in 0..20_000u64 {
        let r = next();
        let from = ep(
            100,
            (r >> 8) as u8,
            (r >> 16) as u8,
            (r >> 24) as u8,
            (r >> 32) as u16,
        );
        let bytes = match r % 7 {
            0 => ClientFrame::Allocate {
                nonce: (r ^ i).to_be_bytes(),
                cookie: [(r >> 40) as u8; 16],
            }
            .encode()
            .unwrap(),
            1 => ClientFrame::Join {
                nonce: r.to_be_bytes(),
                cookie: [0; 16],
                room,
            }
            .encode()
            .unwrap(),
            2 => ClientFrame::Ping {
                room,
                secret: if r & 8 == 0 { gs } else { r },
                id: 1,
                cookie: [0; 16],
            }
            .encode()
            .unwrap(),
            3 => data(
                room,
                if r & 8 == 0 { hs } else { r },
                1,
                &vec![0u8; (r % 1400) as usize],
            ),
            4 => ClientFrame::Leave { room, secret: r }.encode().unwrap(),
            _ => (0..(r % 100)).map(|k| (r >> (k % 56)) as u8).collect(),
        };
        let out = handle(&mut s, ms(i / 10), from, &bytes);
        assert!(out.len() <= 1);
        for o in &out {
            assert!(
                !members.contains(&o.to),
                "a stranger made the relay send to a member"
            );
            assert_eq!(o.to, from);
            assert!(
                o.bytes.len() <= bytes.len(),
                "amplification: {} > {}",
                o.bytes.len(),
                bytes.len()
            );
        }
    }
    let st = s.stats();
    assert!(
        st.unverified_sent_bytes - base.unverified_sent_bytes
            <= st.unverified_received_bytes - base.unverified_received_bytes
    );
    assert_eq!(st.forwarded, base.forwarded);
    assert_eq!(s.members_of(room), Some(0b11));
}

// ----- client ---------------------------------------------------------------------------

/// An in-memory world: one relay server and some links, with optional loss of everything.
struct World {
    now: Instant,
    server: RelayServer,
    links: Vec<(Endpoint, RelayLink)>,
    queue: VecDeque<(Endpoint, Endpoint, Vec<u8>)>,
    delivered: Vec<(usize, Delivered)>,
    events: Vec<(usize, RelayEvent)>,
    relay_down: bool,
}

impl World {
    fn new() -> Self {
        Self {
            now: ms(0),
            server: server(RelayConfig::default()),
            links: Vec::new(),
            queue: VecDeque::new(),
            delivered: Vec::new(),
            events: Vec::new(),
            relay_down: false,
        }
    }

    fn add(&mut self, addr: Endpoint, link: RelayLink) -> usize {
        self.links.push((addr, link));
        self.links.len() - 1
    }

    fn send(&mut self, from: Endpoint, outs: Vec<Outgoing>) {
        for o in outs {
            self.queue.push_back((from, o.to, o.bytes));
        }
    }

    fn pump(&mut self) {
        while let Some((from, to, bytes)) = self.queue.pop_front() {
            if to == RELAY {
                if self.relay_down {
                    continue;
                }
                let mut out = Vec::new();
                self.server.handle(self.now, from, &bytes, &mut out);
                self.send(RELAY, out);
            } else if let Some(i) = self.links.iter().position(|(a, _)| *a == to) {
                let now = self.now;
                match self.links[i].1.handle(now, from, &bytes) {
                    Received::Datagram(d) => self.delivered.push((i, d)),
                    Received::Event(e) => self.events.push((i, e)),
                    Received::NotRelay | Received::Nothing => {}
                }
            }
        }
    }

    fn step(&mut self, millis: u64) {
        self.now = Instant(self.now.0 + Duration::from_millis(millis));
        for i in 0..self.links.len() {
            let mut out = Vec::new();
            let now = self.now;
            let ev = self.links[i].1.poll(now, &mut out);
            self.events.extend(ev.into_iter().map(|e| (i, e)));
            let from = self.links[i].0;
            self.send(from, out);
        }
        self.server.poll(self.now);
        self.pump();
    }

    fn run(&mut self, millis: u64) {
        for _ in 0..millis / 10 {
            self.step(10);
        }
    }
}

#[test]
fn synthetic_endpoints() {
    for k in 0..10 {
        let e = peer_endpoint(k, 1337);
        assert_eq!(member_of(e), Some(k));
        assert!(is_synthetic(e));
        assert!(crate::nat::is_sendable(e));
    }
    assert_eq!(peer_endpoint(0, 1338), ep(0, 0, 0, 1, 1338));
    assert_eq!(member_of(ep(0, 0, 0, 0, 1)), None);
    assert_eq!(member_of(ep(0, 0, 0, 11, 1)), None);
    assert_eq!(member_of(ep(10, 0, 0, 1, 1)), None);
    assert_eq!(member_of(ep(0, 0, 1, 1, 1)), None);
}

#[test]
fn client_wrap_unwrap_round_trip() {
    let mut w = World::new();
    let h = w.add(host_addr(), RelayLink::host(RELAY, [1; 8], ms(0)));
    // Not joined yet.
    let o = Outgoing {
        to: peer_endpoint(1, 1338),
        bytes: vec![1],
    };
    assert_eq!(w.links[h].1.wrap(1338, &o), Err(WrapError::NotJoined));
    w.run(100);
    let LinkState::Joined { room, me: 0 } = w.links[h].1.state() else {
        panic!("{:?}", w.links[h].1.state())
    };
    assert!(w.events.contains(&(h, RelayEvent::Joined { room, me: 0 })));
    let g = w.add(guest_addr(1), RelayLink::guest(RELAY, room, [2; 8], w.now));
    w.run(100);
    assert_eq!(w.links[g].1.state(), LinkState::Joined { room, me: 1 });
    assert_eq!(w.links[g].1.my_endpoint(1338), Some(peer_endpoint(1, 1338)));

    // Guest lobby -> host discovery endpoint, and the host replies to the source it saw.
    let payload: Vec<u8> = (0..1400u32).map(|i| (i * 7) as u8).collect();
    let o = Outgoing {
        to: peer_endpoint(0, 1338),
        bytes: payload.clone(),
    };
    let mut relayed = Vec::new();
    let (direct, dropped) = w.links[g].1.wrap_all(
        1338,
        vec![
            o,
            Outgoing {
                to: ep(255, 255, 255, 255, 1338),
                bytes: vec![9],
            },
        ],
        &mut relayed,
    );
    assert_eq!((direct.len(), dropped, relayed.len()), (1, 0, 1));
    assert_eq!(relayed[0].to, RELAY);
    w.send(guest_addr(1), relayed);
    w.pump();
    let (i, d) = w.delivered.pop().unwrap();
    assert_eq!(i, h);
    assert_eq!(
        d,
        Delivered {
            from: peer_endpoint(1, 1338),
            to_port: 1338,
            payload
        }
    );
    let reply = Outgoing {
        to: d.from,
        bytes: b"announce".to_vec(),
    };
    let wrapped = w.links[h].1.wrap(1338, &reply).unwrap();
    w.send(host_addr(), vec![wrapped]);
    w.pump();
    let (i, d) = w.delivered.pop().unwrap();
    assert_eq!(
        (i, d.from, d.to_port, d.payload.as_slice()),
        (g, peer_endpoint(0, 1338), 1338, &b"announce"[..])
    );
    // Game traffic keeps its ports: from game port to game port.
    let game = Outgoing {
        to: peer_endpoint(1, 6671),
        bytes: b"tick".to_vec(),
    };
    w.send(host_addr(), vec![w.links[h].1.wrap(6670, &game).unwrap()]);
    w.pump();
    let (_, d) = w.delivered.pop().unwrap();
    assert_eq!((d.from, d.to_port), (peer_endpoint(0, 6670), 6671));

    // Wrap refusals.
    let link = &w.links[g].1;
    assert_eq!(
        link.wrap(
            1,
            &Outgoing {
                to: ep(8, 8, 8, 8, 1),
                bytes: vec![]
            }
        ),
        Err(WrapError::NotRelayed)
    );
    assert_eq!(
        link.wrap(
            1,
            &Outgoing {
                to: peer_endpoint(1, 1),
                bytes: vec![]
            }
        ),
        Err(WrapError::ToSelf)
    );
    assert_eq!(
        link.wrap(
            1,
            &Outgoing {
                to: peer_endpoint(0, 1),
                bytes: vec![0; 1401]
            }
        ),
        Err(WrapError::TooLarge {
            len: 1401,
            max: 1400
        })
    );
}

#[test]
fn client_ignores_forged_frames() {
    let mut w = World::new();
    let h = w.add(host_addr(), RelayLink::host(RELAY, [1; 8], ms(0)));
    w.run(100);
    let link = &mut w.links[h].1;
    let forged = ServerFrame::Deliver {
        secret: 12345,
        from: 1,
        src_port: 1,
        dst_port: 2,
        payload: b"evil",
    }
    .encode()
    .unwrap();
    assert_eq!(link.handle(ms(200), RELAY, &forged), Received::Nothing);
    // The same frame from somewhere other than the relay is not the relay's business.
    assert_eq!(
        link.handle(ms(200), ep(6, 6, 6, 6, 6), &forged),
        Received::NotRelay
    );
    assert_eq!(
        link.handle(ms(200), RELAY, b"BL\x01junk"),
        Received::NotRelay
    );
    // A refusal that does not echo our secret cannot end the link.
    let refuse = ServerFrame::Refuse {
        echo: [0; 8],
        reason: RefuseReason::NotMember,
    }
    .encode()
    .unwrap();
    assert_eq!(link.handle(ms(200), RELAY, &refuse), Received::Nothing);
    assert!(matches!(link.state(), LinkState::Joined { .. }));
    // Truncations and garbage never panic.
    for n in 0..forged.len() {
        let _ = link.handle(ms(200), RELAY, &forged[..n]);
    }
}

#[test]
fn client_keepalive_rtt_and_loss() {
    let mut w = World::new();
    let h = w.add(host_addr(), RelayLink::host(RELAY, [1; 8], ms(0)));
    w.run(100);
    assert!(w.links[h].1.rtt().is_none());
    // Answer pings with a 30 ms delay by holding the queue.
    let mut pings = 0;
    for _ in 0..1000 {
        w.now = Instant(w.now.0 + Duration::from_millis(10));
        let mut out = Vec::new();
        let now = w.now;
        w.links[h].1.poll(now, &mut out);
        pings += out.len();
        let mut replies = Vec::new();
        for o in out {
            w.server.handle(now, host_addr(), &o.bytes, &mut replies);
        }
        let later = Instant(now.0 + Duration::from_millis(30));
        for r in replies {
            w.links[h].1.handle(later, RELAY, &r.bytes);
        }
    }
    assert!((2..=3).contains(&pings), "a ping every 4 s: {pings}");
    assert_eq!(w.links[h].1.rtt(), Some(Duration::from_millis(30)));
    assert_eq!(w.links[h].1.latest_rtt(), Some(Duration::from_millis(30)));
    // The relay vanishes: the link reports loss.
    w.relay_down = true;
    w.run(16_000);
    assert!(w.events.contains(&(h, RelayEvent::Failed(LinkError::Lost))));
    assert_eq!(w.links[h].1.next_deadline(), None);
}

#[test]
fn client_times_out_and_reports_refusals() {
    let mut w = World::new();
    w.relay_down = true;
    let h = w.add(host_addr(), RelayLink::host(RELAY, [1; 8], ms(0)));
    w.run(11_000);
    assert_eq!(w.links[h].1.state(), LinkState::Failed(LinkError::Timeout));

    let mut w = World::new();
    let g = w.add(
        guest_addr(1),
        RelayLink::guest(RELAY, 0x1234, [2; 8], ms(0)),
    );
    w.run(200);
    assert_eq!(
        w.links[g].1.state(),
        LinkState::Failed(LinkError::Refused(RefuseReason::NoSuchRoom))
    );
    assert_eq!(
        LinkError::Refused(RefuseReason::NoSuchRoom).to_string(),
        "That relayed game no longer exists."
    );
}

#[test]
fn client_follows_a_nat_rebinding() {
    let mut w = World::new();
    let h = w.add(host_addr(), RelayLink::host(RELAY, [1; 8], ms(0)));
    w.run(100);
    let room = w.links[h].1.room().unwrap();
    let g = w.add(guest_addr(1), RelayLink::guest(RELAY, room, [2; 8], w.now));
    w.run(100);
    // The guest's router gives it a new outside port.
    let moved = ep(192, 0, 2, 11, 62000);
    w.links[g].0 = moved;
    w.run(4500);
    let out = w.links[h]
        .1
        .wrap(
            1338,
            &Outgoing {
                to: peer_endpoint(1, 1338),
                bytes: b"hi".to_vec(),
            },
        )
        .unwrap();
    w.send(host_addr(), vec![out]);
    w.pump();
    assert!(w
        .delivered
        .iter()
        .any(|(i, d)| *i == g && d.payload == b"hi"));
}

#[test]
fn fallback_policy() {
    use crate::nat::traversal::{Status, TraversalFailure};
    let mut p = FallbackPolicy::new();
    p.note_traversal(&Status::Working);
    assert_eq!(p.poll(ms(0)), None);
    p.note_traversal(&Status::Failed(TraversalFailure::PortInUse(1337)));
    assert_eq!(p.poll(ms(0)), None, "a busy port is not fixed by a relay");
    p.note_traversal(&Status::Failed(TraversalFailure::Symmetric));
    assert_eq!(
        p.poll(ms(1)),
        Some(FallbackReason::Traversal(TraversalFailure::Symmetric))
    );
    assert_eq!(p.poll(ms(2)), None, "reported once");

    let mut p = FallbackPolicy::new();
    p.expect_contact(ms(1000));
    assert_eq!(p.poll(ms(10_999)), None);
    assert_eq!(p.poll(ms(11_000)), Some(FallbackReason::NoDirectContact));

    let mut p = FallbackPolicy::new();
    p.expect_contact(ms(0));
    p.note_direct_contact();
    assert_eq!(p.poll(ms(60_000)), None);
}

// ----- end to end -----------------------------------------------------------------------

const BUILD: &[u8] = b"relay-e2e-build";

fn mesa() -> MapInfo {
    MapInfo {
        name: "Mesa".into(),
        identity: crate::session::map_identity(b"d", b"t"),
    }
}

/// A machine: its relay socket address, its link, and its lobby.
enum Lobby {
    Host(Box<HostLobby>),
    Guest(Box<GuestLobby>),
    None,
}

struct Machine {
    addr: Endpoint,
    link: RelayLink,
    lobby: Lobby,
    host_events: Vec<HostEvent>,
    guest_events: Vec<GuestEvent>,
}

impl Machine {
    fn started(&self) -> Option<GameStart> {
        self.host_events
            .iter()
            .find_map(|e| match e {
                HostEvent::Started(g) => Some((**g).clone()),
                _ => None,
            })
            .or_else(|| {
                self.guest_events.iter().find_map(|e| match e {
                    GuestEvent::Started(g) => Some((**g).clone()),
                    _ => None,
                })
            })
    }
}

struct Internet {
    now: Instant,
    server: RelayServer,
    machines: Vec<Machine>,
    queue: VecDeque<(Endpoint, Endpoint, Vec<u8>)>,
    direct_dropped: usize,
}

impl Internet {
    /// Send what a lobby produced from its discovery port: synthetic destinations go
    /// through the relay; every direct path (broadcast, loopback, real peers) drops it.
    fn lobby_sends<E>(&mut self, i: usize, step: Step<E>) -> Vec<E> {
        let mut relayed = Vec::new();
        let (direct, _) = self.machines[i]
            .link
            .wrap_all(DISCOVERY_PORT, step.send, &mut relayed);
        self.direct_dropped += direct.len();
        let from = self.machines[i].addr;
        for o in relayed {
            self.queue.push_back((from, o.to, o.bytes));
        }
        step.events
    }

    fn feed(&mut self, i: usize, from: Endpoint, bytes: &[u8]) {
        let now = self.now;
        let Received::Datagram(d) = self.machines[i].link.handle(now, from, bytes) else {
            return;
        };
        assert_eq!(d.to_port, DISCOVERY_PORT, "only lobby traffic in this test");
        match &mut self.machines[i].lobby {
            Lobby::Host(h) => {
                let s = h.on_datagram(now, d.from, &d.payload);
                let ev = self.lobby_sends(i, s);
                self.machines[i].host_events.extend(ev);
            }
            Lobby::Guest(g) => {
                let s = g.on_datagram(now, d.from, &d.payload);
                let ev = self.lobby_sends(i, s);
                self.machines[i].guest_events.extend(ev);
            }
            Lobby::None => {}
        }
    }

    fn pump(&mut self) {
        let mut guard = 0;
        while let Some((from, to, bytes)) = self.queue.pop_front() {
            guard += 1;
            assert!(guard < 200_000, "datagram storm");
            if to == RELAY {
                let mut out = Vec::new();
                self.server.handle(self.now, from, &bytes, &mut out);
                for o in out {
                    self.queue.push_back((RELAY, o.to, o.bytes));
                }
            } else if let Some(i) = self.machines.iter().position(|m| m.addr == to) {
                self.feed(i, from, &bytes);
            }
        }
    }

    fn run(&mut self, millis: u64) {
        for _ in 0..millis / 50 {
            self.now = Instant(self.now.0 + Duration::from_millis(50));
            let now = self.now;
            for i in 0..self.machines.len() {
                let mut out = Vec::new();
                self.machines[i].link.poll(now, &mut out);
                let from = self.machines[i].addr;
                for o in out {
                    self.queue.push_back((from, o.to, o.bytes));
                }
                match &mut self.machines[i].lobby {
                    Lobby::Host(h) => {
                        let s = h.poll(now);
                        let ev = self.lobby_sends(i, s);
                        self.machines[i].host_events.extend(ev);
                    }
                    Lobby::Guest(g) => {
                        let s = g.poll(now);
                        let ev = self.lobby_sends(i, s);
                        self.machines[i].guest_events.extend(ev);
                    }
                    Lobby::None => {}
                }
            }
            self.server.poll(now);
            self.pump();
        }
    }
}

#[test]
fn end_to_end_lobby_to_game_start_through_the_relay() {
    let mut net = Internet {
        now: ms(0),
        server: server(RelayConfig::default()),
        machines: Vec::new(),
        queue: VecDeque::new(),
        direct_dropped: 0,
    };
    // The host: traversal failed (symmetric NAT), so it opens a relay room.
    let mut policy = FallbackPolicy::new();
    policy.note_traversal(&crate::nat::traversal::Status::Failed(
        crate::nat::traversal::TraversalFailure::Symmetric,
    ));
    assert!(policy.poll(ms(0)).is_some());
    let mut cfg = HostConfig::new("Hosty", "Relayed", BUILD, 0xabcdef, [5; 32]);
    cfg.require_approval = false;
    let mut host = HostLobby::new(cfg, ms(0)).unwrap();
    host.set_map(ms(0), Some(mesa())).unwrap();
    net.machines.push(Machine {
        addr: ep(198, 51, 100, 1, 40000),
        link: RelayLink::host(RELAY, [1; 8], ms(0)),
        lobby: Lobby::Host(Box::new(host)),
        host_events: Vec::new(),
        guest_events: Vec::new(),
    });
    net.run(500);
    let room = net.machines[0].link.room().expect("room allocated");
    let text = code::encode(&RelayInvite {
        relay: RelayRef::Endpoint(RELAY),
        room,
    })
    .unwrap();

    // Two guests read the code and join the room, then the lobby.
    for (i, name) in [(1u8, "Ann"), (2, "Bob")] {
        let AnyInvite::Relay(inv) = code::decode_any(&text).unwrap() else {
            panic!("a relay code")
        };
        let relay = code::resolve(inv.relay, &[]).unwrap();
        net.machines.push(Machine {
            addr: ep(100, 64, i, 7, 50000),
            link: RelayLink::guest(relay, inv.room, [10 + i; 8], net.now),
            lobby: Lobby::None,
            host_events: Vec::new(),
            guest_events: Vec::new(),
        });
        let k = net.machines.len() - 1;
        net.run(300);
        assert_eq!(net.machines[k].link.me(), Some(i));
        let mut g = GuestConfig::new(name, BUILD, peer_endpoint(0, DISCOVERY_PORT), [i; 16]);
        g.maps = vec![mesa()];
        g.colour = 3 + i;
        g.via_code = true;
        net.machines[k].lobby = Lobby::Guest(Box::new(GuestLobby::new(g, net.now).unwrap()));
    }

    let seated = |n: &Internet| {
        n.machines[1..].iter().all(|m| {
            m.guest_events
                .iter()
                .any(|e| matches!(e, GuestEvent::Seated(_)))
        })
    };
    for _ in 0..200 {
        if seated(&net) {
            break;
        }
        net.run(100);
    }
    assert!(seated(&net), "{:?}", net.machines[2].guest_events);
    net.run(2000);
    for k in 1..3 {
        let now = net.now;
        let Lobby::Guest(g) = &mut net.machines[k].lobby else {
            panic!()
        };
        let s = g.set_ready(now, true);
        let ev = net.lobby_sends(k, s);
        net.machines[k].guest_events.extend(ev);
    }
    net.run(2000);
    let now = net.now;
    let Lobby::Host(h) = &mut net.machines[0].lobby else {
        panic!()
    };
    assert_eq!(h.start_blocker(), None);
    let s = h.start(now, 0x5eed).unwrap();
    let ev = net.lobby_sends(0, s);
    net.machines[0].host_events.extend(ev);
    net.run(4000);

    let starts: Vec<GameStart> = net
        .machines
        .iter()
        .map(|m| m.started().expect("started"))
        .collect();
    assert!(
        net.direct_dropped > 0,
        "the direct paths really carried nothing"
    );
    let seeds: Vec<u64> = starts.iter().map(GameStart::simulation_seed).collect();
    assert!(seeds.iter().all(|s| *s == seeds[0]));
    // Every peer's addresses are synthetic and name the same relay member everywhere.
    let host_start = &starts[0];
    assert_eq!(host_start.peers.len(), 2);
    for (id, e) in &host_start.peers {
        let m = member_of(*e).expect("synthetic");
        assert_eq!(e.port(), GAME_PORT);
        let k = starts.iter().position(|s| s.my_seat == *id).unwrap();
        assert_eq!(net.machines[k].link.me(), Some(m));
    }
    for gs in &starts[1..] {
        assert_eq!(
            gs.endpoint_of(crate::types::PlayerId(0)),
            Some(peer_endpoint(0, GAME_PORT))
        );
        for (id, e) in &host_start.peers {
            if *id != gs.my_seat {
                assert_eq!(gs.endpoint_of(*id), Some(*e));
            }
        }
    }
}
