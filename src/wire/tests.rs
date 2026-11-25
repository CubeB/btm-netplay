#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use super::*;
use crate::types::{Instant, PlayerId};

fn at(ms: u64) -> Instant {
    Instant(Duration::from_millis(ms))
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn sample_update() -> Update {
    Update {
        sender: PlayerId(3),
        packet_id: 77,
        run: RunState {
            scene_time: 123_456,
            speed: 1500,
            chosen: 2000,
            paused: true,
            stalled: false,
            capacity: 900,
        },
        pause: SharedPause {
            revision: 9,
            player: PlayerId(2),
            paused: true,
        },
        ack_delay_ms: 42,
        commands: Chunk {
            first: 1000,
            ack: 998,
            items: vec![vec![], vec![1, 2, 3], vec![0xFF; 300]],
        },
        hashes: Chunk {
            first: 5,
            ack: 6,
            items: vec![0xDEAD_BEEF, 0, u32::MAX],
        },
        chat: Chunk {
            first: 2,
            ack: 0,
            items: vec![ChatLine {
                text: "héllo".as_bytes().to_vec(),
                label: ChatLabel::Allies,
            }],
        },
        held: vec![(PlayerId(0), 5), (PlayerId(9), 70_000)],
        relay: Some(Relay {
            player: PlayerId(1),
            first: 40,
            sets: vec![vec![], vec![9; 20]],
        }),
    }
}

fn header(sender: u8) -> Header {
    Header::new(
        PlayerId(sender),
        RunState::default(),
        SharedPause::default(),
    )
}

#[test]
fn round_trip() {
    let msgs = [
        Message::Update(sample_update()),
        Message::Update(Update::default()),
        Message::LoadStatus(LoadStatus {
            sender: PlayerId(9),
            ready: true,
        }),
    ];
    for m in msgs {
        let d = encode_datagram(&m).unwrap();
        assert_eq!(d[0], VERSION);
        assert_eq!(decode_datagram(&d).unwrap(), m);
    }
}

#[test]
fn crc_rejects_every_single_bit_flip() {
    let d = encode_datagram(&Message::Update(sample_update())).unwrap();
    for byte in 0..d.len() {
        for bit in 0..8 {
            let mut c = d.clone();
            c[byte] ^= 1 << bit;
            assert_eq!(decode_datagram(&c), Err(WireError::BadCrc));
        }
    }
    assert_eq!(decode_datagram(&[1, 2, 3]), Err(WireError::TooShort));
    assert!(matches!(
        decode_datagram(&vec![0; 1501]),
        Err(WireError::TooLarge(1501))
    ));
}

#[test]
fn bad_version_and_kind() {
    let mut p = encode_message(&Message::Update(sample_update()));
    p[0] = 2;
    assert_eq!(
        decode_datagram(&seal(p).unwrap()),
        Err(WireError::BadVersion(2))
    );
    assert_eq!(
        decode_datagram(&seal(vec![VERSION, 99]).unwrap()),
        Err(WireError::UnknownKind(99))
    );
}

#[test]
fn truncated_and_random_bytes_never_panic() {
    let p = encode_message(&Message::Update(sample_update()));
    for n in 0..p.len() {
        // Every strict prefix fails to parse, even with a valid CRC.
        assert!(decode_datagram(&seal(p[..n].to_vec()).unwrap()).is_err());
    }
    let mut rng = Rng(1);
    for _ in 0..20_000 {
        let len = rng.below(200) as usize;
        let mut b: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        if rng.below(2) == 0 && len >= 2 {
            b[0] = VERSION;
            b[1] = 2;
        }
        let _ = decode_message(&b);
        let _ = decode_datagram(&seal(b.clone()).unwrap_or_default());
        let _ = decode_datagram(&b);
    }
    // Mutations of a valid message, CRC fixed up.
    for _ in 0..20_000 {
        let mut b = p.clone();
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(b.len() as u64) as usize;
            b[i] = rng.next() as u8;
        }
        let _ = decode_datagram(&seal(b).unwrap());
    }
}

#[test]
fn huge_counts_are_refused_before_allocating() {
    let mut w = Writer::new();
    w.u8(VERSION);
    w.u8(2);
    w.u8(0); // sender
    for _ in 0..5 {
        w.varint(0); // packet id, scene, speed, chosen, capacity
    }
    w.u8(0); // flags
    w.varint(0); // pause revision
    w.u8(0); // pause player
    w.varint(0); // ack delay
    w.varint(0); // held count
    w.varint(0); // first command
    w.varint(0); // command ack
    w.varint(u64::from(u32::MAX)); // command count
    assert_eq!(decode_message(&w.finish()), Err(WireError::Truncated));
}

/// Two links joined by a lossy, reordering, duplicating channel deliver every
/// item of every stream exactly once and in order.
#[test]
fn resend_and_ack_under_loss() {
    let mut rng = Rng(7);
    let mut a = Link::new(0, 0);
    let mut b = Link::new(0, 0);
    let total = 400u32;
    let mut got_cmds: Vec<Vec<u8>> = Vec::new();
    let mut got_hashes = Vec::new();
    let mut got_chat = Vec::new();
    let mut in_flight: Vec<(u64, bool, Vec<u8>)> = Vec::new(); // (deliver at, to_b, bytes)
    let mut pushed = 0u32;
    let mut chat_pushed = 0u32;
    for t in 0..20_000u64 {
        let now = at(t);
        if t % 5 == 0 && pushed < total {
            a.push_command(pushed.to_le_bytes().to_vec());
            a.push_hash(pushed.wrapping_mul(31));
            pushed += 1;
        }
        if t % 37 == 0
            && chat_pushed < 100
            && a.push_chat(ChatLine {
                text: chat_pushed.to_string().into_bytes(),
                label: ChatLabel::None,
            })
            .is_ok()
        {
            chat_pushed += 1;
        }
        for (link, to_b) in [(&mut a, true), (&mut b, false)] {
            if link.due(now) {
                let built = link.build(now, header(u8::from(!to_b)));
                assert!(built.error.is_none());
                assert!(built.bytes.len() <= MAX_DATAGRAM);
                if rng.below(100) < 40 {
                    continue; // lost
                }
                let copies = if rng.below(100) < 10 { 2 } else { 1 };
                for _ in 0..copies {
                    in_flight.push((t + 5 + rng.below(30), to_b, built.bytes.clone()));
                }
            }
        }
        let (due, rest): (Vec<_>, Vec<_>) = in_flight.into_iter().partition(|x| x.0 <= t);
        in_flight = rest;
        for (_, to_b, bytes) in due {
            let Ok(Message::Update(u)) = decode_datagram(&bytes) else {
                panic!("bad datagram")
            };
            let room = Room {
                commands: 900,
                hashes: 900,
                accept_commands: true,
            };
            if to_b {
                let inc = b.receive(now, &u, room, |_| true);
                got_cmds.extend(inc.commands);
                got_hashes.extend(inc.hashes);
                got_chat.extend(inc.chat);
            } else {
                a.receive(now, &u, room, |_| true);
            }
        }
    }
    let want: Vec<Vec<u8>> = (0..total).map(|i| i.to_le_bytes().to_vec()).collect();
    assert_eq!(got_cmds, want);
    assert_eq!(
        got_hashes,
        (0..total).map(|i| i.wrapping_mul(31)).collect::<Vec<_>>()
    );
    assert_eq!(got_chat.len(), chat_pushed as usize);
    for (i, c) in got_chat.iter().enumerate() {
        assert_eq!(c.text, i.to_string().into_bytes());
    }
    assert_eq!(a.unacked_commands(), 0);
    assert!(a.rtt().has_sample());
}

#[test]
fn caps() {
    // Chat: 32 unacked lines per peer.
    let mut a = Link::new(0, 0);
    for _ in 0..MAX_UNACKED_CHAT {
        a.push_chat(ChatLine::default()).unwrap();
    }
    assert_eq!(a.push_chat(ChatLine::default()), Err(ChatFull));

    // Packets stay under 1500 bytes however much is queued; the longest prefix goes.
    let mut a = Link::new(0, 0);
    for _ in 0..50 {
        a.push_command(vec![7; 500]);
    }
    let built = a.build(at(0), header(0));
    assert!(built.bytes.len() <= MAX_DATAGRAM);
    let Ok(Message::Update(u)) = decode_datagram(&built.bytes) else {
        panic!()
    };
    assert_eq!(u.commands.items.len(), 2);

    // A set that can never fit is reported.
    let mut a = Link::new(0, 0);
    a.push_command(vec![1; 1600]);
    assert!(matches!(
        a.build(at(0), header(0)).error,
        Some(BuildError::SetTooLarge { seq: 0, .. })
    ));

    // Receiver room: only what fits is taken (and so acknowledged).
    let mut src = Link::new(0, 0);
    for i in 0..10u8 {
        src.push_command(vec![i]);
    }
    let Ok(Message::Update(u)) = decode_datagram(&src.build(at(0), header(0)).bytes) else {
        panic!()
    };
    let mut dst = Link::new(0, 0);
    let room = Room {
        commands: 4,
        hashes: 0,
        accept_commands: true,
    };
    let inc = dst.receive(at(1), &u, room, |_| true);
    assert_eq!(inc.commands.len(), 4);
    assert_eq!(dst.commands_expected(), 4);
    // Not accepting: nothing taken, nothing acked.
    let mut dst = Link::new(0, 0);
    let room = Room {
        commands: 900,
        hashes: 900,
        accept_commands: false,
    };
    assert!(dst.receive(at(1), &u, room, |_| true).commands.is_empty());
    assert_eq!(dst.commands_expected(), 0);
    // A set that fails to decode means none of the new ones is taken.
    let mut dst = Link::new(0, 0);
    let room = Room {
        commands: 900,
        hashes: 900,
        accept_commands: true,
    };
    let inc = dst.receive(at(1), &u, room, |s| s != [5]);
    assert!(inc.commands.is_empty());
    assert!(inc.notes.contains(&LinkNote::BadSet { seq: 5 }));
}

#[test]
fn gaps_duplicates_and_bad_acks() {
    let mut src = Link::new(0, 0);
    let mut dst = Link::new(0, 0);
    let room = Room {
        commands: 900,
        hashes: 900,
        accept_commands: true,
    };
    src.push_command(vec![1]);
    let p1 = src.build(at(0), header(0)).bytes;
    src.push_command(vec![2]);
    let p2 = src.build(at(20), header(0)).bytes;
    let Ok(Message::Update(u2)) = decode_datagram(&p2) else {
        panic!()
    };
    let Ok(Message::Update(u1)) = decode_datagram(&p1) else {
        panic!()
    };
    // Newer first (it resends everything), then the older duplicate.
    assert_eq!(
        dst.receive(at(21), &u2, room, |_| true).commands,
        vec![vec![1], vec![2]]
    );
    assert!(dst.receive(at(22), &u1, room, |_| true).commands.is_empty());
    // A gap is ignored.
    let mut gap = u2.clone();
    gap.commands.first = 10;
    assert!(dst
        .receive(at(23), &gap, room, |_| true)
        .commands
        .is_empty());
    // An ack beyond what was sent is reported and ignored.
    let mut bad = u2;
    bad.commands.ack = 99;
    let inc = src.receive(at(24), &bad, room, |_| true);
    assert!(matches!(
        inc.notes[0],
        LinkNote::AckBeyond {
            stream: "commands",
            ..
        }
    ));
    assert_eq!(src.unacked_commands(), 2);
}

#[test]
fn rtt_estimation() {
    let mut a = Link::new(0, 0);
    let mut b = Link::new(0, 0);
    let room = Room {
        commands: 900,
        hashes: 900,
        accept_commands: true,
    };
    for i in 0..20u64 {
        let t = i * 100;
        a.push_command(vec![]);
        let Ok(Message::Update(u)) = decode_datagram(&a.build(at(t), header(0)).bytes) else {
            panic!()
        };
        b.receive(at(t + 20), &u, room, |_| true);
        // b answers 10 ms later and says so in its ack delay.
        let Ok(Message::Update(r)) = decode_datagram(&b.build(at(t + 30), header(1)).bytes) else {
            panic!()
        };
        assert_eq!(r.ack_delay_ms, 10);
        a.receive(at(t + 50), &r, room, |_| true);
    }
    assert_eq!(a.rtt().latest_ms(), Some(40));
    assert_eq!(a.rtt().smoothed_ms(), 40);
    assert_eq!(a.rtt().window_min_max(), Some((40, 40)));
    // Deviation was seeded at rtt/2 and decays towards 0.
    assert!(a.rtt().dev_ms() < 20);
}

#[test]
fn heartbeat_and_rate_limit() {
    let mut a = Link::new(0, 0);
    assert!(a.due(at(0)));
    a.build(at(0), header(0));
    assert!(!a.due(at(50)));
    assert!(a.due(at(100)));
    a.build(at(100), header(0));
    a.push_hash(1);
    assert!(!a.due(at(105)));
    assert!(a.due(at(110)));
}
