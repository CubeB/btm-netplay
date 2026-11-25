//! A deterministic in-memory network of N peers driving toy engines.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::time::Duration;

use super::*;
use crate::types::{Endpoint, Engine, Instant, PlayerId, Tick};

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

/// Folds every command into an order-sensitive hash.
#[derive(Default)]
struct Toy {
    hash: u32,
    history: Vec<u32>,
    corrupt_at: Option<u32>,
    controls: Vec<(Tick, Command)>,
}

fn fnv(h: u32, b: u8) -> u32 {
    (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
}

impl Engine for Toy {
    fn step(&mut self, tick: Tick, commands: &[(PlayerId, Vec<u8>)]) {
        assert_eq!(tick.0 as usize, self.history.len() + 1, "ticks are gapless");
        let ids: Vec<u8> = commands.iter().map(|c| c.0 .0).collect();
        assert!(ids.windows(2).all(|w| w[0] > w[1]), "highest id first");
        let mut h = self.hash ^ tick.0.wrapping_mul(0x9E37_79B1);
        for (p, set) in commands {
            h = fnv(h, p.0);
            for b in set {
                h = fnv(h, *b);
            }
            h = fnv(h, 0xFF);
            for c in decode_set(set).unwrap() {
                if !matches!(c, Command::Game(_)) {
                    self.controls.push((tick, c));
                }
            }
        }
        if self.corrupt_at == Some(tick.0) {
            h ^= 1;
        }
        self.hash = h;
        self.history.push(h);
    }
    fn state_hash(&self) -> u32 {
        self.hash
    }
    fn dump(&self) -> String {
        format!("{{\"hash\":{}}}", self.hash)
    }
}

#[derive(Clone, Copy)]
struct LinkParams {
    latency_ms: u64,
    jitter_ms: u64,
    loss_pct: u64,
    dup_pct: u64,
}

const LAN: LinkParams = LinkParams {
    latency_ms: 0,
    jitter_ms: 1,
    loss_pct: 0,
    dup_pct: 0,
};

const BAD: LinkParams = LinkParams {
    latency_ms: 25,
    jitter_ms: 30,
    loss_pct: 15,
    dup_pct: 10,
};

struct Node {
    ls: Lockstep,
    engine: Toy,
    alive: bool,
    events: Vec<Event>,
}

struct Sim {
    now: u64,
    nodes: Vec<Node>,
    params: Box<dyn Fn(usize, usize) -> LinkParams>,
    queue: Vec<(u64, usize, Endpoint, Vec<u8>)>,
    rng: Rng,
    frame_ms: u64,
    commands: bool,
}

fn ep(i: usize) -> Endpoint {
    Endpoint::new(Ipv4Addr::new(10, 0, 0, i as u8 + 1), 6670 + i as u16)
}

fn config(i: usize, n: usize) -> Config {
    Config::new(
        PlayerId(i as u8),
        (0..n)
            .map(|j| PlayerConfig {
                id: PlayerId(j as u8),
                name: format!("p{j}"),
                endpoint: (j != i).then(|| ep(j)),
            })
            .collect(),
    )
}

impl Sim {
    fn new(n: usize, seed: u64, params: impl Fn(usize, usize) -> LinkParams + 'static) -> Sim {
        Self::with(n, seed, params, |_| {})
    }

    fn with(
        n: usize,
        seed: u64,
        params: impl Fn(usize, usize) -> LinkParams + 'static,
        tweak: impl Fn(&mut Config),
    ) -> Sim {
        let nodes = (0..n)
            .map(|i| {
                let mut c = config(i, n);
                tweak(&mut c);
                Node {
                    ls: Lockstep::new(c).unwrap(),
                    engine: Toy::default(),
                    alive: true,
                    events: Vec::new(),
                }
            })
            .collect();
        Sim {
            now: 0,
            nodes,
            params: Box::new(params),
            queue: Vec::new(),
            rng: Rng(seed),
            frame_ms: 16,
            commands: true,
        }
    }

    fn at(&self) -> Instant {
        Instant(Duration::from_millis(self.now))
    }

    fn step(&mut self) {
        self.now += 1;
        let now = self.at();
        let mut due = Vec::new();
        self.queue.retain(|q| {
            if q.0 <= self.now {
                due.push(q.clone());
                false
            } else {
                true
            }
        });
        for (_, to, from, bytes) in due {
            let node = &mut self.nodes[to];
            if node.alive {
                let _ = node.ls.handle_datagram(now, from, &bytes);
            }
        }
        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive || !(self.now + i as u64 * 5).is_multiple_of(self.frame_ms) {
                continue;
            }
            if self.commands && self.rng.below(4) == 0 {
                let len = self.rng.below(20) as usize;
                let cmd: Vec<u8> = (0..len).map(|_| self.rng.next() as u8).collect();
                self.nodes[i].ls.submit(cmd).unwrap();
            }
            let node = &mut self.nodes[i];
            let out = node.ls.poll(now, &mut node.engine);
            node.events.extend(out.events);
            for o in out.outgoing {
                let Some(to) = (0..self.nodes.len()).find(|&j| ep(j) == o.to) else {
                    continue;
                };
                let p = (self.params)(i, to);
                if self.rng.below(100) < p.loss_pct {
                    continue;
                }
                let copies = if self.rng.below(100) < p.dup_pct {
                    2
                } else {
                    1
                };
                for _ in 0..copies {
                    let at = self.now + p.latency_ms + self.rng.below(p.jitter_ms + 1);
                    self.queue.push((at, to, ep(i), o.bytes.clone()));
                }
            }
        }
    }

    fn run_until(&mut self, max_ms: u64, mut done: impl FnMut(&Sim) -> bool) -> bool {
        let end = self.now + max_ms;
        while self.now < end {
            if done(self) {
                return true;
            }
            self.step();
        }
        done(self)
    }

    fn run_for(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now < end {
            self.step();
        }
    }

    fn scene(&self, i: usize) -> u32 {
        self.nodes[i].ls.scene_time().0
    }

    fn all_reach(&self, nodes: &[usize], t: u32) -> bool {
        nodes.iter().all(|&i| self.scene(i) >= t)
    }

    fn assert_same_history(&self, nodes: &[usize], upto: usize) {
        let first = &self.nodes[nodes[0]].engine.history;
        assert!(first.len() >= upto);
        for &i in nodes {
            let h = &self.nodes[i].engine.history;
            assert!(h.len() >= upto, "node {i} ran {} ticks", h.len());
            assert_eq!(&h[..upto], &first[..upto], "node {i} diverged");
        }
    }

    fn left(&self, i: usize) -> Vec<(PlayerId, Tick)> {
        self.nodes[i]
            .events
            .iter()
            .filter_map(|e| match e {
                Event::PlayerLeft { player, at } => Some((*player, *at)),
                _ => None,
            })
            .collect()
    }

    fn no_desync(&self) {
        for (i, n) in self.nodes.iter().enumerate() {
            assert!(n.ls.desync().is_none(), "node {i} desynced");
        }
    }
}

#[test]
fn peers_agree_under_loss_reorder_and_duplication() {
    let mut sim = Sim::new(3, 1, |_, _| BAD);
    assert!(sim.run_until(60_000, |s| s.all_reach(&[0, 1, 2], 300)));
    sim.assert_same_history(&[0, 1, 2], 300);
    sim.no_desync();
    // Peers stay level: within a few ticks of each other.
    let scenes: Vec<u32> = (0..3).map(|i| sim.scene(i)).collect();
    let spread = scenes.iter().max().unwrap() - scenes.iter().min().unwrap();
    assert!(spread <= 12, "spread {spread}");
    let st = sim.nodes[0].ls.stats(sim.at());
    assert_eq!(st.peers.len(), 2);
    assert!(st.rtt_ms > 0);
    assert!(st.order_delay >= 2);
}

#[test]
fn input_delay_is_two_ticks_on_a_lan() {
    let mut sim = Sim::new(2, 2, |_, _| LAN);
    sim.run_for(3000);
    for i in 0..2 {
        assert_eq!(sim.nodes[i].ls.order_delay(), 2);
        assert_eq!(sim.nodes[i].ls.stats(sim.at()).order_delay_ms, 66);
    }
    // About 30 ticks per second.
    assert!((85..=95).contains(&sim.scene(0)), "ran {}", sim.scene(0));
    sim.assert_same_history(&[0, 1], 80);
}

#[test]
fn single_player_feeds_on_demand() {
    let mut sim = Sim::new(1, 3, |_, _| LAN);
    sim.run_for(2000);
    assert_eq!(sim.nodes[0].ls.order_delay(), 0);
    assert!((58..=62).contains(&sim.scene(0)), "ran {}", sim.scene(0));
    assert!(sim.nodes[0].ls.stats(sim.at()).no_remote_players);
}

#[test]
fn desync_is_detected_at_the_same_tick_by_every_peer() {
    let mut sim = Sim::new(3, 4, |_, _| BAD);
    sim.nodes[1].engine.corrupt_at = Some(50);
    assert!(sim.run_until(30_000, |s| s.nodes.iter().all(|n| n.ls.desync().is_some())));
    for (i, n) in sim.nodes.iter().enumerate() {
        let d = n.ls.desync().unwrap();
        assert_eq!(d.tick, Tick(50), "node {i}");
        assert_eq!(d.local, PlayerId(i as u8));
        assert!(d.noticed_at.0 >= 50);
        assert_eq!(d.hashes.len(), 3);
        assert!(d.report(Some("x")).contains("at tick 50."));
        assert!(n.events.iter().any(|e| matches!(e, Event::Desync(_))));
    }
    // No tick runs after the desync.
    let before: Vec<u32> = (0..3).map(|i| sim.scene(i)).collect();
    sim.run_for(1000);
    assert_eq!(before, (0..3).map(|i| sim.scene(i)).collect::<Vec<_>>());
}

/// Lossy between survivors; the lost peer's last packets reach everyone (a lost
/// peer whose final sets reach only some survivors is an inherent spec limitation).
fn drop_params(lost: &'static [usize]) -> impl Fn(usize, usize) -> LinkParams {
    move |a, b| {
        if lost.contains(&a) || lost.contains(&b) {
            LinkParams {
                latency_ms: 10,
                jitter_ms: 5,
                loss_pct: 0,
                dup_pct: 0,
            }
        } else {
            BAD
        }
    }
}

#[test]
fn lost_player_is_dropped_at_the_same_tick_everywhere() {
    let mut sim = Sim::new(3, 5, drop_params(&[2]));
    assert!(sim.run_until(20_000, |s| s.all_reach(&[0, 1, 2], 60)));
    sim.nodes[2].alive = false;
    let killed = sim.now;
    assert!(sim.run_until(30_000, |s| !s.left(0).is_empty() && !s.left(1).is_empty()));
    let (p, at) = sim.left(0)[0];
    assert_eq!(p, PlayerId(2));
    assert_eq!(sim.left(1), vec![(p, at)]);
    assert!(sim.now - killed >= 10_000, "dropped before the timeout");
    // Only the designated declarer (player 0) issued it; everyone counted down.
    assert!(sim.nodes[0]
        .events
        .iter()
        .any(|e| matches!(e, Event::DropIssued { .. })));
    assert!(!sim.nodes[1]
        .events
        .iter()
        .any(|e| matches!(e, Event::DropIssued { .. })));
    for i in 0..2 {
        assert!(sim.nodes[i]
            .events
            .iter()
            .any(|e| matches!(e, Event::DropCountdown { seconds: 1..=9, .. })));
        // The engine saw the same drop command at the same tick.
        assert_eq!(sim.nodes[i].engine.controls.len(), 1);
    }
    assert_eq!(sim.nodes[0].engine.controls, sim.nodes[1].engine.controls);
    assert!(sim.run_until(30_000, |s| s.all_reach(&[0, 1], at.0 + 100)));
    sim.assert_same_history(&[0, 1], at.0 as usize + 100);
    sim.no_desync();
    assert!(sim.nodes[0].ls.is_dropped(PlayerId(2)));
}

/// Deviation from 5.5: the two lowest peers lost together no longer hang the game.
#[test]
fn two_lowest_lost_together_are_both_dropped() {
    let mut sim = Sim::new(4, 6, drop_params(&[0, 1]));
    assert!(sim.run_until(20_000, |s| s.all_reach(&[0, 1, 2, 3], 60)));
    sim.nodes[0].alive = false;
    sim.nodes[1].alive = false;
    assert!(sim.run_until(60_000, |s| s.left(2).len() == 2 && s.left(3).len() == 2));
    assert_eq!(sim.left(2), sim.left(3));
    let last = sim.left(2).iter().map(|x| x.1 .0).max().unwrap();
    assert!(sim.run_until(30_000, |s| s.all_reach(&[2, 3], last + 50)));
    sim.assert_same_history(&[2, 3], last as usize + 50);
    sim.no_desync();
}

#[test]
fn rejoin_catches_up_and_matches_hashes() {
    let mut sim = Sim::new(3, 7, drop_params(&[2]));
    assert!(sim.run_until(20_000, |s| s.all_reach(&[0, 1, 2], 60)));
    sim.nodes[2].alive = false;
    assert!(sim.run_until(30_000, |s| !s.left(0).is_empty() && !s.left(1).is_empty()));
    sim.run_for(500);

    // Player 1 is not the speaker; player 0 is.
    assert_eq!(
        sim.nodes[1].ls.request_rejoin(PlayerId(2)),
        Err(RejoinRefusal::NotSpeaker)
    );
    assert_eq!(
        sim.nodes[0].ls.request_rejoin(PlayerId(1)),
        Err(RejoinRefusal::NotDropped)
    );
    let r = sim.nodes[0].ls.request_rejoin(PlayerId(2)).unwrap();
    assert_eq!(
        sim.nodes[0].ls.request_rejoin(PlayerId(2)),
        Err(RejoinRefusal::AlreadyInProgress)
    );
    assert_eq!(
        sim.nodes[0].ls.cut_bundle(PlayerId(2)),
        Err(RejoinRefusal::NotReady)
    );
    assert!(sim.run_until(20_000, |s| s.nodes[0]
        .events
        .iter()
        .any(|e| matches!(e, Event::RejoinBundleReady { .. }))));
    let bundle = sim.nodes[0].ls.cut_bundle(PlayerId(2)).unwrap();
    let bundle = Bundle::decode(&bundle.encode()).unwrap();
    assert_eq!(bundle.last_tick, Tick(r.0 - 1));

    // A bundle that ends early is refused.
    let short = Bundle {
        last_tick: Tick(r.0 - 2),
        ticks: Vec::new(),
    };
    assert!(matches!(
        Lockstep::rejoin(config(2, 3), short, r),
        Err(ConfigError::BundleTooShort { .. })
    ));

    // The others are stalled at R until the returning peer sends.
    sim.run_for(1000);
    assert_eq!(sim.scene(0), r.0 - 1);
    assert_eq!(sim.scene(1), r.0 - 1);

    sim.nodes[2] = Node {
        ls: Lockstep::rejoin(config(2, 3), bundle, r).unwrap(),
        engine: Toy::default(),
        alive: true,
        events: Vec::new(),
    };
    assert!(sim.run_until(30_000, |s| s.all_reach(&[0, 1, 2], r.0 + 150)));
    assert!(sim.nodes[2]
        .events
        .iter()
        .any(|e| matches!(e, Event::Rejoined { .. })));
    for i in 0..2 {
        assert!(sim.nodes[i].events.iter().any(|e| matches!(
            e,
            Event::PlayerRejoined {
                player: PlayerId(2),
                ..
            }
        )));
    }
    sim.assert_same_history(&[0, 1, 2], r.0 as usize + 150);
    sim.no_desync();
    assert!(!sim.nodes[1].ls.is_dropped(PlayerId(2)));
}

#[test]
fn rejoined_peer_desync_is_still_detected() {
    let mut sim = Sim::new(2, 8, drop_params(&[1]));
    assert!(sim.run_until(20_000, |s| s.all_reach(&[0, 1], 40)));
    sim.nodes[1].alive = false;
    assert!(sim.run_until(30_000, |s| !s.left(0).is_empty()));
    let r = sim.nodes[0].ls.request_rejoin(PlayerId(1)).unwrap();
    assert!(sim.run_until(20_000, |s| s.nodes[0]
        .events
        .iter()
        .any(|e| matches!(e, Event::RejoinBundleReady { .. }))));
    let bundle = sim.nodes[0].ls.cut_bundle(PlayerId(1)).unwrap();
    let engine = Toy {
        corrupt_at: Some(r.0 + 5),
        ..Toy::default()
    };
    sim.nodes[1] = Node {
        ls: Lockstep::rejoin(config(1, 2), bundle, r).unwrap(),
        engine,
        alive: true,
        events: Vec::new(),
    };
    assert!(sim.run_until(30_000, |s| s.nodes.iter().all(|n| n.ls.desync().is_some())));
    for n in &sim.nodes {
        assert_eq!(n.ls.desync().unwrap().tick, Tick(r.0 + 5));
    }
}

#[test]
fn chat_is_delivered_during_a_stall() {
    let mut sim = Sim::with(3, 9, |_, _| BAD, |c| c.drop_timeout = Duration::ZERO);
    assert!(sim.run_until(20_000, |s| s.all_reach(&[0, 1, 2], 30)));
    sim.nodes[2].alive = false;
    assert!(sim.run_until(5000, |s| s.nodes[0].ls.is_stalled()
        && s.nodes[1].ls.is_stalled()));
    sim.run_for(1500);
    let (s0, s1) = (sim.scene(0), sim.scene(1));
    assert_eq!(
        sim.nodes[0]
            .ls
            .send_chat("hello\u{7} there ", &[PlayerId(1)], ChatLabel::Allies),
        Ok(())
    );
    assert_eq!(
        sim.nodes[0]
            .ls
            .send_chat("x", &[PlayerId(7)], ChatLabel::None),
        Err(ChatError::NoSuchPlayer)
    );
    assert!(sim.run_until(5000, |s| {
        s.nodes[1].events.iter().any(|e| matches!(
        e,
        Event::Chat { from: PlayerId(0), text, label: ChatLabel::Allies } if text == "hello there"
    ))
    }));
    assert_eq!((sim.scene(0), sim.scene(1)), (s0, s1), "still stalled");
    assert_eq!(
        sim.nodes[1].ls.caption(sim.at()),
        Some(Caption::Waiting {
            players: vec![PlayerId(2)],
            dropping_in: None
        })
    );
    let st = sim.nodes[1].ls.stats(sim.at());
    assert!(st.stalled_ms.unwrap() > 1000);
    assert_eq!(st.waiting_for, vec![PlayerId(2)]);

    // The silent peer cannot take more than 32 unanswered lines.
    let mut sent = 0;
    while sim.nodes[0]
        .ls
        .send_chat("ping", &[PlayerId(2)], ChatLabel::None)
        .is_ok()
    {
        sent += 1;
    }
    assert_eq!(sent, 32);
    assert_eq!(
        sim.nodes[0]
            .ls
            .send_chat("ping", &[PlayerId(2)], ChatLabel::None),
        Err(ChatError::NotAnswering)
    );
}

#[test]
fn pause_and_speed_are_shared() {
    let mut sim = Sim::new(2, 10, |_, _| BAD);
    assert!(sim.run_until(20_000, |s| s.all_reach(&[0, 1], 30)));
    assert!(sim.nodes[1].ls.toggle_pause());
    sim.run_for(1000);
    assert!(sim.nodes[0].ls.is_paused());
    let paused_at = (sim.scene(0), sim.scene(1));
    sim.run_for(1000);
    assert_eq!(paused_at, (sim.scene(0), sim.scene(1)));
    // A stale toggle from the other side supersedes by (revision, player).
    assert!(!sim.nodes[0].ls.toggle_pause());
    sim.run_for(500);
    assert!(!sim.nodes[1].ls.is_paused());

    sim.nodes[0].ls.set_speed(2000).unwrap();
    let t0 = sim.scene(0);
    sim.run_for(3000);
    assert_eq!(sim.nodes[1].ls.chosen_speed(), 2000);
    let ran = sim.scene(0) - t0;
    assert!(ran > 140, "ran {ran} ticks in 3 s at 2x");
    let upto = sim.scene(0).min(sim.scene(1)) as usize;
    sim.assert_same_history(&[0, 1], upto);
}

#[test]
fn garbage_datagrams_are_harmless() {
    let mut sim = Sim::new(2, 11, |_, _| LAN);
    sim.run_for(500);
    let mut rng = Rng(99);
    let now = sim.at();
    for _ in 0..5000 {
        let len = rng.below(100) as usize;
        let b: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        assert!(sim.nodes[0].ls.handle_datagram(now, ep(1), &b).is_err());
    }
    // From an unknown address outside the /16: ignored.
    let stranger = Endpoint::new(Ipv4Addr::new(192, 168, 0, 1), 1);
    let mut probe = Lockstep::new(config(1, 2)).unwrap();
    let out = probe.poll(now, &mut Toy::default());
    let bytes = &out.outgoing[0].bytes;
    assert!(matches!(
        sim.nodes[0].ls.handle_datagram(now, stranger, bytes),
        Err(RecvError::UnknownSource { .. })
    ));
    // From a new port in the same /16: the address follows.
    let moved = Endpoint::new(Ipv4Addr::new(10, 0, 9, 9), 4000);
    assert!(sim.nodes[0].ls.handle_datagram(now, moved, bytes).is_ok());
    sim.run_for(200);
}
