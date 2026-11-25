//! A command-line demo of btm-netplay with a toy deterministic engine.
//!
//! ```text
//! btm-netplay-demo host [--name N] [--port P] [--password X] ...
//! btm-netplay-demo join <CODE|ip:port> [--name N] ...
//! btm-netplay-demo lan [ip[:port]] [--seconds S]
//! ```
//!
//! Run with `--help` for every option. Lines typed on stdin are room or game chat;
//! `/start`, `/accept [name]`, `/requests`, `/relay` (host), `/ready`, `/unready` (guest)
//! and `/quit` are commands; a reply code typed by the host pre-approves that player.

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant as StdInstant};

use btm_netplay::io::toy::ToyEngine;
use btm_netplay::io::{Ended, Event, Node, NodeConfig, Phase, Rng, Role, Socket, Stun};
use btm_netplay::lockstep::Stats;
use btm_netplay::types::{Endpoint, Tick};

const USAGE: &str = "\
Usage:
  btm-netplay-demo host [options]
  btm-netplay-demo join <CODE|ip[:port]> [options]
  btm-netplay-demo lan [ip[:port]] [--seconds S]

Options:
  --name N             your display name (default: Host / Guest)
  --port P             game UDP port (host default 1337, guest default any)
  --discovery-port D   lobby UDP port (host default 1338, guest default any)
  --bind IP            local IPv4 address to bind (default 0.0.0.0)
  --password X         room password (host) or the password to answer with (guest)
  --no-stun            skip internet traversal; use the local address (LAN, tests)
  --ticks N            end the game after N ticks and print the final hash
  --build-id B         build identity to announce (to test version mismatches)
  --desync-at T        report a wrong state hash at tick T (to test desync detection)
  --auto-start K       host: start once K guests are seated and ready
  --relay IP:PORT      host: relay to fall back to when direct play cannot work
  --relay-always       host: use the relay from the start
  --drop-timeout S     seconds of silence before a player is dropped (default 10)
  --seconds S          lan: how long to listen (default 10)

Typed lines: chat, or /start /accept [name] /requests /relay /invite (host),
/ready /unready (guest), /quit. A reply code typed by the host pre-approves that player.";

#[derive(Debug)]
struct Args {
    role: Role,
    cfg: NodeConfig,
    ticks: Option<u32>,
    desync_at: Option<u32>,
    auto_start: Option<usize>,
    seconds: u64,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut it = argv.iter();
    let cmd = it
        .next()
        .ok_or_else(|| "Say host, join or lan.".to_owned())?;
    let mut positional: Vec<String> = Vec::new();
    let mut name = None;
    let mut port = None;
    let mut disc = None;
    let mut bind = Ipv4Addr::UNSPECIFIED;
    let mut password = None;
    let mut no_stun = false;
    let mut ticks = None;
    let mut build = None;
    let mut desync_at = None;
    let mut auto_start = None;
    let mut relay: Option<Endpoint> = None;
    let mut relay_always = false;
    let mut drop_timeout = None;
    let mut seconds = 10;
    fn val<'a>(it: &mut impl Iterator<Item = &'a String>, flag: &str) -> Result<String, String> {
        it.next()
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value."))
    }
    fn num<T: std::str::FromStr>(s: &str, flag: &str) -> Result<T, String> {
        s.parse()
            .map_err(|_| format!("{flag} needs a number, not \"{s}\"."))
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "--name" => name = Some(val(&mut it, a)?),
            "--port" => port = Some(num(&val(&mut it, a)?, a)?),
            "--discovery-port" => disc = Some(num(&val(&mut it, a)?, a)?),
            "--bind" => bind = num(&val(&mut it, a)?, a)?,
            "--password" => password = Some(val(&mut it, a)?),
            "--no-stun" => no_stun = true,
            "--ticks" => ticks = Some(num(&val(&mut it, a)?, a)?),
            "--build-id" => build = Some(val(&mut it, a)?),
            "--desync-at" => desync_at = Some(num(&val(&mut it, a)?, a)?),
            "--auto-start" => auto_start = Some(num(&val(&mut it, a)?, a)?),
            "--relay" => {
                let v = val(&mut it, a)?;
                relay = Some(
                    v.parse()
                        .map_err(|_| format!("--relay needs ip:port, not \"{v}\"."))?,
                );
            }
            "--relay-always" => relay_always = true,
            "--drop-timeout" => drop_timeout = Some(num::<u64>(&val(&mut it, a)?, a)?),
            "--seconds" => seconds = num(&val(&mut it, a)?, a)?,
            s if s.starts_with("--") => return Err(format!("Unknown option {s}.")),
            s => positional.push(s.to_owned()),
        }
    }
    let (role, default_name, ports) = match cmd.as_str() {
        "host" => (Role::Host, "Host", (1338, 1337)),
        "join" => {
            let target = positional
                .first()
                .cloned()
                .ok_or_else(|| "join needs an invite code or ip:port.".to_owned())?;
            (Role::Join(target), "Guest", (0, 0))
        }
        "lan" => (Role::Browse(positional.first().cloned()), "Lister", (0, 0)),
        other => return Err(format!("Unknown command \"{other}\".")),
    };
    let mut cfg = NodeConfig::new(name.as_deref().unwrap_or(default_name));
    cfg.bind_ip = bind;
    cfg.discovery_port = disc.unwrap_or(ports.0);
    cfg.game_port = port.unwrap_or(ports.1);
    cfg.password = password;
    if no_stun {
        cfg.stun = Stun::Off;
    }
    if let Some(b) = build {
        cfg.build_id = b.into_bytes();
    }
    cfg.relay = relay;
    cfg.relay_always = relay_always;
    if let Some(s) = drop_timeout {
        cfg.drop_timeout = Duration::from_secs(s);
    }
    Ok(Args {
        role,
        cfg,
        ticks,
        desync_at,
        auto_start,
        seconds,
    })
}

fn status_line(node: &Node, s: &Stats) -> String {
    let mut line = format!(
        "tick {} | {:.1} of {:.0} ticks/s | order delay {} ticks ({} ms), rtt {} jitter {} | \
         stalls {}, longest {} ms",
        s.tick.0,
        s.ticks_per_s,
        s.expected_ticks_per_s,
        s.order_delay,
        s.order_delay_ms,
        s.rtt_ms,
        s.jitter_ms,
        s.stalls,
        s.longest_stall_ms
    );
    let names = |ps: &[btm_netplay::types::PlayerId]| {
        ps.iter()
            .map(|p| node.player_name(*p))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if s.no_remote_players {
        line.push_str(" | no remote players");
    } else if let Some(ms) = s.stalled_ms {
        line.push_str(&format!(
            " | STALLED {ms} ms, waiting for {}",
            names(&s.waiting_for)
        ));
    } else if !s.last_stall_waited_for.is_empty() {
        line.push_str(&format!(
            " | last stall waited for {}",
            names(&s.last_stall_waited_for)
        ));
    }
    for p in &s.peers {
        line.push_str(&format!("\n    {}: rtt {} ms", p.name, p.rtt_ms));
        if let Some((lo, hi)) = p.rtt_min_max {
            line.push_str(&format!(" ({lo}-{hi})"));
        }
        if let Some(b) = p.no_ack_bound_ms {
            line.push_str(&format!(", rtt >= {b} ms, no ack"));
        }
        line.push_str(&format!(
            ", quiet {} ms, tick {:+}, unacked {}, buffered {}{}",
            p.quiet_ms,
            p.tick_delta,
            p.unacked,
            p.buffered,
            if p.dropped { ", dropped" } else { "" }
        ));
    }
    line
}

fn write_dump(d: &btm_netplay::lockstep::Desync, build: &str) -> Option<String> {
    let name = d.file_name("btm-netplay-demo");
    let json = d.dump_json("btm-netplay-demo", "unknown", build);
    std::fs::write(&name, json).ok().map(|()| name)
}

fn run(args: Args) -> Result<(), String> {
    let build = String::from_utf8_lossy(&args.cfg.build_id).into_owned();
    let browse = matches!(args.role, Role::Browse(_));
    let mut node = Node::new(args.cfg, args.role).map_err(|e| e.to_string())?;
    if !browse {
        println!(
            "Lobby on UDP port {}, game on UDP port {}.",
            node.local_port(Socket::Discovery).unwrap_or(0),
            node.local_port(Socket::Game).unwrap_or(0)
        );
    }

    // Stdin on its own thread (the only one), lines through a channel. End of input just
    // stops the thread; the game goes on.
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        while let Ok(n) = stdin.read_line(&mut line) {
            if n == 0 || tx.send(line.trim_end().to_owned()).is_err() {
                break;
            }
            line.clear();
        }
    });

    // The node loads it with the agreed seed (Engine::load) when the game starts.
    let mut engine = ToyEngine::default().corrupt_at(args.desync_at.map(Tick));
    let mut rng = Rng::from_entropy();
    let mut next_cmd = 1u32;
    let mut last_status = StdInstant::now();
    let started_at = StdInstant::now();
    let mut finished: Option<(u32, u32, StdInstant)> = None;
    let mut auto_started = false;

    loop {
        for line in rx.try_iter() {
            match line.trim() {
                "/quit" => {
                    node.leave();
                    println!("Bye.");
                    return Ok(());
                }
                "/requests" => {
                    let reqs = node.pending_requests();
                    if reqs.is_empty() {
                        println!("No join requests are waiting.");
                    }
                    for r in reqs {
                        println!("Join request from {} at {}", r.name, r.from);
                    }
                }
                _ => node.submit_line(&line),
            }
        }

        for e in node.pump(&mut engine) {
            match &e {
                Event::Ended(Ended::Desync(d)) => {
                    let path = write_dump(d, &build);
                    eprintln!("{}", d.report(path.as_deref()));
                    return Err("The game stopped because of a desync.".to_owned());
                }
                Event::Ended(Ended::Left) => return Ok(()),
                Event::Ended(why) => return Err(why.to_string()),
                Event::Host(btm_netplay::session::HostEvent::JoinRequest { name, .. }) => {
                    println!("{e}");
                    println!("  (type /accept or /accept {name})");
                }
                Event::Log(s) => println!("  [log] {s}"),
                _ => println!("{e}"),
            }
        }

        // Host: start by itself once enough guests are ready (scripts and tests).
        if let (Some(k), false) = (args.auto_start, auto_started) {
            let seated = node.host_lobby().map_or(0, |h| {
                h.view()
                    .seats
                    .iter()
                    .filter(|s| s.kind == btm_netplay::session::SeatKind::Network)
                    .count()
            });
            if seated >= k && node.start_blocker().is_none() && node.phase() == Phase::Lobby {
                auto_started = true;
                if let Err(e) = node.start() {
                    println!("{e}");
                }
            }
        }

        if node.phase() == Phase::Game {
            let t = node.scene_time().0;
            if t >= next_cmd && finished.is_none() {
                let len = 1 + rng.below(8) as usize;
                let mut cmd = vec![0u8; len];
                rng.fill(&mut cmd);
                if let Err(e) = node.submit_command(cmd) {
                    println!("{e}");
                }
                next_cmd = t + 2 + rng.below(6) as u32;
            }
            if last_status.elapsed() >= Duration::from_secs(1) {
                last_status = StdInstant::now();
                if let Some(s) = node.stats() {
                    println!("{}", status_line(&node, &s));
                }
            }
            if let (Some(n), None) = (args.ticks, finished) {
                if let Some(h) = engine.hash_at(Tick(n)) {
                    // Keep the network going briefly so the others get our last sets.
                    finished = Some((n, h, StdInstant::now() + Duration::from_secs(2)));
                }
            }
        }
        if let Some((n, h, until)) = finished {
            if StdInstant::now() >= until {
                println!("Final hash at tick {n}: 0x{h:08x}");
                return Ok(());
            }
        }
        if browse && started_at.elapsed() >= Duration::from_secs(args.seconds) {
            return Ok(());
        }
        node.wait();
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || argv.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return if argv.is_empty() {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
