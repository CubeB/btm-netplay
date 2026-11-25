//! `btm-relay`: a small UDP relay for btm-netplay games whose players cannot reach each
//! other directly. It drives the sans-IO [`btm_netplay::relay::RelayServer`] from one
//! `std::net::UdpSocket`. See `RELAY.md`.
//!
//! ```text
//! btm-relay [--bind ADDR:PORT] [--max-rooms N] [--log quiet|info|debug]
//! ```

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use btm_netplay::relay::{RelayConfig, RelayServer, ServerEvent, DEFAULT_RELAY_PORT};
use btm_netplay::session::sha256;
use btm_netplay::types::{Instant, Outgoing};

const USAGE: &str = "\
btm-relay: UDP relay for btm-netplay games

USAGE:
    btm-relay [--bind ADDR:PORT] [--max-rooms N] [--log LEVEL]

OPTIONS:
    --bind ADDR:PORT   IPv4 address and port to listen on (default 0.0.0.0:3479)
    --max-rooms N      rooms held at once (default 1024)
    --log LEVEL        quiet: start-up and errors only; info (default): rooms opened and
                       closed, a summary every minute; debug: every event,
                       with addresses
    -h, --help         this text
";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Quiet,
    Info,
    Debug,
}

struct Args {
    bind: SocketAddr,
    max_rooms: usize,
    level: Level,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args {
        bind: SocketAddr::from(([0, 0, 0, 0], DEFAULT_RELAY_PORT)),
        max_rooms: RelayConfig::default().max_rooms,
        level: Level::Info,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "-h" | "--help" => return Ok(None),
            "--bind" => {
                let v = value("--bind")?;
                args.bind = v
                    .parse()
                    .map_err(|_| format!("--bind: '{v}' is not ADDR:PORT"))?;
                if !args.bind.is_ipv4() {
                    return Err("--bind: the relay is IPv4 only".into());
                }
            }
            "--max-rooms" => {
                let v = value("--max-rooms")?;
                args.max_rooms = v
                    .parse()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| format!("--max-rooms: '{v}' is not a positive number"))?;
            }
            "--log" => {
                let v = value("--log")?;
                args.level = match v.as_str() {
                    "quiet" => Level::Quiet,
                    "info" => Level::Info,
                    "debug" => Level::Debug,
                    _ => return Err(format!("--log: '{v}' is not quiet, info or debug")),
                };
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(Some(args))
}

/// 32 unpredictable bytes without dependencies: the standard library's per-process random
/// hash keys (taken from the operating system), the time and the process id, through
/// SHA-256.
fn seed() -> [u8; 32] {
    let mut buf = Vec::with_capacity(128);
    for i in 0..8u64 {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(i);
        buf.extend_from_slice(&h.finish().to_le_bytes());
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    buf.extend_from_slice(&nanos.to_le_bytes());
    buf.extend_from_slice(&std::process::id().to_le_bytes());
    let marker = 0u8;
    buf.extend_from_slice(&(std::ptr::addr_of!(marker) as usize).to_le_bytes());
    sha256(&buf)
}

fn log_event(level: Level, e: &ServerEvent) {
    let text = match (level, e) {
        (Level::Quiet, _) => return,
        (Level::Debug, e) => format!("{e:?}"),
        (_, ServerEvent::RoomOpened { room, .. }) => format!("room {room:016x} opened"),
        (_, ServerEvent::RoomClosed { room }) => format!("room {room:016x} closed"),
        (_, ServerEvent::MemberJoined { room, member, .. }) => {
            format!("room {room:016x}: member {member} joined")
        }
        (_, ServerEvent::MemberLeft { room, member, why }) => {
            format!("room {room:016x}: member {member} left ({why:?})")
        }
        (_, ServerEvent::MemberMoved { room, member, .. }) => {
            format!("room {room:016x}: member {member} changed address")
        }
        // Refusals can be caused by strangers; at info they are only counted.
        (_, ServerEvent::Refused { .. }) => return,
    };
    eprintln!("btm-relay: {text}");
}

fn send_all(socket: &UdpSocket, out: &mut Vec<Outgoing>) {
    for o in out.drain(..) {
        // A failed send costs only that datagram.
        let _ = socket.send_to(&o.bytes, SocketAddr::V4(o.to));
    }
}

fn run(args: Args) -> Result<(), String> {
    let cfg = RelayConfig {
        max_rooms: args.max_rooms,
        ..RelayConfig::default()
    };
    let mut server = RelayServer::new(cfg, seed()).map_err(|e| e.to_string())?;
    let socket =
        UdpSocket::bind(args.bind).map_err(|e| format!("cannot listen on {}: {e}", args.bind))?;
    eprintln!(
        "btm-relay: listening on {} (max {} rooms)",
        args.bind, args.max_rooms
    );
    let start = StdInstant::now();
    let now = || Instant(start.elapsed());
    let mut buf = [0u8; 2048];
    let mut out = Vec::new();
    let mut next_poll = Duration::from_secs(1);
    let mut next_summary = Duration::from_secs(60);
    loop {
        let t = now();
        let wait = next_poll.saturating_sub(t.0).max(Duration::from_millis(10));
        let _ = socket.set_read_timeout(Some(wait));
        match socket.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(from))) => {
                let bytes = buf.get(..n).unwrap_or(&[]);
                for e in server.handle(now(), from, bytes, &mut out) {
                    log_event(args.level, &e);
                }
                send_all(&socket, &mut out);
            }
            Ok((_, SocketAddr::V6(_))) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock
                        | ErrorKind::TimedOut
                        | ErrorKind::ConnectionReset
                        | ErrorKind::Interrupted
                ) => {}
            Err(e) => {
                // Never let one bad receive stop the relay.
                eprintln!("btm-relay: receive error: {e}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let t = now();
        if t.0 >= next_poll {
            for e in server.poll(t) {
                log_event(args.level, &e);
            }
            next_poll = t.0 + Duration::from_secs(1);
            if let Some(d) = server.next_deadline() {
                next_poll = next_poll.min(d.0.max(t.0));
            }
        }
        if args.level >= Level::Info && t.0 >= next_summary {
            next_summary = t.0 + Duration::from_secs(60);
            let s = server.stats();
            eprintln!(
                "btm-relay: {} rooms, {} members; forwarded {} ({} B), challenges {}, refusals {}, dropped {} (rate-limited {})",
                server.room_count(),
                server.member_count(),
                s.forwarded,
                s.forwarded_bytes,
                s.challenges,
                s.refusals,
                s.dropped,
                s.rate_limited
            );
        }
    }
}

fn main() -> ExitCode {
    match parse_args() {
        Ok(None) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Some(args)) => match run(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("btm-relay: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("btm-relay: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
