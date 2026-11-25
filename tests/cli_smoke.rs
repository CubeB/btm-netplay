//! Smoke test of the demo binary: a host and a guest process on localhost play 60 ticks
//! and print the same final hash.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_btm-netplay-demo"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Wait for exit (killing after the deadline) and return (success, stdout, stderr).
fn finish(mut c: Child, deadline: Instant) -> (bool, String, String) {
    let ok = loop {
        if let Some(status) = c.try_wait().unwrap() {
            break status.success();
        }
        if Instant::now() > deadline {
            let _ = c.kill();
            let _ = c.wait();
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut out = String::new();
    let mut err = String::new();
    c.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    c.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    (ok, out, err)
}

fn final_hash(out: &str) -> Option<&str> {
    out.lines()
        .find_map(|l| l.strip_prefix("Final hash at tick 60: "))
}

#[test]
fn host_and_guest_processes_agree_after_60_ticks() {
    let (disc, game) = (free_port(), free_port());
    let (disc_s, game_s) = (disc.to_string(), game.to_string());
    let host = spawn(&[
        "host",
        "--no-stun",
        "--ticks",
        "60",
        "--auto-start",
        "1",
        "--bind",
        "127.0.0.1",
        "--discovery-port",
        &disc_s,
        "--port",
        &game_s,
    ]);
    std::thread::sleep(Duration::from_millis(300));
    let target = format!("127.0.0.1:{disc}");
    let guest = spawn(&[
        "join",
        &target,
        "--no-stun",
        "--ticks",
        "60",
        "--bind",
        "127.0.0.1",
    ]);
    let deadline = Instant::now() + Duration::from_secs(60);
    let (gok, gout, gerr) = finish(guest, deadline);
    let (hok, hout, herr) = finish(host, deadline);
    let report = format!("host:\n{hout}\n{herr}\nguest:\n{gout}\n{gerr}");
    assert!(hok && gok, "{report}");
    let (h, g) = (final_hash(&hout), final_hash(&gout));
    assert!(h.is_some(), "{report}");
    assert_eq!(h, g, "{report}");
    assert!(hout.contains("Guest has joined"), "{report}");
    assert!(hout.contains("tick "), "no status line: {report}");
}

#[test]
fn bad_arguments_exit_non_zero() {
    let c = spawn(&["join"]);
    let (ok, _, err) = finish(c, Instant::now() + Duration::from_secs(10));
    assert!(!ok);
    assert!(err.contains("join needs an invite code"), "{err}");
    let c = spawn(&["join", "not an address!", "--no-stun"]);
    let (ok, _, err) = finish(c, Instant::now() + Duration::from_secs(10));
    assert!(!ok);
    assert!(err.contains("Invalid TCP/IP Address"), "{err}");
}
