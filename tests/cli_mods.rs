//! The demo's `--mods`: two directories resolved with btm-mod are the lobby's mod set.
//! A guest with the same set plays on; one with a mod at another version is refused, and
//! the refusal names that mod. Needs `--features mods`.
#![cfg(feature = "mods")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A scratch directory that is removed at the end of the test.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("btm-netplay-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// A content mod `<name>/` holding one data file, at `version`; returns its path.
    fn mod_dir(&self, dir: &str, id: &str, version: &str) -> String {
        let path = self.0.join(dir);
        std::fs::create_dir_all(path.join("data")).unwrap();
        std::fs::write(path.join("data").join(format!("{id}.txt")), id).unwrap();
        let manifest = format!(
            r#"{{"manifest": 1, "id": "{id}", "version": "{version}", "kind": ["content"],
                "engine": ">=0.4, <0.5", "content": ["data/*.txt"]}}"#
        );
        std::fs::write(path.join("btm_mod.json"), manifest).unwrap();
        path.to_str().unwrap().to_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn spawn(args: &[&str], mods: &[&str]) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_btm-netplay-demo"));
    cmd.args(args);
    for m in mods {
        cmd.args(["--mods", m]);
    }
    cmd.stdin(Stdio::null())
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

/// A host with `host_mods`, and a guest with `guest_mods` joining it. The guest is waited
/// for; the host is stopped if it is still running. Returns both reports.
fn play(
    host_mods: &[&str],
    guest_mods: &[&str],
) -> ((bool, String, String), (bool, String, String)) {
    let (disc, game) = (free_port(), free_port());
    let (disc_s, game_s) = (disc.to_string(), game.to_string());
    let host = spawn(
        &[
            "host",
            "--no-stun",
            "--ticks",
            "30",
            "--auto-start",
            "1",
            "--bind",
            "127.0.0.1",
            "--discovery-port",
            &disc_s,
            "--port",
            &game_s,
        ],
        host_mods,
    );
    std::thread::sleep(Duration::from_millis(300));
    let target = format!("127.0.0.1:{disc}");
    let guest = spawn(
        &[
            "join",
            &target,
            "--no-stun",
            "--ticks",
            "30",
            "--bind",
            "127.0.0.1",
        ],
        guest_mods,
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let g = finish(guest, deadline);
    // The host plays on until it is done or, if its guest was refused, until stopped.
    let h = finish(host, Instant::now() + Duration::from_secs(5));
    (h, g)
}

fn final_hash(out: &str) -> Option<&str> {
    out.lines()
        .find_map(|l| l.strip_prefix("Final hash at tick 30: "))
}

#[test]
fn same_mods_join_and_a_different_version_is_refused_by_name() {
    let s = Scratch::new("mods");
    let a = s.mod_dir("host-a", "mod-a", "1.0.0");
    let b = s.mod_dir("host-b", "mod-b", "2.1.0");
    // The same two mods from other directories, in the other order: the same set.
    let a_copy = s.mod_dir("guest-a", "mod-a", "1.0.0");
    let b_copy = s.mod_dir("guest-b", "mod-b", "2.1.0");
    let ((hok, hout, herr), (gok, gout, gerr)) = play(&[&a, &b], &[&b_copy, &a_copy]);
    let report = format!("host:\n{hout}\n{herr}\nguest:\n{gout}\n{gerr}");
    assert!(hok && gok, "{report}");
    assert!(hout.contains("Guest has joined"), "{report}");
    assert!(final_hash(&hout).is_some(), "{report}");
    assert_eq!(final_hash(&hout), final_hash(&gout), "{report}");

    // One mod at another version.
    let a_new = s.mod_dir("guest-a-new", "mod-a", "1.0.1");
    let (h, (gok, gout, gerr)) = play(&[&a, &b], &[&a_new, &b_copy]);
    let report = format!("host:\n{}\n{}\nguest:\n{gout}\n{gerr}", h.1, h.2);
    assert!(!gok, "{report}");
    assert!(
        gerr.contains("mod-a (different version or contents)"),
        "{report}"
    );
    assert!(!gerr.contains("mod-b"), "{report}");
    assert!(!h.1.contains("Guest has joined"), "{report}");
    assert!(final_hash(&gout).is_none(), "{report}");
}

#[test]
fn a_mod_directory_that_does_not_resolve_is_an_error() {
    let s = Scratch::new("badmods");
    let missing = Path::new(&s.0).join("nowhere");
    let c = spawn(&["host", "--no-stun"], &[missing.to_str().unwrap()]);
    let (ok, _, err) = finish(c, Instant::now() + Duration::from_secs(10));
    assert!(!ok);
    assert!(err.contains("nowhere"), "{err}");
}
