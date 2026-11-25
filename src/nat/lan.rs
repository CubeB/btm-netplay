//! LAN discovery (SPEC 2.10): the announcement schedule and probe replies of a host, the
//! probe schedule of a guest, expiry of heard announcements, typed-address parsing and the
//! host-name lookup cache.
//!
//! The announcement text itself (3.1) is `session`'s; this module only decides when to
//! send it and where. A probe is a fixed short datagram, [`PROBE_DATAGRAM`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use super::{after, elapsed};
use crate::invite;
use crate::types::{Endpoint, Instant, Outgoing};

/// Default discovery port.
pub const DISCOVERY_PORT: u16 = 1338;
/// A lobby is announced this often.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_millis(1000);
/// A changed announcement goes out at most this often (coalescing).
pub const CHANGE_GAP: Duration = Duration::from_millis(100);
/// Heard announcements expire this long after the last one.
pub const ANNOUNCEMENT_TTL: Duration = Duration::from_millis(3500);
/// A prober gets an answer at most this often.
pub const PROBE_REPLY_GAP: Duration = Duration::from_millis(250);
/// Probers tracked for the reply rate limit.
pub const MAX_PROBERS: usize = 64;
/// A guest probes a typed address or a joined host this often.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(1000);
/// Maximum lobby datagram.
pub const MAX_ANNOUNCEMENT: usize = 1400;
/// Explicit announce targets kept (reply codes); not in the spec, a sanity bound.
pub const MAX_EXTRA_TARGETS: usize = 32;
/// Resolved host names stay cached this long.
pub const RESOLVE_TTL: Duration = Duration::from_secs(60);
/// A failed lookup is not retried sooner than this.
pub const RESOLVE_RETRY: Duration = Duration::from_secs(5);
/// Lookups in flight at once.
pub const MAX_LOOKUPS: usize = 8;

/// The fixed discovery probe: "please announce to me".
pub const PROBE_DATAGRAM: [u8; 7] = [0xB7, b'P', b'R', b'O', b'B', b'E', 1];

/// Whether a datagram on the discovery socket is a probe.
pub fn is_probe(bytes: &[u8]) -> bool {
    bytes == PROBE_DATAGRAM
}

/// Why an announcement was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanError {
    /// Larger than [`MAX_ANNOUNCEMENT`]; the lobby is not advertised.
    TooLarge(usize),
}

/// The limited-broadcast destination for a discovery port.
pub fn broadcast_target(port: u16) -> Endpoint {
    SocketAddrV4::new(Ipv4Addr::BROADCAST, port)
}

/// The loopback destination (so two copies on one machine see each other).
pub fn loopback_target(port: u16) -> Endpoint {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

/// A host's announcer: periodic and change-driven announcements plus unicast probe
/// replies.
#[derive(Clone, Debug)]
pub struct Announcer {
    port: u16,
    extra: Vec<Endpoint>,
    payload: Option<Vec<u8>>,
    last_sent: Option<Instant>,
    dirty: bool,
    probers: Vec<(Endpoint, Instant)>,
}

impl Announcer {
    /// An announcer for the given discovery port, not advertising anything yet.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            extra: Vec::new(),
            payload: None,
            last_sent: None,
            dirty: false,
            probers: Vec::new(),
        }
    }

    /// Set the current announcement, or `None` to stop advertising. Identical content is a
    /// no-op ("identical re-advertising sends nothing extra"); different content goes out
    /// at the next poll, but never sooner than 100 ms after the previous send.
    pub fn set_announcement(&mut self, payload: Option<Vec<u8>>) -> Result<(), LanError> {
        if let Some(p) = &payload {
            if p.len() > MAX_ANNOUNCEMENT {
                self.payload = None;
                return Err(LanError::TooLarge(p.len()));
            }
        }
        if self.payload != payload {
            self.dirty = payload.is_some();
            self.payload = payload;
        }
        Ok(())
    }

    /// Also announce to this endpoint (a pasted reply code). Returns whether it was new.
    pub fn add_target(&mut self, ep: Endpoint) -> bool {
        if self.extra.contains(&ep) || self.extra.len() >= MAX_EXTRA_TARGETS {
            return false;
        }
        self.extra.push(ep);
        self.dirty = true;
        true
    }

    pub fn remove_target(&mut self, ep: Endpoint) {
        self.extra.retain(|e| *e != ep);
    }

    pub fn targets(&self) -> &[Endpoint] {
        &self.extra
    }

    /// When [`Announcer::poll`] next has something to send; `None` if not advertising.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.payload.as_ref()?;
        let Some(last) = self.last_sent else {
            return Some(Instant::default());
        };
        let periodic = after(last, ANNOUNCE_INTERVAL);
        Some(if self.dirty {
            after(last, CHANGE_GAP).min(periodic)
        } else {
            periodic
        })
    }

    /// Send the announcement if it is due: to the broadcast address, loopback and every
    /// explicit target.
    pub fn poll(&mut self, now: Instant, out: &mut Vec<Outgoing>) {
        let Some(payload) = &self.payload else {
            return;
        };
        let due = match self.last_sent {
            None => true,
            Some(last) => {
                elapsed(now, last) >= ANNOUNCE_INTERVAL
                    || (self.dirty && elapsed(now, last) >= CHANGE_GAP)
            }
        };
        if !due {
            return;
        }
        let mut dests = vec![broadcast_target(self.port), loopback_target(self.port)];
        for &e in &self.extra {
            if !dests.contains(&e) {
                dests.push(e);
            }
        }
        for to in dests {
            out.push(Outgoing {
                to,
                bytes: payload.clone(),
            });
        }
        self.last_sent = Some(now);
        self.dirty = false;
    }

    /// Offer a datagram from the discovery socket. If it is a probe, answer it with the
    /// announcement (unicast, at most once per 250 ms per prober, 64 probers tracked) and
    /// return `true`; otherwise return `false` and the caller handles it.
    pub fn handle_probe(
        &mut self,
        now: Instant,
        from: Endpoint,
        bytes: &[u8],
        out: &mut Vec<Outgoing>,
    ) -> bool {
        if !is_probe(bytes) {
            return false;
        }
        let Some(payload) = &self.payload else {
            return true;
        };
        match self.probers.iter_mut().find(|(e, _)| *e == from) {
            Some((_, last)) => {
                if elapsed(now, *last) < PROBE_REPLY_GAP {
                    return true;
                }
                *last = now;
            }
            None => {
                if self.probers.len() >= MAX_PROBERS {
                    let oldest = self
                        .probers
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, (_, t))| *t)
                        .map(|(i, _)| i);
                    if let Some(i) = oldest {
                        self.probers.swap_remove(i);
                    }
                }
                self.probers.push((from, now));
            }
        }
        out.push(Outgoing {
            to: from,
            bytes: payload.clone(),
        });
        true
    }
}

/// A guest's probe schedule: probes every target once per second.
#[derive(Clone, Debug, Default)]
pub struct Prober {
    targets: Vec<Endpoint>,
    last_sent: Option<Instant>,
}

impl Prober {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the targets (a typed address or code, or the host a guest has joined).
    /// A new target is probed at the next poll.
    pub fn set_targets(&mut self, targets: &[Endpoint]) {
        if self.targets != targets {
            self.targets = targets.to_vec();
            self.last_sent = None;
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        if self.targets.is_empty() {
            return None;
        }
        Some(
            self.last_sent
                .map_or(Instant::default(), |t| after(t, PROBE_INTERVAL)),
        )
    }

    pub fn poll(&mut self, now: Instant, out: &mut Vec<Outgoing>) {
        if self.targets.is_empty() {
            return;
        }
        if self
            .last_sent
            .is_some_and(|t| elapsed(now, t) < PROBE_INTERVAL)
        {
            return;
        }
        for &to in &self.targets {
            out.push(Outgoing {
                to,
                bytes: PROBE_DATAGRAM.to_vec(),
            });
        }
        self.last_sent = Some(now);
    }
}

/// Heard announcements, remembered for 3.5 s after the last one.
#[derive(Clone, Debug)]
pub struct HeardAnnouncements<K> {
    entries: Vec<(K, Instant)>,
}

impl<K> Default for HeardAnnouncements<K> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<K: PartialEq + Clone> HeardAnnouncements<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Note an announcement from `key` at `now`. Returns whether `key` is new (or had
    /// already expired).
    pub fn hear(&mut self, key: K, now: Instant) -> bool {
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some((_, t)) => {
                let was_alive = elapsed(now, *t) < ANNOUNCEMENT_TTL;
                *t = now;
                !was_alive
            }
            None => {
                self.entries.push((key, now));
                true
            }
        }
    }

    /// Forget and return everything not heard for 3.5 s.
    pub fn expire(&mut self, now: Instant) -> Vec<K> {
        let mut gone = Vec::new();
        self.entries.retain(|(k, t)| {
            let alive = elapsed(now, *t) < ANNOUNCEMENT_TTL;
            if !alive {
                gone.push(k.clone());
            }
            alive
        });
        gone
    }

    /// Keys still alive at `now`, in the order first heard.
    pub fn alive(&self, now: Instant) -> Vec<K> {
        self.entries
            .iter()
            .filter(|(_, t)| elapsed(now, *t) < ANNOUNCEMENT_TTL)
            .map(|(k, _)| k.clone())
            .collect()
    }
}

/// What the user typed into the address box.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypedTarget {
    /// A dotted IPv4 address with optional port.
    Ipv4(Endpoint),
    /// An IPv6 address with optional port (the IPv6 socket is incidental in the spec).
    Ipv6(SocketAddrV6),
    /// An invite code, carrying its endpoint.
    Code(Endpoint),
    /// A host name to resolve.
    Name { host: String, port: u16 },
}

/// Typed text is neither an address, a host name nor a valid code ("Invalid TCP/IP
/// Address").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTarget;

fn valid_host_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.trim_end_matches('.').split('.').collect();
    let ok_label = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    // A purely numeric last label would be a malformed IPv4 literal, not a name.
    let last_numeric = labels
        .last()
        .is_some_and(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()));
    labels.iter().all(ok_label) && !last_numeric
}

/// Parse typed text: an IPv4 or IPv6 address, an invite code, or a host name, each with an
/// optional port (default `default_port`).
pub fn parse_target(text: &str, default_port: u16) -> Result<TypedTarget, InvalidTarget> {
    let t = text.trim();
    if t.is_empty() || t.chars().count() > 255 {
        return Err(InvalidTarget);
    }
    match t.parse::<SocketAddr>() {
        Ok(SocketAddr::V4(a)) => return Ok(TypedTarget::Ipv4(a)),
        Ok(SocketAddr::V6(a)) => return Ok(TypedTarget::Ipv6(a)),
        Err(_) => {}
    }
    match t.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => return Ok(TypedTarget::Ipv4(SocketAddrV4::new(a, default_port))),
        Ok(IpAddr::V6(a)) => {
            return Ok(TypedTarget::Ipv6(SocketAddrV6::new(a, default_port, 0, 0)));
        }
        Err(_) => {}
    }
    if let Ok(ep) = invite::decode(t) {
        return Ok(TypedTarget::Code(ep));
    }
    let (host, port) = match t.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let port: u16 = p.parse().map_err(|_| InvalidTarget)?;
            if port == 0 {
                return Err(InvalidTarget);
            }
            (h, port)
        }
        Some(_) => return Err(InvalidTarget),
        None => (t, default_port),
    };
    if !valid_host_name(host) {
        return Err(InvalidTarget);
    }
    Ok(TypedTarget::Name {
        host: host.to_ascii_lowercase(),
        port,
    })
}

/// What to do about a host name right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Resolved: use this address.
    Ready(Ipv4Addr),
    /// The caller should start a lookup and later call [`ResolveCache::complete`].
    Start,
    /// A lookup is already running (or too many are, try again later).
    Pending,
    /// The last lookup failed; it will not be retried yet.
    BackedOff,
}

#[derive(Clone, Debug)]
enum Resolution {
    InFlight,
    Done(Ipv4Addr, Instant),
    Failed(Instant),
}

/// Host-name resolution state: results cached 60 s, failures retried no sooner than 5 s,
/// at most 8 lookups in flight. The caller performs the lookups (off the UI thread).
#[derive(Clone, Debug, Default)]
pub struct ResolveCache {
    entries: Vec<(String, Resolution)>,
}

impl ResolveCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn in_flight(&self) -> usize {
        self.entries
            .iter()
            .filter(|(_, r)| matches!(r, Resolution::InFlight))
            .count()
    }

    pub fn lookup(&mut self, name: &str, now: Instant) -> Lookup {
        let key = name.to_ascii_lowercase();
        let idx = self.entries.iter().position(|(n, _)| *n == key);
        let state = idx
            .and_then(|i| self.entries.get(i))
            .map(|(_, r)| r.clone());
        match state {
            Some(Resolution::InFlight) => Lookup::Pending,
            Some(Resolution::Done(ip, at)) if elapsed(now, at) < RESOLVE_TTL => Lookup::Ready(ip),
            Some(Resolution::Failed(at)) if elapsed(now, at) < RESOLVE_RETRY => Lookup::BackedOff,
            _ => {
                if self.in_flight() >= MAX_LOOKUPS {
                    return Lookup::Pending;
                }
                // Stale or never seen: (re)start.
                match idx {
                    Some(i) => {
                        if let Some(e) = self.entries.get_mut(i) {
                            e.1 = Resolution::InFlight;
                        }
                    }
                    None => self.entries.push((key, Resolution::InFlight)),
                }
                Lookup::Start
            }
        }
    }

    /// Record the result of a lookup the caller started (`None` = failed, no IPv4).
    pub fn complete(&mut self, name: &str, now: Instant, result: Option<Ipv4Addr>) {
        let key = name.to_ascii_lowercase();
        let new = match result {
            Some(ip) => Resolution::Done(ip, now),
            None => Resolution::Failed(now),
        };
        match self.entries.iter_mut().find(|(n, _)| *n == key) {
            Some(e) => e.1 = new,
            None => self.entries.push((key, new)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
    }

    fn ms(n: u64) -> Instant {
        Instant(Duration::from_millis(n))
    }

    fn dests(out: &[Outgoing]) -> Vec<Endpoint> {
        out.iter().map(|o| o.to).collect()
    }

    #[test]
    fn announce_every_second_to_broadcast_loopback_and_targets() {
        let mut a = Announcer::new(1338);
        let mut out = Vec::new();
        a.poll(ms(0), &mut out);
        assert!(out.is_empty(), "nothing to advertise yet");
        assert_eq!(a.next_deadline(), None);
        a.set_announcement(Some(b"lobby v1".to_vec())).unwrap();
        a.add_target(ep(9, 9, 9, 9, 1338));
        assert!(!a.add_target(ep(9, 9, 9, 9, 1338)));
        a.poll(ms(10), &mut out);
        assert_eq!(
            dests(&out),
            vec![
                ep(255, 255, 255, 255, 1338),
                ep(127, 0, 0, 1, 1338),
                ep(9, 9, 9, 9, 1338)
            ]
        );
        assert!(out.iter().all(|o| o.bytes == b"lobby v1"));
        out.clear();
        a.poll(ms(1009), &mut out);
        assert!(out.is_empty());
        assert_eq!(a.next_deadline(), Some(ms(1010)));
        a.poll(ms(1010), &mut out);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn changes_are_coalesced_to_100ms_and_identical_is_free() {
        let mut a = Announcer::new(1338);
        a.set_announcement(Some(b"A".to_vec())).unwrap();
        let mut out = Vec::new();
        a.poll(ms(1000), &mut out);
        out.clear();
        // Change 30 ms later: held until 100 ms after the last send.
        a.set_announcement(Some(b"B".to_vec())).unwrap();
        a.poll(ms(1030), &mut out);
        assert!(out.is_empty());
        assert_eq!(a.next_deadline(), Some(ms(1100)));
        // Further changes meanwhile coalesce: the send carries the latest.
        a.set_announcement(Some(b"C".to_vec())).unwrap();
        a.poll(ms(1100), &mut out);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|o| o.bytes == b"C"));
        // Re-setting identical content sends nothing extra.
        out.clear();
        a.set_announcement(Some(b"C".to_vec())).unwrap();
        a.poll(ms(1150), &mut out);
        assert!(out.is_empty());
        // Periodic still runs from the last send.
        a.poll(ms(2100), &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn oversize_announcement_is_refused() {
        let mut a = Announcer::new(1338);
        a.set_announcement(Some(vec![b'x'; 1400])).unwrap();
        assert_eq!(
            a.set_announcement(Some(vec![b'x'; 1401])),
            Err(LanError::TooLarge(1401))
        );
        let mut out = Vec::new();
        a.poll(ms(0), &mut out);
        assert!(out.is_empty(), "not advertised");
    }

    #[test]
    fn probe_replies_are_unicast_and_rate_limited() {
        let mut a = Announcer::new(1338);
        let mut out = Vec::new();
        let p1 = ep(10, 0, 0, 1, 5000);
        let p2 = ep(10, 0, 0, 2, 5000);
        // Not advertising: probe consumed, no reply.
        assert!(a.handle_probe(ms(0), p1, &PROBE_DATAGRAM, &mut out));
        assert!(out.is_empty());
        a.set_announcement(Some(b"hello".to_vec())).unwrap();
        assert!(a.handle_probe(ms(100), p1, &PROBE_DATAGRAM, &mut out));
        assert_eq!(dests(&out), vec![p1]);
        assert_eq!(out[0].bytes, b"hello");
        // Same prober within 250 ms: nothing. Another prober: reply.
        assert!(a.handle_probe(ms(300), p1, &PROBE_DATAGRAM, &mut out));
        assert_eq!(out.len(), 1);
        assert!(a.handle_probe(ms(300), p2, &PROBE_DATAGRAM, &mut out));
        assert_eq!(out.len(), 2);
        // 250 ms after the last answer to p1.
        assert!(a.handle_probe(ms(350), p1, &PROBE_DATAGRAM, &mut out));
        assert_eq!(out.len(), 3);
        // Not a probe.
        assert!(!a.handle_probe(ms(400), p1, b"something else", &mut out));
        assert!(!a.handle_probe(ms(400), p1, &[], &mut out));
    }

    #[test]
    fn prober_tracking_is_bounded() {
        let mut a = Announcer::new(1338);
        a.set_announcement(Some(b"x".to_vec())).unwrap();
        let mut out = Vec::new();
        for i in 0..200u16 {
            let from = ep(10, 0, (i >> 8) as u8, i as u8, 1);
            a.handle_probe(ms(u64::from(i)), from, &PROBE_DATAGRAM, &mut out);
        }
        assert_eq!(out.len(), 200);
        assert!(a.probers.len() <= MAX_PROBERS);
    }

    #[test]
    fn prober_once_per_second() {
        let mut p = Prober::new();
        let mut out = Vec::new();
        p.poll(ms(0), &mut out);
        assert!(out.is_empty());
        assert_eq!(p.next_deadline(), None);
        let t = ep(1, 2, 3, 4, 1338);
        p.set_targets(&[t]);
        p.poll(ms(5), &mut out);
        assert_eq!(dests(&out), vec![t]);
        assert!(is_probe(&out[0].bytes));
        out.clear();
        p.poll(ms(1004), &mut out);
        assert!(out.is_empty());
        assert_eq!(p.next_deadline(), Some(ms(1005)));
        p.poll(ms(1005), &mut out);
        assert_eq!(out.len(), 1);
        // Unchanged targets do not reset the schedule; changed ones do.
        out.clear();
        p.set_targets(&[t]);
        p.poll(ms(1100), &mut out);
        assert!(out.is_empty());
        p.set_targets(&[t, ep(5, 6, 7, 8, 1338)]);
        p.poll(ms(1100), &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn heard_announcements_expire_after_3500ms() {
        let mut h: HeardAnnouncements<u32> = HeardAnnouncements::new();
        assert!(h.hear(1, ms(0)));
        assert!(h.hear(2, ms(1000)));
        assert!(!h.hear(1, ms(1000)));
        assert_eq!(h.alive(ms(4499)), vec![1, 2]);
        assert!(h.expire(ms(4499)).is_empty());
        // 1 was last heard at 1000, 2 at 1000; both expire at 4500.
        assert_eq!(h.expire(ms(4500)), vec![1, 2]);
        assert!(h.alive(ms(4500)).is_empty());
        // Back after expiry counts as new.
        assert!(h.hear(1, ms(9000)));
    }

    #[test]
    fn parse_targets() {
        let d = 1338;
        assert_eq!(
            parse_target("192.168.1.5", d),
            Ok(TypedTarget::Ipv4(ep(192, 168, 1, 5, 1338)))
        );
        assert_eq!(
            parse_target(" 192.168.1.5:4000 ", d),
            Ok(TypedTarget::Ipv4(ep(192, 168, 1, 5, 4000)))
        );
        assert!(matches!(
            parse_target("[::1]:99", d),
            Ok(TypedTarget::Ipv6(a)) if a.port() == 99
        ));
        assert!(matches!(
            parse_target("fe80::1", d),
            Ok(TypedTarget::Ipv6(a)) if a.port() == 1338
        ));
        assert_eq!(
            parse_target("MyPC.local", d),
            Ok(TypedTarget::Name {
                host: "mypc.local".into(),
                port: 1338
            })
        );
        assert_eq!(
            parse_target("mypc:77", d),
            Ok(TypedTarget::Name {
                host: "mypc".into(),
                port: 77
            })
        );
        let code = invite::encode(ep(203, 0, 113, 9, 4321)).unwrap();
        assert_eq!(
            parse_target(&code, d),
            Ok(TypedTarget::Code(ep(203, 0, 113, 9, 4321)))
        );
        for bad in [
            "",
            "   ",
            "bad host",
            "-x",
            "a..b",
            "1.2.3",
            "host:0",
            "host:99999",
            "host:x",
            "a:b:c",
            "under_score",
            "300.1.1.1",
        ] {
            assert_eq!(parse_target(bad, d), Err(InvalidTarget), "{bad:?}");
        }
        assert_eq!(parse_target(&"a".repeat(300), d), Err(InvalidTarget));
    }

    #[test]
    fn resolve_cache_rules() {
        let mut c = ResolveCache::new();
        assert_eq!(c.lookup("Host", ms(0)), Lookup::Start);
        assert_eq!(c.lookup("host", ms(10)), Lookup::Pending);
        c.complete("host", ms(100), Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(
            c.lookup("host", ms(200)),
            Lookup::Ready(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(
            c.lookup("host", ms(60_099)),
            Lookup::Ready(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(c.lookup("host", ms(60_100)), Lookup::Start);
        // Failure: no retry for 5 s.
        c.complete("host", ms(61_000), None);
        assert_eq!(c.lookup("host", ms(65_999)), Lookup::BackedOff);
        assert_eq!(c.lookup("host", ms(66_000)), Lookup::Start);
        // At most 8 in flight.
        let mut c = ResolveCache::new();
        for i in 0..8 {
            assert_eq!(c.lookup(&format!("h{i}"), ms(0)), Lookup::Start);
        }
        assert_eq!(c.lookup("h9", ms(0)), Lookup::Pending);
        c.complete("h0", ms(1), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(c.lookup("h9", ms(2)), Lookup::Start);
    }
}
