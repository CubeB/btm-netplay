//! The sans-IO relay server: rooms, members, stateless cookies, budgets and expiry.
//!
//! The server keeps state only for admitted members. Before admission a source is
//! *unverified*: it gets at most one reply per datagram, never larger than the datagram it
//! sent (a challenge carrying a stateless cookie, or a refusal), and nothing is stored for
//! it. A hello is answered with a welcome only when it echoes a cookie that was sent to the
//! same address, which proves the source address is real (return routability).

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use super::proto::{
    decode_client, ClientFrame, Cookie, RefuseReason, RoomId, ServerFrame, COOKIE_LEN, MAX_MEMBERS,
    MAX_PAYLOAD,
};
use super::{ct_eq, Prf};
use crate::session::hmac_sha256;
use crate::types::{Endpoint, Instant, Outgoing};

const PURPOSE_ALLOCATE: u8 = 1;
const PURPOSE_JOIN: u8 = 2;
const PURPOSE_REBIND: u8 = 3;

/// Limits of one relay. See `RELAY.md` for the reasoning behind the defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayConfig {
    /// Rooms held at once.
    pub max_rooms: usize,
    /// Rooms one source IPv4 address may own (allocate) at once.
    pub max_rooms_per_ip: usize,
    /// Members per room, at most 10.
    pub max_members: u8,
    /// Largest payload forwarded, at most 1400.
    pub max_payload: usize,
    /// Per-member budget, packets per second (pings included). The bucket holds one
    /// second's worth.
    pub member_packets_per_sec: u32,
    /// Per-member budget, payload bytes per second.
    pub member_bytes_per_sec: u32,
    /// A member that sends nothing for this long is removed; an empty room is closed.
    pub idle_expiry: Duration,
    /// A cookie is valid in the period it was made and the next one.
    pub cookie_period: Duration,
    /// Minimum gap between two non-fatal refusals sent to the same member.
    pub refusal_gap: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_rooms: 1024,
            max_rooms_per_ip: 4,
            max_members: MAX_MEMBERS,
            max_payload: MAX_PAYLOAD,
            member_packets_per_sec: 600,
            member_bytes_per_sec: 256 * 1024,
            idle_expiry: Duration::from_secs(30),
            cookie_period: Duration::from_secs(10),
            refusal_gap: Duration::from_secs(1),
        }
    }
}

/// A configuration the server refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `max_members` is 0 or more than 10.
    MaxMembers,
    /// `max_payload` is 0 or more than 1400.
    MaxPayload,
    /// A limit that must be non-zero is zero.
    Zero(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxMembers => write!(f, "max members must be 1..={MAX_MEMBERS}"),
            Self::MaxPayload => write!(f, "max payload must be 1..={MAX_PAYLOAD}"),
            Self::Zero(what) => write!(f, "{what} must not be zero"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Why a member left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaveReason {
    /// It sent a leave.
    Left,
    /// It was silent for the idle expiry.
    Idle,
}

/// Something worth logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerEvent {
    RoomOpened {
        room: RoomId,
        host: Endpoint,
    },
    MemberJoined {
        room: RoomId,
        member: u8,
        addr: Endpoint,
    },
    MemberLeft {
        room: RoomId,
        member: u8,
        why: LeaveReason,
    },
    /// A member's address changed (NAT rebinding), confirmed by a cookie.
    MemberMoved {
        room: RoomId,
        member: u8,
        from: Endpoint,
        to: Endpoint,
    },
    RoomClosed {
        room: RoomId,
    },
    Refused {
        to: Endpoint,
        reason: RefuseReason,
    },
}

/// Counters, for the log and for tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerStats {
    pub received: u64,
    pub received_bytes: u64,
    /// Bytes sent to sources that were not admitted members.
    pub unverified_sent_bytes: u64,
    /// Bytes received from sources that were not admitted members.
    pub unverified_received_bytes: u64,
    pub forwarded: u64,
    pub forwarded_bytes: u64,
    pub challenges: u64,
    pub refusals: u64,
    /// Datagrams dropped without an answer (garbage, bad secrets, budget, ...).
    pub dropped: u64,
    pub rate_limited: u64,
}

#[derive(Clone, Debug)]
struct Bucket {
    /// Milli-packets and milli-bytes, so integer refill per millisecond is exact.
    packets: u64,
    bytes: u64,
    last: Instant,
}

impl Bucket {
    fn full(cfg: &RelayConfig, now: Instant) -> Self {
        Self {
            packets: u64::from(cfg.member_packets_per_sec) * 1000,
            bytes: u64::from(cfg.member_bytes_per_sec) * 1000,
            last: now,
        }
    }

    /// Charge one packet of `len` bytes; false if over budget (nothing charged then).
    fn charge(&mut self, cfg: &RelayConfig, now: Instant, len: usize) -> bool {
        let ms = u64::try_from(now.0.saturating_sub(self.last.0).as_millis()).unwrap_or(u64::MAX);
        self.last = now;
        let p_cap = u64::from(cfg.member_packets_per_sec) * 1000;
        let b_cap = u64::from(cfg.member_bytes_per_sec) * 1000;
        self.packets = self
            .packets
            .saturating_add(ms.saturating_mul(u64::from(cfg.member_packets_per_sec)))
            .min(p_cap);
        self.bytes = self
            .bytes
            .saturating_add(ms.saturating_mul(u64::from(cfg.member_bytes_per_sec)))
            .min(b_cap);
        let p_cost = 1000;
        let b_cost = u64::try_from(len).unwrap_or(u64::MAX).saturating_mul(1000);
        if self.packets < p_cost || self.bytes < b_cost {
            return false;
        }
        self.packets -= p_cost;
        self.bytes -= b_cost;
        true
    }
}

#[derive(Clone, Debug)]
struct Member {
    secret: u64,
    addr: Endpoint,
    nonce: [u8; 8],
    last_heard: Instant,
    bucket: Bucket,
    last_refusal: Option<Instant>,
}

#[derive(Clone, Debug)]
struct Room {
    owner_ip: Ipv4Addr,
    members: [Option<Member>; MAX_MEMBERS as usize],
}

impl Room {
    fn bitmap(&self) -> u16 {
        self.members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.is_some())
            .fold(0u16, |acc, (i, _)| acc | (1 << i))
    }

    fn count(&self) -> usize {
        self.members.iter().filter(|m| m.is_some()).count()
    }

    fn by_secret(&self, secret: u64) -> Option<u8> {
        let wanted = secret.to_be_bytes();
        let mut found = None;
        // Look at every slot so the time taken does not say which one matched.
        for (i, m) in self.members.iter().enumerate() {
            if let Some(m) = m {
                if ct_eq(&m.secret.to_be_bytes(), &wanted) {
                    found = u8::try_from(i).ok();
                }
            }
        }
        found
    }

    fn by_addr(&self, addr: Endpoint) -> Option<u8> {
        self.members
            .iter()
            .position(|m| m.as_ref().is_some_and(|m| m.addr == addr))
            .and_then(|i| u8::try_from(i).ok())
    }

    fn member(&self, i: u8) -> Option<&Member> {
        self.members.get(usize::from(i)).and_then(Option::as_ref)
    }

    fn member_mut(&mut self, i: u8) -> Option<&mut Member> {
        self.members
            .get_mut(usize::from(i))
            .and_then(Option::as_mut)
    }
}

/// The relay. Feed it every datagram with [`RelayServer::handle`] and call
/// [`RelayServer::poll`] at [`RelayServer::next_deadline`] (or once a second).
#[derive(Clone)]
pub struct RelayServer {
    cfg: RelayConfig,
    cookie_key: [u8; 32],
    rng: Prf,
    rooms: HashMap<RoomId, Room>,
    stats: ServerStats,
}

impl fmt::Debug for RelayServer {
    // Keys and member secrets are left out on purpose.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayServer")
            .field("cfg", &self.cfg)
            .field("rooms", &self.rooms.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl RelayServer {
    /// A server with `seed` as its only secret: room ids, member secrets and the cookie
    /// key are all derived from it, so it must be unpredictable (32 random bytes).
    pub fn new(cfg: RelayConfig, seed: [u8; 32]) -> Result<Self, ConfigError> {
        if cfg.max_members == 0 || cfg.max_members > MAX_MEMBERS {
            return Err(ConfigError::MaxMembers);
        }
        if cfg.max_payload == 0 || cfg.max_payload > MAX_PAYLOAD {
            return Err(ConfigError::MaxPayload);
        }
        for (v, what) in [
            (cfg.max_rooms, "max rooms"),
            (cfg.max_rooms_per_ip, "max rooms per address"),
            (cfg.member_packets_per_sec as usize, "packets per second"),
            (cfg.member_bytes_per_sec as usize, "bytes per second"),
        ] {
            if v == 0 {
                return Err(ConfigError::Zero(what));
            }
        }
        if cfg.idle_expiry.is_zero() {
            return Err(ConfigError::Zero("idle expiry"));
        }
        if cfg.cookie_period.is_zero() {
            return Err(ConfigError::Zero("cookie period"));
        }
        let cookie_key = hmac_sha256(&seed, b"btm-relay-cookie-key");
        let rng = Prf::new(hmac_sha256(&seed, b"btm-relay-ids"));
        Ok(Self {
            cfg,
            cookie_key,
            rng,
            rooms: HashMap::new(),
            stats: ServerStats::default(),
        })
    }

    pub fn config(&self) -> &RelayConfig {
        &self.cfg
    }

    pub fn stats(&self) -> ServerStats {
        self.stats
    }

    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    pub fn member_count(&self) -> usize {
        self.rooms.values().map(Room::count).sum()
    }

    /// Members present in `room`, as a bitmap (bit k = member k).
    pub fn members_of(&self, room: RoomId) -> Option<u16> {
        self.rooms.get(&room).map(Room::bitmap)
    }

    /// When [`RelayServer::poll`] next has something to expire.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.rooms
            .values()
            .flat_map(|r| r.members.iter().flatten())
            .map(|m| Instant(m.last_heard.0.saturating_add(self.cfg.idle_expiry)))
            .min()
    }

    /// Expire silent members and close empty rooms.
    pub fn poll(&mut self, now: Instant) -> Vec<ServerEvent> {
        let mut events = Vec::new();
        let expiry = self.cfg.idle_expiry;
        for (id, room) in &mut self.rooms {
            for (i, slot) in room.members.iter_mut().enumerate() {
                let idle = slot
                    .as_ref()
                    .is_some_and(|m| now.0.saturating_sub(m.last_heard.0) >= expiry);
                if idle {
                    *slot = None;
                    events.push(ServerEvent::MemberLeft {
                        room: *id,
                        member: u8::try_from(i).unwrap_or(u8::MAX),
                        why: LeaveReason::Idle,
                    });
                }
            }
        }
        self.close_empty(&mut events);
        events
    }

    fn close_empty(&mut self, events: &mut Vec<ServerEvent>) {
        let empty: Vec<RoomId> = self
            .rooms
            .iter()
            .filter(|(_, r)| r.count() == 0)
            .map(|(id, _)| *id)
            .collect();
        for room in empty {
            self.rooms.remove(&room);
            events.push(ServerEvent::RoomClosed { room });
        }
    }

    /// Handle one datagram from `from`, appending what to send to `out`.
    pub fn handle(
        &mut self,
        now: Instant,
        from: Endpoint,
        bytes: &[u8],
        out: &mut Vec<Outgoing>,
    ) -> Vec<ServerEvent> {
        self.stats.received += 1;
        self.stats.received_bytes += bytes.len() as u64;
        let mut events = Vec::new();
        let frame = match decode_client(bytes) {
            Ok(f) => f,
            Err(_) => {
                self.stats.unverified_received_bytes += bytes.len() as u64;
                self.stats.dropped += 1;
                return events;
            }
        };
        match frame {
            ClientFrame::Allocate { nonce, cookie } => {
                self.on_allocate(now, from, bytes.len(), nonce, cookie, out, &mut events)
            }
            ClientFrame::Join {
                nonce,
                cookie,
                room,
            } => self.on_join(
                now,
                from,
                bytes.len(),
                nonce,
                cookie,
                room,
                out,
                &mut events,
            ),
            ClientFrame::Data {
                room,
                secret,
                to,
                src_port,
                dst_port,
                payload,
            } => self.on_data(
                now,
                from,
                bytes.len(),
                room,
                secret,
                (to, src_port, dst_port),
                payload,
                out,
                &mut events,
            ),
            ClientFrame::Ping {
                room,
                secret,
                id,
                cookie,
            } => self.on_ping(
                now,
                from,
                bytes.len(),
                room,
                secret,
                id,
                cookie,
                out,
                &mut events,
            ),
            ClientFrame::Leave { room, secret } => {
                self.on_leave(from, bytes.len(), room, secret, &mut events)
            }
        }
        events
    }

    // -----------------------------------------------------------------------------------

    fn cookie_for(
        &self,
        period: u64,
        from: Endpoint,
        purpose: u8,
        nonce: [u8; 8],
        room: RoomId,
    ) -> Cookie {
        let mut msg = [0u8; 1 + 8 + 4 + 2 + 8 + 8];
        msg[0] = purpose;
        msg[1..9].copy_from_slice(&period.to_be_bytes());
        msg[9..13].copy_from_slice(&from.ip().octets());
        msg[13..15].copy_from_slice(&from.port().to_be_bytes());
        msg[15..23].copy_from_slice(&nonce);
        msg[23..31].copy_from_slice(&room.to_be_bytes());
        let mac = hmac_sha256(&self.cookie_key, &msg);
        let mut c = [0u8; COOKIE_LEN];
        c.copy_from_slice(&mac[..COOKIE_LEN]);
        c
    }

    fn period(&self, now: Instant) -> u64 {
        let p = self.cfg.cookie_period.as_millis().max(1);
        u64::try_from(now.0.as_millis() / p).unwrap_or(u64::MAX)
    }

    fn make_cookie(
        &self,
        now: Instant,
        from: Endpoint,
        purpose: u8,
        nonce: [u8; 8],
        room: RoomId,
    ) -> Cookie {
        self.cookie_for(self.period(now), from, purpose, nonce, room)
    }

    fn cookie_ok(
        &self,
        now: Instant,
        from: Endpoint,
        purpose: u8,
        nonce: [u8; 8],
        room: RoomId,
        cookie: &Cookie,
    ) -> bool {
        if cookie.iter().all(|&b| b == 0) {
            return false;
        }
        let p = self.period(now);
        let current = self.cookie_for(p, from, purpose, nonce, room);
        let previous = self.cookie_for(p.saturating_sub(1), from, purpose, nonce, room);
        // Evaluate both so timing does not say which period matched.
        let a = ct_eq(&current, cookie);
        let b = ct_eq(&previous, cookie);
        a | b
    }

    /// Send to a source that is not an admitted member: at most as many bytes as it sent.
    fn send_unverified(
        &mut self,
        to: Endpoint,
        received: usize,
        frame: &ServerFrame<'_>,
        out: &mut Vec<Outgoing>,
    ) {
        self.stats.unverified_received_bytes += received as u64;
        match frame.encode() {
            Ok(bytes) if bytes.len() <= received => {
                self.stats.unverified_sent_bytes += bytes.len() as u64;
                out.push(Outgoing { to, bytes });
            }
            _ => self.stats.dropped += 1,
        }
    }

    fn send_verified(&mut self, to: Endpoint, frame: &ServerFrame<'_>, out: &mut Vec<Outgoing>) {
        if let Ok(bytes) = frame.encode() {
            out.push(Outgoing { to, bytes });
        }
    }

    fn refuse_unverified(
        &mut self,
        to: Endpoint,
        received: usize,
        echo: [u8; 8],
        reason: RefuseReason,
        out: &mut Vec<Outgoing>,
        events: &mut Vec<ServerEvent>,
    ) {
        self.stats.refusals += 1;
        self.send_unverified(to, received, &ServerFrame::Refuse { echo, reason }, out);
        events.push(ServerEvent::Refused { to, reason });
    }

    fn welcome(&mut self, room_id: RoomId, member: u8, out: &mut Vec<Outgoing>) {
        let Some(room) = self.rooms.get(&room_id) else {
            return;
        };
        let members = room.bitmap();
        let Some(m) = room.member(member) else {
            return;
        };
        let frame = ServerFrame::Welcome {
            nonce: m.nonce,
            room: room_id,
            secret: m.secret,
            member,
            members,
            max_payload: u16::try_from(self.cfg.max_payload).unwrap_or(u16::MAX),
        };
        let to = m.addr;
        self.send_verified(to, &frame, out);
    }

    fn fresh_nonzero(&mut self) -> u64 {
        loop {
            let v = self.rng.next_u64();
            if v != 0 {
                return v;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_allocate(
        &mut self,
        now: Instant,
        from: Endpoint,
        len: usize,
        nonce: [u8; 8],
        cookie: Cookie,
        out: &mut Vec<Outgoing>,
        events: &mut Vec<ServerEvent>,
    ) {
        // A retransmitted allocate from the host of an existing room: welcome again.
        let existing = self.rooms.iter().find_map(|(id, r)| {
            r.member(0)
                .filter(|m| m.addr == from && m.nonce == nonce)
                .map(|_| *id)
        });
        if let Some(room) = existing {
            if let Some(m) = self.rooms.get_mut(&room).and_then(|r| r.member_mut(0)) {
                m.last_heard = now;
            }
            self.welcome(room, 0, out);
            return;
        }
        if !self.cookie_ok(now, from, PURPOSE_ALLOCATE, nonce, 0, &cookie) {
            self.stats.challenges += 1;
            let cookie = self.make_cookie(now, from, PURPOSE_ALLOCATE, nonce, 0);
            self.send_unverified(from, len, &ServerFrame::Challenge { nonce, cookie }, out);
            return;
        }
        // The source is verified from here on, but it holds no state yet: refusals still
        // go through the unverified path (and are smaller than the hello anyway).
        if self.rooms.len() >= self.cfg.max_rooms {
            self.refuse_unverified(from, len, nonce, RefuseReason::ServerFull, out, events);
            return;
        }
        let owned = self
            .rooms
            .values()
            .filter(|r| r.owner_ip == *from.ip())
            .count();
        if owned >= self.cfg.max_rooms_per_ip {
            self.refuse_unverified(from, len, nonce, RefuseReason::TooManyRooms, out, events);
            return;
        }
        let room_id = loop {
            let id = self.fresh_nonzero();
            if !self.rooms.contains_key(&id) {
                break id;
            }
        };
        let secret = self.fresh_nonzero();
        let mut room = Room {
            owner_ip: *from.ip(),
            members: Default::default(),
        };
        room.members[0] = Some(Member {
            secret,
            addr: from,
            nonce,
            last_heard: now,
            bucket: Bucket::full(&self.cfg, now),
            last_refusal: None,
        });
        self.rooms.insert(room_id, room);
        self.stats.unverified_received_bytes += len as u64;
        events.push(ServerEvent::RoomOpened {
            room: room_id,
            host: from,
        });
        self.welcome(room_id, 0, out);
    }

    #[allow(clippy::too_many_arguments)]
    fn on_join(
        &mut self,
        now: Instant,
        from: Endpoint,
        len: usize,
        nonce: [u8; 8],
        cookie: Cookie,
        room_id: RoomId,
        out: &mut Vec<Outgoing>,
        events: &mut Vec<ServerEvent>,
    ) {
        // Already a member from this exact address (a lost welcome): welcome again.
        if let Some(i) = self.rooms.get(&room_id).and_then(|r| r.by_addr(from)) {
            if let Some(m) = self.rooms.get_mut(&room_id).and_then(|r| r.member_mut(i)) {
                m.last_heard = now;
                m.nonce = nonce;
            }
            self.welcome(room_id, i, out);
            return;
        }
        // The challenge comes before any lookup, so an unverified source cannot learn
        // whether a room id exists.
        if !self.cookie_ok(now, from, PURPOSE_JOIN, nonce, room_id, &cookie) {
            self.stats.challenges += 1;
            let cookie = self.make_cookie(now, from, PURPOSE_JOIN, nonce, room_id);
            self.send_unverified(from, len, &ServerFrame::Challenge { nonce, cookie }, out);
            return;
        }
        let max = usize::from(self.cfg.max_members);
        let free = match self.rooms.get(&room_id) {
            None => Err(RefuseReason::NoSuchRoom),
            Some(r) => r
                .members
                .iter()
                .take(max)
                .position(Option::is_none)
                .and_then(|i| u8::try_from(i).ok())
                .ok_or(RefuseReason::RoomFull),
        };
        let index = match free {
            Ok(i) => i,
            Err(reason) => {
                self.refuse_unverified(from, len, nonce, reason, out, events);
                return;
            }
        };
        let secret = self.fresh_nonzero();
        let bucket = Bucket::full(&self.cfg, now);
        if let Some(slot) = self
            .rooms
            .get_mut(&room_id)
            .and_then(|r| r.members.get_mut(usize::from(index)))
        {
            *slot = Some(Member {
                secret,
                addr: from,
                nonce,
                last_heard: now,
                bucket,
                last_refusal: None,
            });
        }
        self.stats.unverified_received_bytes += len as u64;
        events.push(ServerEvent::MemberJoined {
            room: room_id,
            member: index,
            addr: from,
        });
        self.welcome(room_id, index, out);
    }

    /// A non-fatal refusal to an admitted member, at most one per `refusal_gap`.
    fn refuse_member(
        &mut self,
        now: Instant,
        room_id: RoomId,
        index: u8,
        reason: RefuseReason,
        out: &mut Vec<Outgoing>,
        events: &mut Vec<ServerEvent>,
    ) {
        let gap = self.cfg.refusal_gap;
        let Some(m) = self
            .rooms
            .get_mut(&room_id)
            .and_then(|r| r.member_mut(index))
        else {
            return;
        };
        if m.last_refusal
            .is_some_and(|t| now.0.saturating_sub(t.0) < gap)
        {
            return;
        }
        m.last_refusal = Some(now);
        let (to, echo) = (m.addr, m.secret.to_be_bytes());
        self.stats.refusals += 1;
        self.send_verified(to, &ServerFrame::Refuse { echo, reason }, out);
        events.push(ServerEvent::Refused { to, reason });
    }

    #[allow(clippy::too_many_arguments)]
    fn on_data(
        &mut self,
        now: Instant,
        from: Endpoint,
        len: usize,
        room_id: RoomId,
        secret: u64,
        (to, src_port, dst_port): (u8, u16, u16),
        payload: &[u8],
        out: &mut Vec<Outgoing>,
        events: &mut Vec<ServerEvent>,
    ) {
        let sender = self
            .rooms
            .get(&room_id)
            .and_then(|r| r.by_secret(secret).map(|i| (i, r)))
            .filter(|(i, r)| r.member(*i).is_some_and(|m| m.addr == from))
            .map(|(i, _)| i);
        // Unknown room, unknown secret, or a known secret from another address (that is
        // settled by a cookie on the ping path): drop silently.
        let Some(index) = sender else {
            self.stats.unverified_received_bytes += len as u64;
            self.stats.dropped += 1;
            return;
        };
        let cfg = self.cfg.clone();
        let allowed = match self
            .rooms
            .get_mut(&room_id)
            .and_then(|r| r.member_mut(index))
        {
            Some(m) => {
                m.last_heard = now;
                m.bucket.charge(&cfg, now, payload.len())
            }
            None => false,
        };
        if !allowed {
            self.stats.rate_limited += 1;
            self.stats.dropped += 1;
            self.refuse_member(now, room_id, index, RefuseReason::RateLimited, out, events);
            return;
        }
        if payload.len() > cfg.max_payload {
            self.stats.dropped += 1;
            self.refuse_member(now, room_id, index, RefuseReason::TooLarge, out, events);
            return;
        }
        let target = self
            .rooms
            .get(&room_id)
            .and_then(|r| r.member(to))
            .filter(|_| to != index)
            .map(|m| (m.addr, m.secret));
        let Some((addr, their_secret)) = target else {
            self.stats.dropped += 1;
            self.refuse_member(now, room_id, index, RefuseReason::NoSuchMember, out, events);
            return;
        };
        let frame = ServerFrame::Deliver {
            secret: their_secret,
            from: index,
            src_port,
            dst_port,
            payload,
        };
        if let Ok(bytes) = frame.encode() {
            self.stats.forwarded += 1;
            self.stats.forwarded_bytes += bytes.len() as u64;
            out.push(Outgoing { to: addr, bytes });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_ping(
        &mut self,
        now: Instant,
        from: Endpoint,
        len: usize,
        room_id: RoomId,
        secret: u64,
        id: u32,
        cookie: Cookie,
        out: &mut Vec<Outgoing>,
        events: &mut Vec<ServerEvent>,
    ) {
        let found = self.rooms.get(&room_id).and_then(|r| {
            r.by_secret(secret)
                .and_then(|i| r.member(i).map(|m| (i, m.addr)))
        });
        let Some((index, addr)) = found else {
            // Tell the client its membership is gone (no larger than its ping).
            self.refuse_unverified(
                from,
                len,
                secret.to_be_bytes(),
                RefuseReason::NotMember,
                out,
                events,
            );
            return;
        };
        if addr != from {
            let nonce = secret.to_be_bytes();
            if self.cookie_ok(now, from, PURPOSE_REBIND, nonce, room_id, &cookie) {
                if let Some(m) = self
                    .rooms
                    .get_mut(&room_id)
                    .and_then(|r| r.member_mut(index))
                {
                    m.addr = from;
                }
                self.stats.unverified_received_bytes += len as u64;
                events.push(ServerEvent::MemberMoved {
                    room: room_id,
                    member: index,
                    from: addr,
                    to: from,
                });
            } else {
                self.stats.challenges += 1;
                let cookie = self.make_cookie(now, from, PURPOSE_REBIND, nonce, room_id);
                let frame = ServerFrame::Pong {
                    secret,
                    id,
                    members: 0,
                    cookie,
                };
                self.send_unverified(from, len, &frame, out);
                return;
            }
        }
        let cfg = self.cfg.clone();
        let allowed = match self
            .rooms
            .get_mut(&room_id)
            .and_then(|r| r.member_mut(index))
        {
            Some(m) => {
                m.last_heard = now;
                m.bucket.charge(&cfg, now, 0)
            }
            None => false,
        };
        if !allowed {
            self.stats.rate_limited += 1;
            self.stats.dropped += 1;
            return;
        }
        let members = self.rooms.get(&room_id).map(Room::bitmap).unwrap_or(0);
        let frame = ServerFrame::Pong {
            secret,
            id,
            members,
            cookie: [0; COOKIE_LEN],
        };
        self.send_verified(from, &frame, out);
    }

    fn on_leave(
        &mut self,
        from: Endpoint,
        len: usize,
        room_id: RoomId,
        secret: u64,
        events: &mut Vec<ServerEvent>,
    ) {
        let index = self
            .rooms
            .get(&room_id)
            .and_then(|r| r.by_secret(secret).map(|i| (i, r)))
            .filter(|(i, r)| r.member(*i).is_some_and(|m| m.addr == from))
            .map(|(i, _)| i);
        let Some(index) = index else {
            self.stats.unverified_received_bytes += len as u64;
            self.stats.dropped += 1;
            return;
        };
        if let Some(slot) = self
            .rooms
            .get_mut(&room_id)
            .and_then(|r| r.members.get_mut(usize::from(index)))
        {
            *slot = None;
        }
        events.push(ServerEvent::MemberLeft {
            room: room_id,
            member: index,
            why: LeaveReason::Left,
        });
        self.close_empty(events);
    }
}
