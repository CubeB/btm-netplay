//! Rejoin through the host (SPEC 5.6, without the external launcher), sans-IO.
//!
//! The spec carries a rejoin through a central lobby server. Here the host keeps its
//! discovery socket (and relay link) open during the game and is the speaker itself:
//!
//! 1. The dropped player runs the ordinary join again, with the same code or address.
//!    Its lobby probes and claims reach the host, which is in the game now, and answers
//!    each with "in game" (session id and a fresh password challenge).
//! 2. The returning player asks for its seat back by name ([`RejoinClient`]), with a
//!    password proof when the room has a password.
//! 3. The host ([`RejoinServer`]) reports the request ([`ServerEvent::Asked`]); its caller
//!    finds the dropped seat of that name and answers: wait (the seat is not dropped yet),
//!    refuse, or offer it with the rejoin tick R the lockstep chose.
//! 4. Once the lockstep has cut the catch-up bundle (scene time R-1), the host sends the
//!    payload: the game's setup as an announcement (seats, seed, map, options, path
//!    table) followed by the bundle, in chunks with a sliding window, acknowledged by
//!    how many leading bytes the returning player holds.
//! 5. The returning player rebuilds the [`GameStart`] from the setup and hands it, the
//!    bundle bytes and R to its driver ([`ClientEvent::Ready`]), which loads the engine and
//!    fast-forwards with `Lockstep::rejoin`.
//!
//! Every datagram is a lobby datagram (same magic and framing, new kinds).
//!
//! Limits: only the host serves rejoins, so a dropped host cannot come back, and the host
//! must be the lockstep's designated declarer for that player (it is, unless the host was
//! itself dropped). The returning machine's new game address is learnt by address
//! following (2.8), so it must keep its /16 (or rejoin through the relay).

use std::fmt;
use std::time::Duration;

use super::codec::{
    self, encode_ack, encode_announce, encode_answer, encode_ask, encode_chunk, encode_in_game,
    Ack, Announce, Answer, AnswerKind, Ask, Chunk, InGame, Msg,
};
use super::guest::view_from_announce;
use super::sha256::{ct_eq, Sha256};
use super::{
    build_compatible, clean, password_proof, since, Endpoint, GameStart, GuestConfig, Instant,
    Outgoing, PlayerId, Step, MAX_NAME,
};
use crate::types::Tick;

/// A returning player repeats its request this often until it is answered.
pub const ASK_INTERVAL: Duration = Duration::from_millis(500);
/// Payload bytes per chunk.
pub const CHUNK_BYTES: usize = 1024;
/// Chunks in flight beyond the acknowledged point.
pub const WINDOW_CHUNKS: usize = 32;
/// The host sends the window again from the acknowledged point after this long without
/// progress; the returning player acknowledges this often while receiving.
pub const RESEND_AFTER: Duration = Duration::from_millis(200);
/// Either side gives up after this long without hearing the other.
pub const GIVE_UP_AFTER: Duration = Duration::from_secs(15);
/// The largest payload a returning player accepts (setup plus bundle).
pub const MAX_PAYLOAD: usize = crate::lockstep::MAX_LOG_BYTES + 4096;
/// "In game" goes to one source at most this often.
const IN_GAME_GAP: Duration = Duration::from_millis(250);
const MAX_SERVES: usize = 10;
const MAX_IN_GAME_TRACK: usize = 64;

/// Why the host refused a rejoin. [`fmt::Display`] is the sentence for the returning player.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejoinRefused {
    /// No seat of that name has left the game.
    NoSuchPlayer,
    IncorrectPassword,
    VersionMismatch,
    /// The host is not the one to speak for that player (5.3).
    NotSpeaker,
    /// The host keeps no record of the game to catch up from.
    NotRecording,
    /// A reason this build does not know.
    Other(u8),
}

impl RejoinRefused {
    fn code(self) -> u8 {
        match self {
            Self::NoSuchPlayer => 0,
            Self::IncorrectPassword => 1,
            Self::VersionMismatch => 2,
            Self::NotSpeaker => 3,
            Self::NotRecording => 4,
            Self::Other(c) => c,
        }
    }

    fn from_code(c: u8) -> Self {
        match c {
            0 => Self::NoSuchPlayer,
            1 => Self::IncorrectPassword,
            2 => Self::VersionMismatch,
            3 => Self::NotSpeaker,
            4 => Self::NotRecording,
            c => Self::Other(c),
        }
    }
}

impl fmt::Display for RejoinRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchPlayer => write!(
                f,
                "The game has already started, and no player of that name has left it"
            ),
            Self::IncorrectPassword => write!(f, "Incorrect password"),
            Self::VersionMismatch => write!(f, "This program's version differs from the host's"),
            Self::NotSpeaker => write!(f, "The host cannot let you back in"),
            Self::NotRecording => write!(f, "The host has no record of the game to catch up from"),
            Self::Other(c) => write!(f, "The host refused the rejoin (reason {c})"),
        }
    }
}

impl std::error::Error for RejoinRefused {}

/// What the host's rejoin service reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerEvent {
    /// A returning player asks for the seat of the player called `name`. Answer with
    /// [`RejoinServer::offer`], [`RejoinServer::wait`] or [`RejoinServer::refuse`].
    Asked {
        nonce: u32,
        name: String,
        from: Endpoint,
    },
    /// The whole payload reached the player in `seat`.
    Delivered { seat: PlayerId },
    /// A returning player went quiet; its request is forgotten.
    GaveUp { seat: Option<PlayerId> },
}

#[derive(Clone, Debug)]
struct Serve {
    nonce: u32,
    to: Endpoint,
    offer: Option<(u8, u32)>,
    payload: Option<Vec<u8>>,
    acked: usize,
    sent_to: usize,
    last_progress: Instant,
    last_heard: Instant,
}

/// The host's side: answers lobby traffic during the game and serves rejoins.
#[derive(Clone, Debug)]
pub struct RejoinServer {
    build: Vec<u8>,
    session: u64,
    challenge: [u8; 16],
    password: Option<String>,
    serves: Vec<Serve>,
    in_game_sent: Vec<(Endpoint, Instant)>,
}

impl RejoinServer {
    /// `entropy` seeds the password challenge; `password` is the room's.
    pub fn new(build: &[u8], session: u64, entropy: [u8; 32], password: Option<String>) -> Self {
        let mut h = Sha256::new();
        h.update(&entropy);
        h.update(b"btm-rejoin-challenge");
        h.update(&session.to_le_bytes());
        let d = h.finish();
        let mut challenge = [0u8; 16];
        challenge.copy_from_slice(&d[..16]);
        Self {
            build: build.to_vec(),
            session,
            challenge,
            password: password.filter(|p| !p.is_empty()),
            serves: Vec::new(),
            in_game_sent: Vec::new(),
        }
    }

    /// The seat whose rejoin is under way (offered), if any.
    pub fn serving(&self, seat: PlayerId) -> bool {
        self.serves
            .iter()
            .any(|s| s.offer.map(|o| o.0) == Some(seat.0))
    }

    /// A datagram from the discovery socket during the game.
    pub fn on_datagram(&mut self, now: Instant, from: Endpoint, bytes: &[u8]) -> Step<ServerEvent> {
        let mut step = Step::default();
        match codec::decode(bytes) {
            Ok(Msg::Probe | Msg::Claim(_)) => self.say_in_game(now, from, &mut step),
            Ok(Msg::Ask(a)) => self.on_ask(now, from, a, &mut step),
            Ok(Msg::Ack(a)) => self.on_ack(now, from, a, &mut step),
            _ => {}
        }
        step
    }

    fn say_in_game(&mut self, now: Instant, to: Endpoint, step: &mut Step<ServerEvent>) {
        if let Some((_, at)) = self.in_game_sent.iter_mut().find(|(e, _)| *e == to) {
            if since(now, *at) < IN_GAME_GAP {
                return;
            }
            *at = now;
        } else {
            if self.in_game_sent.len() >= MAX_IN_GAME_TRACK {
                self.in_game_sent.remove(0);
            }
            self.in_game_sent.push((to, now));
        }
        let m = InGame {
            session: self.session,
            challenge: self.challenge,
        };
        step.send.push(Outgoing {
            to,
            bytes: encode_in_game(&self.build, &m),
        });
    }

    fn answer(&self, to: Endpoint, nonce: u32, kind: AnswerKind, step: &mut Step<ServerEvent>) {
        let m = Answer {
            session: self.session,
            nonce,
            kind,
        };
        step.send.push(Outgoing {
            to,
            bytes: encode_answer(&self.build, &m),
        });
    }

    fn on_ask(&mut self, now: Instant, from: Endpoint, a: Ask, step: &mut Step<ServerEvent>) {
        if a.session != self.session {
            return;
        }
        if !build_compatible(&self.build, &a.build) {
            let code = RejoinRefused::VersionMismatch.code();
            return self.answer(from, a.nonce, AnswerKind::Refuse(code), step);
        }
        if let Some(pw) = &self.password {
            let ok = a.proof.is_some_and(|p| {
                ct_eq(
                    &p,
                    &password_proof(pw, self.session, &self.challenge, a.nonce),
                )
            });
            if !ok {
                let code = RejoinRefused::IncorrectPassword.code();
                return self.answer(from, a.nonce, AnswerKind::Refuse(code), step);
            }
        }
        if let Some(s) = self.serves.iter_mut().find(|s| s.nonce == a.nonce) {
            s.to = from;
            s.last_heard = now;
            // The answer was lost: offer again.
            if let Some((seat, at)) = s.offer {
                let (to, nonce) = (s.to, s.nonce);
                self.answer(to, nonce, AnswerKind::Offer { seat, at }, step);
            } else {
                step.events.push(ServerEvent::Asked {
                    nonce: a.nonce,
                    name: clean(&a.name, MAX_NAME),
                    from,
                });
            }
            return;
        }
        if self.serves.len() >= MAX_SERVES {
            return;
        }
        self.serves.push(Serve {
            nonce: a.nonce,
            to: from,
            offer: None,
            payload: None,
            acked: 0,
            sent_to: 0,
            last_progress: now,
            last_heard: now,
        });
        step.events.push(ServerEvent::Asked {
            nonce: a.nonce,
            name: clean(&a.name, MAX_NAME),
            from,
        });
    }

    /// The seat is not free yet; the returning player keeps asking.
    pub fn wait(&mut self, nonce: u32) -> Step<ServerEvent> {
        let mut step = Step::default();
        if let Some(s) = self.serves.iter().find(|s| s.nonce == nonce) {
            self.answer(s.to, nonce, AnswerKind::Wait, &mut step);
        }
        step
    }

    /// Refuse the request.
    pub fn refuse(&mut self, nonce: u32, why: RejoinRefused) -> Step<ServerEvent> {
        let mut step = Step::default();
        if let Some(i) = self.serves.iter().position(|s| s.nonce == nonce) {
            let s = self.serves.remove(i);
            self.answer(s.to, nonce, AnswerKind::Refuse(why.code()), &mut step);
        }
        step
    }

    /// Offer `seat`, rejoining at tick `at`. A previous request for the same seat (an
    /// earlier attempt by the same player) is forgotten.
    pub fn offer(&mut self, nonce: u32, seat: PlayerId, at: Tick) -> Step<ServerEvent> {
        let mut step = Step::default();
        let old_payload = self
            .serves
            .iter()
            .find(|s| s.nonce != nonce && s.offer.map(|o| o.0) == Some(seat.0))
            .and_then(|s| s.payload.clone());
        self.serves
            .retain(|s| s.nonce == nonce || s.offer.map(|o| o.0) != Some(seat.0));
        if let Some(s) = self.serves.iter_mut().find(|s| s.nonce == nonce) {
            s.offer = Some((seat.0, at.0));
            if s.payload.is_none() {
                s.payload = old_payload;
            }
            let to = s.to;
            self.answer(
                to,
                nonce,
                AnswerKind::Offer {
                    seat: seat.0,
                    at: at.0,
                },
                &mut step,
            );
        }
        step
    }

    /// The rejoin tick of the offer for `seat`, if one was made.
    pub fn offered_at(&self, seat: PlayerId) -> Option<Tick> {
        self.serves
            .iter()
            .find_map(|s| s.offer.filter(|o| o.0 == seat.0).map(|o| Tick(o.1)))
    }

    /// The catch-up for `seat` is ready: `start` is the host's own game setup, `bundle`
    /// the encoded `lockstep::Bundle`. Starts sending.
    pub fn provide(
        &mut self,
        now: Instant,
        seat: PlayerId,
        start: &GameStart,
        host_name: &str,
        label: &str,
        bundle: &[u8],
    ) -> Step<ServerEvent> {
        let mut step = Step::default();
        let setup = Announce {
            build: self.build.clone(),
            session: self.session,
            label: label.to_owned(),
            host_name: host_name.to_owned(),
            game_port: start.local_game_port,
            map: Some(start.map.clone()),
            challenge: None,
            epoch: 0,
            launching: true,
            seed: start.seed,
            approval: false,
            seats: start.seats.clone(),
            options: start.options.clone(),
            chat: Vec::new(),
            mods_hash: [0; 32],
            paths: start.paths.clone(),
        };
        let Some(setup) = encode_announce(&setup) else {
            return step;
        };
        let mut payload = Vec::with_capacity(4 + setup.len() + bundle.len());
        payload.extend_from_slice(&u32::try_from(setup.len()).unwrap_or(0).to_le_bytes());
        payload.extend_from_slice(&setup);
        payload.extend_from_slice(bundle);
        if payload.len() > MAX_PAYLOAD {
            return step;
        }
        if let Some(i) = self
            .serves
            .iter()
            .position(|s| s.offer.map(|o| o.0) == Some(seat.0))
        {
            if let Some(s) = self.serves.get_mut(i) {
                s.payload = Some(payload);
                s.acked = 0;
                s.sent_to = 0;
                s.last_progress = now;
            }
            self.send_window(i, &mut step);
        }
        step
    }

    fn on_ack(&mut self, now: Instant, from: Endpoint, a: Ack, step: &mut Step<ServerEvent>) {
        if a.session != self.session {
            return;
        }
        let Some(i) = self
            .serves
            .iter()
            .position(|s| s.nonce == a.nonce && s.to == from)
        else {
            return;
        };
        let Some(s) = self.serves.get_mut(i) else {
            return;
        };
        s.last_heard = now;
        let total = s.payload.as_ref().map_or(0, Vec::len);
        let have = usize::try_from(a.have).unwrap_or(usize::MAX);
        if s.payload.is_none() || have <= s.acked || have > total {
            return;
        }
        s.acked = have;
        s.last_progress = now;
        if have == total {
            let seat = s.offer.map(|o| PlayerId(o.0));
            self.serves.remove(i);
            if let Some(seat) = seat {
                step.events.push(ServerEvent::Delivered { seat });
            }
            return;
        }
        self.send_window(i, step);
    }

    /// Send the chunks from the high-water mark up to a window past the acknowledged point.
    fn send_window(&mut self, i: usize, step: &mut Step<ServerEvent>) {
        let (build, session) = (self.build.clone(), self.session);
        let Some(s) = self.serves.get_mut(i) else {
            return;
        };
        let Some(payload) = &s.payload else {
            return;
        };
        let total = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let end = (s.acked + WINDOW_CHUNKS * CHUNK_BYTES).min(payload.len());
        let mut at = s.sent_to.max(s.acked);
        while at < end {
            let stop = (at + CHUNK_BYTES).min(end);
            let data = payload
                .get(at..stop)
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            let m = Chunk {
                session,
                nonce: s.nonce,
                offset: u32::try_from(at).unwrap_or(u32::MAX),
                total,
                data,
            };
            step.send.push(Outgoing {
                to: s.to,
                bytes: encode_chunk(&build, &m),
            });
            at = stop;
        }
        s.sent_to = at;
    }

    /// Resend after a stall; forget players gone quiet.
    pub fn poll(&mut self, now: Instant) -> Step<ServerEvent> {
        let mut step = Step::default();
        let mut i = 0;
        while i < self.serves.len() {
            let Some(s) = self.serves.get_mut(i) else {
                break;
            };
            if since(now, s.last_heard) > GIVE_UP_AFTER {
                let seat = s.offer.map(|o| PlayerId(o.0));
                self.serves.remove(i);
                step.events.push(ServerEvent::GaveUp { seat });
                continue;
            }
            if s.payload.is_some() && since(now, s.last_progress) >= RESEND_AFTER {
                s.sent_to = s.acked;
                s.last_progress = now;
                self.send_window(i, &mut step);
            }
            i += 1;
        }
        step
    }
}

/// What the returning player's side reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    /// The host has not let the old connection go yet.
    Waiting,
    /// The seat is offered; the catch-up follows.
    Offered {
        seat: PlayerId,
        at: Tick,
    },
    /// Received `have` of `total` bytes of the catch-up.
    Progress {
        have: usize,
        total: usize,
    },
    Refused(RejoinRefused),
    /// The host stopped answering.
    HostSilent,
    /// The catch-up arrived but does not read as one.
    Corrupt,
    /// The catch-up is complete.
    Ready(Box<Rejoin>),
}

/// Everything a returning player needs to start: the game setup, the encoded
/// `lockstep::Bundle` and the rejoin tick R.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejoin {
    pub start: GameStart,
    pub bundle: Vec<u8>,
    pub at: Tick,
}

/// "In game" from a host: `(session, challenge)`, if `bytes` is one.
pub fn read_in_game(bytes: &[u8]) -> Option<(u64, [u8; 16])> {
    match codec::decode(bytes) {
        Ok(Msg::InGame(m)) => Some((m.session, m.challenge)),
        _ => None,
    }
}

/// The returning player's side.
#[derive(Clone, Debug)]
pub struct RejoinClient {
    cfg: GuestConfig,
    session: u64,
    challenge: [u8; 16],
    nonce: u32,
    offer: Option<(u8, u32)>,
    buf: Vec<u8>,
    total: Option<usize>,
    last_send: Option<Instant>,
    last_heard: Instant,
    reported: usize,
    done: bool,
}

impl RejoinClient {
    /// Start asking the host named by `cfg.host`, after it said "in game" with `session`
    /// and `challenge`. `nonce` is random.
    pub fn new(
        cfg: GuestConfig,
        session: u64,
        challenge: [u8; 16],
        nonce: u32,
        now: Instant,
    ) -> Self {
        Self {
            cfg,
            session,
            challenge,
            nonce,
            offer: None,
            buf: Vec::new(),
            total: None,
            last_send: None,
            last_heard: now,
            reported: 0,
            done: false,
        }
    }

    /// The host this client talks to.
    pub fn host(&self) -> Endpoint {
        self.cfg.host
    }

    fn send(&mut self, now: Instant, step: &mut Step<ClientEvent>) {
        self.last_send = Some(now);
        let bytes = if self.offer.is_none() {
            let proof = self
                .cfg
                .password
                .as_deref()
                .filter(|p| !p.is_empty())
                .map(|pw| password_proof(pw, self.session, &self.challenge, self.nonce));
            encode_ask(&Ask {
                build: self.cfg.build_id.clone(),
                session: self.session,
                nonce: self.nonce,
                name: self.cfg.name.clone(),
                proof,
            })
        } else {
            encode_ack(
                &self.cfg.build_id,
                &Ack {
                    session: self.session,
                    nonce: self.nonce,
                    have: u32::try_from(self.buf.len()).unwrap_or(u32::MAX),
                },
            )
        };
        step.send.push(Outgoing {
            to: self.cfg.host,
            bytes,
        });
    }

    /// Ask until answered, then acknowledge while receiving; give up on a silent host.
    pub fn poll(&mut self, now: Instant) -> Step<ClientEvent> {
        let mut step = Step::default();
        if self.done {
            return step;
        }
        if since(now, self.last_heard) > GIVE_UP_AFTER {
            self.done = true;
            step.events.push(ClientEvent::HostSilent);
            return step;
        }
        let gap = if self.offer.is_none() {
            ASK_INTERVAL
        } else {
            RESEND_AFTER
        };
        if self.last_send.is_none_or(|t| since(now, t) >= gap) {
            self.send(now, &mut step);
        }
        step
    }

    /// A datagram from the discovery socket.
    pub fn on_datagram(&mut self, now: Instant, from: Endpoint, bytes: &[u8]) -> Step<ClientEvent> {
        let mut step = Step::default();
        if self.done || from.ip() != self.cfg.host.ip() {
            return step;
        }
        match codec::decode(bytes) {
            Ok(Msg::Answer(a)) if a.session == self.session && a.nonce == self.nonce => {
                self.last_heard = now;
                match a.kind {
                    AnswerKind::Wait => step.events.push(ClientEvent::Waiting),
                    AnswerKind::Refuse(code) => {
                        self.done = true;
                        step.events
                            .push(ClientEvent::Refused(RejoinRefused::from_code(code)));
                    }
                    AnswerKind::Offer { seat, at } => {
                        if self.offer.is_none() {
                            self.offer = Some((seat, at));
                            step.events.push(ClientEvent::Offered {
                                seat: PlayerId(seat),
                                at: Tick(at),
                            });
                            self.send(now, &mut step);
                        }
                    }
                }
            }
            Ok(Msg::Chunk(c)) if c.session == self.session && c.nonce == self.nonce => {
                self.last_heard = now;
                self.on_chunk(now, from, c, &mut step);
            }
            _ => {}
        }
        step
    }

    fn on_chunk(&mut self, now: Instant, from: Endpoint, c: Chunk, step: &mut Step<ClientEvent>) {
        let Some((seat, at)) = self.offer else {
            return;
        };
        let total = usize::try_from(c.total).unwrap_or(usize::MAX);
        if total > MAX_PAYLOAD || self.total.is_some_and(|t| t != total) {
            return;
        }
        self.total = Some(total);
        let offset = usize::try_from(c.offset).unwrap_or(usize::MAX);
        // Only the next bytes in order are kept; anything else is resent by the host.
        if offset == self.buf.len() && offset + c.data.len() <= total && !c.data.is_empty() {
            self.buf.extend_from_slice(&c.data);
        }
        self.send(now, step);
        if self.buf.len() > self.reported + total / 10 || self.buf.len() == total {
            self.reported = self.buf.len();
            step.events.push(ClientEvent::Progress {
                have: self.buf.len(),
                total,
            });
        }
        if self.buf.len() < total {
            return;
        }
        self.done = true;
        match self.finish(from, PlayerId(seat), Tick(at)) {
            Some(r) => step.events.push(ClientEvent::Ready(Box::new(r))),
            None => step.events.push(ClientEvent::Corrupt),
        }
    }

    fn finish(&mut self, from: Endpoint, seat: PlayerId, at: Tick) -> Option<Rejoin> {
        let buf = std::mem::take(&mut self.buf);
        let len = usize::try_from(u32::from_le_bytes(buf.get(..4)?.try_into().ok()?)).ok()?;
        let setup = buf.get(4..4usize.checked_add(len)?)?;
        let Ok(Msg::Announce(a)) = codec::decode(setup) else {
            return None;
        };
        if a.session != self.session {
            return None;
        }
        let view = view_from_announce(from, &a, self.cfg.via_code);
        let start = GameStart::from_view(&view, seat.0, a.seed, self.cfg.game_port)?;
        let bundle = buf.get(4 + len..)?.to_vec();
        Some(Rejoin { start, bundle, at })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::session::{MapInfo, SeatInfo, SeatKind, SEATS};
    use std::net::{Ipv4Addr, SocketAddrV4};

    const BUILD: &[u8] = b"test-build";

    fn ep(last: u8, port: u16) -> Endpoint {
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, last), port)
    }

    fn at(ms: u64) -> Instant {
        Instant(Duration::from_millis(ms))
    }

    fn game() -> GameStart {
        let mut seats: Vec<SeatInfo> = (0..SEATS as u8).map(SeatInfo::open).collect();
        seats[0].kind = SeatKind::Host;
        seats[0].name = "Host".into();
        seats[1].kind = SeatKind::Network;
        seats[1].name = "Ann".into();
        seats[1].addr = Some(ep(2, 4000));
        GameStart {
            session: 77,
            my_seat: PlayerId(0),
            map: MapInfo {
                name: "mesa".into(),
                identity: String::new(),
            },
            options: Vec::new(),
            seed: 1234,
            seats,
            peers: vec![(PlayerId(1), ep(2, 4000))],
            local_game_port: 1337,
            paths: Default::default(),
        }
    }

    fn client(password: Option<&str>, challenge: [u8; 16]) -> RejoinClient {
        let mut cfg = GuestConfig::new("Ann", BUILD, ep(1, 1338), [3; 16]);
        cfg.password = password.map(str::to_owned);
        cfg.game_port = 5000;
        RejoinClient::new(cfg, 77, challenge, 42, at(0))
    }

    /// The server's "in game" answer to a probe, read back.
    fn in_game(server: &mut RejoinServer) -> (u64, [u8; 16]) {
        let probe = crate::session::probe_datagram(BUILD);
        let step = server.on_datagram(at(0), ep(2, 1338), &probe);
        assert_eq!(step.send.len(), 1);
        read_in_game(&step.send[0].bytes).unwrap()
    }

    #[test]
    fn a_returning_player_gets_its_seat_and_the_game_so_far_despite_loss() {
        let mut server = RejoinServer::new(BUILD, 77, [9; 32], Some("pw".into()));
        let (session, challenge) = in_game(&mut server);
        assert_eq!(session, 77);
        let mut c = client(Some("pw"), challenge);
        let (host, me) = (ep(1, 1338), ep(2, 1338));

        // Ask, wait, then the offer.
        let ask = c.poll(at(0)).send;
        let step = server.on_datagram(at(0), me, &ask[0].bytes);
        let nonce = match &step.events[..] {
            [ServerEvent::Asked { nonce, name, .. }] if name == "Ann" => *nonce,
            other => panic!("{other:?}"),
        };
        let w = server.wait(nonce).send;
        assert_eq!(
            c.on_datagram(at(1), host, &w[0].bytes).events,
            vec![ClientEvent::Waiting]
        );
        let o = server.offer(nonce, PlayerId(1), Tick(200)).send;
        let step = c.on_datagram(at(2), host, &o[0].bytes);
        assert!(step.events.contains(&ClientEvent::Offered {
            seat: PlayerId(1),
            at: Tick(200)
        }));
        assert!(server.serving(PlayerId(1)));

        // The catch-up, with every fifth datagram either way lost.
        let bundle: Vec<u8> = (0..50_000u32).map(|i| (i * 7) as u8).collect();
        let mut to_client = server
            .provide(at(3), PlayerId(1), &game(), "Host", "label", &bundle)
            .send;
        let mut to_server: Vec<Outgoing> = Vec::new();
        let (mut ready, mut delivered, mut n) = (None, false, 0u32);
        for t in 4..20_000u64 {
            for o in std::mem::take(&mut to_client) {
                n += 1;
                if n % 5 == 0 {
                    continue;
                }
                let step = c.on_datagram(at(t), host, &o.bytes);
                to_server.extend(step.send);
                for e in step.events {
                    if let ClientEvent::Ready(r) = e {
                        ready = Some(r);
                    }
                }
            }
            for o in std::mem::take(&mut to_server) {
                n += 1;
                if n % 5 == 0 {
                    continue;
                }
                let step = server.on_datagram(at(t), me, &o.bytes);
                delivered |= step
                    .events
                    .contains(&ServerEvent::Delivered { seat: PlayerId(1) });
                to_client.extend(step.send);
            }
            to_client.extend(server.poll(at(t)).send);
            to_server.extend(c.poll(at(t)).send);
            if ready.is_some() && delivered {
                break;
            }
        }
        let r = ready.expect("the catch-up never completed");
        assert!(delivered);
        assert_eq!(r.at, Tick(200));
        assert_eq!(r.bundle, bundle);
        assert_eq!(r.start.my_seat, PlayerId(1));
        assert_eq!(r.start.seed, 1234);
        assert_eq!(r.start.local_game_port, 5000);
        // The host is where its lobby datagrams came from, at its game port.
        assert_eq!(r.start.endpoint_of(PlayerId(0)), Some(ep(1, 1337)));
        assert_eq!(r.start.simulation_seed(), game().simulation_seed());
    }

    #[test]
    fn a_wrong_password_and_an_unknown_name_are_refused() {
        let mut server = RejoinServer::new(BUILD, 77, [9; 32], Some("pw".into()));
        let (_, challenge) = in_game(&mut server);
        let mut c = client(Some("nope"), challenge);
        let ask = c.poll(at(0)).send;
        let step = server.on_datagram(at(0), ep(2, 1338), &ask[0].bytes);
        assert!(step.events.is_empty());
        let step = c.on_datagram(at(1), ep(1, 1338), &step.send[0].bytes);
        assert_eq!(
            step.events,
            vec![ClientEvent::Refused(RejoinRefused::IncorrectPassword)]
        );

        let mut c = client(Some("pw"), challenge);
        let ask = c.poll(at(0)).send;
        let step = server.on_datagram(at(0), ep(2, 1338), &ask[0].bytes);
        let Some(ServerEvent::Asked { nonce, .. }) = step.events.first().cloned() else {
            panic!("{:?}", step.events)
        };
        let r = server.refuse(nonce, RejoinRefused::NoSuchPlayer).send;
        let step = c.on_datagram(at(1), ep(1, 1338), &r[0].bytes);
        assert_eq!(
            step.events,
            vec![ClientEvent::Refused(RejoinRefused::NoSuchPlayer)]
        );
    }

    #[test]
    fn a_silent_host_is_given_up_on() {
        let mut c = client(None, [0; 16]);
        assert_eq!(c.poll(at(0)).send.len(), 1);
        assert!(c.poll(at(100)).send.is_empty());
        assert_eq!(c.poll(at(600)).send.len(), 1);
        let t = GIVE_UP_AFTER.as_millis() as u64 + 1;
        assert_eq!(c.poll(at(t)).events, vec![ClientEvent::HostSilent]);
    }
}
