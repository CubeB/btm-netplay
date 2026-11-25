//! The client side: [`RelayLink`], sans-IO.
//!
//! A link allocates a room (host) or joins one (guest), then wraps the caller's ordinary
//! [`Outgoing`] datagrams addressed to *synthetic peer endpoints* (see
//! [`super::peer_endpoint`]) into relay frames, and unwraps relayed frames back into
//! (synthetic source endpoint, destination port, payload). It keeps the relay mapping alive
//! with pings and measures the round trip to the relay.

use std::fmt;
use std::time::Duration;

use super::proto::{
    decode_server, is_relay_frame, ClientFrame, Cookie, FrameError, RefuseReason, RoomId,
    ServerFrame, COOKIE_LEN, MAX_PAYLOAD,
};
use super::{member_of, peer_endpoint};
use crate::types::{Endpoint, Instant, Outgoing};

/// Hello resend interval while connecting.
pub const HELLO_RETRY: Duration = Duration::from_millis(500);
/// Give up connecting after this long.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Ping interval once admitted (also keeps the NAT mapping to the relay open).
pub const PING_INTERVAL: Duration = Duration::from_secs(4);
/// The relay is considered lost after this long without a pong or a delivery.
pub const LOST_AFTER: Duration = Duration::from_secs(15);

/// Why the link is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// The relay refused the hello or ended the membership.
    Refused(RefuseReason),
    /// No answer while connecting.
    Timeout,
    /// No answer for [`LOST_AFTER`] once admitted.
    Lost,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "{r}"),
            Self::Timeout => write!(f, "The relay did not answer."),
            Self::Lost => write!(f, "The connection to the relay was lost."),
        }
    }
}

impl std::error::Error for LinkError {}

/// Why a datagram could not be wrapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapError {
    /// The link is not admitted yet (or failed).
    NotJoined,
    /// The destination is not a synthetic peer endpoint: send it directly (or drop it).
    NotRelayed,
    /// The destination is this member itself.
    ToSelf,
    /// The payload is larger than the relay accepts.
    TooLarge { len: usize, max: usize },
}

impl fmt::Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJoined => write!(f, "not connected to the relay yet"),
            Self::NotRelayed => write!(f, "not a relayed peer address"),
            Self::ToSelf => write!(f, "addressed to this machine"),
            Self::TooLarge { len, max } => {
                write!(
                    f,
                    "datagram of {len} bytes exceeds the relay limit of {max}"
                )
            }
        }
    }
}

impl std::error::Error for WrapError {}

/// Link state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Connecting,
    Joined { room: RoomId, me: u8 },
    Failed(LinkError),
}

/// Something for the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayEvent {
    /// Admitted. A host now builds its relay invite code from `room`.
    Joined { room: RoomId, me: u8 },
    /// The members present changed (bit k = member k), as last reported by the relay.
    Members(u16),
    /// A non-fatal refusal (rate limit, oversized, unknown member).
    Warning(RefuseReason),
    /// The link is over.
    Failed(LinkError),
}

/// A relayed datagram, unwrapped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    /// The sender's synthetic endpoint: member index in the address, its sending port as
    /// the port. Reply to exactly this endpoint.
    pub from: Endpoint,
    /// The port the sender addressed: route to the local handler for that port.
    pub to_port: u16,
    pub payload: Vec<u8>,
}

/// What [`RelayLink::handle`] made of a datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Received {
    /// Not from the relay, or not a relay frame: hand it to the other handlers.
    NotRelay,
    /// A relayed datagram for the local handler of `to_port`.
    Datagram(Delivered),
    Event(RelayEvent),
    /// Consumed (a pong, a duplicate, a forged or malformed frame).
    Nothing,
}

#[derive(Clone, Copy, Debug)]
struct Admitted {
    room: RoomId,
    secret: u64,
    me: u8,
    members: u16,
    max_payload: usize,
}

/// One machine's membership of one relay room.
#[derive(Clone, Debug)]
pub struct RelayLink {
    relay: Endpoint,
    join: Option<RoomId>,
    nonce: [u8; 8],
    cookie: Cookie,
    started: Instant,
    next_hello: Instant,
    admitted: Option<Admitted>,
    failed: Option<LinkError>,
    next_ping: Instant,
    ping_id: u32,
    ping_sent: Option<(u32, Instant)>,
    rebind: Cookie,
    last_heard: Instant,
    srtt_us: Option<u64>,
    latest_rtt: Option<Duration>,
}

impl RelayLink {
    /// A host's link: allocates a new room. `nonce` must be random.
    pub fn host(relay: Endpoint, nonce: [u8; 8], now: Instant) -> Self {
        Self::new(relay, None, nonce, now)
    }

    /// A guest's link: joins `room` (from the relay invite code). `nonce` must be random.
    pub fn guest(relay: Endpoint, room: RoomId, nonce: [u8; 8], now: Instant) -> Self {
        Self::new(relay, Some(room), nonce, now)
    }

    fn new(relay: Endpoint, join: Option<RoomId>, nonce: [u8; 8], now: Instant) -> Self {
        Self {
            relay,
            join,
            nonce,
            cookie: [0; COOKIE_LEN],
            started: now,
            next_hello: now,
            admitted: None,
            failed: None,
            next_ping: now,
            ping_id: 0,
            ping_sent: None,
            rebind: [0; COOKIE_LEN],
            last_heard: now,
            srtt_us: None,
            latest_rtt: None,
        }
    }

    /// The relay's endpoint (send everything this link produces there).
    pub fn relay(&self) -> Endpoint {
        self.relay
    }

    pub fn state(&self) -> LinkState {
        match (self.failed, self.admitted) {
            (Some(e), _) => LinkState::Failed(e),
            (None, Some(a)) => LinkState::Joined {
                room: a.room,
                me: a.me,
            },
            (None, None) => LinkState::Connecting,
        }
    }

    /// The room id, once admitted.
    pub fn room(&self) -> Option<RoomId> {
        self.admitted.map(|a| a.room)
    }

    /// This machine's member index, once admitted.
    pub fn me(&self) -> Option<u8> {
        self.admitted.map(|a| a.me)
    }

    /// This machine's own synthetic endpoint for `port` (what peers see it as).
    pub fn my_endpoint(&self, port: u16) -> Option<Endpoint> {
        self.me().map(|m| peer_endpoint(m, port))
    }

    /// Members present, as last reported (bit k = member k).
    pub fn members(&self) -> u16 {
        self.admitted.map(|a| a.members).unwrap_or(0)
    }

    /// Smoothed round trip to the relay (EMA, alpha 1/8), once measured.
    pub fn rtt(&self) -> Option<Duration> {
        self.srtt_us.map(Duration::from_micros)
    }

    /// The last round-trip sample.
    pub fn latest_rtt(&self) -> Option<Duration> {
        self.latest_rtt
    }

    /// Largest payload [`RelayLink::wrap`] accepts.
    pub fn max_payload(&self) -> usize {
        self.admitted.map(|a| a.max_payload).unwrap_or(MAX_PAYLOAD)
    }

    /// When [`RelayLink::poll`] next has something to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.failed.is_some() {
            return None;
        }
        let lost = Instant(self.last_heard.0.saturating_add(LOST_AFTER));
        Some(match self.admitted {
            None => self
                .next_hello
                .min(Instant(self.started.0.saturating_add(CONNECT_TIMEOUT))),
            Some(_) => self.next_ping.min(lost),
        })
    }

    /// Send hellos, pings, and detect timeouts.
    pub fn poll(&mut self, now: Instant, out: &mut Vec<Outgoing>) -> Vec<RelayEvent> {
        let mut events = Vec::new();
        if self.failed.is_some() {
            return events;
        }
        match self.admitted {
            None => {
                if now.0.saturating_sub(self.started.0) >= CONNECT_TIMEOUT {
                    self.fail(LinkError::Timeout, &mut events);
                    return events;
                }
                if now >= self.next_hello {
                    self.next_hello = Instant(now.0.saturating_add(HELLO_RETRY));
                    self.send_hello(out);
                }
            }
            Some(a) => {
                if now.0.saturating_sub(self.last_heard.0) >= LOST_AFTER {
                    self.fail(LinkError::Lost, &mut events);
                    return events;
                }
                if now >= self.next_ping {
                    self.next_ping = Instant(now.0.saturating_add(PING_INTERVAL));
                    self.send_ping(a, now, out);
                }
            }
        }
        events
    }

    fn fail(&mut self, e: LinkError, events: &mut Vec<RelayEvent>) {
        self.failed = Some(e);
        events.push(RelayEvent::Failed(e));
    }

    fn send_hello(&self, out: &mut Vec<Outgoing>) {
        let frame = match self.join {
            None => ClientFrame::Allocate {
                nonce: self.nonce,
                cookie: self.cookie,
            },
            Some(room) => ClientFrame::Join {
                nonce: self.nonce,
                cookie: self.cookie,
                room,
            },
        };
        if let Ok(bytes) = frame.encode() {
            out.push(Outgoing {
                to: self.relay,
                bytes,
            });
        }
    }

    fn send_ping(&mut self, a: Admitted, now: Instant, out: &mut Vec<Outgoing>) {
        self.ping_id = self.ping_id.wrapping_add(1);
        self.ping_sent = Some((self.ping_id, now));
        let frame = ClientFrame::Ping {
            room: a.room,
            secret: a.secret,
            id: self.ping_id,
            cookie: std::mem::replace(&mut self.rebind, [0; COOKIE_LEN]),
        };
        if let Ok(bytes) = frame.encode() {
            out.push(Outgoing {
                to: self.relay,
                bytes,
            });
        }
    }

    /// A leave frame, ending the membership at once (also ends this link).
    pub fn leave(&mut self) -> Option<Outgoing> {
        let a = self.admitted.take()?;
        self.failed = Some(LinkError::Refused(RefuseReason::NotMember));
        let bytes = ClientFrame::Leave {
            room: a.room,
            secret: a.secret,
        }
        .encode()
        .ok()?;
        Some(Outgoing {
            to: self.relay,
            bytes,
        })
    }

    /// Wrap one datagram the caller's lobby or game wants to send from local port
    /// `src_port`. `out.to` must be a synthetic peer endpoint.
    pub fn wrap(&self, src_port: u16, out: &Outgoing) -> Result<Outgoing, WrapError> {
        let to = member_of(out.to).ok_or(WrapError::NotRelayed)?;
        let a = match (self.failed, self.admitted) {
            (None, Some(a)) => a,
            _ => return Err(WrapError::NotJoined),
        };
        if to == a.me {
            return Err(WrapError::ToSelf);
        }
        if out.bytes.len() > a.max_payload {
            return Err(WrapError::TooLarge {
                len: out.bytes.len(),
                max: a.max_payload,
            });
        }
        let bytes = ClientFrame::Data {
            room: a.room,
            secret: a.secret,
            to,
            src_port,
            dst_port: out.to.port(),
            payload: &out.bytes,
        }
        .encode()
        .map_err(|e| match e {
            FrameError::TooLarge => WrapError::TooLarge {
                len: out.bytes.len(),
                max: MAX_PAYLOAD,
            },
            _ => WrapError::NotRelayed,
        })?;
        Ok(Outgoing {
            to: self.relay,
            bytes,
        })
    }

    /// Wrap every datagram addressed to a synthetic endpoint into `relayed`; return the
    /// others (real addresses: LAN broadcast, loopback, direct peers) for the caller to send
    /// directly or drop. Datagrams that cannot be relayed (too large, not joined, to self)
    /// are counted in the second value and dropped.
    pub fn wrap_all(
        &self,
        src_port: u16,
        sends: Vec<Outgoing>,
        relayed: &mut Vec<Outgoing>,
    ) -> (Vec<Outgoing>, usize) {
        let mut direct = Vec::new();
        let mut dropped = 0;
        for o in sends {
            match self.wrap(src_port, &o) {
                Ok(w) => relayed.push(w),
                Err(WrapError::NotRelayed) => direct.push(o),
                Err(_) => dropped += 1,
            }
        }
        (direct, dropped)
    }

    /// Handle a datagram received from `from` on the relay socket.
    pub fn handle(&mut self, now: Instant, from: Endpoint, bytes: &[u8]) -> Received {
        if from != self.relay || !is_relay_frame(bytes) {
            return Received::NotRelay;
        }
        if self.failed.is_some() {
            return Received::Nothing;
        }
        let Ok(frame) = decode_server(bytes) else {
            return Received::Nothing;
        };
        match frame {
            ServerFrame::Challenge { nonce, cookie } => {
                if self.admitted.is_none() && nonce == self.nonce {
                    self.cookie = cookie;
                    // Answer at once rather than at the next retry.
                    self.next_hello = now;
                }
                Received::Nothing
            }
            ServerFrame::Welcome {
                nonce,
                room,
                secret,
                member,
                members,
                max_payload,
            } => {
                let room_ok = self.join.is_none_or(|r| r == room);
                // A repeated welcome (our hello crossed the first one) brings nothing new.
                if nonce != self.nonce || !room_ok || self.admitted.is_some() {
                    return Received::Nothing;
                }
                self.admitted = Some(Admitted {
                    room,
                    secret,
                    me: member,
                    members,
                    max_payload: usize::from(max_payload).min(MAX_PAYLOAD),
                });
                self.last_heard = now;
                self.next_ping = Instant(now.0.saturating_add(PING_INTERVAL));
                Received::Event(RelayEvent::Joined { room, me: member })
            }
            ServerFrame::Deliver {
                secret,
                from,
                src_port,
                dst_port,
                payload,
            } => {
                let Some(a) = self.admitted else {
                    return Received::Nothing;
                };
                if secret != a.secret || from == a.me {
                    return Received::Nothing;
                }
                self.last_heard = now;
                Received::Datagram(Delivered {
                    from: peer_endpoint(from, src_port),
                    to_port: dst_port,
                    payload: payload.to_vec(),
                })
            }
            ServerFrame::Pong {
                secret,
                id,
                members,
                cookie,
            } => {
                let Some(a) = self.admitted else {
                    return Received::Nothing;
                };
                if secret != a.secret {
                    return Received::Nothing;
                }
                if cookie.iter().any(|&b| b != 0) {
                    // The relay saw us from a new address: confirm it with the next ping,
                    // sent now.
                    self.rebind = cookie;
                    self.next_ping = now;
                    return Received::Nothing;
                }
                self.last_heard = now;
                if let Some((sent_id, at)) = self.ping_sent {
                    if sent_id == id {
                        self.ping_sent = None;
                        let sample = now.0.saturating_sub(at.0);
                        self.latest_rtt = Some(sample);
                        let s = u64::try_from(sample.as_micros()).unwrap_or(u64::MAX);
                        self.srtt_us = Some(match self.srtt_us {
                            None => s,
                            Some(old) => (old.saturating_mul(7).saturating_add(s)) / 8,
                        });
                    }
                }
                if members != a.members {
                    if let Some(adm) = self.admitted.as_mut() {
                        adm.members = members;
                    }
                    return Received::Event(RelayEvent::Members(members));
                }
                Received::Nothing
            }
            ServerFrame::Refuse { echo, reason } => {
                let expected = match self.admitted {
                    Some(a) => a.secret.to_be_bytes(),
                    None => self.nonce,
                };
                if echo != expected {
                    return Received::Nothing;
                }
                if reason.is_fatal() {
                    self.failed = Some(LinkError::Refused(reason));
                    Received::Event(RelayEvent::Failed(LinkError::Refused(reason)))
                } else {
                    Received::Event(RelayEvent::Warning(reason))
                }
            }
        }
    }
}
