//! Relay fallback: a dumb UDP datagram forwarder for when NAT punching cannot work
//! (symmetric NAT, some carrier NAT and same-router cases; SPEC 2.7 and section 10 item 1).
//! The protocol is specified in `RELAY.md`.
//!
//! The relay carries the **lobby and the game** datagrams unchanged, so `session` and
//! `lockstep` neither know nor care. Everything here is sans-IO.
//!
//! # Parts
//!
//! * [`RelayServer`]: the server state machine (rooms, cookies, budgets, expiry), driven by
//!   the `btm-relay` binary.
//! * [`RelayLink`]: one machine's membership of one room. It wraps outgoing datagrams for
//!   synthetic peer endpoints into relay frames and unwraps relayed ones.
//! * [`code`]: relay invite codes (invite code version 2).
//! * [`FallbackPolicy`]: when to switch to the relay.
//!
//! # Synthetic endpoints, and how the caller maps them
//!
//! Inside a relayed room every member has a small index (the host is 0). Member `k` is
//! addressed as the **synthetic endpoint** `0.0.0.(k+1):port` ([`peer_endpoint`]). The
//! 0.0.0.0/8 range is never a real peer, so synthetic and real endpoints cannot collide,
//! and both `session` and the 2.8 address rules treat it like any other address (all
//! synthetic endpoints share one /16, and none is unspecified).
//!
//! The caller runs one extra UDP socket for the relay (any local port) and:
//!
//! 1. Gives the lobby the host's synthetic discovery endpoint as the place to find the host
//!    (`GuestConfig::host = peer_endpoint(0, DISCOVERY_PORT)`), and no outside game
//!    address (`game_addr: None`): the host then records each guest's game address as
//!    `0.0.0.(k+1):<its game port>`, and every peer's `GameStart::peers` holds synthetic
//!    endpoints that mean the same member on every machine.
//! 2. Passes every datagram the lobby (or the game) wants to send through
//!    [`RelayLink::wrap_all`] with the local port it would have been sent from (the
//!    discovery port for the lobby, the game port for the game). Synthetic destinations
//!    are wrapped and sent to [`RelayLink::relay`] from the relay socket; the rest (LAN
//!    broadcast, loopback) is sent directly as before, or dropped.
//! 3. Feeds every datagram received on the relay socket to [`RelayLink::handle`]. A
//!    [`Received::Datagram`] carries the sender's synthetic endpoint and the port it was
//!    addressed to: hand it to the game when `to_port` is the local game port, else to the
//!    lobby, exactly as if it had arrived on that socket from `from`.
//! 4. Calls [`RelayLink::poll`] at its deadline (hello retries, keepalive pings, RTT).
//!
//! The game layer must keep relayed datagrams within [`RelayLink::max_payload`]
//! (1400 bytes); a larger one is refused by `wrap` rather than fragmented.

mod client;
pub mod code;
mod proto;
mod server;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

pub use client::{
    Delivered, LinkError, LinkState, Received, RelayEvent, RelayLink, WrapError, CONNECT_TIMEOUT,
    HELLO_RETRY, LOST_AFTER, PING_INTERVAL,
};
pub use code::{AnyInvite, RelayCodeError, RelayInvite, RelayRef};
pub use proto::{
    decode_client, decode_server, is_relay_frame, ClientFrame, Cookie, FrameError, RefuseReason,
    RoomId, ServerFrame, C2S_DATA_OVERHEAD, HELLO_LEN, MAGIC, MAX_MEMBERS, MAX_PAYLOAD,
    S2C_DATA_OVERHEAD, VERSION,
};
pub use server::{ConfigError, LeaveReason, RelayConfig, RelayServer, ServerEvent, ServerStats};

use crate::nat::traversal::{Status, TraversalFailure};
use crate::session::hmac_sha256;
use crate::types::{Endpoint, Instant};

/// Default UDP port of a relay.
pub const DEFAULT_RELAY_PORT: u16 = 3479;

/// The synthetic endpoint of relay member `member` (0..=9) at `port`: `0.0.0.(member+1)`.
pub fn peer_endpoint(member: u8, port: u16) -> Endpoint {
    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, member.saturating_add(1)), port)
}

/// The relay member a synthetic endpoint names, or `None` for a real address.
pub fn member_of(ep: Endpoint) -> Option<u8> {
    match ep.ip().octets() {
        [0, 0, 0, d] if (1..=MAX_MEMBERS).contains(&d) => Some(d - 1),
        _ => None,
    }
}

/// Whether `ep` is a synthetic relay endpoint.
pub fn is_synthetic(ep: Endpoint) -> bool {
    member_of(ep).is_some()
}

/// Comparison that does not stop at the first differing byte.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A deterministic generator keyed by a secret: HMAC-SHA-256(key, counter). Unpredictable
/// to anyone without the key.
#[derive(Clone)]
pub(crate) struct Prf {
    key: [u8; 32],
    counter: u64,
}

impl std::fmt::Debug for Prf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prf").finish_non_exhaustive()
    }
}

impl Prf {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self { key, counter: 0 }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.counter = self.counter.wrapping_add(1);
        let d = hmac_sha256(&self.key, &self.counter.to_be_bytes());
        let mut b = [0u8; 8];
        b.copy_from_slice(&d[..8]);
        u64::from_be_bytes(b)
    }
}

/// How long direct contact may take, once expected, before the relay is used.
pub const DIRECT_GRACE: Duration = Duration::from_secs(10);

/// Why the relay should be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FallbackReason {
    /// Traversal failed (symmetric NAT, no STUN reply, no STUN server).
    Traversal(TraversalFailure),
    /// A peer was expected but nothing arrived from it directly within [`DIRECT_GRACE`].
    NoDirectContact,
}

/// When to fall back to the relay (decided once).
///
/// * Traversal `Failed` for any reason except a busy game port (which a relay does not
///   fix) means relay now.
/// * Otherwise, once the caller says a peer should be reachable ([`expect_contact`]: the
///   host when a reply code is pasted or a guest's claim is heard only via a third party;
///   a guest when it starts probing the host's code), relay if no datagram arrives directly
///   from that peer ([`note_direct_contact`]) within [`DIRECT_GRACE`].
///
/// The host acts on the decision by opening a [`RelayLink::host`] and showing the relay
/// code made from its room; a guest can only show "ask the host for a relay code".
///
/// [`expect_contact`]: FallbackPolicy::expect_contact
/// [`note_direct_contact`]: FallbackPolicy::note_direct_contact
#[derive(Clone, Debug, Default)]
pub struct FallbackPolicy {
    expecting_since: Option<Instant>,
    contact: bool,
    decided: Option<FallbackReason>,
    reported: bool,
}

impl FallbackPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the traversal status whenever it changes.
    pub fn note_traversal(&mut self, status: &Status) {
        if self.decided.is_some() {
            return;
        }
        if let Status::Failed(f) = status {
            if !matches!(f, TraversalFailure::PortInUse(_)) {
                self.decided = Some(FallbackReason::Traversal(f.clone()));
            }
        }
    }

    /// A peer should now be reachable directly; start the [`DIRECT_GRACE`] clock (the
    /// first call counts).
    pub fn expect_contact(&mut self, now: Instant) {
        if self.expecting_since.is_none() {
            self.expecting_since = Some(now);
        }
    }

    /// A datagram arrived directly from the expected peer: the relay is not needed.
    pub fn note_direct_contact(&mut self) {
        self.contact = true;
    }

    /// The decision, returned once when it is made.
    pub fn poll(&mut self, now: Instant) -> Option<FallbackReason> {
        if self.decided.is_none() && !self.contact {
            if let Some(t) = self.expecting_since {
                if now.0.saturating_sub(t.0) >= DIRECT_GRACE {
                    self.decided = Some(FallbackReason::NoDirectContact);
                }
            }
        }
        if self.reported {
            return None;
        }
        let d = self.decided.clone()?;
        self.reported = true;
        Some(d)
    }

    /// The decision, if one was made.
    pub fn decision(&self) -> Option<&FallbackReason> {
        self.decided.as_ref()
    }
}

#[cfg(test)]
mod tests;
