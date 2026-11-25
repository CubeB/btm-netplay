//! STUN Binding client (RFC 5389 / 8489, Binding only) and the per-socket probe of
//! SPEC 2.3 and 2.4.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use super::{after, elapsed, is_sendable};
use crate::types::{Endpoint, Instant, Outgoing};

/// A 96-bit STUN transaction id.
pub type TransactionId = [u8; 12];

/// The RFC 5389 magic cookie.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Length of the STUN message header.
pub const HEADER_LEN: usize = 20;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;

/// Re-send to servers that have not answered this often.
pub const RETRY_INTERVAL: Duration = Duration::from_millis(250);
/// A probe settles this long after the first answer even if some servers are silent.
pub const SETTLE_AFTER_FIRST: Duration = Duration::from_millis(1000);
/// A probe that has not heard from anyone by now has failed (settled if anything answered).
pub const TIMEOUT: Duration = Duration::from_millis(4000);
/// After settling, refresh every answering server this often (keepalive and drift check).
pub const REFRESH_INTERVAL: Duration = Duration::from_millis(4000);
/// A refresh round retries unanswered servers for this long.
const REFRESH_RETRY_WINDOW: Duration = Duration::from_millis(1000);
/// Transaction ids remembered per server (old answers still count).
const TXIDS_PER_SERVER: usize = 4;

/// The default servers (SPEC 2.3), as host name and port, for the caller to resolve.
pub const DEFAULT_SERVERS: [(&str, u16); 4] = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.sipgate.net", 3478),
];

/// Why a datagram is not a usable Binding success response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StunError {
    /// Shorter than the 20-byte header.
    Truncated,
    /// The top two bits of the first byte are not zero.
    NotStun,
    /// The magic cookie is wrong (an RFC 3489 server, or not STUN).
    BadCookie,
    /// The length field does not equal the rest of the datagram.
    LengthMismatch,
    /// Not a Binding success response (carries the message type).
    WrongMessageType(u16),
    /// An attribute runs past the end of the message.
    MalformedAttribute,
    /// No (usable) address attribute.
    NoMappedAddress,
    /// The reported address cannot be sent to (port 0, unspecified, multicast, broadcast).
    Unsendable(Endpoint),
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*s.first()?, *s.get(1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([
        *s.first()?,
        *s.get(1)?,
        *s.get(2)?,
        *s.get(3)?,
    ]))
}

/// A bare 20-byte Binding request.
pub fn build_binding_request(id: &TransactionId) -> [u8; HEADER_LEN] {
    let mut m = [0u8; HEADER_LEN];
    m[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message length 0.
    m[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    m[8..20].copy_from_slice(id);
    m
}

/// The cheap shape test (SPEC 2.3): top two bits zero, magic cookie, and a length field
/// equal to the rest of the datagram. Decides whether a datagram on a shared socket is
/// offered to the STUN parser at all.
pub fn looks_like_stun(bytes: &[u8]) -> bool {
    if bytes.len() < HEADER_LEN {
        return false;
    }
    let first_ok = bytes.first().is_some_and(|b| b & 0xC0 == 0);
    let cookie_ok = be32(bytes, 4) == Some(MAGIC_COOKIE);
    let len_ok = be16(bytes, 2).is_some_and(|l| usize::from(l) == bytes.len() - HEADER_LEN);
    first_ok && cookie_ok && len_ok
}

/// A parsed Binding success response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingResponse {
    pub transaction_id: TransactionId,
    /// The reflexive (outside) endpoint the server saw.
    pub mapped: Endpoint,
    /// Whether it came from XOR-MAPPED-ADDRESS (otherwise the MAPPED-ADDRESS fallback).
    pub xor: bool,
}

/// Parse an IPv4 (XOR-)MAPPED-ADDRESS value. `Ok(None)` for another family.
fn parse_address(value: &[u8], xor: bool) -> Result<Option<Endpoint>, StunError> {
    let family = *value.get(1).ok_or(StunError::MalformedAttribute)?;
    if family != FAMILY_IPV4 {
        return Ok(None);
    }
    if value.len() != 8 {
        return Err(StunError::MalformedAttribute);
    }
    let mut port = be16(value, 2).ok_or(StunError::MalformedAttribute)?;
    let mut addr = be32(value, 4).ok_or(StunError::MalformedAttribute)?;
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
        addr ^= MAGIC_COOKIE;
    }
    Ok(Some(SocketAddrV4::new(Ipv4Addr::from(addr), port)))
}

/// Parse a Binding success response from arbitrary bytes. Every read is bounds-checked.
/// MESSAGE-INTEGRITY and FINGERPRINT are not verified (the caller matches transaction id
/// and source, which is all SPEC 2.3 asks for).
pub fn parse_binding_response(bytes: &[u8]) -> Result<BindingResponse, StunError> {
    if bytes.len() < HEADER_LEN {
        return Err(StunError::Truncated);
    }
    if bytes.first().is_none_or(|b| b & 0xC0 != 0) {
        return Err(StunError::NotStun);
    }
    if be32(bytes, 4) != Some(MAGIC_COOKIE) {
        return Err(StunError::BadCookie);
    }
    let length = be16(bytes, 2).ok_or(StunError::Truncated)?;
    if usize::from(length) != bytes.len() - HEADER_LEN {
        return Err(StunError::LengthMismatch);
    }
    let ty = be16(bytes, 0).ok_or(StunError::Truncated)?;
    if ty != BINDING_SUCCESS {
        return Err(StunError::WrongMessageType(ty));
    }
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(bytes.get(8..20).ok_or(StunError::Truncated)?);

    let mut xor_addr: Option<Result<Option<Endpoint>, StunError>> = None;
    let mut plain_addr: Option<Result<Option<Endpoint>, StunError>> = None;
    let mut rest = bytes.get(HEADER_LEN..).ok_or(StunError::Truncated)?;
    while !rest.is_empty() {
        let attr_type = be16(rest, 0).ok_or(StunError::MalformedAttribute)?;
        let attr_len = usize::from(be16(rest, 2).ok_or(StunError::MalformedAttribute)?);
        let value = rest
            .get(4..4 + attr_len)
            .ok_or(StunError::MalformedAttribute)?;
        let padded = (attr_len + 3) & !3;
        // A final attribute whose padding was left off is tolerated.
        rest = rest.get(4 + padded..).unwrap_or(&[]);
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS if xor_addr.is_none() => {
                xor_addr = Some(parse_address(value, true));
            }
            ATTR_MAPPED_ADDRESS if plain_addr.is_none() => {
                plain_addr = Some(parse_address(value, false));
            }
            _ => {}
        }
    }

    // Prefer XOR-MAPPED-ADDRESS, fall back to MAPPED-ADDRESS; first usable one wins.
    let mut first_error = StunError::NoMappedAddress;
    for (candidate, xor) in [(xor_addr, true), (plain_addr, false)] {
        match candidate {
            Some(Ok(Some(mapped))) if is_sendable(mapped) => {
                return Ok(BindingResponse {
                    transaction_id,
                    mapped,
                    xor,
                });
            }
            Some(Ok(Some(mapped))) => {
                if first_error == StunError::NoMappedAddress {
                    first_error = StunError::Unsendable(mapped);
                }
            }
            Some(Err(e)) => {
                if first_error == StunError::NoMappedAddress {
                    first_error = e;
                }
            }
            Some(Ok(None)) | None => {}
        }
    }
    Err(first_error)
}

/// Mapping behaviour of one socket, from comparing what several servers saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mapping {
    /// Fewer than two servers answered: unknown, treated as fine.
    Unknown,
    /// Two or more servers answered and all agree: good.
    EndpointIndependent,
    /// Two answers differ: "symmetric", direct play cannot work.
    EndpointDependent,
}

/// What a probe knows right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    /// The endpoint reported by the most servers (ties to the earliest server).
    pub endpoint: Endpoint,
    pub mapping: Mapping,
    /// How many servers are voting.
    pub voters: usize,
}

/// Where a probe is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeState {
    Working,
    Settled,
    Failed,
}

/// Something the caller should react to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeEvent {
    /// The first result is in.
    Settled(ProbeResult),
    /// Nobody answered within the timeout.
    Failed,
    /// After settling, a refresh found the outside endpoint moved.
    Changed(ProbeResult),
}

/// The outcome of offering a datagram to a probe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Handled {
    /// It was a valid response to one of this probe's requests.
    pub accepted: bool,
    pub event: Option<ProbeEvent>,
}

#[derive(Clone, Debug)]
struct Server {
    addr: Endpoint,
    txids: Vec<TransactionId>,
    answer: Option<Endpoint>,
    /// The answer is from the latest round (false while a refresh is awaited).
    current: bool,
    /// A request is outstanding and worth re-sending.
    waiting: bool,
    last_sent: Option<Instant>,
}

/// A STUN probe for one socket: queries every server, settles, then keeps refreshing.
///
/// Use one per socket and send its datagrams *from that socket*. Drive it with
/// [`StunProbe::poll`] whenever time passes (or at [`StunProbe::next_deadline`]) and
/// [`StunProbe::handle`] for every datagram that passes [`looks_like_stun`].
#[derive(Clone, Debug)]
pub struct StunProbe {
    servers: Vec<Server>,
    started: Instant,
    state: ProbeState,
    first_answer: Option<Instant>,
    retry_until: Instant,
    next_refresh: Instant,
    reported: Option<Endpoint>,
}

impl StunProbe {
    /// Start a probe at `now`. The first [`StunProbe::poll`] sends to every server.
    /// Duplicate servers are dropped; with no servers the probe is failed from the start.
    pub fn new(servers: &[Endpoint], now: Instant, rng: &mut dyn FnMut() -> TransactionId) -> Self {
        let mut list: Vec<Server> = Vec::new();
        for &addr in servers {
            if list.iter().any(|s| s.addr == addr) {
                continue;
            }
            list.push(Server {
                addr,
                txids: vec![rng()],
                answer: None,
                current: false,
                waiting: true,
                last_sent: None,
            });
        }
        let state = if list.is_empty() {
            ProbeState::Failed
        } else {
            ProbeState::Working
        };
        Self {
            servers: list,
            started: now,
            state,
            first_answer: None,
            retry_until: after(now, TIMEOUT),
            next_refresh: after(now, TIMEOUT),
            reported: None,
        }
    }

    pub fn state(&self) -> ProbeState {
        self.state
    }

    /// The current vote: current answers only if any exist, otherwise stale ones. `None`
    /// until some server has answered.
    pub fn result(&self) -> Option<ProbeResult> {
        let any_current = self.servers.iter().any(|s| s.current && s.answer.is_some());
        let voters: Vec<Endpoint> = self
            .servers
            .iter()
            .filter(|s| s.current || !any_current)
            .filter_map(|s| s.answer)
            .collect();
        let mut best: Option<(usize, Endpoint)> = None;
        for &e in &voters {
            let count = voters.iter().filter(|&&x| x == e).count();
            match best {
                Some((c, _)) if c >= count => {}
                _ => best = Some((count, e)),
            }
        }
        let (_, endpoint) = best?;
        let mapping = if voters.len() < 2 {
            Mapping::Unknown
        } else if voters.iter().all(|&x| x == endpoint) {
            Mapping::EndpointIndependent
        } else {
            Mapping::EndpointDependent
        };
        Some(ProbeResult {
            endpoint,
            mapping,
            voters: voters.len(),
        })
    }

    /// The earliest time at which [`StunProbe::poll`] has something to do, if any.
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.state == ProbeState::Failed {
            return None;
        }
        let mut best: Option<Instant> = None;
        let mut consider = |t: Instant| {
            best = Some(match best {
                Some(b) if b <= t => b,
                _ => t,
            });
        };
        for s in self.servers.iter().filter(|s| s.waiting) {
            let t = match s.last_sent {
                Some(sent) => after(sent, RETRY_INTERVAL),
                None => Instant::default(),
            };
            if t < self.retry_until {
                consider(t);
            }
        }
        match self.state {
            ProbeState::Working => {
                consider(after(self.started, TIMEOUT));
                if let Some(first) = self.first_answer {
                    consider(after(first, SETTLE_AFTER_FIRST));
                }
            }
            ProbeState::Settled => consider(self.next_refresh),
            ProbeState::Failed => {}
        }
        best
    }

    /// Advance time: send initial requests, retries and refreshes into `out`, and report
    /// settling, failing or timing out.
    pub fn poll(
        &mut self,
        now: Instant,
        rng: &mut dyn FnMut() -> TransactionId,
        out: &mut Vec<Outgoing>,
    ) -> Option<ProbeEvent> {
        let mut event = None;
        if self.state == ProbeState::Working {
            event = self.check_working(now);
        }
        if self.state == ProbeState::Settled && now >= self.next_refresh {
            self.start_refresh(now, rng);
        }
        if self.state != ProbeState::Failed && now < self.retry_until {
            for s in self.servers.iter_mut().filter(|s| s.waiting) {
                let due = match s.last_sent {
                    None => true,
                    Some(t) => elapsed(now, t) >= RETRY_INTERVAL,
                };
                if due {
                    if let Some(id) = s.txids.last() {
                        out.push(Outgoing {
                            to: s.addr,
                            bytes: build_binding_request(id).to_vec(),
                        });
                        s.last_sent = Some(now);
                    }
                }
            }
        }
        event
    }

    /// Offer a received datagram. Accepted only if it is a Binding success response whose
    /// transaction id one of our requests used and which came from the server that
    /// request went to.
    pub fn handle(&mut self, now: Instant, from: Endpoint, bytes: &[u8]) -> Handled {
        if self.state == ProbeState::Failed || !looks_like_stun(bytes) {
            return Handled::default();
        }
        let Ok(resp) = parse_binding_response(bytes) else {
            return Handled::default();
        };
        let Some(server) = self
            .servers
            .iter_mut()
            .find(|s| s.addr == from && s.txids.contains(&resp.transaction_id))
        else {
            return Handled::default();
        };
        server.answer = Some(resp.mapped);
        server.current = true;
        server.waiting = false;
        self.first_answer.get_or_insert(now);
        let event = match self.state {
            ProbeState::Working => self.check_working(now),
            ProbeState::Settled => self.detect_change(),
            ProbeState::Failed => None,
        };
        Handled {
            accepted: true,
            event,
        }
    }

    fn check_working(&mut self, now: Instant) -> Option<ProbeEvent> {
        let all_answered = self.servers.iter().all(|s| s.answer.is_some());
        let settle_due = self
            .first_answer
            .is_some_and(|t| now >= after(t, SETTLE_AFTER_FIRST));
        if all_answered || settle_due {
            return Some(self.settle(now));
        }
        if now >= after(self.started, TIMEOUT) {
            return Some(if self.first_answer.is_some() {
                self.settle(now)
            } else {
                self.fail()
            });
        }
        None
    }

    fn settle(&mut self, now: Instant) -> ProbeEvent {
        let Some(result) = self.result() else {
            return self.fail();
        };
        self.state = ProbeState::Settled;
        for s in self.servers.iter_mut().filter(|s| s.answer.is_none()) {
            s.waiting = false;
        }
        self.next_refresh = after(now, REFRESH_INTERVAL);
        self.reported = Some(result.endpoint);
        ProbeEvent::Settled(result)
    }

    fn fail(&mut self) -> ProbeEvent {
        self.state = ProbeState::Failed;
        for s in &mut self.servers {
            s.waiting = false;
        }
        ProbeEvent::Failed
    }

    fn start_refresh(&mut self, now: Instant, rng: &mut dyn FnMut() -> TransactionId) {
        for s in self.servers.iter_mut().filter(|s| s.answer.is_some()) {
            if s.txids.len() >= TXIDS_PER_SERVER {
                s.txids.remove(0);
            }
            s.txids.push(rng());
            s.current = false;
            s.waiting = true;
            s.last_sent = None;
        }
        self.retry_until = after(now, REFRESH_RETRY_WINDOW);
        self.next_refresh = after(now, REFRESH_INTERVAL);
    }

    fn detect_change(&mut self) -> Option<ProbeEvent> {
        let result = self.result()?;
        if self.reported == Some(result.endpoint) {
            return None;
        }
        self.reported = Some(result.endpoint);
        Some(ProbeEvent::Changed(result))
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

    struct Rng(u8);
    impl Rng {
        fn next(&mut self) -> TransactionId {
            self.0 = self.0.wrapping_add(1);
            let mut id = [0u8; 12];
            id[0] = self.0;
            id[11] = 0xEE;
            id
        }
    }

    /// Hand-build a success response with the given attributes (type, value).
    fn response(id: &TransactionId, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut m = Vec::new();
        m.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(id);
        m.extend_from_slice(&body);
        m
    }

    fn xor_attr(e: Endpoint) -> (u16, Vec<u8>) {
        let mut v = vec![0, FAMILY_IPV4];
        v.extend_from_slice(&(e.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        v.extend_from_slice(&(u32::from(*e.ip()) ^ MAGIC_COOKIE).to_be_bytes());
        (ATTR_XOR_MAPPED_ADDRESS, v)
    }

    fn plain_attr(e: Endpoint) -> (u16, Vec<u8>) {
        let mut v = vec![0, FAMILY_IPV4];
        v.extend_from_slice(&e.port().to_be_bytes());
        v.extend_from_slice(&u32::from(*e.ip()).to_be_bytes());
        (ATTR_MAPPED_ADDRESS, v)
    }

    fn answer(id: &TransactionId, e: Endpoint) -> Vec<u8> {
        response(id, &[xor_attr(e)])
    }

    #[test]
    fn request_layout() {
        let id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let r = build_binding_request(&id);
        assert_eq!(r.len(), 20);
        assert_eq!(&r[..2], &[0x00, 0x01]);
        assert_eq!(&r[2..4], &[0, 0]);
        assert_eq!(&r[4..8], &[0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(&r[8..], &id);
        assert!(looks_like_stun(&r));
    }

    /// RFC 5769 section 2.2 (IPv4 response). The header, transaction id, SOFTWARE and
    /// XOR-MAPPED-ADDRESS bytes are the RFC's; MESSAGE-INTEGRITY and FINGERPRINT values are
    /// not reproduced from memory (filler of the right size), and the parser ignores both.
    #[test]
    fn rfc5769_ipv4_response() {
        let mut m: Vec<u8> = vec![
            0x01, 0x01, 0x00, 0x3c, // Binding success, length 60
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, // txid
            0x80, 0x22, 0x00, 0x0b, // SOFTWARE, 11 bytes
            0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72,
            0x20, // "test vector " (padded)
            0x00, 0x20, 0x00, 0x08, // XOR-MAPPED-ADDRESS
            0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, 0x00, 0x08, 0x00,
            0x14, // MESSAGE-INTEGRITY header
        ];
        m.extend_from_slice(&[0xAB; 20]);
        m.extend_from_slice(&[0x80, 0x28, 0x00, 0x04]); // FINGERPRINT header
        m.extend_from_slice(&[0xCD; 4]);
        assert_eq!(m.len(), 20 + 60);
        assert!(looks_like_stun(&m));
        let r = parse_binding_response(&m).unwrap();
        assert_eq!(r.mapped, ep(192, 0, 2, 1, 32853));
        assert!(r.xor);
        assert_eq!(
            r.transaction_id,
            [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae]
        );
    }

    #[test]
    fn xor_preferred_over_plain() {
        let id = [7u8; 12];
        let m = response(
            &id,
            &[
                plain_attr(ep(9, 9, 9, 9, 9)),
                xor_attr(ep(1, 2, 3, 4, 5678)),
            ],
        );
        let r = parse_binding_response(&m).unwrap();
        assert_eq!(r.mapped, ep(1, 2, 3, 4, 5678));
        assert!(r.xor);
    }

    #[test]
    fn mapped_address_fallback() {
        let id = [7u8; 12];
        let m = response(&id, &[plain_attr(ep(1, 2, 3, 4, 5678))]);
        let r = parse_binding_response(&m).unwrap();
        assert_eq!(r.mapped, ep(1, 2, 3, 4, 5678));
        assert!(!r.xor);
    }

    #[test]
    fn rejections() {
        let id = [7u8; 12];
        let good = answer(&id, ep(1, 2, 3, 4, 5678));
        assert!(parse_binding_response(&good).is_ok());

        assert_eq!(
            parse_binding_response(&good[..19]),
            Err(StunError::Truncated)
        );
        assert_eq!(parse_binding_response(&[]), Err(StunError::Truncated));

        let mut bad = good.clone();
        bad[4] ^= 1;
        assert_eq!(parse_binding_response(&bad), Err(StunError::BadCookie));

        let mut bad = good.clone();
        bad[0] |= 0x80;
        assert_eq!(parse_binding_response(&bad), Err(StunError::NotStun));

        // Length field disagrees with the datagram.
        assert_eq!(
            parse_binding_response(&good[..good.len() - 1]),
            Err(StunError::LengthMismatch)
        );
        let mut long = good.clone();
        long.push(0);
        assert_eq!(
            parse_binding_response(&long),
            Err(StunError::LengthMismatch)
        );

        // Error response (0x0111).
        let mut bad = good.clone();
        bad[0] = 0x01;
        bad[1] = 0x11;
        assert_eq!(
            parse_binding_response(&bad),
            Err(StunError::WrongMessageType(0x0111))
        );

        // Request, not response.
        assert_eq!(
            parse_binding_response(&build_binding_request(&id)),
            Err(StunError::WrongMessageType(0x0001))
        );

        // No address attribute.
        let none = response(&id, &[(0x8022, b"srv".to_vec())]);
        assert_eq!(
            parse_binding_response(&none),
            Err(StunError::NoMappedAddress)
        );

        // Attribute length runs past the end.
        let mut m = response(&id, &[xor_attr(ep(1, 2, 3, 4, 5))]);
        m[22] = 0x00;
        m[23] = 0x40;
        assert_eq!(
            parse_binding_response(&m),
            Err(StunError::MalformedAttribute)
        );

        // Unsendable reported address.
        let m = response(&id, &[xor_attr(ep(1, 2, 3, 4, 0))]);
        assert_eq!(
            parse_binding_response(&m),
            Err(StunError::Unsendable(ep(1, 2, 3, 4, 0)))
        );
        let m = response(&id, &[xor_attr(ep(0, 0, 0, 0, 55))]);
        assert!(matches!(
            parse_binding_response(&m),
            Err(StunError::Unsendable(_))
        ));

        // IPv6 only: nothing usable.
        let mut v6 = vec![0, 2, 0, 0];
        v6.extend_from_slice(&[0; 16]);
        let m = response(&id, &[(ATTR_XOR_MAPPED_ADDRESS, v6)]);
        assert_eq!(parse_binding_response(&m), Err(StunError::NoMappedAddress));

        // Truncated address attribute.
        let m = response(&id, &[(ATTR_XOR_MAPPED_ADDRESS, vec![0, 1, 0, 0])]);
        assert_eq!(
            parse_binding_response(&m),
            Err(StunError::MalformedAttribute)
        );
    }

    #[test]
    fn shape_test() {
        let id = [3u8; 12];
        assert!(looks_like_stun(&answer(&id, ep(1, 2, 3, 4, 5))));
        assert!(!looks_like_stun(b"hello world, not stun at all"));
        assert!(!looks_like_stun(&[]));
        let mut m = answer(&id, ep(1, 2, 3, 4, 5));
        m.push(0);
        assert!(!looks_like_stun(&m));
    }

    #[test]
    fn fuzz_never_panics() {
        let mut x: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20000 {
            let len = (next() % 100) as usize;
            let b: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse_binding_response(&b);
            let _ = looks_like_stun(&b);
        }
        // Random bodies behind a valid header.
        for _ in 0..20000 {
            let blen = (next() % 40) as usize;
            let body: Vec<u8> = (0..blen).map(|_| next() as u8).collect();
            let mut m = Vec::new();
            m.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
            m.extend_from_slice(&(blen as u16).to_be_bytes());
            m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            m.extend_from_slice(&[0; 12]);
            m.extend_from_slice(&body);
            let _ = parse_binding_response(&m);
        }
        // Every truncation of a good message.
        let good = answer(&[1; 12], ep(5, 6, 7, 8, 9));
        for n in 0..good.len() {
            assert!(parse_binding_response(&good[..n]).is_err());
        }
    }

    fn servers() -> [Endpoint; 3] {
        [
            ep(74, 125, 1, 1, 19302),
            ep(74, 125, 1, 2, 19302),
            ep(162, 159, 1, 1, 3478),
        ]
    }

    fn id_sent_to(out: &[Outgoing], to: Endpoint) -> TransactionId {
        let o = out.iter().find(|o| o.to == to).unwrap();
        let mut id = [0u8; 12];
        id.copy_from_slice(&o.bytes[8..20]);
        id
    }

    #[test]
    fn probe_settles_when_all_answer() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let s = servers();
        let mut p = StunProbe::new(&s, ms(0), &mut next);
        let mut out = Vec::new();
        assert_eq!(p.poll(ms(0), &mut next, &mut out), None);
        assert_eq!(out.len(), 3);
        let me = ep(203, 0, 113, 5, 40000);
        let mut event = None;
        for &srv in &s {
            let id = id_sent_to(&out, srv);
            let h = p.handle(ms(60), srv, &answer(&id, me));
            assert!(h.accepted);
            event = h.event.or(event);
        }
        match event {
            Some(ProbeEvent::Settled(r)) => {
                assert_eq!(r.endpoint, me);
                assert_eq!(r.mapping, Mapping::EndpointIndependent);
                assert_eq!(r.voters, 3);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(p.state(), ProbeState::Settled);
    }

    #[test]
    fn probe_retries_every_250ms_then_settles_1s_after_first_answer() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let s = servers();
        let mut p = StunProbe::new(&s, ms(1000), &mut next);
        let mut out = Vec::new();
        p.poll(ms(1000), &mut next, &mut out);
        assert_eq!(out.len(), 3);
        let first_ids: Vec<Vec<u8>> = out.iter().map(|o| o.bytes.clone()).collect();
        // Too early for a retry.
        out.clear();
        p.poll(ms(1200), &mut next, &mut out);
        assert!(out.is_empty());
        // 250 ms: all three again, same transaction ids.
        p.poll(ms(1250), &mut next, &mut out);
        assert_eq!(out.len(), 3);
        assert_eq!(
            out.iter().map(|o| o.bytes.clone()).collect::<Vec<_>>(),
            first_ids
        );
        // One server answers at 1300; the others stay silent.
        let me = ep(203, 0, 113, 5, 40000);
        let id = id_sent_to(&out, s[0]);
        let h = p.handle(ms(1300), s[0], &answer(&id, me));
        assert!(h.accepted);
        assert_eq!(h.event, None);
        // The answered server is no longer re-sent to.
        out.clear();
        p.poll(ms(1500), &mut next, &mut out);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|o| o.to != s[0]));
        // Not settled at 2299, settled at 2300.
        assert_eq!(p.poll(ms(2299), &mut next, &mut out), None);
        match p.poll(ms(2300), &mut next, &mut out) {
            Some(ProbeEvent::Settled(r)) => {
                assert_eq!(r.endpoint, me);
                assert_eq!(r.mapping, Mapping::Unknown);
                assert_eq!(r.voters, 1);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn probe_times_out_failed_without_answers() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let mut p = StunProbe::new(&servers(), ms(0), &mut next);
        let mut out = Vec::new();
        assert_eq!(p.poll(ms(0), &mut next, &mut out), None);
        assert_eq!(p.poll(ms(3999), &mut next, &mut out), None);
        assert_eq!(
            p.poll(ms(4000), &mut next, &mut out),
            Some(ProbeEvent::Failed)
        );
        assert_eq!(p.state(), ProbeState::Failed);
        out.clear();
        assert_eq!(p.poll(ms(5000), &mut next, &mut out), None);
        assert!(out.is_empty());
        assert_eq!(p.next_deadline(), None);
    }

    #[test]
    fn probe_with_no_servers_is_failed() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let p = StunProbe::new(&[], ms(0), &mut next);
        assert_eq!(p.state(), ProbeState::Failed);
    }

    #[test]
    fn probe_rejects_wrong_source_and_unknown_txid() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let s = servers();
        let mut p = StunProbe::new(&s, ms(0), &mut next);
        let mut out = Vec::new();
        p.poll(ms(0), &mut next, &mut out);
        let me = ep(203, 0, 113, 5, 40000);
        let id0 = id_sent_to(&out, s[0]);
        // Right id, wrong source (a different server's address).
        assert!(!p.handle(ms(10), s[1], &answer(&id0, me)).accepted);
        // Right id, stranger.
        assert!(
            !p.handle(ms(10), ep(6, 6, 6, 6, 6), &answer(&id0, me))
                .accepted
        );
        // Unknown id.
        assert!(!p.handle(ms(10), s[0], &answer(&[9; 12], me)).accepted);
        // Garbage.
        assert!(!p.handle(ms(10), s[0], b"nope").accepted);
        assert!(p.handle(ms(10), s[0], &answer(&id0, me)).accepted);
    }

    #[test]
    fn tie_goes_to_earliest_server_and_majority_wins() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let s = servers();
        let mut p = StunProbe::new(&s, ms(0), &mut next);
        let mut out = Vec::new();
        p.poll(ms(0), &mut next, &mut out);
        let a = ep(1, 1, 1, 1, 1111);
        let b = ep(2, 2, 2, 2, 2222);
        // Server 0 says b, server 1 says a: tie, earliest server (0) wins.
        p.handle(ms(10), s[1], &answer(&id_sent_to(&out, s[1]), a));
        p.handle(ms(10), s[0], &answer(&id_sent_to(&out, s[0]), b));
        assert_eq!(p.result().unwrap().endpoint, b);
        assert_eq!(p.result().unwrap().mapping, Mapping::EndpointDependent);
        // Server 2 sides with a: a has two votes.
        p.handle(ms(10), s[2], &answer(&id_sent_to(&out, s[2]), a));
        assert_eq!(p.result().unwrap().endpoint, a);
    }

    #[test]
    fn classification_cases() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let s = servers();
        let me = ep(203, 0, 113, 5, 40000);
        let run = |answers: &[Option<Endpoint>]| -> Option<ProbeResult> {
            let mut rng = Rng(0);
            let mut next = || rng.next();
            let mut p = StunProbe::new(&s, ms(0), &mut next);
            let mut out = Vec::new();
            p.poll(ms(0), &mut next, &mut out);
            for (i, a) in answers.iter().enumerate() {
                if let Some(e) = a {
                    p.handle(ms(5), s[i], &answer(&id_sent_to(&out, s[i]), *e));
                }
            }
            p.result()
        };
        let _ = &mut next;
        // All equal.
        assert_eq!(
            run(&[Some(me), Some(me), Some(me)]).unwrap().mapping,
            Mapping::EndpointIndependent
        );
        // Two answers, equal.
        assert_eq!(
            run(&[Some(me), None, Some(me)]).unwrap().mapping,
            Mapping::EndpointIndependent
        );
        // One answer: unknown.
        assert_eq!(
            run(&[Some(me), None, None]).unwrap().mapping,
            Mapping::Unknown
        );
        // No answer.
        assert_eq!(run(&[None, None, None]), None);
        // Port differs.
        assert_eq!(
            run(&[Some(me), Some(ep(203, 0, 113, 5, 40001)), None])
                .unwrap()
                .mapping,
            Mapping::EndpointDependent
        );
        // Address differs.
        assert_eq!(
            run(&[Some(me), Some(me), Some(ep(203, 0, 113, 6, 40000))])
                .unwrap()
                .mapping,
            Mapping::EndpointDependent
        );
    }

    #[test]
    fn keepalive_refresh_and_drift() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let s = servers();
        let mut p = StunProbe::new(&s, ms(0), &mut next);
        let mut out = Vec::new();
        p.poll(ms(0), &mut next, &mut out);
        let me = ep(203, 0, 113, 5, 40000);
        for &srv in &s[..2] {
            p.handle(ms(50), srv, &answer(&id_sent_to(&out, srv), me));
        }
        // Third server never answers. Settles 1000 ms after the first answer (t=1050).
        out.clear();
        assert!(matches!(
            p.poll(ms(1050), &mut next, &mut out),
            Some(ProbeEvent::Settled(_))
        ));
        // Silent server is given up on: no more retries to it.
        out.clear();
        p.poll(ms(2000), &mut next, &mut out);
        assert!(out.is_empty());
        // Refresh at settle + 4000 = 5050, to answering servers only, new ids.
        p.poll(ms(5049), &mut next, &mut out);
        assert!(out.is_empty());
        assert_eq!(p.next_deadline(), Some(ms(5050)));
        p.poll(ms(5050), &mut next, &mut out);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|o| o.to != s[2]));
        let new0 = id_sent_to(&out, s[0]);
        let new1 = id_sent_to(&out, s[1]);
        // Server 0 answers with a moved endpoint; server 1 is still awaited and is left
        // out of the vote because server 0's answer is current.
        let moved = ep(203, 0, 113, 5, 40111);
        let h = p.handle(ms(5100), s[0], &answer(&new0, moved));
        match h.event {
            Some(ProbeEvent::Changed(r)) => assert_eq!(r.endpoint, moved),
            other => panic!("unexpected {other:?}"),
        }
        // Same answer from server 1: no further change.
        let h = p.handle(ms(5120), s[1], &answer(&new1, moved));
        assert!(h.accepted);
        assert_eq!(h.event, None);
        assert_eq!(p.result().unwrap().mapping, Mapping::EndpointIndependent);
        // Unanswered refreshes are retried for 1 s only.
        out.clear();
        p.poll(ms(5200), &mut next, &mut out);
        assert!(out.is_empty());
        // Next refresh at 5050 + 4000.
        p.poll(ms(9050), &mut next, &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn refresh_unanswered_retries_within_window() {
        let mut rng = Rng(0);
        let mut next = || rng.next();
        let s = [ep(74, 125, 1, 1, 19302)];
        let mut p = StunProbe::new(&s, ms(0), &mut next);
        let mut out = Vec::new();
        p.poll(ms(0), &mut next, &mut out);
        let me = ep(203, 0, 113, 5, 40000);
        let h = p.handle(ms(10), s[0], &answer(&id_sent_to(&out, s[0]), me));
        assert!(matches!(h.event, Some(ProbeEvent::Settled(_))));
        out.clear();
        p.poll(ms(4010), &mut next, &mut out);
        assert_eq!(out.len(), 1);
        out.clear();
        p.poll(ms(4100), &mut next, &mut out);
        assert!(out.is_empty());
        p.poll(ms(4260), &mut next, &mut out);
        assert_eq!(out.len(), 1);
        // The stale answer still votes while nobody is current.
        assert_eq!(p.result().unwrap().endpoint, me);
        // A late answer to the first refresh's id is also welcome.
        let id = out[0].bytes[8..20].to_vec();
        let mut idarr = [0u8; 12];
        idarr.copy_from_slice(&id);
        assert!(p.handle(ms(4300), s[0], &answer(&idarr, me)).accepted);
    }
}
