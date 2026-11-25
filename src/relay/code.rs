//! Relay invite codes: invite code version 2 (SPEC 2.2 extended).
//!
//! Version 1 (see [`crate::invite`]) names the host's outside discovery endpoint. Version 2
//! names a relay and a room instead. It uses the same Crockford base32 text form, the same
//! product prefix, the same forgiving reading and the same CRC-8 (polynomial 0x07) over
//! everything before the check byte. The low nibble of the first byte is the *form*:
//!
//! | Form | Payload | Bytes | Characters |
//! |---|---|---|---|
//! | 0, relay by index | `0x20, index, room(8), crc8` | 11 | 18 (`BTM-XXXX-XXXX-XXXXX-XXXXX`) |
//! | 1, relay by endpoint | `0x21, ip(4), port(2), room(8), crc8` | 16 | 26 (`BTM-XXXX-XXXX-XXXX-XXXX-XXXXX-XXXXX`) |
//!
//! The bits are written five at a time from the most significant end; the two bits left
//! over in the last character are zero padding and must be zero when read. CRC-8 detects
//! every error burst of up to 8 bits, so every single-character slip (at most 5 adjacent
//! bits) is caught, as for version 1.
//!
//! The code lengths (13, 18 and 26 without prefix) differ, so one input box can take any
//! code: use [`decode_any`].

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use super::proto::RoomId;
use crate::invite::{self, check_endpoint, crc8, InviteError, CODE_CHARS, MAX_INPUT_CHARS, PREFIX};
use crate::types::Endpoint;

/// Version nibble of a relay invite code.
pub const RELAY_CODE_VERSION: u8 = 2;
/// Characters of a form-0 (relay by index) code, without prefix.
pub const INDEX_CODE_CHARS: usize = 18;
/// Characters of a form-1 (relay by endpoint) code, without prefix.
pub const ENDPOINT_CODE_CHARS: usize = 26;

const FORM_INDEX: u8 = 0;
const FORM_ENDPOINT: u8 = 1;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Known relays by index, for form-0 codes. Empty: whether a hosted relay exists is an
/// open decision (see `RELAY.md`). A launcher may ship its own table; both ends must use
/// the same one.
pub const KNOWN_RELAYS: &[(&str, u16)] = &[];

/// Which relay a code names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RelayRef {
    /// An index into a relay table both ends share (such as [`KNOWN_RELAYS`]).
    Index(u8),
    /// The relay's IPv4 endpoint (a self-hosted relay).
    Endpoint(Endpoint),
}

/// The content of a relay invite code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RelayInvite {
    pub relay: RelayRef,
    pub room: RoomId,
}

/// Any invite code the room box may receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnyInvite {
    /// A version-1 code: the host's (or guest's) discovery endpoint.
    Direct(Endpoint),
    /// A version-2 code: a relay and a room.
    Relay(RelayInvite),
}

/// Why a relay code was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayCodeError {
    /// A refusal shared with version 1 (too long, bad character, padding, version,
    /// checksum, endpoint rules), or any refusal of a version-1 code read by
    /// [`decode_any`].
    Code(InviteError),
    /// The length is none of 13, 18 or 26 (with or without the prefix).
    WrongLength { found: usize },
    /// The form nibble is unknown or does not match the length.
    BadForm(u8),
    /// Room id 0.
    ZeroRoom,
}

impl fmt::Display for RelayCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(e) => write!(f, "{e}"),
            Self::WrongLength { found } => {
                write!(f, "a code has 13, 18 or 26 characters, not {found}")
            }
            Self::BadForm(_) => write!(f, "the code is malformed"),
            Self::ZeroRoom => write!(f, "the code names no relayed game"),
        }
    }
}

impl std::error::Error for RelayCodeError {}

impl From<InviteError> for RelayCodeError {
    fn from(e: InviteError) -> Self {
        Self::Code(e)
    }
}

/// The payload bytes of a relay code, check byte included (no validation).
pub fn payload(inv: &RelayInvite) -> Vec<u8> {
    let mut p = Vec::with_capacity(16);
    match inv.relay {
        RelayRef::Index(i) => {
            p.push((RELAY_CODE_VERSION << 4) | FORM_INDEX);
            p.push(i);
        }
        RelayRef::Endpoint(ep) => {
            p.push((RELAY_CODE_VERSION << 4) | FORM_ENDPOINT);
            p.extend_from_slice(&ep.ip().octets());
            p.extend_from_slice(&ep.port().to_be_bytes());
        }
    }
    p.extend_from_slice(&inv.room.to_be_bytes());
    p.push(crc8(&p));
    p
}

fn check(inv: &RelayInvite) -> Result<(), RelayCodeError> {
    if inv.room == 0 {
        return Err(RelayCodeError::ZeroRoom);
    }
    if let RelayRef::Endpoint(ep) = inv.relay {
        check_endpoint(ep)?;
    }
    Ok(())
}

/// Base32 of `bytes`, zero-padded to whole characters.
fn to_base32(bytes: &[u8]) -> String {
    let bits = bytes.len() * 8;
    let chars = bits.div_ceil(5);
    let bit = |i: usize| -> u8 {
        bytes
            .get(i / 8)
            .map(|b| (b >> (7 - (i % 8))) & 1)
            .unwrap_or(0)
    };
    (0..chars)
        .map(|c| {
            let idx = (0..5).fold(0usize, |acc, k| (acc << 1) | usize::from(bit(c * 5 + k)));
            char::from(ALPHABET.get(idx).copied().unwrap_or(b'0'))
        })
        .collect()
}

/// The bare code, no prefix and no separators.
pub fn encode_bare(inv: &RelayInvite) -> Result<String, RelayCodeError> {
    check(inv)?;
    Ok(to_base32(&payload(inv)))
}

/// The display form, `BTM-` then groups of 4, ending in groups of 5.
pub fn encode(inv: &RelayInvite) -> Result<String, RelayCodeError> {
    let bare = encode_bare(inv)?;
    let groups: &[usize] = if bare.len() == INDEX_CODE_CHARS {
        &[4, 4, 5, 5]
    } else {
        &[4, 4, 4, 4, 5, 5]
    };
    let mut s = String::from(PREFIX);
    let mut rest = bare.as_str();
    for &g in groups {
        let (head, tail) = rest.split_at(g.min(rest.len()));
        s.push('-');
        s.push_str(head);
        rest = tail;
    }
    Ok(s)
}

fn fold(c: char) -> char {
    match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    }
}

fn is_separator(c: char) -> bool {
    matches!(c, '-' | ' ' | '_' | '.' | '\t' | '\r' | '\n')
}

/// Separators removed and look-alikes folded; `TooLong` past [`MAX_INPUT_CHARS`].
fn normalise(text: &str) -> Result<Vec<char>, RelayCodeError> {
    if text.chars().count() > MAX_INPUT_CHARS {
        return Err(InviteError::TooLong.into());
    }
    Ok(text
        .chars()
        .filter(|&c| !is_separator(c))
        .map(fold)
        .collect())
}

/// Strip the optional prefix from a normalised code of a known body length.
fn body(folded: &[char]) -> Result<&[char], RelayCodeError> {
    let n = folded.len();
    match n {
        INDEX_CODE_CHARS | ENDPOINT_CODE_CHARS => Ok(folded),
        _ if n == INDEX_CODE_CHARS + PREFIX.len() || n == ENDPOINT_CODE_CHARS + PREFIX.len() => {
            let (head, rest) = folded.split_at(PREFIX.len());
            if head.iter().copied().eq(PREFIX.chars()) {
                Ok(rest)
            } else {
                Err(InviteError::BadPrefix.into())
            }
        }
        found => Err(RelayCodeError::WrongLength { found }),
    }
}

/// Read a relay code (version 2 only). Refusals in the order of SPEC 2.2: length,
/// alphabet, padding, version, form, check, room, endpoint.
pub fn decode(text: &str) -> Result<RelayInvite, RelayCodeError> {
    let folded = normalise(text)?;
    let body = body(&folded)?;
    let mut bits: Vec<u8> = Vec::with_capacity(body.len() * 5);
    for &c in body {
        let idx = u8::try_from(c)
            .ok()
            .and_then(|b| ALPHABET.iter().position(|&a| a == b))
            .ok_or(InviteError::BadChar(c))?;
        for k in (0..5).rev() {
            bits.push(u8::from((idx >> k) & 1 == 1));
        }
    }
    let n_bytes = bits.len() / 8;
    if bits
        .get(n_bytes * 8..)
        .is_some_and(|pad| pad.iter().any(|&b| b != 0))
    {
        return Err(InviteError::PaddingBit.into());
    }
    let bytes: Vec<u8> = bits
        .as_chunks::<8>()
        .0
        .iter()
        .map(|ch| ch.iter().fold(0u8, |acc, &b| (acc << 1) | b))
        .collect();
    let (Some(&first), Some((&crc, covered))) = (bytes.first(), bytes.split_last()) else {
        return Err(RelayCodeError::WrongLength { found: body.len() });
    };
    let version = first >> 4;
    if version != RELAY_CODE_VERSION {
        return Err(InviteError::BadVersion(version).into());
    }
    let form = first & 0x0f;
    let expected_form = if body.len() == INDEX_CODE_CHARS {
        FORM_INDEX
    } else {
        FORM_ENDPOINT
    };
    if form != expected_form {
        return Err(RelayCodeError::BadForm(form));
    }
    if crc8(covered) != crc {
        return Err(InviteError::BadChecksum.into());
    }
    let at = |i: usize| bytes.get(i).copied().unwrap_or(0);
    let (relay, room_at) = if form == FORM_INDEX {
        (RelayRef::Index(at(1)), 2)
    } else {
        let ep = SocketAddrV4::new(
            Ipv4Addr::new(at(1), at(2), at(3), at(4)),
            u16::from_be_bytes([at(5), at(6)]),
        );
        (RelayRef::Endpoint(ep), 7)
    };
    let mut room = [0u8; 8];
    for (k, b) in room.iter_mut().enumerate() {
        *b = at(room_at + k);
    }
    let inv = RelayInvite {
        relay,
        room: u64::from_be_bytes(room),
    };
    check(&inv)?;
    Ok(inv)
}

/// Read any invite code: version 1 by its length (13 characters), else version 2.
pub fn decode_any(text: &str) -> Result<AnyInvite, RelayCodeError> {
    let folded = normalise(text)?;
    let n = folded.len();
    if n == CODE_CHARS || n == CODE_CHARS + PREFIX.len() {
        return Ok(AnyInvite::Direct(invite::decode(text)?));
    }
    decode(text).map(AnyInvite::Relay)
}

/// Resolve a code's relay against a table (such as [`KNOWN_RELAYS`], resolved to
/// addresses by the caller). `None` for an index the table does not have.
pub fn resolve(relay: RelayRef, table: &[Endpoint]) -> Option<Endpoint> {
    match relay {
        RelayRef::Endpoint(ep) => Some(ep),
        RelayRef::Index(i) => table.get(usize::from(i)).copied(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
    }

    fn by_index() -> RelayInvite {
        RelayInvite {
            relay: RelayRef::Index(3),
            room: 0x0123_4567_89ab_cdef,
        }
    }

    fn by_endpoint() -> RelayInvite {
        RelayInvite {
            relay: RelayRef::Endpoint(ep(203, 0, 113, 9, 3478)),
            room: 0xfedc_ba98_7654_3210,
        }
    }

    /// Base32 of raw bytes with chosen padding bits, to craft bad codes.
    fn raw(bytes: &[u8], pad: u8) -> String {
        let mut s: Vec<char> = to_base32(bytes).chars().collect();
        if let Some(last) = s.last_mut() {
            let idx = ALPHABET
                .iter()
                .position(|&a| char::from(a) == *last)
                .unwrap();
            *last = char::from(ALPHABET[idx | usize::from(pad & 3)]);
        }
        s.into_iter().collect()
    }

    fn with_crc(mut p: Vec<u8>) -> Vec<u8> {
        let n = p.len() - 1;
        p[n] = crc8(&p[..n]);
        p
    }

    #[test]
    fn round_trip_and_format() {
        for inv in [by_index(), by_endpoint()] {
            let s = encode(&inv).unwrap();
            assert!(s.starts_with("BTM-"));
            assert_eq!(decode(&s), Ok(inv));
            assert_eq!(decode_any(&s), Ok(AnyInvite::Relay(inv)));
            assert_eq!(decode(&s.to_lowercase()), Ok(inv));
            assert_eq!(decode(&encode_bare(&inv).unwrap()), Ok(inv));
            assert!(s.len() <= MAX_INPUT_CHARS);
        }
        let s = encode(&by_index()).unwrap();
        let groups: Vec<usize> = s.split('-').map(str::len).collect();
        assert_eq!(groups, [3, 4, 4, 5, 5]);
        let s = encode(&by_endpoint()).unwrap();
        let groups: Vec<usize> = s.split('-').map(str::len).collect();
        assert_eq!(groups, [3, 4, 4, 4, 4, 5, 5]);
        // Version-2 codes start with '4' (00100), version 1 with '2'.
        assert!(encode_bare(&by_index()).unwrap().starts_with('4'));
    }

    #[test]
    fn round_trip_many() {
        let mut x: u64 = 777;
        for _ in 0..2000 {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let room = x.max(1);
            let a = ((x >> 56) as u8).clamp(1, 223);
            for relay in [
                RelayRef::Index((x >> 8) as u8),
                RelayRef::Endpoint(ep(
                    a,
                    (x >> 48) as u8,
                    (x >> 40) as u8,
                    (x >> 32) as u8,
                    ((x >> 16) as u16).max(1),
                )),
            ] {
                let inv = RelayInvite { relay, room };
                assert_eq!(decode(&encode(&inv).unwrap()), Ok(inv));
            }
        }
    }

    #[test]
    fn decode_any_takes_version_one_codes_unchanged() {
        let e = ep(198, 51, 100, 9, 1338);
        let v1 = invite::encode(e).unwrap();
        assert_eq!(decode_any(&v1), Ok(AnyInvite::Direct(e)));
        assert_eq!(
            decode_any(&v1[..v1.len() - 1]),
            Err(RelayCodeError::WrongLength { found: 15 })
        );
        // A version-1 code is not a relay code.
        assert_eq!(decode(&v1), Err(RelayCodeError::WrongLength { found: 16 }));
        // And a version-1 decoder refuses relay codes (by length).
        assert!(invite::decode(&encode(&by_index()).unwrap()).is_err());
    }

    #[test]
    fn refusals() {
        assert_eq!(
            decode(&"0".repeat(65)),
            Err(RelayCodeError::Code(InviteError::TooLong))
        );
        assert_eq!(decode(""), Err(RelayCodeError::WrongLength { found: 0 }));
        let bare = encode_bare(&by_index()).unwrap();
        assert_eq!(
            decode(&format!("XYZ{bare}")),
            Err(RelayCodeError::Code(InviteError::BadPrefix))
        );
        let mut c: Vec<char> = bare.chars().collect();
        c[3] = 'U';
        assert_eq!(
            decode(&c.iter().collect::<String>()),
            Err(RelayCodeError::Code(InviteError::BadChar('U')))
        );
        let p = payload(&by_index());
        assert_eq!(decode(&raw(&p, 0)), Ok(by_index()));
        assert_eq!(
            decode(&raw(&p, 1)),
            Err(RelayCodeError::Code(InviteError::PaddingBit))
        );
        // Version 3 and version 1 in a relay-length code.
        let mut q = p.clone();
        q[0] = 0x30;
        assert_eq!(
            decode(&raw(&with_crc(q), 0)),
            Err(RelayCodeError::Code(InviteError::BadVersion(3)))
        );
        let mut q = p.clone();
        q[0] = 0x10;
        assert_eq!(
            decode(&raw(&with_crc(q), 0)),
            Err(RelayCodeError::Code(InviteError::BadVersion(1)))
        );
        // Form that does not match the length.
        let mut q = p.clone();
        q[0] = 0x21;
        assert_eq!(
            decode(&raw(&with_crc(q), 0)),
            Err(RelayCodeError::BadForm(1))
        );
        let mut q = p.clone();
        q[10] ^= 0x5a;
        assert_eq!(
            decode(&raw(&q, 0)),
            Err(RelayCodeError::Code(InviteError::BadChecksum))
        );
        // Room 0.
        let mut q = p.clone();
        q[2..10].copy_from_slice(&[0; 8]);
        assert_eq!(decode(&raw(&with_crc(q), 0)), Err(RelayCodeError::ZeroRoom));
        // Endpoint rules.
        let mut q = payload(&by_endpoint());
        q[5] = 0;
        q[6] = 0;
        assert_eq!(
            decode(&raw(&with_crc(q), 0)),
            Err(RelayCodeError::Code(InviteError::ZeroPort))
        );
        let mut q = payload(&by_endpoint());
        q[1..5].copy_from_slice(&[224, 0, 0, 1]);
        assert_eq!(
            decode(&raw(&with_crc(q), 0)),
            Err(RelayCodeError::Code(InviteError::MulticastAddress))
        );
        // Encode refuses what decode refuses.
        assert_eq!(
            encode(&RelayInvite {
                relay: RelayRef::Index(0),
                room: 0
            }),
            Err(RelayCodeError::ZeroRoom)
        );
        assert_eq!(
            encode(&RelayInvite {
                relay: RelayRef::Endpoint(ep(0, 0, 0, 0, 1)),
                room: 1
            }),
            Err(RelayCodeError::Code(InviteError::UnspecifiedAddress))
        );
    }

    #[test]
    fn every_single_character_slip_is_caught() {
        for inv in [by_index(), by_endpoint()] {
            let bare = encode_bare(&inv).unwrap();
            let n = bare.chars().count();
            for pos in 0..n {
                for &alt in ALPHABET.iter() {
                    let mut chars: Vec<char> = bare.chars().collect();
                    if chars[pos] == char::from(alt) {
                        continue;
                    }
                    chars[pos] = char::from(alt);
                    let s: String = chars.iter().collect();
                    assert!(decode(&s).is_err(), "slip at {pos} to {alt} accepted: {s}");
                }
            }
        }
    }

    #[test]
    fn resolve_by_table() {
        let t = [ep(1, 2, 3, 4, 5)];
        assert_eq!(resolve(RelayRef::Index(0), &t), Some(t[0]));
        assert_eq!(resolve(RelayRef::Index(1), &t), None);
        let e = ep(9, 9, 9, 9, 9);
        assert_eq!(resolve(RelayRef::Endpoint(e), &[]), Some(e));
    }

    #[test]
    fn fuzz_never_panics() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let alphabet: Vec<char> = "0123456789ABCDEFGHJKMNPQRSTVWXYZoilu -_.\t#é\u{1F600}"
            .chars()
            .collect();
        for _ in 0..5000 {
            let len = (next() % 80) as usize;
            let s: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            let _ = decode(&s);
            let _ = decode_any(&s);
        }
        for inv in [by_index(), by_endpoint()] {
            let good = encode(&inv).unwrap();
            for n in 0..=good.len() {
                let _ = decode_any(&good[..n]);
            }
        }
    }
}
