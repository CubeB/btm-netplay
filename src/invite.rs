//! Invite codes (SPEC 2.2).
//!
//! A code names one IPv4 address and UDP port (the discovery socket's outside
//! endpoint as STUN saw it). The same format is used for the guest's reply code.
//!
//! Layout of the 8-byte payload: `[version<<4, a, b, c, d, port_hi, port_lo, crc8]`.
//! The 64 bits are written five at a time from the most significant end in Crockford
//! base32, giving 13 characters; the last carries 4 data bits and one zero padding bit.
//! The text form is `BTM-XXXX-XXXX-XXXXX`.
//!
//! Decoding is forgiving about case, separators, the look-alike letters O, I and L, and a
//! missing prefix, and strict about everything that matters (see [`InviteError`]).

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::types::Endpoint;

/// The product prefix shown before the code.
pub const PREFIX: &str = "BTM";
/// Version nibble written in the high half of the first payload byte.
pub const VERSION: u8 = 1;
/// Input longer than this many characters is refused outright.
pub const MAX_INPUT_CHARS: usize = 64;
/// Length of the bare code, without prefix or separators.
pub const CODE_CHARS: usize = 13;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Why a code was refused (or an endpoint could not be encoded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteError {
    /// More than [`MAX_INPUT_CHARS`] characters were given.
    TooLong,
    /// After removing separators the length is neither 13 nor 16 (with prefix).
    WrongLength { found: usize },
    /// Sixteen characters were given but they do not start with the prefix.
    BadPrefix,
    /// A character outside the alphabet (after O/I/L folding and case folding).
    BadChar(char),
    /// The padding bit in the last character was set.
    PaddingBit,
    /// The version nibble was not [`VERSION`].
    BadVersion(u8),
    /// The CRC-8 did not match: a typo.
    BadChecksum,
    /// Port 0.
    ZeroPort,
    /// Address 0.0.0.0.
    UnspecifiedAddress,
    /// A multicast address (224.0.0.0/4).
    MulticastAddress,
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "the code is too long"),
            Self::WrongLength { found } => write!(f, "a code has 13 characters, not {found}"),
            Self::BadPrefix => write!(f, "the code does not start with {PREFIX}"),
            Self::BadChar(c) => write!(f, "'{c}' cannot appear in a code"),
            Self::PaddingBit => write!(f, "the code is malformed"),
            Self::BadVersion(v) => write!(f, "unsupported code version {v}"),
            Self::BadChecksum => write!(f, "the code has a typing mistake"),
            Self::ZeroPort => write!(f, "the code names port 0"),
            Self::UnspecifiedAddress => write!(f, "the code names no address"),
            Self::MulticastAddress => write!(f, "the code names a multicast address"),
        }
    }
}

impl std::error::Error for InviteError {}

/// CRC-8, polynomial 0x07, initial value 0, no reflection, no final XOR.
pub fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Check the endpoint rules that [`decode`] enforces, so that `encode` never produces a
/// code that `decode` would refuse.
pub fn check_endpoint(ep: Endpoint) -> Result<(), InviteError> {
    if ep.port() == 0 {
        return Err(InviteError::ZeroPort);
    }
    if ep.ip().is_unspecified() {
        return Err(InviteError::UnspecifiedAddress);
    }
    if ep.ip().is_multicast() {
        return Err(InviteError::MulticastAddress);
    }
    Ok(())
}

/// The 8 payload bytes for an endpoint (no validation).
pub fn payload(ep: Endpoint) -> [u8; 8] {
    let ip = ep.ip().octets();
    let port = ep.port().to_be_bytes();
    let mut p = [
        VERSION << 4,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        port[0],
        port[1],
        0,
    ];
    p[7] = crc8(&p[..7]);
    p
}

/// The bare 13-character code, no prefix and no separators.
pub fn encode_bare(ep: Endpoint) -> Result<String, InviteError> {
    check_endpoint(ep)?;
    // 64 data bits followed by one zero padding bit.
    let v = u128::from(u64::from_be_bytes(payload(ep))) << 1;
    let mut s = String::with_capacity(CODE_CHARS);
    for i in 0..CODE_CHARS {
        let shift = 5 * (CODE_CHARS - 1 - i);
        let idx = ((v >> shift) & 31) as usize;
        s.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'0')));
    }
    Ok(s)
}

/// The display form `BTM-XXXX-XXXX-XXXXX`.
pub fn encode(ep: Endpoint) -> Result<String, InviteError> {
    let bare = encode_bare(ep)?;
    let mut s = String::with_capacity(PREFIX.len() + CODE_CHARS + 3);
    s.push_str(PREFIX);
    for (i, c) in bare.chars().enumerate() {
        if i == 0 || i == 4 || i == 8 {
            s.push('-');
        }
        s.push(c);
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

/// Read a code. Refusal reasons are checked in the order of SPEC 2.2: length, alphabet,
/// padding bit, version, check, port, address.
pub fn decode(text: &str) -> Result<Endpoint, InviteError> {
    if text.chars().count() > MAX_INPUT_CHARS {
        return Err(InviteError::TooLong);
    }
    let folded: Vec<char> = text
        .chars()
        .filter(|&c| !is_separator(c))
        .map(fold)
        .collect();
    let body: &[char] = match folded.len() {
        CODE_CHARS => &folded,
        n if n == CODE_CHARS + PREFIX.len() => {
            let (head, rest) = folded.split_at(PREFIX.len());
            if !head.iter().copied().eq(PREFIX.chars()) {
                return Err(InviteError::BadPrefix);
            }
            rest
        }
        found => return Err(InviteError::WrongLength { found }),
    };

    let mut v: u128 = 0;
    for &c in body {
        let idx = u8::try_from(c)
            .ok()
            .and_then(|b| ALPHABET.iter().position(|&a| a == b))
            .ok_or(InviteError::BadChar(c))?;
        v = (v << 5) | idx as u128;
    }
    if v & 1 != 0 {
        return Err(InviteError::PaddingBit);
    }
    let bytes = ((v >> 1) as u64).to_be_bytes();
    let version = bytes[0] >> 4;
    if version != VERSION {
        return Err(InviteError::BadVersion(version));
    }
    if crc8(&bytes[..7]) != bytes[7] {
        return Err(InviteError::BadChecksum);
    }
    let ep = SocketAddrV4::new(
        Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]),
        u16::from_be_bytes([bytes[5], bytes[6]]),
    );
    check_endpoint(ep)?;
    Ok(ep)
}

/// A reply code (the guest's outside discovery endpoint); same format as an invite code.
pub fn encode_reply(ep: Endpoint) -> Result<String, InviteError> {
    encode(ep)
}

/// Read a reply code; same rules as [`decode`].
pub fn decode_reply(text: &str) -> Result<Endpoint, InviteError> {
    decode(text)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
    }

    /// Re-encode raw payload bytes the way `encode_bare` does, to craft bad codes.
    fn bare_from(bytes: [u8; 8], pad: u8) -> String {
        let v = (u128::from(u64::from_be_bytes(bytes)) << 1) | u128::from(pad);
        (0..CODE_CHARS)
            .map(|i| char::from(ALPHABET[((v >> (5 * (CODE_CHARS - 1 - i))) & 31) as usize]))
            .collect()
    }

    fn with_crc(mut p: [u8; 8]) -> [u8; 8] {
        p[7] = crc8(&p[..7]);
        p
    }

    #[test]
    fn crc8_check_value() {
        // Standard CRC-8 (poly 0x07) check value for "123456789".
        assert_eq!(crc8(b"123456789"), 0xF4);
        assert_eq!(crc8(&[]), 0);
    }

    #[test]
    fn round_trip_and_format() {
        let e = ep(203, 0, 113, 77, 54321);
        let s = encode(e).unwrap();
        assert_eq!(s.len(), 3 + 3 + 13);
        assert!(s.starts_with("BTM-"));
        let groups: Vec<&str> = s.split('-').collect();
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            [3, 4, 4, 5]
        );
        assert_eq!(decode(&s), Ok(e));
        assert_eq!(decode_reply(&encode_reply(e).unwrap()), Ok(e));
    }

    #[test]
    fn round_trip_many() {
        let mut x: u32 = 12345;
        for _ in 0..2000 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let a = (x >> 24) as u8;
            let e = ep(
                a.clamp(1, 223),
                (x >> 16) as u8,
                (x >> 8) as u8,
                x as u8,
                (x as u16).max(1),
            );
            assert_eq!(decode(&encode(e).unwrap()), Ok(e));
        }
    }

    #[test]
    fn known_vector() {
        // 0x10, 192.0.2.1, port 0x1234, crc.
        let p = payload(ep(192, 0, 2, 1, 0x1234));
        assert_eq!(&p[..7], &[0x10, 192, 0, 2, 1, 0x12, 0x34]);
        assert_eq!(p[7], crc8(&p[..7]));
        let s = encode_bare(ep(192, 0, 2, 1, 0x1234)).unwrap();
        assert_eq!(s.len(), 13);
        // First character is the top five bits of 0x10: 00010 = '2'.
        assert!(s.starts_with('2'));
    }

    #[test]
    fn forgiving_input() {
        let e = ep(198, 51, 100, 9, 1338);
        let s = encode(e).unwrap();
        let lower = s.to_lowercase();
        assert_eq!(decode(&lower), Ok(e));
        let messy: String = s
            .chars()
            .flat_map(|c| {
                if c == '-' {
                    vec![' ', '_', '.']
                } else {
                    vec![c]
                }
            })
            .collect();
        assert_eq!(decode(&format!("  {messy}\r\n\t")), Ok(e));
        // Prefix omitted.
        assert_eq!(decode(&encode_bare(e).unwrap()), Ok(e));
        assert_eq!(decode(&s[4..]), Ok(e));
        // O, I, L read as 0, 1, 1.
        let bare = encode_bare(e).unwrap();
        let swapped: String = bare
            .chars()
            .map(|c| match c {
                '0' => 'o',
                '1' => 'l',
                other => other,
            })
            .collect();
        assert_eq!(decode(&swapped), Ok(e));
        let swapped_i: String = bare
            .chars()
            .map(|c| if c == '1' { 'I' } else { c })
            .collect();
        assert_eq!(decode(&swapped_i), Ok(e));
    }

    #[test]
    fn refusal_too_long() {
        let long = "0".repeat(65);
        assert_eq!(decode(&long), Err(InviteError::TooLong));
        // 64 is not "too long" (it is a wrong length instead).
        assert_eq!(
            decode(&"0".repeat(64)),
            Err(InviteError::WrongLength { found: 64 })
        );
        // Separators count toward the 64.
        let spaced = format!(
            "{}{}",
            encode_bare(ep(1, 2, 3, 4, 5)).unwrap(),
            " ".repeat(60)
        );
        assert_eq!(decode(&spaced), Err(InviteError::TooLong));
    }

    #[test]
    fn refusal_wrong_length() {
        assert_eq!(decode(""), Err(InviteError::WrongLength { found: 0 }));
        let s = encode_bare(ep(1, 2, 3, 4, 5)).unwrap();
        assert_eq!(
            decode(&s[..12]),
            Err(InviteError::WrongLength { found: 12 })
        );
        assert_eq!(
            decode(&format!("{s}0")),
            Err(InviteError::WrongLength { found: 14 })
        );
        assert_eq!(decode("BTM"), Err(InviteError::WrongLength { found: 3 }));
    }

    #[test]
    fn refusal_bad_prefix() {
        let s = encode_bare(ep(1, 2, 3, 4, 5)).unwrap();
        assert_eq!(decode(&format!("XYZ-{s}")), Err(InviteError::BadPrefix));
    }

    #[test]
    fn refusal_bad_char() {
        let s = encode_bare(ep(1, 2, 3, 4, 5)).unwrap();
        // U is not in the alphabet.
        let mut chars: Vec<char> = s.chars().collect();
        chars[5] = 'U';
        let bad: String = chars.iter().collect();
        assert_eq!(decode(&bad), Err(InviteError::BadChar('U')));
        let mut chars: Vec<char> = s.chars().collect();
        chars[0] = '#';
        let bad: String = chars.iter().collect();
        assert_eq!(decode(&bad), Err(InviteError::BadChar('#')));
        // Non-ASCII.
        let mut chars: Vec<char> = s.chars().collect();
        chars[2] = 'é';
        let bad: String = chars.iter().collect();
        assert_eq!(decode(&bad), Err(InviteError::BadChar('é')));
    }

    #[test]
    fn refusal_padding_bit() {
        let p = payload(ep(1, 2, 3, 4, 5));
        assert_eq!(decode(&bare_from(p, 0)), Ok(ep(1, 2, 3, 4, 5)));
        assert_eq!(decode(&bare_from(p, 1)), Err(InviteError::PaddingBit));
    }

    #[test]
    fn refusal_version() {
        let mut p = payload(ep(1, 2, 3, 4, 5));
        p[0] = 0x20;
        let p = with_crc(p);
        assert_eq!(decode(&bare_from(p, 0)), Err(InviteError::BadVersion(2)));
        let mut p = payload(ep(1, 2, 3, 4, 5));
        p[0] = 0x00;
        let p = with_crc(p);
        assert_eq!(decode(&bare_from(p, 0)), Err(InviteError::BadVersion(0)));
    }

    #[test]
    fn refusal_checksum() {
        let mut p = payload(ep(1, 2, 3, 4, 5));
        p[7] ^= 0x55;
        assert_eq!(decode(&bare_from(p, 0)), Err(InviteError::BadChecksum));
    }

    #[test]
    fn refusal_port_and_address() {
        let mut p = payload(ep(1, 2, 3, 4, 5));
        p[5] = 0;
        p[6] = 0;
        assert_eq!(
            decode(&bare_from(with_crc(p), 0)),
            Err(InviteError::ZeroPort)
        );
        let mut p = payload(ep(1, 2, 3, 4, 5));
        p[1..5].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            decode(&bare_from(with_crc(p), 0)),
            Err(InviteError::UnspecifiedAddress)
        );
        let mut p = payload(ep(1, 2, 3, 4, 5));
        p[1..5].copy_from_slice(&[239, 1, 2, 3]);
        assert_eq!(
            decode(&bare_from(with_crc(p), 0)),
            Err(InviteError::MulticastAddress)
        );
    }

    #[test]
    fn encode_refuses_what_decode_refuses() {
        assert_eq!(encode(ep(1, 2, 3, 4, 0)), Err(InviteError::ZeroPort));
        assert_eq!(
            encode(ep(0, 0, 0, 0, 5)),
            Err(InviteError::UnspecifiedAddress)
        );
        assert_eq!(
            encode(ep(224, 0, 0, 1, 5)),
            Err(InviteError::MulticastAddress)
        );
    }

    #[test]
    fn every_single_character_slip_is_caught() {
        let e = ep(93, 184, 216, 34, 40001);
        let bare = encode_bare(e).unwrap();
        for pos in 0..CODE_CHARS {
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

    #[test]
    fn display_is_human() {
        assert!(InviteError::BadChecksum.to_string().contains("typing"));
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
        let alphabet: Vec<char> = "0123456789ABCDEFGHJKMNPQRSTVWXYZoilu -_.\t\r\n#é\u{1F600}"
            .chars()
            .collect();
        for _ in 0..5000 {
            let len = (next() % 80) as usize;
            let s: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            let _ = decode(&s);
        }
        // Truncations of a good code.
        let good = encode(ep(8, 8, 8, 8, 1338)).unwrap();
        for n in 0..=good.len() {
            if good.is_char_boundary(n) {
                let _ = decode(&good[..n]);
            }
        }
    }
}
