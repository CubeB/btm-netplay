//! The relay frame codec (see `RELAY.md` for the tables).
//!
//! Every frame starts with a 4-byte header `[0xB7, b'R', VERSION, kind]`. Integers are
//! big-endian. Every read is bounds-checked; decoding arbitrary bytes returns an error and
//! never panics.

use std::fmt;

/// First two header bytes.
pub const MAGIC: [u8; 2] = [0xB7, b'R'];
/// Protocol version, third header byte.
pub const VERSION: u8 = 1;
/// Header length.
pub const HEADER_LEN: usize = 4;
/// Largest relayed payload (the inner datagram), in bytes.
pub const MAX_PAYLOAD: usize = 1400;
/// Members per room (ten seats).
pub const MAX_MEMBERS: u8 = 10;
/// Length of a stateless cookie.
pub const COOKIE_LEN: usize = 16;
/// Every hello is padded to exactly this length, so that the challenge and the refusal
/// sent back to a not-yet-verified source are always smaller than what it sent.
pub const HELLO_LEN: usize = 64;
/// Client data frame overhead: header, room, secret, destination, two ports.
pub const C2S_DATA_OVERHEAD: usize = HEADER_LEN + 8 + 8 + 1 + 2 + 2;
/// Server data frame overhead: header, recipient secret, source member, two ports.
pub const S2C_DATA_OVERHEAD: usize = HEADER_LEN + 8 + 1 + 2 + 2;
/// Length of a ping (fixed).
pub const PING_LEN: usize = HEADER_LEN + 8 + 8 + 4 + COOKIE_LEN;
/// Length of a pong (fixed).
pub const PONG_LEN: usize = HEADER_LEN + 8 + 4 + 2 + COOKIE_LEN;
/// Length of a challenge (fixed).
pub const CHALLENGE_LEN: usize = HEADER_LEN + 8 + COOKIE_LEN;
/// Length of a welcome (fixed).
pub const WELCOME_LEN: usize = HEADER_LEN + 8 + 8 + 8 + 1 + 2 + 2;
/// Length of a refusal (fixed).
pub const REFUSE_LEN: usize = HEADER_LEN + 8 + 1;
/// Length of a leave (fixed).
pub const LEAVE_LEN: usize = HEADER_LEN + 8 + 8;

// Anti-amplification, checked at compile time: every reply the relay may send to a source
// it has not admitted is no larger than the request that caused it.
const _: () = {
    assert!(CHALLENGE_LEN < HELLO_LEN);
    assert!(REFUSE_LEN < HELLO_LEN);
    assert!(WELCOME_LEN < HELLO_LEN);
    assert!(PONG_LEN <= PING_LEN);
    assert!(REFUSE_LEN <= PING_LEN);
};

const K_ALLOCATE: u8 = 0x01;
const K_JOIN: u8 = 0x02;
const K_DATA: u8 = 0x03;
const K_PING: u8 = 0x04;
const K_LEAVE: u8 = 0x05;
const K_CHALLENGE: u8 = 0x81;
const K_WELCOME: u8 = 0x82;
const K_DELIVER: u8 = 0x83;
const K_PONG: u8 = 0x84;
const K_REFUSE: u8 = 0x85;

/// A random room id. Zero is never a room.
pub type RoomId = u64;
/// A stateless cookie.
pub type Cookie = [u8; COOKIE_LEN];

/// Why a frame could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Shorter than its fixed part.
    Truncated,
    /// The first two bytes are not [`MAGIC`].
    BadMagic,
    /// Another protocol version.
    BadVersion(u8),
    /// An unknown kind byte.
    UnknownKind(u8),
    /// A hello that is not exactly [`HELLO_LEN`] bytes, or a fixed frame of the wrong size.
    BadLength,
    /// A member index of 10 or more, or a zero room id.
    BadField,
    /// A data payload longer than [`MAX_PAYLOAD`].
    TooLarge,
    /// A frame that only the other side sends.
    WrongDirection,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated relay frame"),
            Self::BadMagic => write!(f, "not a relay frame"),
            Self::BadVersion(v) => write!(f, "relay protocol version {v} is not supported"),
            Self::UnknownKind(k) => write!(f, "unknown relay frame kind {k:#04x}"),
            Self::BadLength => write!(f, "relay frame has the wrong length"),
            Self::BadField => write!(f, "relay frame has an invalid field"),
            Self::TooLarge => write!(f, "relayed payload is larger than {MAX_PAYLOAD} bytes"),
            Self::WrongDirection => write!(f, "relay frame sent in the wrong direction"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Why the relay refused something. Carried in a [`ServerFrame::Refuse`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefuseReason {
    /// The relay holds its maximum number of rooms.
    ServerFull,
    /// This source address holds its maximum number of rooms.
    TooManyRooms,
    /// The room has ten members.
    RoomFull,
    /// No room has that id (or it expired).
    NoSuchRoom,
    /// The sender is not (or no longer) a member: unknown secret.
    NotMember,
    /// The destination member index is not in the room.
    NoSuchMember,
    /// The payload exceeded the relay's limit.
    TooLarge,
    /// The member exceeded its packet or byte budget; frames are being dropped.
    RateLimited,
    /// A code this version does not know.
    Other(u8),
}

impl RefuseReason {
    fn to_byte(self) -> u8 {
        match self {
            Self::ServerFull => 1,
            Self::TooManyRooms => 2,
            Self::RoomFull => 3,
            Self::NoSuchRoom => 4,
            Self::NotMember => 5,
            Self::NoSuchMember => 6,
            Self::TooLarge => 7,
            Self::RateLimited => 8,
            Self::Other(b) => b,
        }
    }

    fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::ServerFull,
            2 => Self::TooManyRooms,
            3 => Self::RoomFull,
            4 => Self::NoSuchRoom,
            5 => Self::NotMember,
            6 => Self::NoSuchMember,
            7 => Self::TooLarge,
            8 => Self::RateLimited,
            other => Self::Other(other),
        }
    }

    /// Whether the client's membership (or attempt) is over.
    pub fn is_fatal(self) -> bool {
        !matches!(
            self,
            Self::NoSuchMember | Self::TooLarge | Self::RateLimited
        )
    }
}

impl fmt::Display for RefuseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerFull => write!(f, "The relay is full; try again later."),
            Self::TooManyRooms => write!(f, "This address already has too many relay rooms."),
            Self::RoomFull => write!(f, "The relayed game is full."),
            Self::NoSuchRoom => write!(f, "That relayed game no longer exists."),
            Self::NotMember => write!(f, "The relay no longer knows this machine."),
            Self::NoSuchMember => write!(f, "That player is not connected to the relay."),
            Self::TooLarge => write!(f, "A datagram was too large for the relay."),
            Self::RateLimited => write!(f, "Sending too fast for the relay."),
            Self::Other(c) => write!(f, "The relay refused (code {c})."),
        }
    }
}

/// A frame a client sends to the relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientFrame<'a> {
    /// Ask for a new room. `cookie` is zero on the first try.
    Allocate { nonce: [u8; 8], cookie: Cookie },
    /// Ask to join `room`. `cookie` is zero on the first try.
    Join {
        nonce: [u8; 8],
        cookie: Cookie,
        room: RoomId,
    },
    /// Forward `payload` to member `to`. The ports are opaque to the relay.
    Data {
        room: RoomId,
        secret: u64,
        to: u8,
        src_port: u16,
        dst_port: u16,
        payload: &'a [u8],
    },
    /// Keepalive and RTT probe. `cookie` echoes a rebind cookie, else zero.
    Ping {
        room: RoomId,
        secret: u64,
        id: u32,
        cookie: Cookie,
    },
    /// Leave the room now.
    Leave { room: RoomId, secret: u64 },
}

/// A frame the relay sends to a client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerFrame<'a> {
    /// Echo this cookie in the hello to prove the source address is real.
    Challenge { nonce: [u8; 8], cookie: Cookie },
    /// Admitted: the room, this member's secret and index, who is present, the payload
    /// limit.
    Welcome {
        nonce: [u8; 8],
        room: RoomId,
        secret: u64,
        member: u8,
        members: u16,
        max_payload: u16,
    },
    /// A payload from member `from`, authenticated to the recipient by its own secret.
    Deliver {
        secret: u64,
        from: u8,
        src_port: u16,
        dst_port: u16,
        payload: &'a [u8],
    },
    /// Answer to a ping. A non-zero `cookie` asks the client to confirm a new address.
    Pong {
        secret: u64,
        id: u32,
        members: u16,
        cookie: Cookie,
    },
    /// Refused. `echo` is the hello's nonce or the secret the client sent (big-endian),
    /// so an off-path attacker cannot forge one.
    Refuse { echo: [u8; 8], reason: RefuseReason },
}

/// Whether `bytes` carry a relay header (magic and version), without decoding further.
pub fn is_relay_frame(bytes: &[u8]) -> bool {
    matches!(bytes, [m0, m1, v, _, ..] if [*m0, *m1] == MAGIC && *v == VERSION)
}

fn header(kind: u8, cap: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(cap);
    v.extend_from_slice(&MAGIC);
    v.push(VERSION);
    v.push(kind);
    v
}

impl ClientFrame<'_> {
    /// Encode. Hellos are padded to [`HELLO_LEN`]. Fails only for an oversized payload or
    /// a bad member index.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        Ok(match self {
            Self::Allocate { nonce, cookie } => {
                let mut v = header(K_ALLOCATE, HELLO_LEN);
                v.extend_from_slice(nonce);
                v.extend_from_slice(cookie);
                v.extend_from_slice(&0u64.to_be_bytes());
                v.resize(HELLO_LEN, 0);
                v
            }
            Self::Join {
                nonce,
                cookie,
                room,
            } => {
                if *room == 0 {
                    return Err(FrameError::BadField);
                }
                let mut v = header(K_JOIN, HELLO_LEN);
                v.extend_from_slice(nonce);
                v.extend_from_slice(cookie);
                v.extend_from_slice(&room.to_be_bytes());
                v.resize(HELLO_LEN, 0);
                v
            }
            Self::Data {
                room,
                secret,
                to,
                src_port,
                dst_port,
                payload,
            } => {
                if payload.len() > MAX_PAYLOAD {
                    return Err(FrameError::TooLarge);
                }
                if *to >= MAX_MEMBERS {
                    return Err(FrameError::BadField);
                }
                let mut v = header(K_DATA, C2S_DATA_OVERHEAD + payload.len());
                v.extend_from_slice(&room.to_be_bytes());
                v.extend_from_slice(&secret.to_be_bytes());
                v.push(*to);
                v.extend_from_slice(&src_port.to_be_bytes());
                v.extend_from_slice(&dst_port.to_be_bytes());
                v.extend_from_slice(payload);
                v
            }
            Self::Ping {
                room,
                secret,
                id,
                cookie,
            } => {
                let mut v = header(K_PING, PING_LEN);
                v.extend_from_slice(&room.to_be_bytes());
                v.extend_from_slice(&secret.to_be_bytes());
                v.extend_from_slice(&id.to_be_bytes());
                v.extend_from_slice(cookie);
                v
            }
            Self::Leave { room, secret } => {
                let mut v = header(K_LEAVE, LEAVE_LEN);
                v.extend_from_slice(&room.to_be_bytes());
                v.extend_from_slice(&secret.to_be_bytes());
                v
            }
        })
    }
}

/// Decode a frame sent to the relay.
pub fn decode_client(bytes: &[u8]) -> Result<ClientFrame<'_>, FrameError> {
    let (kind, mut r) = open(bytes)?;
    match kind {
        K_ALLOCATE | K_JOIN => {
            if bytes.len() != HELLO_LEN {
                return Err(FrameError::BadLength);
            }
            let nonce = r.array::<8>()?;
            let cookie = r.array::<COOKIE_LEN>()?;
            let room = r.u64()?;
            if kind == K_ALLOCATE {
                Ok(ClientFrame::Allocate { nonce, cookie })
            } else if room == 0 {
                Err(FrameError::BadField)
            } else {
                Ok(ClientFrame::Join {
                    nonce,
                    cookie,
                    room,
                })
            }
        }
        K_DATA => {
            let room = r.u64()?;
            let secret = r.u64()?;
            let to = r.u8()?;
            let src_port = r.u16()?;
            let dst_port = r.u16()?;
            let payload = r.rest();
            if to >= MAX_MEMBERS {
                return Err(FrameError::BadField);
            }
            if payload.len() > MAX_PAYLOAD {
                return Err(FrameError::TooLarge);
            }
            Ok(ClientFrame::Data {
                room,
                secret,
                to,
                src_port,
                dst_port,
                payload,
            })
        }
        K_PING => {
            if bytes.len() != PING_LEN {
                return Err(FrameError::BadLength);
            }
            Ok(ClientFrame::Ping {
                room: r.u64()?,
                secret: r.u64()?,
                id: r.u32()?,
                cookie: r.array::<COOKIE_LEN>()?,
            })
        }
        K_LEAVE => {
            if bytes.len() != LEAVE_LEN {
                return Err(FrameError::BadLength);
            }
            Ok(ClientFrame::Leave {
                room: r.u64()?,
                secret: r.u64()?,
            })
        }
        K_CHALLENGE | K_WELCOME | K_DELIVER | K_PONG | K_REFUSE => Err(FrameError::WrongDirection),
        other => Err(FrameError::UnknownKind(other)),
    }
}

impl ServerFrame<'_> {
    /// Encode. Fails only for an oversized payload or a bad member index.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        Ok(match self {
            Self::Challenge { nonce, cookie } => {
                let mut v = header(K_CHALLENGE, CHALLENGE_LEN);
                v.extend_from_slice(nonce);
                v.extend_from_slice(cookie);
                v
            }
            Self::Welcome {
                nonce,
                room,
                secret,
                member,
                members,
                max_payload,
            } => {
                if *member >= MAX_MEMBERS {
                    return Err(FrameError::BadField);
                }
                let mut v = header(K_WELCOME, WELCOME_LEN);
                v.extend_from_slice(nonce);
                v.extend_from_slice(&room.to_be_bytes());
                v.extend_from_slice(&secret.to_be_bytes());
                v.push(*member);
                v.extend_from_slice(&members.to_be_bytes());
                v.extend_from_slice(&max_payload.to_be_bytes());
                v
            }
            Self::Deliver {
                secret,
                from,
                src_port,
                dst_port,
                payload,
            } => {
                if payload.len() > MAX_PAYLOAD {
                    return Err(FrameError::TooLarge);
                }
                if *from >= MAX_MEMBERS {
                    return Err(FrameError::BadField);
                }
                let mut v = header(K_DELIVER, S2C_DATA_OVERHEAD + payload.len());
                v.extend_from_slice(&secret.to_be_bytes());
                v.push(*from);
                v.extend_from_slice(&src_port.to_be_bytes());
                v.extend_from_slice(&dst_port.to_be_bytes());
                v.extend_from_slice(payload);
                v
            }
            Self::Pong {
                secret,
                id,
                members,
                cookie,
            } => {
                let mut v = header(K_PONG, PONG_LEN);
                v.extend_from_slice(&secret.to_be_bytes());
                v.extend_from_slice(&id.to_be_bytes());
                v.extend_from_slice(&members.to_be_bytes());
                v.extend_from_slice(cookie);
                v
            }
            Self::Refuse { echo, reason } => {
                let mut v = header(K_REFUSE, REFUSE_LEN);
                v.extend_from_slice(echo);
                v.push(reason.to_byte());
                v
            }
        })
    }
}

/// Decode a frame sent by the relay.
pub fn decode_server(bytes: &[u8]) -> Result<ServerFrame<'_>, FrameError> {
    let (kind, mut r) = open(bytes)?;
    let fixed = |len: usize| {
        if bytes.len() == len {
            Ok(())
        } else {
            Err(FrameError::BadLength)
        }
    };
    match kind {
        K_CHALLENGE => {
            fixed(CHALLENGE_LEN)?;
            Ok(ServerFrame::Challenge {
                nonce: r.array::<8>()?,
                cookie: r.array::<COOKIE_LEN>()?,
            })
        }
        K_WELCOME => {
            fixed(WELCOME_LEN)?;
            let nonce = r.array::<8>()?;
            let room = r.u64()?;
            let secret = r.u64()?;
            let member = r.u8()?;
            let members = r.u16()?;
            let max_payload = r.u16()?;
            if member >= MAX_MEMBERS || room == 0 {
                return Err(FrameError::BadField);
            }
            Ok(ServerFrame::Welcome {
                nonce,
                room,
                secret,
                member,
                members,
                max_payload,
            })
        }
        K_DELIVER => {
            let secret = r.u64()?;
            let from = r.u8()?;
            let src_port = r.u16()?;
            let dst_port = r.u16()?;
            let payload = r.rest();
            if from >= MAX_MEMBERS {
                return Err(FrameError::BadField);
            }
            if payload.len() > MAX_PAYLOAD {
                return Err(FrameError::TooLarge);
            }
            Ok(ServerFrame::Deliver {
                secret,
                from,
                src_port,
                dst_port,
                payload,
            })
        }
        K_PONG => {
            fixed(PONG_LEN)?;
            Ok(ServerFrame::Pong {
                secret: r.u64()?,
                id: r.u32()?,
                members: r.u16()?,
                cookie: r.array::<COOKIE_LEN>()?,
            })
        }
        K_REFUSE => {
            fixed(REFUSE_LEN)?;
            Ok(ServerFrame::Refuse {
                echo: r.array::<8>()?,
                reason: RefuseReason::from_byte(r.u8()?),
            })
        }
        K_ALLOCATE | K_JOIN | K_DATA | K_PING | K_LEAVE => Err(FrameError::WrongDirection),
        other => Err(FrameError::UnknownKind(other)),
    }
}

/// Check the header and return the kind and a reader positioned after it.
fn open(bytes: &[u8]) -> Result<(u8, Reader<'_>), FrameError> {
    let mut r = Reader { b: bytes, pos: 0 };
    let magic = r.array::<2>()?;
    if magic != MAGIC {
        return Err(FrameError::BadMagic);
    }
    let version = r.u8()?;
    if version != VERSION {
        return Err(FrameError::BadVersion(version));
    }
    let kind = r.u8()?;
    Ok((kind, r))
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        let end = self.pos.checked_add(n).ok_or(FrameError::Truncated)?;
        let s = self.b.get(self.pos..end).ok_or(FrameError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, FrameError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, FrameError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, FrameError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn rest(&mut self) -> &'a [u8] {
        let s = self.b.get(self.pos..).unwrap_or(&[]);
        self.pos = self.b.len();
        s
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn client_frames_round_trip() {
        let payload = vec![7u8; MAX_PAYLOAD];
        let frames = [
            ClientFrame::Allocate {
                nonce: [1; 8],
                cookie: [2; 16],
            },
            ClientFrame::Join {
                nonce: [3; 8],
                cookie: [0; 16],
                room: 0xdead_beef,
            },
            ClientFrame::Data {
                room: 5,
                secret: 6,
                to: 9,
                src_port: 1338,
                dst_port: 1337,
                payload: &payload,
            },
            ClientFrame::Ping {
                room: 5,
                secret: 6,
                id: 77,
                cookie: [9; 16],
            },
            ClientFrame::Leave { room: 5, secret: 6 },
        ];
        for f in &frames {
            let b = f.encode().unwrap();
            assert!(is_relay_frame(&b));
            assert_eq!(&decode_client(&b).unwrap(), f);
            assert_eq!(decode_server(&b), Err(FrameError::WrongDirection));
        }
        assert_eq!(frames[0].encode().unwrap().len(), HELLO_LEN);
    }

    #[test]
    fn server_frames_round_trip() {
        let frames = [
            ServerFrame::Challenge {
                nonce: [1; 8],
                cookie: [2; 16],
            },
            ServerFrame::Welcome {
                nonce: [1; 8],
                room: 9,
                secret: 10,
                member: 3,
                members: 0b1011,
                max_payload: 1400,
            },
            ServerFrame::Deliver {
                secret: 4,
                from: 0,
                src_port: 1,
                dst_port: 2,
                payload: b"hello",
            },
            ServerFrame::Pong {
                secret: 4,
                id: 8,
                members: 3,
                cookie: [0; 16],
            },
            ServerFrame::Refuse {
                echo: [5; 8],
                reason: RefuseReason::RoomFull,
            },
            ServerFrame::Refuse {
                echo: [5; 8],
                reason: RefuseReason::Other(200),
            },
        ];
        for f in &frames {
            let b = f.encode().unwrap();
            assert_eq!(&decode_server(&b).unwrap(), f);
            assert_eq!(decode_client(&b), Err(FrameError::WrongDirection));
        }
    }

    #[test]
    fn refusals() {
        let big = vec![0u8; MAX_PAYLOAD + 1];
        let f = ClientFrame::Data {
            room: 1,
            secret: 1,
            to: 0,
            src_port: 0,
            dst_port: 0,
            payload: &big,
        };
        assert_eq!(f.encode(), Err(FrameError::TooLarge));
        let f = ClientFrame::Data {
            room: 1,
            secret: 1,
            to: 10,
            src_port: 0,
            dst_port: 0,
            payload: &[],
        };
        assert_eq!(f.encode(), Err(FrameError::BadField));
        // A hello must be exactly HELLO_LEN.
        let mut b = ClientFrame::Allocate {
            nonce: [0; 8],
            cookie: [0; 16],
        }
        .encode()
        .unwrap();
        b.pop();
        assert_eq!(decode_client(&b), Err(FrameError::BadLength));
        assert_eq!(
            decode_client(&[0xB7, b'R', 2, 1]),
            Err(FrameError::BadVersion(2))
        );
        assert_eq!(
            decode_client(&[0xB7, b'X', 1, 1]),
            Err(FrameError::BadMagic)
        );
        assert_eq!(
            decode_client(&[0xB7, b'R', 1, 0x77]),
            Err(FrameError::UnknownKind(0x77))
        );
        assert_eq!(decode_client(&[0xB7]), Err(FrameError::Truncated));
    }

    #[test]
    fn fuzz_truncated_and_random_never_panic() {
        let payload = [1u8, 2, 3];
        let samples = [
            ClientFrame::Join {
                nonce: [3; 8],
                cookie: [4; 16],
                room: 1,
            }
            .encode()
            .unwrap(),
            ClientFrame::Data {
                room: 5,
                secret: 6,
                to: 1,
                src_port: 1,
                dst_port: 2,
                payload: &payload,
            }
            .encode()
            .unwrap(),
            ServerFrame::Welcome {
                nonce: [1; 8],
                room: 9,
                secret: 10,
                member: 3,
                members: 1,
                max_payload: 1400,
            }
            .encode()
            .unwrap(),
            ServerFrame::Pong {
                secret: 1,
                id: 2,
                members: 3,
                cookie: [4; 16],
            }
            .encode()
            .unwrap(),
        ];
        for s in &samples {
            for n in 0..=s.len() {
                let _ = decode_client(&s[..n]);
                let _ = decode_server(&s[..n]);
            }
        }
        let mut x: u64 = 0x1234_5678_9abc_def1;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 80) as usize;
            let mut b: Vec<u8> = (0..len)
                .map(|i| (x >> ((i % 8) * 8)) as u8 ^ i as u8)
                .collect();
            if len >= 4 && x & 1 == 0 {
                b[0] = MAGIC[0];
                b[1] = MAGIC[1];
                b[2] = VERSION;
            }
            let _ = decode_client(&b);
            let _ = decode_server(&b);
        }
    }
}
