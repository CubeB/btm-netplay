//! Command sets (1.2): what one player issued for one tick.
//!
//! The bytes handed to [`crate::types::Engine::step`] for each player are an encoded
//! set; the engine reads it with [`decode_set`]. Game commands are opaque to lockstep;
//! the control commands (speed, player dropped, player rejoined) are understood by it.

use std::fmt;

use crate::types::{PlayerId, Tick};
use crate::wire::{varint_len, Reader, WireError, Writer, MAX_SEATS};

/// A set's encoded size cap (1.2). The first command always goes, even if larger.
pub const MAX_SET_BYTES: usize = 1000;
/// The largest single command accepted for sending: anything bigger could never fit
/// a datagram beside the update header (10, item 16).
pub const MAX_COMMAND_BYTES: usize = 1400;

const TAG_GAME: u8 = 0;
const TAG_SPEED: u8 = 1;
const TAG_DROPPED: u8 = 2;
const TAG_REJOINED: u8 = 3;

/// One command in a set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// An opaque game command (unit orders etc.).
    Game(Vec<u8>),
    /// Game speed change, per mille (1.8). Takes effect after the tick it runs on.
    Speed(u16),
    /// "Player dropped": from `from` on the player contributes empty sets (5.3).
    Dropped { player: PlayerId, from: Tick },
    /// "Player rejoined": the player's stream reopens at `at` (5.6).
    Rejoined { player: PlayerId, at: Tick },
}

/// A set failed to decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetError(pub WireError);

impl fmt::Display for SetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad command set: {}", self.0)
    }
}

impl std::error::Error for SetError {}

impl Command {
    /// Encoded size in a set.
    pub fn encoded_len(&self) -> usize {
        match self {
            Command::Game(b) => 1 + varint_len(b.len() as u64) + b.len(),
            Command::Speed(s) => 1 + varint_len(u64::from(*s)),
            Command::Dropped { from: t, .. } | Command::Rejoined { at: t, .. } => {
                2 + varint_len(u64::from(t.0))
            }
        }
    }

    fn write(&self, w: &mut Writer) {
        match self {
            Command::Game(b) => {
                w.u8(TAG_GAME);
                w.bytes(b);
            }
            Command::Speed(s) => {
                w.u8(TAG_SPEED);
                w.varint(u64::from(*s));
            }
            Command::Dropped { player, from } => {
                w.u8(TAG_DROPPED);
                w.u8(player.0);
                w.varint(u64::from(from.0));
            }
            Command::Rejoined { player, at } => {
                w.u8(TAG_REJOINED);
                w.u8(player.0);
                w.varint(u64::from(at.0));
            }
        }
    }
}

/// Encodes a set. The empty set is zero bytes.
pub fn encode_set(commands: &[Command]) -> Vec<u8> {
    let mut w = Writer::new();
    for c in commands {
        c.write(&mut w);
    }
    w.finish()
}

/// Decodes a set.
pub fn decode_set(bytes: &[u8]) -> Result<Vec<Command>, SetError> {
    let mut r = Reader::new(bytes);
    let mut out = Vec::new();
    while !r.at_end() {
        let c = match r.u8().map_err(SetError)? {
            TAG_GAME => Command::Game(r.bytes().map_err(SetError)?.to_vec()),
            TAG_SPEED => Command::Speed(r.u16v("speed").map_err(SetError)?),
            tag @ (TAG_DROPPED | TAG_REJOINED) => {
                let p = r.u8().map_err(SetError)?;
                if p >= MAX_SEATS {
                    return Err(SetError(WireError::BadValue("seat")));
                }
                let t = Tick(r.u32v("tick").map_err(SetError)?);
                if tag == TAG_DROPPED {
                    Command::Dropped {
                        player: PlayerId(p),
                        from: t,
                    }
                } else {
                    Command::Rejoined {
                        player: PlayerId(p),
                        at: t,
                    }
                }
            }
            _ => return Err(SetError(WireError::BadValue("command tag"))),
        };
        out.push(c);
    }
    Ok(out)
}

/// Takes the commands for one set from the front of `pending`: as many as fit in
/// 1000 bytes, and at least one (1.2).
pub fn take_set(pending: &mut std::collections::VecDeque<Command>) -> Vec<Command> {
    let mut size = 0usize;
    let mut out = Vec::new();
    while let Some(c) = pending.front() {
        let len = c.encoded_len();
        if !out.is_empty() && size + len > MAX_SET_BYTES {
            break;
        }
        size += len;
        if let Some(c) = pending.pop_front() {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn round_trip_and_split() {
        let cmds = vec![
            Command::Game(vec![1, 2, 3]),
            Command::Speed(2000),
            Command::Dropped {
                player: PlayerId(4),
                from: Tick(1234),
            },
            Command::Rejoined {
                player: PlayerId(9),
                at: Tick(99_999),
            },
        ];
        let b = encode_set(&cmds);
        assert_eq!(
            b.len(),
            cmds.iter().map(Command::encoded_len).sum::<usize>()
        );
        assert_eq!(decode_set(&b).unwrap(), cmds);
        assert_eq!(decode_set(&[]).unwrap(), vec![]);
        assert!(decode_set(&[TAG_DROPPED, 10, 1]).is_err());
        assert!(decode_set(&[7]).is_err());

        let mut pending: VecDeque<Command> = (0..100).map(|_| Command::Game(vec![0; 30])).collect();
        let first = take_set(&mut pending);
        assert!(encode_set(&first).len() <= MAX_SET_BYTES);
        assert_eq!(first.len(), 31);
        let mut big: VecDeque<Command> = [Command::Game(vec![0; 1200])].into();
        assert_eq!(take_set(&mut big).len(), 1);
    }
}
