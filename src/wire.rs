//! The game-port wire protocol (SPEC section 8): the datagram codec with its CRC-32,
//! and the per-peer reliable streams with cumulative acks, full resend of everything
//! unacknowledged, the heartbeat, and RTT estimation. Sans-IO.

mod codec;
mod crc;
mod link;

pub use codec::{
    chat_size, decode_datagram, decode_message, encode_datagram, encode_message, open, seal,
    set_size, varint_len, ChatLabel, ChatLine, Chunk, LoadStatus, Message, Reader, RunState,
    SharedPause, Update, WireError, Writer, MAX_DATAGRAM, MAX_PAYLOAD, MAX_SEATS, VERSION,
};
pub use crc::crc32;
pub use link::{
    AckBeyond, BuildError, Built, ChatFull, Header, Incoming, Link, LinkNote, OutStream, Room, Rtt,
    HEARTBEAT, MAX_BUFFERED, MAX_UNACKED_CHAT, RTT_WINDOW, SUBMIT_GAP,
};

#[cfg(test)]
mod tests;
