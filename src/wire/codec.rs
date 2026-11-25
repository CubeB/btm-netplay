//! The datagram codec: a compact binary encoding of the game-port messages (8.2),
//! sealed with a little-endian CRC-32 (8.1).
//!
//! Layout of every datagram: `version u8, kind u8, body..., crc32 (4 bytes LE)`.
//! Integers are LEB128 varints unless noted; byte strings are a varint length then
//! the bytes. Trailing bytes after a known body are ignored (forward compatibility).

use std::fmt;

use super::crc::crc32;
use crate::types::PlayerId;

/// Encoding version carried in the first byte of every datagram.
pub const VERSION: u8 = 1;
/// Maximum datagram, CRC included (8.6).
pub const MAX_DATAGRAM: usize = 1500;
/// Maximum encoded message, CRC excluded.
pub const MAX_PAYLOAD: usize = MAX_DATAGRAM - 4;
/// Seats are 0..=9 (3.8).
pub const MAX_SEATS: u8 = 10;

const KIND_LOAD_STATUS: u8 = 1;
const KIND_UPDATE: u8 = 2;

/// Why a datagram or message could not be decoded or encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Shorter than the CRC.
    TooShort,
    /// The CRC does not match.
    BadCrc,
    /// Over 1500 bytes.
    TooLarge(usize),
    /// An encoding version this build does not speak.
    BadVersion(u8),
    /// A message kind this build does not know.
    UnknownKind(u8),
    /// The body ended early.
    Truncated,
    /// A field holds a value that is out of range.
    BadValue(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::TooShort => write!(f, "datagram shorter than its checksum"),
            WireError::BadCrc => write!(f, "checksum mismatch"),
            WireError::TooLarge(n) => write!(f, "datagram of {n} bytes exceeds {MAX_DATAGRAM}"),
            WireError::BadVersion(v) => write!(f, "unknown encoding version {v}"),
            WireError::UnknownKind(k) => write!(f, "unknown message kind {k}"),
            WireError::Truncated => write!(f, "message truncated"),
            WireError::BadValue(what) => write!(f, "bad value for {what}"),
        }
    }
}

impl std::error::Error for WireError {}

/// Load handshake status (8.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadStatus {
    pub sender: PlayerId,
    pub ready: bool,
}

/// The sender's run state, for the drift gate and the speed governor (1.6, 1.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunState {
    pub scene_time: u32,
    /// Effective speed, per mille: what the sender actually runs at.
    pub speed: u16,
    /// Chosen speed, per mille. A capacity at or above it does not limit.
    pub chosen: u16,
    pub paused: bool,
    pub stalled: bool,
    pub capacity: u16,
}

impl Default for RunState {
    fn default() -> Self {
        RunState {
            scene_time: 0,
            speed: 1000,
            chosen: 1000,
            paused: false,
            stalled: false,
            capacity: 1000,
        }
    }
}

/// The shared pause value (1.8). Revision 0 means "none".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedPause {
    pub revision: u32,
    pub player: PlayerId,
    pub paused: bool,
}

impl Default for SharedPause {
    fn default() -> Self {
        SharedPause {
            revision: 0,
            player: PlayerId(0),
            paused: false,
        }
    }
}

impl SharedPause {
    /// True if `other` supersedes `self`: (revision, player) lexicographically greater.
    pub fn superseded_by(&self, other: &SharedPause) -> bool {
        (other.revision, other.player.0) > (self.revision, self.player.0)
    }
}

/// How a chat line is tagged for display (7). It never selects recipients.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ChatLabel {
    #[default]
    None,
    Allies,
    Enemies,
}

impl ChatLabel {
    fn to_byte(self) -> u8 {
        match self {
            ChatLabel::None => 0,
            ChatLabel::Allies => 1,
            ChatLabel::Enemies => 2,
        }
    }

    fn from_byte(b: u8) -> Result<Self, WireError> {
        match b {
            0 => Ok(ChatLabel::None),
            1 => Ok(ChatLabel::Allies),
            2 => Ok(ChatLabel::Enemies),
            _ => Err(WireError::BadValue("chat label")),
        }
    }
}

/// One chat line as carried; the text is raw bytes, sanitised by the receiver.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ChatLine {
    pub text: Vec<u8>,
    pub label: ChatLabel,
}

/// One stream's part of an update: the sequence number of the first included item,
/// the cumulative ack of the peer's stream (the next number expected), and items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk<T> {
    pub first: u32,
    pub ack: u32,
    pub items: Vec<T>,
}

impl<T> Default for Chunk<T> {
    fn default() -> Self {
        Chunk {
            first: 0,
            ack: 0,
            items: Vec::new(),
        }
    }
}

/// The lockstep update (8.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub sender: PlayerId,
    /// Per-sender counter, for logging only.
    pub packet_id: u32,
    pub run: RunState,
    pub pause: SharedPause,
    /// Milliseconds since this sender last took new commands from the recipient.
    pub ack_delay_ms: u32,
    pub commands: Chunk<Vec<u8>>,
    pub hashes: Chunk<u32>,
    pub chat: Chunk<ChatLine>,
    /// For each player, how many of its sets the sender holds (pushed so far).
    /// Used to agree a drop cut and to relay a lost player's sets (lockstep 5.4).
    pub held: Vec<(PlayerId, u32)>,
    /// Best-effort relay of another player's sets, for a survivor that lacks them.
    pub relay: Option<Relay>,
}

/// Sets of `player`'s stream, numbers `first..`, forwarded by a third peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relay {
    pub player: PlayerId,
    pub first: u32,
    pub sets: Vec<Vec<u8>>,
}

/// Worst-case encoded size of a relay's fixed fields.
pub const RELAY_OVERHEAD: usize = 1 + 1 + 5 + 5;

impl Default for Update {
    fn default() -> Self {
        Update {
            sender: PlayerId(0),
            packet_id: 0,
            run: RunState::default(),
            pause: SharedPause::default(),
            ack_delay_ms: 0,
            commands: Chunk::default(),
            hashes: Chunk::default(),
            chat: Chunk::default(),
            held: Vec::new(),
            relay: None,
        }
    }
}

/// Every message the game port carries after the lobby.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    LoadStatus(LoadStatus),
    Update(Update),
}

// ---------------------------------------------------------------- primitives

/// Bytes a varint of `v` takes.
pub fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Appends values to a buffer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer::default()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.buf.push((v as u8) | 0x80);
            v >>= 7;
        }
        self.buf.push(v as u8);
    }

    pub fn u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.varint(b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Reads values from a slice; every read is bounds-checked.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn at_end(&self) -> bool {
        self.remaining() == 0
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        let b = *self.data.get(self.pos).ok_or(WireError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn varint(&mut self) -> Result<u64, WireError> {
        let mut v: u64 = 0;
        for i in 0..10 {
            let b = self.u8()?;
            let part = u64::from(b & 0x7F);
            if i == 9 && part > 1 {
                return Err(WireError::BadValue("varint"));
            }
            v |= part << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(WireError::BadValue("varint"))
    }

    pub fn u32v(&mut self, what: &'static str) -> Result<u32, WireError> {
        u32::try_from(self.varint()?).map_err(|_| WireError::BadValue(what))
    }

    pub fn u16v(&mut self, what: &'static str) -> Result<u16, WireError> {
        u16::try_from(self.varint()?).map_err(|_| WireError::BadValue(what))
    }

    pub fn u32_le(&mut self) -> Result<u32, WireError> {
        let end = self.pos.checked_add(4).ok_or(WireError::Truncated)?;
        let s = self.data.get(self.pos..end).ok_or(WireError::Truncated)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(s);
        self.pos = end;
        Ok(u32::from_le_bytes(a))
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.varint()?).map_err(|_| WireError::Truncated)?;
        if len > self.remaining() {
            return Err(WireError::Truncated);
        }
        let end = self.pos + len;
        let s = self.data.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    /// A count of items each at least `min_item` bytes long, checked against what is left.
    pub fn count(&mut self, min_item: usize) -> Result<usize, WireError> {
        let n = usize::try_from(self.varint()?).map_err(|_| WireError::Truncated)?;
        if n.saturating_mul(min_item.max(1)) > self.remaining() {
            return Err(WireError::Truncated);
        }
        Ok(n)
    }

    pub fn seat(&mut self) -> Result<PlayerId, WireError> {
        let s = self.u8()?;
        if s >= MAX_SEATS {
            return Err(WireError::BadValue("seat"));
        }
        Ok(PlayerId(s))
    }
}

// ---------------------------------------------------------------- sizes

/// Encoded size of one command set inside an update.
pub fn set_size(set: &[u8]) -> usize {
    varint_len(set.len() as u64) + set.len()
}

/// Encoded size of one hash inside an update.
pub const HASH_SIZE: usize = 4;

/// Encoded size of one chat line inside an update.
pub fn chat_size(line: &ChatLine) -> usize {
    varint_len(line.text.len() as u64) + line.text.len() + 1
}

/// Worst-case encoded size of a chunk's `first`, `ack` and item count.
pub const CHUNK_OVERHEAD: usize = 15;

// ---------------------------------------------------------------- messages

fn write_header(w: &mut Writer, u: &Update) {
    w.u8(u.sender.0);
    w.varint(u64::from(u.packet_id));
    w.varint(u64::from(u.run.scene_time));
    w.varint(u64::from(u.run.speed));
    w.varint(u64::from(u.run.chosen));
    w.varint(u64::from(u.run.capacity));
    let flags =
        u8::from(u.run.paused) | (u8::from(u.run.stalled) << 1) | (u8::from(u.pause.paused) << 2);
    w.u8(flags);
    w.varint(u64::from(u.pause.revision));
    w.u8(u.pause.player.0);
    w.varint(u64::from(u.ack_delay_ms));
    w.varint(u.held.len() as u64);
    for (p, n) in &u.held {
        w.u8(p.0);
        w.varint(u64::from(*n));
    }
}

fn write_update(w: &mut Writer, u: &Update) {
    write_header(w, u);
    w.varint(u64::from(u.commands.first));
    w.varint(u64::from(u.commands.ack));
    w.varint(u.commands.items.len() as u64);
    for s in &u.commands.items {
        w.bytes(s);
    }

    w.varint(u64::from(u.hashes.first));
    w.varint(u64::from(u.hashes.ack));
    w.varint(u.hashes.items.len() as u64);
    for h in &u.hashes.items {
        w.u32_le(*h);
    }

    w.varint(u64::from(u.chat.first));
    w.varint(u64::from(u.chat.ack));
    w.varint(u.chat.items.len() as u64);
    for c in &u.chat.items {
        w.bytes(&c.text);
        w.u8(c.label.to_byte());
    }

    match &u.relay {
        None => w.u8(0),
        Some(r) => {
            w.u8(1);
            w.u8(r.player.0);
            w.varint(u64::from(r.first));
            w.varint(r.sets.len() as u64);
            for s in &r.sets {
                w.bytes(s);
            }
        }
    }
}

fn read_update(r: &mut Reader<'_>) -> Result<Update, WireError> {
    let sender = r.seat()?;
    let packet_id = r.u32v("packet id")?;
    let scene_time = r.u32v("scene time")?;
    let speed = r.u16v("speed")?;
    let chosen = r.u16v("chosen speed")?;
    let capacity = r.u16v("capacity")?;
    let flags = r.u8()?;
    if flags & !0b111 != 0 {
        return Err(WireError::BadValue("flags"));
    }
    let revision = r.u32v("pause revision")?;
    let pause_player = r.seat()?;
    let ack_delay_ms = r.u32v("ack delay")?;
    let n = r.count(2)?;
    if n > usize::from(MAX_SEATS) {
        return Err(WireError::BadValue("held count"));
    }
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        let p = r.seat()?;
        held.push((p, r.u32v("held")?));
    }

    let first = r.u32v("command seq")?;
    let ack = r.u32v("command ack")?;
    let n = r.count(1)?;
    let mut sets = Vec::with_capacity(n);
    for _ in 0..n {
        sets.push(r.bytes()?.to_vec());
    }
    let commands = Chunk {
        first,
        ack,
        items: sets,
    };

    let first = r.u32v("hash seq")?;
    let ack = r.u32v("hash ack")?;
    let n = r.count(HASH_SIZE)?;
    let mut hs = Vec::with_capacity(n);
    for _ in 0..n {
        hs.push(r.u32_le()?);
    }
    let hashes = Chunk {
        first,
        ack,
        items: hs,
    };

    let first = r.u32v("chat seq")?;
    let ack = r.u32v("chat ack")?;
    let n = r.count(2)?;
    let mut lines = Vec::with_capacity(n);
    for _ in 0..n {
        let text = r.bytes()?.to_vec();
        let label = ChatLabel::from_byte(r.u8()?)?;
        lines.push(ChatLine { text, label });
    }
    let chat = Chunk {
        first,
        ack,
        items: lines,
    };

    let relay = match r.u8()? {
        0 => None,
        1 => {
            let player = r.seat()?;
            let first = r.u32v("relay seq")?;
            let n = r.count(1)?;
            let mut sets = Vec::with_capacity(n);
            for _ in 0..n {
                sets.push(r.bytes()?.to_vec());
            }
            Some(Relay {
                player,
                first,
                sets,
            })
        }
        _ => return Err(WireError::BadValue("relay flag")),
    };

    Ok(Update {
        sender,
        packet_id,
        run: RunState {
            scene_time,
            speed,
            chosen,
            paused: flags & 1 != 0,
            stalled: flags & 2 != 0,
            capacity,
        },
        pause: SharedPause {
            revision,
            player: pause_player,
            paused: flags & 4 != 0,
        },
        ack_delay_ms,
        commands,
        hashes,
        chat,
        held,
        relay,
    })
}

/// Encodes a message without its CRC.
pub fn encode_message(m: &Message) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(VERSION);
    match m {
        Message::LoadStatus(s) => {
            w.u8(KIND_LOAD_STATUS);
            w.u8(s.sender.0);
            w.u8(u8::from(s.ready));
        }
        Message::Update(u) => {
            w.u8(KIND_UPDATE);
            write_update(&mut w, u);
        }
    }
    w.finish()
}

/// Decodes a message without its CRC.
pub fn decode_message(payload: &[u8]) -> Result<Message, WireError> {
    let mut r = Reader::new(payload);
    let version = r.u8()?;
    if version != VERSION {
        return Err(WireError::BadVersion(version));
    }
    match r.u8()? {
        KIND_LOAD_STATUS => {
            let sender = r.seat()?;
            let ready = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(WireError::BadValue("load status")),
            };
            Ok(Message::LoadStatus(LoadStatus { sender, ready }))
        }
        KIND_UPDATE => Ok(Message::Update(read_update(&mut r)?)),
        k => Err(WireError::UnknownKind(k)),
    }
}

/// Appends the CRC to a payload.
pub fn seal(mut payload: Vec<u8>) -> Result<Vec<u8>, WireError> {
    let crc = crc32(&payload);
    payload.extend_from_slice(&crc.to_le_bytes());
    if payload.len() > MAX_DATAGRAM {
        return Err(WireError::TooLarge(payload.len()));
    }
    Ok(payload)
}

/// Checks the CRC and returns the payload.
pub fn open(datagram: &[u8]) -> Result<&[u8], WireError> {
    if datagram.len() > MAX_DATAGRAM {
        return Err(WireError::TooLarge(datagram.len()));
    }
    let split = datagram.len().checked_sub(4).ok_or(WireError::TooShort)?;
    let (payload, tail) = datagram.split_at(split);
    let mut a = [0u8; 4];
    a.copy_from_slice(tail);
    if u32::from_le_bytes(a) != crc32(payload) {
        return Err(WireError::BadCrc);
    }
    Ok(payload)
}

/// Encodes a message as a sealed datagram.
pub fn encode_datagram(m: &Message) -> Result<Vec<u8>, WireError> {
    seal(encode_message(m))
}

/// Checks and decodes a datagram.
pub fn decode_datagram(datagram: &[u8]) -> Result<Message, WireError> {
    decode_message(open(datagram)?)
}

/// Size of an update's fixed fields (everything but the three chunks), CRC excluded.
pub fn update_header_size(u: &Update) -> usize {
    let mut w = Writer::new();
    w.u8(VERSION);
    w.u8(KIND_UPDATE);
    write_header(&mut w, u);
    w.len()
}
