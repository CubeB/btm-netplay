//! Lobby datagram encoding.
//!
//! ```text
//! magic "BL" | version (1) | kind | build id (len u8, bytes) | fields...
//! field = tag u8 | length u16 LE | payload
//! ```
//!
//! Fields are looked up by tag, the first of a repeated tag wins, and unknown tags are
//! skipped (forward compatibility, 3.1). Strings are a length byte then UTF-8; they are
//! cleaned and bounded on the way in. Nothing here can panic on arbitrary input.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use super::{
    clean, option_name_ok, ChatLine, Endpoint, MapInfo, ModDiff, ModDiffKind, ModDifference,
    ModEntry, ModSet, PathTable, RelaySeat, SeatInfo, SeatKind, MAX_ANNOUNCED_CHAT, MAX_BUILD_ID,
    MAX_CHAT_LINE, MAX_CLAIM_CHAT, MAX_LABEL, MAX_LOBBY_DATAGRAM, MAX_MAP_IDENTITY, MAX_MAP_NAME,
    MAX_MODS, MAX_MOD_ID, MAX_MOD_VERSION, MAX_NAME, MAX_OPTIONS, MAX_OPTION_NAME,
    MAX_OPTION_VALUE, MAX_PERSONALITY, MAX_RESOURCE, SEATS,
};

const MAGIC: [u8; 2] = *b"BL";
const VERSION: u8 = 1;
const MAX_INCOMING: usize = 1500;
const MAX_FIELDS: usize = 48;

/// Why a datagram was not understood.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Ended inside a value.
    Truncated,
    /// Not a lobby datagram.
    BadMagic,
    /// A version this build does not read.
    BadVersion(u8),
    /// An unknown message kind.
    BadKind(u8),
    /// Over the datagram bound.
    TooLong,
    /// A required field is absent (the tag).
    Missing(u8),
    /// A value out of range.
    Invalid,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated lobby message"),
            Self::BadMagic => write!(f, "not a lobby message"),
            Self::BadVersion(v) => write!(f, "unsupported lobby message version {v}"),
            Self::BadKind(k) => write!(f, "unknown lobby message kind {k}"),
            Self::TooLong => write!(f, "lobby message too long"),
            Self::Missing(t) => write!(f, "lobby message lacks field {t}"),
            Self::Invalid => write!(f, "invalid value in lobby message"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ---------------------------------------------------------------------------------------
// Messages.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Announce {
    pub build: Vec<u8>,
    pub session: u64,
    pub label: String,
    pub host_name: String,
    pub game_port: u16,
    pub map: Option<MapInfo>,
    pub challenge: Option<[u8; 16]>,
    pub epoch: u32,
    pub launching: bool,
    pub seed: u64,
    pub approval: bool,
    pub seats: Vec<SeatInfo>,
    pub options: Vec<(String, String)>,
    pub chat: Vec<ChatLine>,
    pub mods_hash: [u8; 32],
    pub paths: PathTable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Claim {
    pub build: Vec<u8>,
    pub session: u64,
    pub token: u32,
    pub name: String,
    pub seat: u8,
    pub side: u8,
    pub colour: u8,
    pub team: i8,
    pub ready: bool,
    pub epoch: Option<u32>,
    pub game_port: u16,
    pub game_addr: Option<Endpoint>,
    pub stun_addr: Option<Endpoint>,
    pub approval: bool,
    pub chat: Vec<(u32, String)>,
    pub proof: Option<[u8; 32]>,
    pub mods: ModSet,
    /// The sender's member index in the room's relay room, once joined.
    pub relay_member: Option<u8>,
    /// A bit per seat the sender has heard a punch from.
    pub heard: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RefuseReason {
    Build,
    Password,
    Mods,
    Full,
    Launching,
    Declined,
    Removed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Refuse {
    /// Build identity of the sender (the host), used for the version message.
    pub build: Vec<u8>,
    pub session: u64,
    pub token: u32,
    pub reason: RefuseReason,
    pub diff: ModDiff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Leave {
    pub session: u64,
    pub token: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Msg {
    Announce(Announce),
    Claim(Claim),
    Probe,
    Refuse(Refuse),
    Leave(Leave),
}

const KIND_ANNOUNCE: u8 = 1;
const KIND_CLAIM: u8 = 2;
const KIND_PROBE: u8 = 3;
const KIND_REFUSE: u8 = 4;
const KIND_LEAVE: u8 = 5;

// ---------------------------------------------------------------------------------------
// Writing.

fn put_str(out: &mut Vec<u8>, s: &str, max: usize) {
    let s = clean(s, max.min(255));
    out.push(u8::try_from(s.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(s.as_bytes());
}

fn put_addr(out: &mut Vec<u8>, a: Endpoint) {
    out.extend_from_slice(&a.ip().octets());
    out.extend_from_slice(&a.port().to_le_bytes());
}

fn put_opt_addr(out: &mut Vec<u8>, a: Option<Endpoint>) {
    match a {
        Some(a) => {
            out.push(1);
            put_addr(out, a);
        }
        None => out.push(0),
    }
}

fn put_field(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    let len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    out.push(tag);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body.get(..usize::from(len)).unwrap_or(body));
}

fn header(kind: u8, build: &[u8]) -> Vec<u8> {
    let mut out = vec![MAGIC[0], MAGIC[1], VERSION, kind];
    let build = build.get(..MAX_BUILD_ID).unwrap_or(build);
    out.push(u8::try_from(build.len()).unwrap_or(0));
    out.extend_from_slice(build);
    out
}

fn put_mods(out: &mut Vec<u8>, m: &ModSet) {
    out.extend_from_slice(m.hash());
    let list = m.mods();
    let n = list.len().min(MAX_MODS);
    out.push(u8::try_from(n).unwrap_or(0));
    for e in list.iter().take(n) {
        put_str(out, &e.id, MAX_MOD_ID);
        put_str(out, &e.version, MAX_MOD_VERSION);
        out.extend_from_slice(&e.hash);
    }
}

fn put_seat(out: &mut Vec<u8>, s: &SeatInfo) {
    let mut b = vec![
        s.index,
        match s.kind {
            SeatKind::Open => 0,
            SeatKind::Host => 1,
            SeatKind::Network => 2,
            SeatKind::Computer => 3,
        },
        s.side,
        s.colour,
    ];
    b.extend_from_slice(&s.team.to_le_bytes());
    b.push(u8::from(s.ready) | (u8::from(s.addr.is_some()) << 1));
    // Names only for seats a person plays (3.1: they seed the RNG).
    put_str(
        &mut b,
        if s.kind.is_human() { &s.name } else { "" },
        MAX_NAME,
    );
    if let Some(a) = s.addr {
        put_addr(&mut b, a);
    }
    b.extend_from_slice(&s.metal.min(MAX_RESOURCE).to_le_bytes());
    b.extend_from_slice(&s.energy.min(MAX_RESOURCE).to_le_bytes());
    put_str(&mut b, &s.personality, MAX_PERSONALITY);
    b.extend_from_slice(&s.token.to_le_bytes());
    let len = u16::try_from(b.len()).unwrap_or(0);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&b);
}

const NO_MEMBER: u8 = 0xFF;

fn put_paths(out: &mut Vec<u8>, p: &PathTable) {
    match p.relay {
        Some((relay, room)) => {
            out.push(1);
            put_addr(out, relay);
            out.extend_from_slice(&room.to_le_bytes());
        }
        None => out.push(0),
    }
    for (m, h) in p.members.iter().zip(p.heard.iter()) {
        match m {
            Some(r) => {
                out.push(r.member);
                out.extend_from_slice(&r.game_port.to_le_bytes());
            }
            None => {
                out.push(NO_MEMBER);
                out.extend_from_slice(&0u16.to_le_bytes());
            }
        }
        out.extend_from_slice(&h.to_le_bytes());
    }
}

fn announce_bytes(a: &Announce, chat_n: usize, opt_n: usize) -> Vec<u8> {
    let mut out = header(KIND_ANNOUNCE, &a.build);
    put_field(&mut out, 1, &a.session.to_le_bytes());
    let mut b = Vec::new();
    put_str(&mut b, &a.label, MAX_LABEL);
    put_str(&mut b, &a.host_name, MAX_NAME);
    put_field(&mut out, 2, &b);
    put_field(&mut out, 3, &a.game_port.to_le_bytes());
    if let Some(m) = &a.map {
        let mut b = Vec::new();
        put_str(&mut b, &m.name, MAX_MAP_NAME);
        put_str(&mut b, &m.identity, MAX_MAP_IDENTITY);
        put_field(&mut out, 4, &b);
    }
    if let Some(c) = &a.challenge {
        put_field(&mut out, 5, c);
    }
    put_field(&mut out, 6, &a.epoch.to_le_bytes());
    let mut b = vec![u8::from(a.launching) | (u8::from(a.approval) << 1)];
    b.extend_from_slice(&a.seed.to_le_bytes());
    put_field(&mut out, 7, &b);
    put_field(&mut out, 8, &a.mods_hash);
    let mut b = vec![u8::try_from(a.seats.len().min(SEATS)).unwrap_or(0)];
    for s in a.seats.iter().take(SEATS) {
        put_seat(&mut b, s);
    }
    put_field(&mut out, 9, &b);
    if opt_n > 0 {
        let mut b = vec![u8::try_from(opt_n).unwrap_or(0)];
        for (n, v) in a.options.iter().take(opt_n) {
            put_str(&mut b, n, MAX_OPTION_NAME);
            put_str(&mut b, v, MAX_OPTION_VALUE);
        }
        put_field(&mut out, 10, &b);
    }
    if chat_n > 0 {
        let mut b = vec![u8::try_from(chat_n).unwrap_or(0)];
        let skip = a.chat.len().saturating_sub(chat_n);
        for l in a.chat.iter().skip(skip) {
            b.extend_from_slice(&l.seq.to_le_bytes());
            put_str(&mut b, &l.from, MAX_NAME);
            put_str(&mut b, &l.text, MAX_CHAT_LINE);
        }
        put_field(&mut out, 11, &b);
    }
    let mut b = Vec::new();
    put_paths(&mut b, &a.paths);
    put_field(&mut out, 12, &b);
    out
}

/// Encode an announcement into one datagram of at most 1400 bytes: whole chat lines are
/// dropped oldest first, then trailing options one at a time (3.1); `None` if it still does
/// not fit (the lobby is then not advertised).
pub(super) fn encode_announce(a: &Announce) -> Option<Vec<u8>> {
    let mut chat_n = a.chat.len().min(MAX_ANNOUNCED_CHAT);
    let mut opt_n = a.options.len().min(MAX_OPTIONS);
    loop {
        let bytes = announce_bytes(a, chat_n, opt_n);
        if bytes.len() <= MAX_LOBBY_DATAGRAM {
            return Some(bytes);
        }
        if chat_n > 0 {
            chat_n -= 1;
        } else if opt_n > 0 {
            opt_n -= 1;
        } else {
            return None;
        }
    }
}

fn claim_bytes(c: &Claim, chat_n: usize) -> Vec<u8> {
    let mut out = header(KIND_CLAIM, &c.build);
    put_field(&mut out, 1, &c.session.to_le_bytes());
    put_field(&mut out, 2, &c.token.to_le_bytes());
    let mut b = Vec::new();
    put_str(&mut b, &c.name, MAX_NAME);
    put_field(&mut out, 3, &b);
    let mut b = vec![c.seat, c.side, c.colour];
    b.extend_from_slice(&c.team.to_le_bytes());
    put_field(&mut out, 4, &b);
    let mut b = vec![u8::from(c.ready) | (u8::from(c.epoch.is_some()) << 1)];
    b.extend_from_slice(&c.epoch.unwrap_or(0).to_le_bytes());
    put_field(&mut out, 5, &b);
    let mut b = c.game_port.to_le_bytes().to_vec();
    put_opt_addr(&mut b, c.game_addr);
    put_opt_addr(&mut b, c.stun_addr);
    b.push(u8::from(c.approval));
    put_field(&mut out, 6, &b);
    if let Some(p) = &c.proof {
        put_field(&mut out, 7, p);
    }
    let mut b = Vec::new();
    put_mods(&mut b, &c.mods);
    put_field(&mut out, 8, &b);
    if chat_n > 0 {
        let mut b = vec![u8::try_from(chat_n).unwrap_or(0)];
        let skip = c.chat.len().saturating_sub(chat_n);
        for (seq, text) in c.chat.iter().skip(skip) {
            b.extend_from_slice(&seq.to_le_bytes());
            put_str(&mut b, text, MAX_CHAT_LINE);
        }
        put_field(&mut out, 9, &b);
    }
    let mut b = vec![c.relay_member.unwrap_or(NO_MEMBER)];
    b.extend_from_slice(&c.heard.to_le_bytes());
    put_field(&mut out, 10, &b);
    out
}

/// Encode a claim; chat lines are dropped oldest first if it would not fit.
pub(super) fn encode_claim(c: &Claim) -> Option<Vec<u8>> {
    let mut n = c.chat.len().min(MAX_CLAIM_CHAT);
    loop {
        let bytes = claim_bytes(c, n);
        if bytes.len() <= MAX_LOBBY_DATAGRAM {
            return Some(bytes);
        }
        if n == 0 {
            return None;
        }
        n -= 1;
    }
}

pub(super) fn encode_probe(build: &[u8]) -> Vec<u8> {
    header(KIND_PROBE, build)
}

pub(super) fn encode_leave(build: &[u8], l: &Leave) -> Vec<u8> {
    let mut out = header(KIND_LEAVE, build);
    put_field(&mut out, 1, &l.session.to_le_bytes());
    put_field(&mut out, 2, &l.token.to_le_bytes());
    out
}

pub(super) fn encode_refuse(r: &Refuse) -> Vec<u8> {
    let mut out = header(KIND_REFUSE, &r.build);
    put_field(&mut out, 1, &r.session.to_le_bytes());
    put_field(&mut out, 2, &r.token.to_le_bytes());
    let code = match r.reason {
        RefuseReason::Build => 0,
        RefuseReason::Password => 1,
        RefuseReason::Mods => 2,
        RefuseReason::Full => 3,
        RefuseReason::Launching => 4,
        RefuseReason::Declined => 5,
        RefuseReason::Removed => 6,
    };
    put_field(&mut out, 3, &[code]);
    let mut b = Vec::new();
    let n = r.diff.entries.len().min(2 * MAX_MODS);
    b.push(u8::try_from(n).unwrap_or(0));
    for e in r.diff.entries.iter().take(n) {
        b.push(match e.kind {
            ModDiffKind::MissingFromGuest => 0,
            ModDiffKind::ExtraOnGuest => 1,
            ModDiffKind::Different => 2,
        });
        put_str(&mut b, &e.id, MAX_MOD_ID);
    }
    put_field(&mut out, 4, &b);
    out
}

// ---------------------------------------------------------------------------------------
// Reading.

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let s = self.b.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?.try_into().map_err(|_| DecodeError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    fn i8(&mut self) -> Result<i8, DecodeError> {
        Ok(i8::from_le_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn string(&mut self, max: usize) -> Result<String, DecodeError> {
        let n = usize::from(self.u8()?);
        let raw = self.take(n)?;
        Ok(clean(&String::from_utf8_lossy(raw), max))
    }

    fn addr(&mut self) -> Result<Endpoint, DecodeError> {
        let ip = Ipv4Addr::from(self.array::<4>()?);
        Ok(SocketAddrV4::new(ip, self.u16()?))
    }

    fn opt_addr(&mut self) -> Result<Option<Endpoint>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.addr()?)),
            _ => Err(DecodeError::Invalid),
        }
    }
}

struct Fields<'a>(Vec<(u8, &'a [u8])>);

impl<'a> Fields<'a> {
    fn parse(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let mut v = Vec::new();
        while r.pos < r.b.len() {
            if v.len() >= MAX_FIELDS {
                return Err(DecodeError::Invalid);
            }
            let tag = r.u8()?;
            let len = usize::from(r.u16()?);
            v.push((tag, r.take(len)?));
        }
        Ok(Self(v))
    }

    fn find(&self, tag: u8) -> Option<&'a [u8]> {
        self.0.iter().find(|(t, _)| *t == tag).map(|(_, b)| *b)
    }

    fn need(&self, tag: u8) -> Result<Reader<'a>, DecodeError> {
        self.find(tag)
            .map(Reader::new)
            .ok_or(DecodeError::Missing(tag))
    }
}

fn read_mods(r: &mut Reader<'_>) -> Result<ModSet, DecodeError> {
    let hash = r.array::<32>()?;
    let n = usize::from(r.u8()?);
    if n > MAX_MODS {
        return Err(DecodeError::Invalid);
    }
    let mut mods = Vec::with_capacity(n);
    for _ in 0..n {
        let id = r.string(MAX_MOD_ID)?;
        let version = r.string(MAX_MOD_VERSION)?;
        let hash = r.array::<32>()?;
        mods.push(ModEntry { id, version, hash });
    }
    ModSet::new(hash, mods).map_err(|_| DecodeError::Invalid)
}

fn read_seat(r: &mut Reader<'_>) -> Result<SeatInfo, DecodeError> {
    let len = usize::from(r.u16()?);
    let mut s = Reader::new(r.take(len)?);
    let index = s.u8()?;
    if usize::from(index) >= SEATS {
        return Err(DecodeError::Invalid);
    }
    let kind = match s.u8()? {
        0 => SeatKind::Open,
        1 => SeatKind::Host,
        2 => SeatKind::Network,
        3 => SeatKind::Computer,
        _ => return Err(DecodeError::Invalid),
    };
    let side = s.u8()?;
    let colour = s.u8()?;
    let team = s.i8()?.clamp(-1, 9);
    let flags = s.u8()?;
    let name = s.string(MAX_NAME)?;
    let addr = if flags & 2 != 0 {
        Some(s.addr()?)
    } else {
        None
    };
    let metal = s.u32()?.min(MAX_RESOURCE);
    let energy = s.u32()?.min(MAX_RESOURCE);
    let personality = s.string(MAX_PERSONALITY)?;
    let token = s.u32()?;
    Ok(SeatInfo {
        index,
        kind,
        side,
        colour,
        team,
        name: if kind.is_human() { name } else { String::new() },
        addr,
        metal,
        energy,
        personality,
        ready: flags & 1 != 0,
        token,
    })
}

fn read_member(member: u8) -> Result<Option<u8>, DecodeError> {
    match member {
        NO_MEMBER => Ok(None),
        m if m < crate::relay::MAX_MEMBERS => Ok(Some(m)),
        _ => Err(DecodeError::Invalid),
    }
}

fn read_paths(r: &mut Reader<'_>) -> Result<PathTable, DecodeError> {
    let relay = match r.u8()? {
        0 => None,
        1 => Some((r.addr()?, r.u64()?)),
        _ => return Err(DecodeError::Invalid),
    };
    let mut p = PathTable {
        relay,
        ..PathTable::default()
    };
    for i in 0..SEATS {
        let member = read_member(r.u8()?)?;
        let game_port = r.u16()?;
        let heard = r.u16()?;
        if let Some(slot) = p.members.get_mut(i) {
            *slot = member.map(|member| RelaySeat { member, game_port });
        }
        if let Some(slot) = p.heard.get_mut(i) {
            *slot = heard & ((1 << SEATS) - 1);
        }
    }
    Ok(p)
}

fn read_announce(build: Vec<u8>, f: &Fields<'_>) -> Result<Announce, DecodeError> {
    let session = f.need(1)?.u64()?;
    let mut r = f.need(2)?;
    let label = r.string(MAX_LABEL)?;
    let host_name = r.string(MAX_NAME)?;
    let game_port = f.need(3)?.u16()?;
    let map = match f.find(4) {
        Some(b) => {
            let mut r = Reader::new(b);
            let name = r.string(MAX_MAP_NAME)?;
            let identity = r.string(MAX_MAP_IDENTITY)?;
            if name.is_empty() {
                None
            } else {
                Some(MapInfo { name, identity })
            }
        }
        None => None,
    };
    let challenge = match f.find(5) {
        Some(b) => Some(Reader::new(b).array::<16>()?),
        None => None,
    };
    let epoch = f.need(6)?.u32()?;
    let mut r = f.need(7)?;
    let flags = r.u8()?;
    let seed = r.u64()?;
    let mods_hash = f.need(8)?.array::<32>()?;
    let mut r = f.need(9)?;
    let n = usize::from(r.u8()?);
    if n > SEATS {
        return Err(DecodeError::Invalid);
    }
    let mut seats: Vec<SeatInfo> = Vec::with_capacity(n);
    for _ in 0..n {
        let s = read_seat(&mut r)?;
        if seats.iter().any(|o| o.index == s.index) {
            return Err(DecodeError::Invalid);
        }
        seats.push(s);
    }
    let mut options: Vec<(String, String)> = Vec::new();
    if let Some(b) = f.find(10) {
        let mut r = Reader::new(b);
        let n = usize::from(r.u8()?);
        if n > MAX_OPTIONS {
            return Err(DecodeError::Invalid);
        }
        for _ in 0..n {
            let name = r.string(MAX_OPTION_NAME)?;
            let value = r.string(MAX_OPTION_VALUE)?;
            // First of a repeated name wins; malformed names are skipped (3.1).
            if option_name_ok(&name) && !options.iter().any(|(o, _)| *o == name) {
                options.push((name, value));
            }
        }
    }
    let mut chat = Vec::new();
    if let Some(b) = f.find(11) {
        let mut r = Reader::new(b);
        let n = usize::from(r.u8()?);
        if n > MAX_ANNOUNCED_CHAT {
            return Err(DecodeError::Invalid);
        }
        for _ in 0..n {
            let seq = r.u32()?;
            let from = r.string(MAX_NAME)?;
            let text = r.string(MAX_CHAT_LINE)?;
            chat.push(ChatLine { seq, from, text });
        }
    }
    Ok(Announce {
        build,
        session,
        label,
        host_name,
        game_port,
        map,
        challenge,
        epoch,
        launching: flags & 1 != 0,
        seed,
        approval: flags & 2 != 0,
        seats,
        options,
        chat,
        mods_hash,
        paths: match f.find(12) {
            Some(b) => read_paths(&mut Reader::new(b))?,
            None => PathTable::default(),
        },
    })
}

fn read_claim(build: Vec<u8>, f: &Fields<'_>) -> Result<Claim, DecodeError> {
    let session = f.need(1)?.u64()?;
    let token = f.need(2)?.u32()?;
    let name = f.need(3)?.string(MAX_NAME)?;
    let mut r = f.need(4)?;
    let seat = r.u8()?;
    let side = r.u8()?;
    let colour = r.u8()?;
    let team = r.i8()?.clamp(-1, 9);
    let mut r = f.need(5)?;
    let flags = r.u8()?;
    let epoch_raw = r.u32()?;
    let mut r = f.need(6)?;
    let game_port = r.u16()?;
    let game_addr = r.opt_addr()?;
    let stun_addr = r.opt_addr()?;
    let approval = r.u8()? != 0;
    let proof = match f.find(7) {
        Some(b) => Some(Reader::new(b).array::<32>()?),
        None => None,
    };
    let mods = read_mods(&mut f.need(8)?)?;
    let mut chat = Vec::new();
    if let Some(b) = f.find(9) {
        let mut r = Reader::new(b);
        let n = usize::from(r.u8()?);
        if n > MAX_CLAIM_CHAT {
            return Err(DecodeError::Invalid);
        }
        for _ in 0..n {
            let seq = r.u32()?;
            chat.push((seq, r.string(MAX_CHAT_LINE)?));
        }
    }
    let (relay_member, heard) = match f.find(10) {
        Some(b) => {
            let mut r = Reader::new(b);
            (read_member(r.u8()?)?, r.u16()?)
        }
        None => (None, 0),
    };
    Ok(Claim {
        build,
        session,
        token,
        name,
        seat,
        side,
        colour,
        team,
        ready: flags & 1 != 0,
        epoch: (flags & 2 != 0).then_some(epoch_raw),
        game_port,
        game_addr,
        stun_addr,
        approval,
        chat,
        proof,
        mods,
        relay_member,
        heard: heard & ((1 << SEATS) - 1),
    })
}

fn read_refuse(build: Vec<u8>, f: &Fields<'_>) -> Result<Refuse, DecodeError> {
    let session = f.need(1)?.u64()?;
    let token = f.need(2)?.u32()?;
    let reason = match f.need(3)?.u8()? {
        0 => RefuseReason::Build,
        1 => RefuseReason::Password,
        2 => RefuseReason::Mods,
        3 => RefuseReason::Full,
        4 => RefuseReason::Launching,
        5 => RefuseReason::Declined,
        6 => RefuseReason::Removed,
        _ => return Err(DecodeError::Invalid),
    };
    let mut entries = Vec::new();
    if let Some(b) = f.find(4) {
        let mut r = Reader::new(b);
        let n = usize::from(r.u8()?);
        if n > 2 * MAX_MODS {
            return Err(DecodeError::Invalid);
        }
        for _ in 0..n {
            let kind = match r.u8()? {
                0 => ModDiffKind::MissingFromGuest,
                1 => ModDiffKind::ExtraOnGuest,
                2 => ModDiffKind::Different,
                _ => return Err(DecodeError::Invalid),
            };
            entries.push(ModDifference {
                id: r.string(MAX_MOD_ID)?,
                kind,
            });
        }
    }
    Ok(Refuse {
        build,
        session,
        token,
        reason,
        diff: ModDiff { entries },
    })
}

/// Decode one datagram. Total: any byte string gives a `Msg` or an error.
pub(super) fn decode(bytes: &[u8]) -> Result<Msg, DecodeError> {
    if bytes.len() > MAX_INCOMING {
        return Err(DecodeError::TooLong);
    }
    let mut r = Reader::new(bytes);
    if r.array::<2>()? != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let version = r.u8()?;
    if version != VERSION {
        return Err(DecodeError::BadVersion(version));
    }
    let kind = r.u8()?;
    let blen = usize::from(r.u8()?);
    if blen > MAX_BUILD_ID {
        return Err(DecodeError::Invalid);
    }
    let build = r.take(blen)?.to_vec();
    let fields = Fields::parse(&mut r)?;
    match kind {
        KIND_ANNOUNCE => read_announce(build, &fields).map(Msg::Announce),
        KIND_CLAIM => read_claim(build, &fields).map(Msg::Claim),
        KIND_PROBE => Ok(Msg::Probe),
        KIND_REFUSE => read_refuse(build, &fields).map(Msg::Refuse),
        KIND_LEAVE => Ok(Msg::Leave(Leave {
            session: fields.need(1)?.u64()?,
            token: fields.need(2)?.u32()?,
        })),
        k => Err(DecodeError::BadKind(k)),
    }
}
