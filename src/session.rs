//! The lobby (SPEC section 3 and 2.9): announcements, seats, ready flags, identity checks,
//! password, host approval and the start handshake.
//!
//! Sans-IO. A [`HostLobby`] and a [`GuestLobby`] are state machines. The caller passes the
//! current [`Instant`], received datagrams with their source [`Endpoint`], and UI actions.
//! Every call returns a [`Step`]: datagrams to send and typed events. The lobby never reads a
//! clock and never touches a socket. Randomness (session id, claim tokens, the password
//! challenge) comes in through the configuration.
//!
//! The datagrams use this crate's own compact binary encoding (see `codec`): a magic, a
//! version byte, a kind byte, the sender's build identity, then tagged fields. Unknown tags
//! are skipped, so newer senders stay readable. Every read is bounds-checked.
//!
//! # Deliberate deviations from the spec
//!
//! * **Mod sets are checked in the lobby.** SPEC 3.9 leaves archive matching to a separate
//!   launcher. Here every peer announces a resolved mod-set hash plus a list of
//!   `(mod id, version, hash)` ([`ModSet`]); the host refuses a guest whose set differs and the
//!   refusal names exactly the mods that differ ([`ModDiff`]). The host announcement carries
//!   only the hash (a full list does not fit a 1400-byte datagram next to ten seats); the
//!   guest's claim carries its list, and the host answers a mismatch with a refusal naming
//!   the differing mods.
//! * The password is never sent. The host announces a random challenge; a claim carries
//!   `HMAC-SHA-256(password, context || session || challenge || claim token)`.
//! * Guests are refused with an explicit message as well as being shown by the announcement
//!   (faster and typed); the announcement alone would also converge, as in the spec.
//!
//! # Choices where the spec is silent
//!
//! See the notes on each item; the main ones: the host always sits in seat 0; claims go by
//! unicast to the host only (the caller may duplicate them to a broadcast address); a seat
//! token has its own field rather than reusing the personality string; the claim token is
//! 32 bits; the seed is chosen by the caller at start and travels in the launching
//! announcement; a start needs at least one network seat.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::types::{Endpoint, Instant, Outgoing, PlayerId};

mod codec;
mod guest;
mod host;
mod sha256;

pub use codec::DecodeError;
pub use guest::{GuestConfig, GuestEvent, GuestLobby, GuestStatus};
pub use host::{AcceptError, HostConfig, HostEvent, HostLobby, PendingRequest};
pub use sha256::{hmac_sha256, sha256};

/// Number of seats; the seat index is the player id (3.8).
pub const SEATS: usize = 10;
/// Default discovery port.
pub const DISCOVERY_PORT: u16 = 1338;
/// Default in-game lobby game port.
pub const GAME_PORT: u16 = 1337;
/// Longest display name in bytes (3.1).
pub const MAX_NAME: usize = 20;
/// Longest chat line in bytes (3.1).
pub const MAX_CHAT_LINE: usize = 80;
/// Chat lines carried in an announcement (3.1).
pub const MAX_ANNOUNCED_CHAT: usize = 8;
/// Chat lines kept in the host transcript (3.2).
pub const MAX_TRANSCRIPT: usize = 200;
/// Chat lines a claim repeats (3.2).
pub const MAX_CLAIM_CHAT: usize = 4;
/// Options per announcement (3.1).
pub const MAX_OPTIONS: usize = 32;
/// Longest option name / value.
pub const MAX_OPTION_NAME: usize = 32;
pub const MAX_OPTION_VALUE: usize = 64;
/// Longest build identity in bytes.
pub const MAX_BUILD_ID: usize = 48;
/// Longest map name / map identity.
pub const MAX_MAP_NAME: usize = 64;
pub const MAX_MAP_IDENTITY: usize = 64;
/// Longest game label.
pub const MAX_LABEL: usize = 32;
/// Longest AI personality.
pub const MAX_PERSONALITY: usize = 32;
/// Mod list bounds (a claim must fit one datagram).
pub const MAX_MODS: usize = 16;
pub const MAX_MOD_ID: usize = 24;
pub const MAX_MOD_VERSION: usize = 12;
/// Resource clamp (3.1).
pub const MAX_RESOURCE: u32 = 1_000_000;
/// Default starting resources.
pub const DEFAULT_RESOURCE: u32 = 1000;
/// Largest lobby datagram (3.1).
pub const MAX_LOBBY_DATAGRAM: usize = 1400;
/// Pending join requests kept (2.9).
pub const MAX_PENDING: usize = 10;

/// Host announcement period (2.10).
pub const ANNOUNCE_PERIOD: Duration = Duration::from_millis(1000);
/// Minimum gap between change announcements (2.10).
pub const ANNOUNCE_CHANGE_GAP: Duration = Duration::from_millis(100);
/// A heard claim or announcement is forgotten this long after the last one (3.2).
pub const CLAIM_EXPIRY: Duration = Duration::from_millis(3500);
/// Launching window (3.7).
pub const LAUNCH_WINDOW: Duration = Duration::from_millis(2500);
/// Guest: host gone (3.2).
pub const HOST_GONE: Duration = Duration::from_secs(5);
/// Guest: host did not answer (3.2).
pub const HOST_NO_ANSWER: Duration = Duration::from_secs(8);
/// A guest holds its own side/colour/team choice this long (3.2).
pub const CHOICE_HOLD: Duration = Duration::from_secs(2);

/// What a seat holds (3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SeatKind {
    /// Free.
    Open,
    /// The host's own human.
    Host,
    /// A person playing from another machine.
    Network,
    /// A computer player.
    Computer,
}

impl SeatKind {
    /// A seat a person plays (names are only carried for these; they seed the RNG).
    pub fn is_human(self) -> bool {
        matches!(self, Self::Host | Self::Network)
    }
}

/// One seat as announced (3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatInfo {
    pub index: u8,
    pub kind: SeatKind,
    pub side: u8,
    /// 0..=255 on the wire, 0..=9 meaningful.
    pub colour: u8,
    /// -1 (none) ..= 9 on the wire, -1..=4 used.
    pub team: i8,
    /// Only for human seats.
    pub name: String,
    /// Game address of a human seat, once known.
    pub addr: Option<Endpoint>,
    pub metal: u32,
    pub energy: u32,
    /// AI personality (computer seats).
    pub personality: String,
    pub ready: bool,
    /// Claim token of the guest holding a network seat (0 otherwise).
    pub token: u32,
}

impl SeatInfo {
    pub fn open(index: u8) -> Self {
        Self {
            index,
            kind: SeatKind::Open,
            side: 0,
            colour: index,
            team: -1,
            name: String::new(),
            addr: None,
            metal: DEFAULT_RESOURCE,
            energy: DEFAULT_RESOURCE,
            personality: String::new(),
            ready: false,
            token: 0,
        }
    }
}

/// Which map the room plays and how to recognise the same files (3.5).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MapInfo {
    pub name: String,
    /// See [`map_identity`]; empty means unknown (not checked).
    pub identity: String,
}

/// One chat line (3.1, 3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatLine {
    /// Host-assigned sequence number.
    pub seq: u32,
    pub from: String,
    pub text: String,
}

impl fmt::Display for ChatLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.from, self.text)
    }
}

/// Why a mod set was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModSetError {
    /// More than [`MAX_MODS`].
    TooMany,
    /// An id or version is empty (id), too long, or has control characters.
    BadText(String),
}

impl fmt::Display for ModSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooMany => write!(f, "more than {MAX_MODS} mods"),
            Self::BadText(s) => write!(f, "bad mod id or version: {s}"),
        }
    }
}

impl std::error::Error for ModSetError {}

/// One installed mod.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModEntry {
    pub id: String,
    pub version: String,
    pub hash: [u8; 32],
}

/// A peer's resolved mod set: one hash over everything plus the per-mod list used to name
/// differences. Bounded; build it with [`ModSet::new`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ModSet {
    hash: [u8; 32],
    mods: Vec<ModEntry>,
}

/// How one mod differs between host and guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModDiffKind {
    /// The host has it, the guest does not.
    MissingFromGuest,
    /// The guest has it, the host does not.
    ExtraOnGuest,
    /// Both have it, with another version or contents.
    Different,
}

/// One differing mod.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModDifference {
    pub id: String,
    pub kind: ModDiffKind,
}

/// The mods that differ between two sets. Empty `entries` with a refusal means the sets'
/// hashes differ although every listed mod matches (for example a different load order).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ModDiff {
    pub entries: Vec<ModDifference>,
}

impl fmt::Display for ModDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.entries.is_empty() {
            return write!(f, "the mod sets differ (check mods and load order)");
        }
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            let why = match e.kind {
                ModDiffKind::MissingFromGuest => "missing from the guest",
                ModDiffKind::ExtraOnGuest => "not on the host",
                ModDiffKind::Different => "different version or contents",
            };
            write!(f, "{} ({why})", e.id)?;
        }
        Ok(())
    }
}

impl ModSet {
    /// Validate and build. `hash` is the caller's resolved mod-set hash (it should cover load
    /// order); the per-mod hashes are the caller's per-archive digests.
    pub fn new(hash: [u8; 32], mods: Vec<ModEntry>) -> Result<Self, ModSetError> {
        if mods.len() > MAX_MODS {
            return Err(ModSetError::TooMany);
        }
        for m in &mods {
            let ok = !m.id.is_empty()
                && m.id.len() <= MAX_MOD_ID
                && m.version.len() <= MAX_MOD_VERSION
                && !m.id.chars().chain(m.version.chars()).any(char::is_control);
            if !ok {
                return Err(ModSetError::BadText(m.id.clone()));
            }
        }
        Ok(Self { hash, mods })
    }

    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn mods(&self) -> &[ModEntry] {
        &self.mods
    }

    /// Host-side comparison: `self` is the host's set, `guest` the guest's. `None` if they
    /// agree (equal hashes).
    pub fn diff(&self, guest: &ModSet) -> Option<ModDiff> {
        if self.hash == guest.hash {
            return None;
        }
        let find = |list: &'_ [ModEntry], id: &str| list.iter().position(|m| m.id == id);
        let mut entries = Vec::new();
        for m in &self.mods {
            match find(&guest.mods, &m.id).and_then(|i| guest.mods.get(i)) {
                None => entries.push(ModDifference {
                    id: m.id.clone(),
                    kind: ModDiffKind::MissingFromGuest,
                }),
                Some(g) if g.version != m.version || g.hash != m.hash => {
                    entries.push(ModDifference {
                        id: m.id.clone(),
                        kind: ModDiffKind::Different,
                    })
                }
                Some(_) => {}
            }
        }
        for g in &guest.mods {
            if find(&self.mods, &g.id).is_none() {
                entries.push(ModDifference {
                    id: g.id.clone(),
                    kind: ModDiffKind::ExtraOnGuest,
                });
            }
        }
        Some(ModDiff { entries })
    }
}

/// The room as every peer sees it: the host's announcement, mirrored (3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LobbyView {
    pub session: u64,
    pub label: String,
    pub host_name: String,
    pub map: Option<MapInfo>,
    /// Name/value options, at most [`MAX_OPTIONS`].
    pub options: Vec<(String, String)>,
    /// Always [`SEATS`] entries, indexed by seat.
    pub seats: Vec<SeatInfo>,
    /// Setup epoch (3.3).
    pub epoch: u32,
    pub launching: bool,
    pub approval_required: bool,
    /// Tail of the room chat (at most 8 lines).
    pub chat: Vec<ChatLine>,
}

impl LobbyView {
    pub fn option(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Lowest-numbered open seat.
    pub fn first_open_seat(&self) -> Option<u8> {
        self.seats
            .iter()
            .find(|s| s.kind == SeatKind::Open)
            .map(|s| s.index)
    }
}

/// Everything `lockstep` needs once the lobby has agreed (3.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameStart {
    /// The room's session id.
    pub session: u64,
    /// This peer's seat (= player id).
    pub my_seat: PlayerId,
    /// The map.
    pub map: MapInfo,
    /// The agreed options: known names with valid values only (see [`option_valid`]).
    pub options: Vec<(String, String)>,
    /// The random seed the host chose.
    pub seed: u64,
    /// The seat table, all [`SEATS`] entries, with addresses of human seats.
    pub seats: Vec<SeatInfo>,
    /// Seat to game endpoint for every *remote* human seat.
    pub peers: Vec<(PlayerId, Endpoint)>,
    /// The game port this peer should bind (the same port as the lobby used).
    pub local_game_port: u16,
}

impl GameStart {
    /// Human seats in seat order: `(player, name)`, including this peer.
    pub fn human_players(&self) -> Vec<(PlayerId, &str)> {
        self.seats
            .iter()
            .filter(|s| s.kind.is_human())
            .map(|s| (PlayerId(s.index), s.name.as_str()))
            .collect()
    }

    /// Computer seats in seat order: `(player, personality)`.
    pub fn computer_players(&self) -> Vec<(PlayerId, &str)> {
        self.seats
            .iter()
            .filter(|s| s.kind == SeatKind::Computer)
            .map(|s| (PlayerId(s.index), s.personality.as_str()))
            .collect()
    }

    /// The endpoint of a remote human seat.
    pub fn endpoint_of(&self, p: PlayerId) -> Option<Endpoint> {
        self.peers.iter().find(|(id, _)| *id == p).map(|(_, e)| *e)
    }

    /// A seed for the simulation derived from the agreed seed and the human names in seat
    /// order (1.9: the names seed the RNG, so they must agree). FNV-1a, 64 bit.
    pub fn simulation_seed(&self) -> u64 {
        let mut h = fnv1a(0xcbf2_9ce4_8422_2325, &self.seed.to_le_bytes());
        for (id, name) in self.human_players() {
            h = fnv1a(h, &[id.0, 0]);
            h = fnv1a(h, name.as_bytes());
            h = fnv1a(h, &[0xff]);
        }
        h
    }

    pub(crate) fn from_view(
        view: &LobbyView,
        my_seat: u8,
        seed: u64,
        local_game_port: u16,
    ) -> Option<Self> {
        let mut seats = view.seats.clone();
        for s in &mut seats {
            if !s.kind.is_human() {
                s.name.clear();
            }
        }
        let peers = seats
            .iter()
            .filter(|s| s.kind.is_human() && s.index != my_seat)
            .filter_map(|s| s.addr.map(|a| (PlayerId(s.index), a)))
            .collect();
        Some(Self {
            session: view.session,
            my_seat: PlayerId(my_seat),
            map: view.map.clone()?,
            options: view
                .options
                .iter()
                .filter(|(n, v)| option_known(n) && option_valid(n, v))
                .cloned()
                .collect(),
            seed,
            seats,
            peers,
            local_game_port,
        })
    }
}

/// Datagrams to send and events to show, returned by every call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step<E> {
    pub send: Vec<crate::types::Outgoing>,
    pub events: Vec<E>,
}

impl<E> Default for Step<E> {
    fn default() -> Self {
        Self {
            send: Vec::new(),
            events: Vec::new(),
        }
    }
}

/// Why a join failed or ended: the guest's messages (3.2, section 9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinError {
    NameRequired,
    AlreadyStarted,
    VersionMismatch {
        theirs: String,
        mine: String,
    },
    IncorrectPassword,
    NoMap(String),
    MapMismatch(String),
    GameFull,
    /// The host named the mods that differ.
    ModMismatch(ModDiff),
    /// The host declined the join request (host approval).
    Declined,
    HostLeft,
    HostDidNotAnswer,
    Removed,
    CouldNotLoadMap(String),
    /// A claim could not be built (cannot happen with a valid configuration).
    BadConfig,
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameRequired => write!(f, "You must enter your name"),
            Self::AlreadyStarted => write!(f, "That game has already started"),
            Self::VersionMismatch { theirs, mine } => {
                write!(f, "That game is version {theirs} and this is {mine}")
            }
            Self::IncorrectPassword => write!(f, "Incorrect password"),
            Self::NoMap(m) => write!(f, "You do not have the map {m}"),
            Self::MapMismatch(m) => write!(f, "Your copy of the map {m} is not the host's"),
            Self::GameFull => write!(f, "The game is full"),
            Self::ModMismatch(d) => write!(f, "Your mods do not match the host's: {d}"),
            Self::Declined => write!(f, "The host declined your join request"),
            Self::HostLeft => write!(f, "The host has left"),
            Self::HostDidNotAnswer => write!(f, "The host did not answer"),
            Self::Removed => write!(f, "You were removed from the game"),
            Self::CouldNotLoadMap(m) => write!(f, "Could not load the map {m}"),
            Self::BadConfig => write!(f, "The join request could not be built"),
        }
    }
}

impl std::error::Error for JoinError {}

/// Why the host cannot start yet (3.3); the help line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartBlocker {
    NoMap,
    WaitingForReady(String),
    WaitingForPlayer,
}

impl fmt::Display for StartBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMap => write!(f, "Select a map"),
            Self::WaitingForReady(n) => write!(f, "Waiting for {n} to be ready"),
            Self::WaitingForPlayer => write!(f, "Waiting for another player to join"),
        }
    }
}

/// Errors from host actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostError {
    NameRequired,
    GameNameRequired,
    ModSet(ModSetError),
    NoSuchSeat(u8),
    /// The seat is held by a guest (use removal) or is the host's.
    SeatNotEditable(u8),
    ColourTaken(u8),
    BadOption,
    TooManyOptions,
    StartBlocked(StartBlocker),
    AlreadyLaunching,
    NotRunning,
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameRequired => write!(f, "You must enter your name"),
            Self::GameNameRequired => write!(f, "You must enter a game name"),
            Self::ModSet(e) => write!(f, "{e}"),
            Self::NoSuchSeat(i) => write!(f, "There is no seat {i}"),
            Self::SeatNotEditable(i) => write!(f, "Seat {i} cannot be changed that way"),
            Self::ColourTaken(c) => write!(f, "Colour {c} is already taken"),
            Self::BadOption => write!(f, "Invalid game option"),
            Self::TooManyOptions => write!(f, "Too many game options"),
            Self::StartBlocked(b) => write!(f, "{b}"),
            Self::AlreadyLaunching => write!(f, "Starting game..."),
            Self::NotRunning => write!(f, "The lobby is closed"),
        }
    }
}

impl std::error::Error for HostError {}

// ---------------------------------------------------------------------------------------
// Small shared helpers.

/// Remove control characters, trim, and cut to at most `max` bytes on a character boundary.
pub(crate) fn clean(s: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_control() {
            continue;
        }
        if out.len() + ch.len_utf8() > max {
            break;
        }
        out.push(ch);
    }
    out.trim().to_owned()
}

/// 64-bit FNV-1a continued from `h`.
pub fn fnv1a(mut h: u64, data: &[u8]) -> u64 {
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Map identity (3.5): `<desc size hex>-<terrain size hex>-<FNV-1a 64 over desc, 0xFF,
/// terrain, 16 hex digits>`.
pub fn map_identity(description: &[u8], terrain: &[u8]) -> String {
    let h = fnv1a(0xcbf2_9ce4_8422_2325, description);
    let h = fnv1a(h, &[0xff]);
    let h = fnv1a(h, terrain);
    format!("{:x}-{:x}-{h:016x}", description.len(), terrain.len())
}

/// Build compatibility (3.4), `mine` vs `theirs`: compatible if mine is empty or
/// `unknown`; incompatible if theirs is empty (absent); compatible if theirs is `unknown`;
/// otherwise compatible exactly when the byte strings are equal.
pub fn build_compatible(mine: &[u8], theirs: &[u8]) -> bool {
    if mine.is_empty() || mine == b"unknown" {
        return true;
    }
    if theirs.is_empty() {
        return false;
    }
    theirs == b"unknown" || mine == theirs
}

/// Display form of a build identity: first 8 characters plus `-d` if dirty; "an older
/// version" for absent.
pub fn display_build(id: &[u8]) -> String {
    if id.is_empty() {
        return "an older version".to_owned();
    }
    let s = String::from_utf8_lossy(id);
    let (body, dirty) = match s.strip_suffix("-d") {
        Some(b) => (b, true),
        None => (&*s, false),
    };
    let mut out: String = body.chars().take(8).collect();
    if dirty {
        out.push_str("-d");
    }
    out
}

fn same_net16(a: Ipv4Addr, b: Ipv4Addr) -> bool {
    let (a, b) = (a.octets(), b.octets());
    a[0] == b[0] && a[1] == b[1]
}

/// Which address a peer is believed to be at (2.8): the announced game address if it is in
/// the same /16 as the source of its lobby datagrams, else source IP plus the game port.
pub(crate) fn resolve_addr(src: Endpoint, announced: Option<Endpoint>, port: u16) -> Endpoint {
    match announced {
        Some(a) if same_net16(*a.ip(), *src.ip()) => a,
        _ => SocketAddrV4::new(*src.ip(), port),
    }
}

const KNOWN_OPTIONS: &[(&str, &[&str])] = &[
    ("commander_rule", &["ends", "continues", "deathmatch"]),
    ("start_locations", &["fixed", "random"]),
    ("mapping", &["unmapped", "mapped"]),
    ("line_of_sight", &["permanent", "true", "circular"]),
    ("difficulty", &["easy", "medium", "hard"]),
    ("community", &["on", "off"]),
];

/// Whether the option name is one the lobby knows how to apply.
pub fn option_known(name: &str) -> bool {
    KNOWN_OPTIONS.iter().any(|(n, _)| *n == name)
}

/// An option name is `[A-Za-z0-9_]{1,32}`.
pub fn option_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_OPTION_NAME
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Whether a name/value pair may be carried: the name is `[A-Za-z0-9_]{1,32}`, the value at
/// most 64 characters without control characters, and for a known name the value is one of
/// its allowed values. (A guest applying options ignores unknown names and out-of-range
/// values.)
pub fn option_valid(name: &str, value: &str) -> bool {
    let name_ok = option_name_ok(name);
    let value_ok = value.len() <= MAX_OPTION_VALUE && !value.chars().any(char::is_control);
    if !name_ok || !value_ok {
        return false;
    }
    match KNOWN_OPTIONS.iter().find(|(n, _)| *n == name) {
        Some((_, allowed)) => allowed.contains(&value),
        None => true,
    }
}

/// HMAC-SHA-256 proof of knowing the password for one claim (3.6, replaced by a
/// challenge): keyed by the password, bound to session, challenge and claim token.
pub(crate) fn password_proof(
    password: &str,
    session: u64,
    challenge: &[u8; 16],
    token: u32,
) -> [u8; 32] {
    let mut msg = Vec::with_capacity(48);
    msg.extend_from_slice(b"btm-lobby-password-v1");
    msg.extend_from_slice(&session.to_le_bytes());
    msg.extend_from_slice(challenge);
    msg.extend_from_slice(&token.to_le_bytes());
    hmac_sha256(password.as_bytes(), &msg)
}

pub(crate) fn since(now: Instant, then: Instant) -> Duration {
    now.0.saturating_sub(then.0)
}

#[cfg(test)]
mod tests;
