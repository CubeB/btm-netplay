//! The lockstep (SPEC sections 1, 4, 5, 6 and 7): one [`Lockstep`] per local peer.
//!
//! Sans-IO: the caller feeds received datagrams with [`Lockstep::handle_datagram`]
//! and calls [`Lockstep::poll`] every frame with the current time and the engine.
//! `poll` runs every tick it may and returns the datagrams to send and the events.
//!
//! Choices where the spec leaves room (see also the crate report):
//! - Sets are applied highest player id first (1.2); the engine receives every
//!   player of the roster each tick, an empty `Vec` for an empty set.
//! - Computer players are the engine's business: it generates their commands inside
//!   [`Engine::step`], which only runs on ticks that actually run (1.3).
//! - **Deviation (5.5 gap):** if the designated declarer for a lost player is itself
//!   silent past the drop timeout, the next-lowest survivor declares after its own
//!   timeout. To make that possible a drop is accepted from any undropped peer other
//!   than the lost one (the spec requires exactly the designated declarer).

mod bundle;
mod commands;
mod desync;
mod stats;

#[cfg(test)]
mod sim_test;

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

pub use bundle::{Bundle, CommandLog, RecordedTick, MAX_LOG_BYTES};
pub use commands::{
    decode_set, encode_set, take_set, Command, SetError, MAX_COMMAND_BYTES, MAX_SET_BYTES,
};
pub use desync::{Desync, HashCompare};
pub use stats::{Caption, PeerSample, PeerStats, Sample, Stats, SAMPLE_HISTORY, SAMPLE_INTERVAL};

use crate::types::{Endpoint, Engine, Instant, Outgoing, PlayerId, Tick};
use crate::wire::{
    decode_datagram, BuildError, ChatLabel, ChatLine, Header, Link, LinkNote, Message, Room,
    RunState, SharedPause, WireError, MAX_BUFFERED,
};

/// Per-tick budget (1.1).
pub const TICK_MS: u32 = 33;
const TICK_US: u64 = 33_000;
/// Max ticks per frame (1.6), and while a rejoining peer winds forward (5.6).
pub const MAX_TICKS_PER_FRAME: u32 = 10;
pub const MAX_TICKS_PER_FRAME_REJOIN: u32 = 2000;
/// Drop margin and max lead (5.3, 5.4).
pub const DROP_MARGIN: u32 = 60;
pub const MAX_LEAD: u32 = 900;
/// Rejoin margin, grace and own-set history (5.6).
pub const REJOIN_MARGIN: u32 = 120;
pub const REJOIN_GRACE: Duration = Duration::from_secs(180);
pub const HISTORY_SETS: usize = 3600;
/// Drop timeout default and maximum (5.1).
pub const DEFAULT_DROP_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_DROP_TIMEOUT: Duration = Duration::from_secs(600);
/// Caption delay and counted stall (1.5).
pub const STALL_CAPTION_DELAY: Duration = Duration::from_secs(1);
pub const COUNTED_STALL: Duration = Duration::from_millis(33);
/// Governor floor and recovery (1.7).
pub const GOVERNOR_FLOOR: u16 = 100;
pub const GOVERNOR_RECOVERY_PER_S: f64 = 100.0;
/// Chat line length (7).
pub const MAX_CHAT_CHARS: usize = 128;
/// Bound on queued local commands.
pub const MAX_PENDING_COMMANDS: usize = 65_536;

/// One human player of the game.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlayerConfig {
    pub id: PlayerId,
    pub name: String,
    /// The remote peer's game address; None for the local player.
    pub endpoint: Option<Endpoint>,
}

/// Lockstep configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub local: PlayerId,
    /// Every human player, the local one included. Computer players are not listed.
    pub players: Vec<PlayerConfig>,
    /// 0 means never drop; values above 600 s are clamped.
    pub drop_timeout: Duration,
    /// Keep the command log, needed to speak for a rejoining player.
    pub record: bool,
    /// Initial game speed, per mille.
    pub speed: u16,
}

impl Config {
    pub fn new(local: PlayerId, players: Vec<PlayerConfig>) -> Self {
        Config {
            local,
            players,
            drop_timeout: DEFAULT_DROP_TIMEOUT,
            record: true,
            speed: 1000,
        }
    }
}

/// The configuration or bundle cannot start a lockstep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    LocalNotListed,
    DuplicatePlayer(PlayerId),
    BadSeat(PlayerId),
    RemoteWithoutEndpoint(PlayerId),
    BadRejoinTick(Tick),
    /// "Rejoin bundle ends at tick X but a rejoin at tick R needs it through tick Y".
    BundleTooShort {
        ends: Tick,
        at: Tick,
        needs: Tick,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::LocalNotListed => write!(f, "the local player is not in the roster"),
            ConfigError::DuplicatePlayer(p) => write!(f, "player {} is listed twice", p.0),
            ConfigError::BadSeat(p) => write!(f, "seat {} is out of range", p.0),
            ConfigError::RemoteWithoutEndpoint(p) => {
                write!(f, "remote player {} has no address", p.0)
            }
            ConfigError::BadRejoinTick(t) => write!(f, "cannot rejoin at tick {}", t.0),
            ConfigError::BundleTooShort { ends, at, needs } => write!(
                f,
                "Rejoin bundle ends at tick {} but a rejoin at tick {} needs it through tick {}",
                ends.0, at.0, needs.0
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A received datagram was not used. None of these stop the receive loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecvError {
    Wire(WireError),
    UnknownSeat(PlayerId),
    FromSelf,
    /// From an address not assigned to that seat and not followable (2.8).
    UnknownSource {
        from: Endpoint,
        seat: PlayerId,
    },
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvError::Wire(e) => write!(f, "{e}"),
            RecvError::UnknownSeat(p) => write!(f, "packet names unknown seat {}", p.0),
            RecvError::FromSelf => write!(f, "packet names our own seat"),
            RecvError::UnknownSource { from, seat } => {
                write!(f, "packet for seat {} from unknown address {from}", seat.0)
            }
        }
    }
}

impl std::error::Error for RecvError {}

impl From<WireError> for RecvError {
    fn from(e: WireError) -> Self {
        RecvError::Wire(e)
    }
}

/// A command could not be queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// Larger than [`MAX_COMMAND_BYTES`]; it could never be sent.
    TooLarge(usize),
    QueueFull,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubmitError::TooLarge(n) => write!(f, "a command of {n} bytes cannot be sent"),
            SubmitError::QueueFull => write!(f, "too many commands are queued"),
        }
    }
}

impl std::error::Error for SubmitError {}

/// A chat line was not sent (7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatError {
    NoSuchPlayer,
    NotAnswering,
    Empty,
}

impl fmt::Display for ChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChatError::NoSuchPlayer => write!(f, "Message not sent: no such player"),
            ChatError::NotAnswering => write!(f, "Message not sent: a player is not answering"),
            ChatError::Empty => write!(f, "Message not sent: it is empty"),
        }
    }
}

impl std::error::Error for ChatError {}

/// A rejoin request or bundle cut was refused (5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejoinRefusal {
    NotDropped,
    NotSpeaker,
    AlreadyInProgress,
    NotRecording,
    /// The bundle can be cut only once scene time reaches R-1.
    NotReady,
}

impl fmt::Display for RejoinRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RejoinRefusal::NotDropped => "that player has not been dropped",
            RejoinRefusal::NotSpeaker => "this peer is not the one to speak for that player",
            RejoinRefusal::AlreadyInProgress => "that player is already on their way back",
            RejoinRefusal::NotRecording => "this peer is not recording a replay",
            RejoinRefusal::NotReady => "the rejoin tick has not been reached",
        })
    }
}

impl std::error::Error for RejoinRefusal {}

/// What the lockstep tells the game.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Fatal (4.3). Raised once; no tick runs afterwards.
    Desync(Desync),
    /// "DROPPING IN n" changed (5.2): the silent players being counted down.
    DropCountdown {
        players: Vec<PlayerId>,
        seconds: u32,
    },
    /// This peer declared a drop (5.3).
    DropIssued { player: PlayerId, from: Tick },
    /// The drop command's tick ran (5.4): "<name> has left the game". The player's
    /// units go at `at`, which the engine reads from the command itself.
    PlayerLeft { player: PlayerId, at: Tick },
    /// The rejoin command's tick ran: "<name> has rejoined the game".
    PlayerRejoined { player: PlayerId, at: Tick },
    /// The speaker reached R-1: call [`Lockstep::cut_bundle`] and hand it on.
    RejoinBundleReady { player: PlayerId, at: Tick },
    /// This (returning) peer finished catching up: "Rejoined the game".
    Rejoined { at: Tick },
    /// A chat line from another player, already sanitised.
    Chat {
        from: PlayerId,
        text: String,
        label: ChatLabel,
    },
    /// A line for the log.
    Log(String),
}

/// What one call to [`Lockstep::poll`] produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub outgoing: Vec<Outgoing>,
    pub events: Vec<Event>,
}

/// The input delay of 1.4, in sets, from the worst smoothed RTT and deviation (ms).
pub fn order_delay(rtt_ms: u32, dev_ms: u32) -> u32 {
    let ms = (rtt_ms / 2)
        .saturating_add(dev_ms.saturating_mul(4))
        .saturating_add(10 + 50)
        .min(2700);
    ms / TICK_MS + 1
}

/// Sanitises received chat text (7): invalid UTF-8 as `?`, control characters
/// removed, at most 128 code points, trimmed.
pub fn sanitize_chat(raw: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(raw);
    let s: String = lossy
        .chars()
        .map(|c| {
            if c == char::REPLACEMENT_CHARACTER {
                '?'
            } else {
                c
            }
        })
        .filter(|c| !c.is_control())
        .take(MAX_CHAT_CHARS)
        .collect();
    s.trim().to_string()
}

fn same_16(a: &Endpoint, b: &Endpoint) -> bool {
    let (x, y) = (a.ip().octets(), b.ip().octets());
    x[0] == y[0] && x[1] == y[1]
}

fn ms(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

#[derive(Clone, Copy, Debug)]
struct Report {
    run: RunState,
    at: Instant,
    /// Estimated scene time at receipt (1.6 step 2).
    est: u32,
}

#[derive(Clone, Debug)]
struct Peer {
    id: PlayerId,
    name: String,
    endpoint: Option<Endpoint>,
    buffer: VecDeque<Vec<u8>>,
    /// Sets pushed so far (the next set number); always >= scene time.
    pushed: u32,
    /// Set on arrival of a valid drop: from this tick on, empty sets.
    dropped_from: Option<u32>,
    link: Option<Link>,
    last_heard: Option<Instant>,
    report: Option<Report>,
    grace_until: Option<Instant>,
    drop_issued: bool,
    rejoin_requested: bool,
    /// After the rejoin tick ran: open the link once own stream reaches R-1.
    reopen_at: Option<u32>,
    reopen_logged: bool,
    /// Speaker: raise RejoinBundleReady at scene R-1.
    bundle_due: Option<u32>,
    bundle_ready: Option<u32>,
    too_large_logged: bool,
}

impl Peer {
    fn new(c: &PlayerConfig, local: bool) -> Self {
        Peer {
            id: c.id,
            name: c.name.clone(),
            endpoint: if local { None } else { c.endpoint },
            buffer: VecDeque::new(),
            pushed: 0,
            dropped_from: None,
            link: if local { None } else { Some(Link::new(0, 0)) },
            last_heard: None,
            report: None,
            grace_until: None,
            drop_issued: false,
            rejoin_requested: false,
            reopen_at: None,
            reopen_logged: false,
            bundle_due: None,
            bundle_ready: None,
            too_large_logged: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Stall {
    since: Option<Instant>,
    waiting: Vec<PlayerId>,
    count: u32,
    longest_ms: u32,
    total: Duration,
    last_waited: Vec<PlayerId>,
}

#[derive(Clone, Debug)]
struct Wind {
    at: u32,
    ticks: VecDeque<RecordedTick>,
    speed: Option<u16>,
}

enum Attempt {
    Ran,
    Blocked,
    Ended,
}

/// The lockstep state machine of one local peer.
#[derive(Clone, Debug)]
pub struct Lockstep {
    local: PlayerId,
    peers: Vec<Peer>,
    has_remotes: bool,
    drop_timeout: Duration,
    record: bool,
    scene: u32,
    acc_us: u64,
    started: Option<Instant>,
    last_poll: Option<Instant>,
    chosen: u16,
    eff: f64,
    speed_raised: bool,
    capacity: u16,
    tick_cost_ms: Option<f64>,
    prev_lost: bool,
    lost_to_cap: u64,
    pause: SharedPause,
    pending: VecDeque<Command>,
    history: VecDeque<Vec<u8>>,
    history_base: u32,
    log: CommandLog,
    hashes: HashCompare,
    ended: bool,
    desync: Option<Desync>,
    last_blocked: bool,
    stall: Stall,
    countdown: Option<u32>,
    countdown_players: Vec<PlayerId>,
    wind: Option<Wind>,
    events: Vec<Event>,
    outgoing: Vec<Outgoing>,
    sampler: stats::Sampler,
}

impl Lockstep {
    /// A lockstep for a game starting at tick 1.
    pub fn new(config: Config) -> Result<Self, ConfigError> {
        let mut players = config.players.clone();
        players.sort_by_key(|p| p.id);
        for w in players.windows(2) {
            if let [a, b] = w {
                if a.id == b.id {
                    return Err(ConfigError::DuplicatePlayer(a.id));
                }
            }
        }
        if !players.iter().any(|p| p.id == config.local) {
            return Err(ConfigError::LocalNotListed);
        }
        let mut peers = Vec::with_capacity(players.len());
        let mut hashes = HashCompare::new();
        for p in &players {
            if p.id.0 >= crate::wire::MAX_SEATS {
                return Err(ConfigError::BadSeat(p.id));
            }
            let local = p.id == config.local;
            if !local && p.endpoint.is_none() {
                return Err(ConfigError::RemoteWithoutEndpoint(p.id));
            }
            peers.push(Peer::new(p, local));
            hashes.add_source(p.id, 1);
        }
        let speed = config.speed.max(1);
        Ok(Lockstep {
            local: config.local,
            has_remotes: peers.len() > 1,
            peers,
            drop_timeout: config.drop_timeout.min(MAX_DROP_TIMEOUT),
            record: config.record,
            scene: 0,
            acc_us: 0,
            started: None,
            last_poll: None,
            chosen: speed,
            eff: f64::from(speed),
            speed_raised: false,
            capacity: speed,
            tick_cost_ms: None,
            prev_lost: false,
            lost_to_cap: 0,
            pause: SharedPause::default(),
            pending: VecDeque::new(),
            history: VecDeque::new(),
            history_base: 0,
            log: CommandLog::default(),
            hashes,
            ended: false,
            desync: None,
            last_blocked: false,
            stall: Stall::default(),
            countdown: None,
            countdown_players: Vec::new(),
            wind: None,
            events: Vec::new(),
            outgoing: Vec::new(),
            sampler: stats::Sampler::default(),
        })
    }

    /// A returning peer (5.6 steps 9-12): winds the engine forward through `bundle`
    /// to R-1, then joins at `at` = R. It does not wait for a load handshake.
    pub fn rejoin(config: Config, bundle: Bundle, at: Tick) -> Result<Self, ConfigError> {
        if at.0 < 2 {
            return Err(ConfigError::BadRejoinTick(at));
        }
        let r = at.0;
        if bundle.last_tick.0 < r - 1 {
            return Err(ConfigError::BundleTooShort {
                ends: bundle.last_tick,
                at,
                needs: Tick(r - 1),
            });
        }
        let mut ls = Lockstep::new(config)?;
        for p in &mut ls.peers {
            if p.link.is_some() {
                p.link = Some(Link::new(r - 1, r - 1));
            }
            ls.hashes.add_source(p.id, r);
        }
        ls.hashes.start_at(r);
        ls.wind = Some(Wind {
            at: r,
            ticks: bundle.ticks.into_iter().filter(|t| t.tick.0 < r).collect(),
            speed: None,
        });
        Ok(ls)
    }

    // ------------------------------------------------------------ queries

    /// Local scene time: ticks run so far.
    pub fn scene_time(&self) -> Tick {
        Tick(self.scene)
    }

    pub fn local(&self) -> PlayerId {
        self.local
    }

    /// True while a returning peer winds forward.
    pub fn is_rejoining(&self) -> bool {
        self.wind.is_some()
    }

    pub fn is_paused(&self) -> bool {
        self.pause.paused
    }

    /// The shared pause value (1.8).
    pub fn pause_state(&self) -> SharedPause {
        self.pause
    }

    /// The game speed chosen by commands, per mille.
    pub fn chosen_speed(&self) -> u16 {
        self.chosen
    }

    /// The effective speed (1.7), per mille.
    pub fn effective_speed(&self) -> u16 {
        self.eff.round() as u16
    }

    /// True if the last tick attempt was blocked.
    pub fn is_stalled(&self) -> bool {
        self.last_blocked
    }

    /// True once a player's drop has been applied here.
    pub fn is_dropped(&self, p: PlayerId) -> bool {
        self.peer(p).is_some_and(|x| x.dropped_from.is_some())
    }

    /// The desync, once found.
    pub fn desync(&self) -> Option<&Desync> {
        self.desync.as_ref()
    }

    /// The order delay D currently targeted (1.4); 0 with no remote players.
    pub fn order_delay(&self) -> u32 {
        if !self.has_remotes {
            return 0;
        }
        let (rtt, dev) = self.worst_rtt();
        order_delay(rtt, dev)
    }

    fn worst_rtt(&self) -> (u32, u32) {
        self.peers
            .iter()
            .filter_map(|p| p.link.as_ref())
            .fold((0, 0), |(r, d), l| {
                (r.max(l.rtt().smoothed_ms()), d.max(l.rtt().dev_ms()))
            })
    }

    fn idx(&self, p: PlayerId) -> Option<usize> {
        self.peers.iter().position(|x| x.id == p)
    }

    fn peer(&self, p: PlayerId) -> Option<&Peer> {
        self.peers.iter().find(|x| x.id == p)
    }

    fn local_idx(&self) -> usize {
        self.idx(self.local).unwrap_or(0)
    }

    fn log(&mut self, s: String) {
        self.events.push(Event::Log(s));
    }

    // ------------------------------------------------------------ inputs

    /// Queues an opaque game command for the local player's next set.
    pub fn submit(&mut self, command: Vec<u8>) -> Result<(), SubmitError> {
        self.queue(Command::Game(command))
    }

    /// Queues a game speed change (1.8), per mille.
    pub fn set_speed(&mut self, per_mille: u16) -> Result<(), SubmitError> {
        self.queue(Command::Speed(per_mille.max(1)))
    }

    fn queue(&mut self, c: Command) -> Result<(), SubmitError> {
        let len = c.encoded_len();
        if len > MAX_COMMAND_BYTES {
            return Err(SubmitError::TooLarge(len));
        }
        if self.pending.len() >= MAX_PENDING_COMMANDS {
            return Err(SubmitError::QueueFull);
        }
        self.pending.push_back(c);
        Ok(())
    }

    /// Toggles the shared pause (1.8) and returns the new paused flag.
    pub fn toggle_pause(&mut self) -> bool {
        self.pause = SharedPause {
            revision: self.pause.revision.saturating_add(1),
            player: self.local,
            paused: !self.pause.paused,
        };
        self.pause.paused
    }

    /// Feeds one measured tick cost to the governor's moving average (1.7).
    pub fn record_tick_cost(&mut self, cost: Duration) {
        let x = cost.as_secs_f64() * 1000.0;
        self.tick_cost_ms = Some(match self.tick_cost_ms {
            None => x,
            Some(a) => 0.9 * a + 0.1 * x,
        });
    }

    /// Sends a chat line to `recipients` (7). The caller shows its own line.
    pub fn send_chat(
        &mut self,
        text: &str,
        recipients: &[PlayerId],
        label: ChatLabel,
    ) -> Result<(), ChatError> {
        if recipients.is_empty() {
            return Err(ChatError::NoSuchPlayer);
        }
        for r in recipients {
            match self.peer(*r) {
                Some(p) if p.id != self.local => {
                    if p.dropped_from.is_some() || p.link.as_ref().is_none_or(Link::chat_full) {
                        return Err(ChatError::NotAnswering);
                    }
                }
                _ => return Err(ChatError::NoSuchPlayer),
            }
        }
        let text = sanitize_chat(text.as_bytes());
        if text.is_empty() {
            return Err(ChatError::Empty);
        }
        for r in recipients {
            if let Some(link) = self
                .peers
                .iter_mut()
                .find(|p| p.id == *r)
                .and_then(|p| p.link.as_mut())
            {
                let _ = link.push_chat(ChatLine {
                    text: text.clone().into_bytes(),
                    label,
                });
            }
        }
        Ok(())
    }

    /// The speaker asks for a dropped player to come back (5.6 steps 3-4).
    /// Returns R, the rejoin tick.
    pub fn request_rejoin(&mut self, player: PlayerId) -> Result<Tick, RejoinRefusal> {
        let Some(p) = self.peer(player) else {
            return Err(RejoinRefusal::NotDropped);
        };
        if p.dropped_from.is_none() {
            return Err(RejoinRefusal::NotDropped);
        }
        if p.rejoin_requested {
            return Err(RejoinRefusal::AlreadyInProgress);
        }
        if self.declarer(player) != Some(self.local) {
            return Err(RejoinRefusal::NotSpeaker);
        }
        let r = self.scene + REJOIN_MARGIN;
        self.pending.push_back(Command::Rejoined {
            player,
            at: Tick(r),
        });
        if let Some(i) = self.idx(player) {
            if let Some(p) = self.peers.get_mut(i) {
                p.rejoin_requested = true;
            }
        }
        Ok(Tick(r))
    }

    /// The speaker's catch-up bundle (5.6 step 7), once RejoinBundleReady was raised.
    pub fn cut_bundle(&self, player: PlayerId) -> Result<Bundle, RejoinRefusal> {
        if !self.record || !self.log.usable() {
            return Err(RejoinRefusal::NotRecording);
        }
        match self.peer(player).and_then(|p| p.bundle_ready) {
            Some(r) if self.scene + 1 >= r => Ok(self.log.cut(Tick(self.scene))),
            _ => Err(RejoinRefusal::NotReady),
        }
    }

    // ------------------------------------------------------------ receive

    /// Takes one received datagram. An error costs only this datagram.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        from: Endpoint,
        bytes: &[u8],
    ) -> Result<(), RecvError> {
        self.started.get_or_insert(now);
        let u = match decode_datagram(bytes)? {
            Message::Update(u) => u,
            Message::LoadStatus(s) => {
                // A peer still in its load handshake is alive.
                if let Some(p) = self
                    .peers
                    .iter_mut()
                    .find(|p| p.id == s.sender && p.endpoint == Some(from))
                {
                    p.last_heard = Some(now);
                }
                return Ok(());
            }
        };
        let i = self.idx(u.sender).ok_or(RecvError::UnknownSeat(u.sender))?;
        if u.sender == self.local {
            return Err(RecvError::FromSelf);
        }
        let Some(current) = self.peers.get(i).and_then(|p| p.endpoint) else {
            return Err(RecvError::UnknownSeat(u.sender));
        };
        if current != from {
            let taken = self.peers.iter().any(|p| p.endpoint == Some(from));
            if taken || !same_16(&current, &from) {
                return Err(RecvError::UnknownSource {
                    from,
                    seat: u.sender,
                });
            }
            if let Some(p) = self.peers.get_mut(i) {
                p.endpoint = Some(from);
            }
            self.log(format!(
                "player {} moved from {current} to {from}",
                u.sender.0
            ));
        }

        let winding = self.wind.is_some();
        let hash_room = self.hashes.room(u.sender);
        let Some(p) = self.peers.get_mut(i) else {
            return Ok(());
        };
        if p.dropped_from.is_some() {
            return Ok(()); // 5.4: packets from a dropped player are ignored
        }
        p.last_heard = Some(now);
        p.grace_until = None;
        let rtt = p.link.as_ref().map_or(0, |l| l.rtt().smoothed_ms());
        p.report = Some(Report {
            run: u.run,
            at: now,
            est: u.run.scene_time.saturating_add(rtt / 2 / TICK_MS),
        });
        let room = Room {
            commands: MAX_BUFFERED.saturating_sub(p.buffer.len()),
            hashes: hash_room,
            accept_commands: !winding,
        };
        let inc = match p.link.as_mut() {
            Some(l) => l.receive(now, &u, room, |s| decode_set(s).is_ok()),
            None => Default::default(),
        };
        if self.pause.superseded_by(&u.pause) {
            self.pause = u.pause;
        }
        for n in inc.notes {
            match n {
                LinkNote::Gap { .. } => {}
                other => self.log(format!("player {}: {other:?}", u.sender.0)),
            }
        }
        for set in inc.commands {
            self.arrive(i, set);
        }
        for h in inc.hashes {
            self.hashes.push(u.sender, h);
        }
        for line in inc.chat {
            let text = sanitize_chat(&line.text);
            if !text.is_empty() {
                self.events.push(Event::Chat {
                    from: u.sender,
                    text,
                    label: line.label,
                });
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ arrival

    /// A set enters player `i`'s buffer: control commands are validated and
    /// applied now (5.4, 5.6 step 5); invalid ones are stripped.
    fn arrive(&mut self, i: usize, bytes: Vec<u8>) {
        let Some(issuer) = self.peers.get(i).map(|p| p.id) else {
            return;
        };
        let bytes = match decode_set(&bytes) {
            Ok(cmds)
                if cmds
                    .iter()
                    .all(|c| matches!(c, Command::Game(_) | Command::Speed(_))) =>
            {
                bytes
            }
            Ok(cmds) => {
                let mut kept = Vec::with_capacity(cmds.len());
                let mut stripped = false;
                for c in cmds {
                    let ok = match &c {
                        Command::Dropped { player, from } => {
                            self.apply_drop(issuer, *player, from.0)
                        }
                        Command::Rejoined { player, at } => {
                            self.apply_rejoin(issuer, *player, at.0)
                        }
                        _ => true,
                    };
                    if ok {
                        kept.push(c);
                    } else {
                        stripped = true;
                    }
                }
                if stripped {
                    encode_set(&kept)
                } else {
                    bytes
                }
            }
            Err(e) => {
                self.log(format!("player {}: {e}; using an empty set", issuer.0));
                Vec::new()
            }
        };
        if let Some(p) = self.peers.get_mut(i) {
            p.buffer.push_back(bytes);
            p.pushed = p.pushed.saturating_add(1);
        }
    }

    /// The designated declarer for `lost` (5.3): the lowest undropped player other than it.
    fn declarer(&self, lost: PlayerId) -> Option<PlayerId> {
        self.peers
            .iter()
            .find(|p| p.id != lost && p.dropped_from.is_none())
            .map(|p| p.id)
    }

    fn apply_drop(&mut self, issuer: PlayerId, player: PlayerId, from: u32) -> bool {
        let scene = self.scene;
        let issuer_ok = issuer != player && !self.is_dropped(issuer);
        let Some(pi) = self.idx(player) else {
            self.log(format!("drop of unknown player {} stripped", player.0));
            return false;
        };
        if !issuer_ok || self.is_dropped(player) || from == 0 || from > scene + MAX_LEAD {
            self.log(format!(
                "invalid drop of player {} from tick {from} by player {} stripped",
                player.0, issuer.0
            ));
            return false;
        }
        let target = from - 1;
        if target < scene {
            self.log(format!(
                "unrecoverable desync: player {} dropped from tick {from} but tick {scene} already ran",
                player.0
            ));
        }
        let keep = target.saturating_sub(scene) as usize;
        if let Some(p) = self.peers.get_mut(pi) {
            if p.buffer.len() > keep {
                p.buffer.truncate(keep);
            }
            while p.buffer.len() < keep {
                p.buffer.push_back(Vec::new());
            }
            p.pushed = scene + keep as u32;
            p.dropped_from = Some(from);
            p.rejoin_requested = false;
            p.reopen_at = None;
            p.bundle_due = None;
            p.bundle_ready = None;
        }
        self.hashes.remove_source(player);
        true
    }

    fn apply_rejoin(&mut self, issuer: PlayerId, player: PlayerId, at: u32) -> bool {
        let scene = self.scene;
        let Some(pi) = self.idx(player) else {
            return false;
        };
        let dropped = self.peers.get(pi).and_then(|p| p.dropped_from);
        let ok = self.declarer(player) == Some(issuer)
            && at <= scene + MAX_LEAD
            && dropped.is_some_and(|f| at > f)
            && at > scene;
        if !ok {
            self.log(format!(
                "invalid rejoin of player {} at tick {at} by player {} stripped",
                player.0, issuer.0
            ));
            return false;
        }
        if let Some(p) = self.peers.get_mut(pi) {
            p.pushed = p.pushed.max(scene);
            while p.pushed < at - 1 {
                p.buffer.push_back(Vec::new());
                p.pushed += 1;
            }
            p.dropped_from = None;
            p.drop_issued = false;
            p.rejoin_requested = false;
            p.link = None;
            p.last_heard = None;
        }
        self.hashes.add_source(player, at);
        true
    }

    // ------------------------------------------------------------ local sets

    fn push_local_set(&mut self, cmds: Vec<Command>) {
        let li = self.local_idx();
        if self.is_dropped(self.local) {
            return;
        }
        let bytes = encode_set(&cmds);
        let seq = self.peers.get(li).map_or(0, |p| p.pushed);
        if self.history.len() >= HISTORY_SETS {
            self.history.pop_front();
            self.history_base += 1;
        }
        if self.history.is_empty() {
            self.history_base = seq;
        }
        self.history.push_back(bytes.clone());
        for p in &mut self.peers {
            if let Some(l) = p.link.as_mut() {
                if l.commands_end() == seq {
                    l.push_command(bytes.clone());
                }
            }
        }
        self.arrive(li, bytes);
    }

    fn own_buffered(&self) -> u32 {
        self.peers
            .get(self.local_idx())
            .map_or(0, |p| p.buffer.len() as u32)
    }

    // ------------------------------------------------------------ poll

    /// Runs one frame: feeds the local buffer, runs every tick it may, handles
    /// liveness, and returns the datagrams to send and the events.
    pub fn poll(&mut self, now: Instant, engine: &mut impl Engine) -> Output {
        self.started.get_or_insert(now);
        let elapsed = self
            .last_poll
            .map_or(Duration::ZERO, |t| now.0.saturating_sub(t.0));
        self.last_poll = Some(now);
        self.sampler.roll(now);

        if self.wind.is_some() {
            self.wind_step(now, engine);
        } else if !self.ended {
            self.frame(now, elapsed, engine);
        }
        self.flush(now);
        self.sample_peers(now);
        Output {
            outgoing: std::mem::take(&mut self.outgoing),
            events: std::mem::take(&mut self.events),
        }
    }

    fn frame(&mut self, now: Instant, elapsed: Duration, engine: &mut impl Engine) {
        if self.check_desync(engine) {
            return;
        }
        self.reopen_links();
        self.update_effective_speed(elapsed);

        // 1.4: feed the local buffer before ticks run.
        if self.has_remotes {
            let d = self.order_delay();
            if self.own_buffered() <= d
                || (self.last_blocked
                    && !self.pending.is_empty()
                    && (self.own_buffered() as usize) < MAX_BUFFERED)
            {
                let set = take_set(&mut self.pending);
                self.push_local_set(set);
            }
            while self.own_buffered() < d && !self.is_dropped(self.local) {
                self.push_local_set(Vec::new());
            }
        }

        let paused = self.pause.paused;
        if !paused {
            let add = (elapsed.as_micros() as f64 * self.eff / 1000.0) as u64;
            self.acc_us = self.acc_us.saturating_add(add);
        }
        let cost = self.tick_cost_us(now);
        let mut ran = 0u32;
        let mut blocked = false;
        while !paused && self.acc_us >= cost && ran < MAX_TICKS_PER_FRAME {
            match self.attempt(now, engine) {
                Attempt::Ran => {
                    self.acc_us -= cost;
                    ran += 1;
                }
                Attempt::Blocked => {
                    blocked = true;
                    break;
                }
                Attempt::Ended => return,
            }
        }
        let mut lost = 0u64;
        if ran == MAX_TICKS_PER_FRAME && self.acc_us >= cost {
            lost = self.acc_us / cost;
            self.acc_us %= cost;
            self.lost_to_cap += lost;
        }
        if blocked {
            self.acc_us = self.acc_us.min(cost * u64::from(MAX_TICKS_PER_FRAME));
        }
        self.sampler.add_ticks(ran);

        // Stall bookkeeping (1.5).
        if blocked {
            if self.stall.since.is_none() {
                self.stall.since = Some(now);
            } else {
                self.stall.total += elapsed;
                self.sampler.add_stalled(elapsed);
            }
        } else if ran > 0 {
            self.end_stall(now);
        }
        self.last_blocked = blocked;
        self.governor(ran, lost, blocked, paused);
        if blocked {
            self.liveness(now);
        }
    }

    fn end_stall(&mut self, now: Instant) {
        if let Some(since) = self.stall.since.take() {
            let d = now.0.saturating_sub(since.0);
            if d >= COUNTED_STALL {
                self.stall.count += 1;
                self.stall.longest_ms = self.stall.longest_ms.max(ms(d));
                let names: Vec<String> =
                    self.stall.waiting.iter().map(|p| p.0.to_string()).collect();
                self.log(format!(
                    "stalled {} ms at tick {} waiting for player {}",
                    ms(d),
                    self.scene,
                    names.join(", ")
                ));
            }
            self.stall.last_waited = std::mem::take(&mut self.stall.waiting);
        }
        if self.countdown.take().is_some() {
            self.countdown_players.clear();
        }
    }

    fn check_desync(&mut self, engine: &impl Engine) -> bool {
        if self.ended {
            return true;
        }
        let Some((tick, hashes)) = self.hashes.check().cloned() else {
            return false;
        };
        self.ended = true;
        let d = Desync {
            tick,
            local: self.local,
            noticed_at: Tick(self.scene),
            hashes,
            dump: engine.dump(),
        };
        self.log(format!("desync detected at tick {}", tick.0));
        self.desync = Some(d.clone());
        self.events.push(Event::Desync(d));
        true
    }

    fn attempt(&mut self, now: Instant, engine: &mut impl Engine) -> Attempt {
        if self.check_desync(engine) {
            return Attempt::Ended;
        }
        let t = self.scene + 1;
        if !self.has_remotes && self.own_buffered() == 0 {
            let set = take_set(&mut self.pending);
            self.push_local_set(set);
        }
        let waiting: Vec<PlayerId> = self
            .peers
            .iter()
            .filter(|p| p.buffer.is_empty() && p.dropped_from.is_none())
            .map(|p| p.id)
            .collect();
        if !waiting.is_empty() {
            self.stall.waiting = waiting;
            return Attempt::Blocked;
        }
        let mut sets: Vec<(PlayerId, Vec<u8>)> = Vec::with_capacity(self.peers.len());
        for p in self.peers.iter_mut().rev() {
            let set = p.buffer.pop_front().unwrap_or_default();
            p.pushed = p.pushed.max(t);
            sets.push((p.id, set));
        }
        if self.record {
            self.log.record(Tick(t), &sets);
        }
        engine.step(Tick(t), &sets);
        self.scene = t;
        for (issuer, set) in &sets {
            self.on_tick_ran(now, *issuer, set, false);
        }

        // 4.1: hash after every tick run, stored and sent.
        let h = engine.state_hash();
        if self.hashes.next_push_tick(self.local) == Some(t) {
            self.hashes.push(self.local, h);
        }
        for p in &mut self.peers {
            if let Some(l) = p.link.as_mut() {
                if l.hashes_end().saturating_add(1) == t {
                    l.push_hash(h);
                }
            }
        }

        // 1.4: top up after every tick that ran.
        if self.has_remotes {
            let d = self.order_delay();
            while self.own_buffered() < d && !self.is_dropped(self.local) {
                let set = take_set(&mut self.pending);
                self.push_local_set(set);
            }
        }
        self.reopen_links();
        let scene = self.scene;
        let mut ready = Vec::new();
        for p in &mut self.peers {
            if let Some(r) = p.bundle_due {
                if scene + 1 >= r {
                    p.bundle_due = None;
                    p.bundle_ready = Some(r);
                    ready.push(Event::RejoinBundleReady {
                        player: p.id,
                        at: Tick(r),
                    });
                }
            }
        }
        self.events.extend(ready);
        Attempt::Ran
    }

    /// Control commands take their visible effect when their own tick runs.
    fn on_tick_ran(&mut self, now: Instant, issuer: PlayerId, set: &[u8], winding: bool) {
        if set.is_empty() {
            return;
        }
        let Ok(cmds) = decode_set(set) else {
            return;
        };
        for c in cmds {
            match c {
                Command::Game(_) => {}
                Command::Speed(s) => {
                    if let Some(w) = self.wind.as_mut() {
                        w.speed = Some(s);
                    } else {
                        if s > self.chosen {
                            self.speed_raised = true;
                        }
                        self.chosen = s.max(1);
                    }
                }
                Command::Dropped { player, from } => {
                    if winding {
                        if let Some(i) = self.idx(player) {
                            if let Some(p) = self.peers.get_mut(i) {
                                p.dropped_from = Some(from.0);
                            }
                        }
                        continue;
                    }
                    if let Some(i) = self.idx(player) {
                        if let Some(p) = self.peers.get_mut(i) {
                            p.link = None; // the address stays remembered
                        }
                    }
                    self.events.push(Event::PlayerLeft { player, at: from });
                }
                Command::Rejoined { player, at } => {
                    if winding {
                        if let Some(i) = self.idx(player) {
                            if let Some(p) = self.peers.get_mut(i) {
                                p.dropped_from = None;
                            }
                        }
                        continue;
                    }
                    let local = self.local;
                    if let Some(i) = self.idx(player) {
                        if let Some(p) = self.peers.get_mut(i) {
                            p.grace_until = Some(Instant(now.0 + REJOIN_GRACE));
                            p.reopen_at = Some(at.0);
                            p.reopen_logged = false;
                            if issuer == local {
                                p.bundle_due = Some(at.0);
                            }
                        }
                    }
                    self.events.push(Event::PlayerRejoined { player, at });
                }
            }
        }
    }

    /// 5.6 step 6: once own stream reaches R-1, send to the returning peer again,
    /// resending own sets from R-1 out of the history.
    fn reopen_links(&mut self) {
        let li = self.local_idx();
        let own_pushed = self.peers.get(li).map_or(0, |p| p.pushed);
        let base = self.history_base;
        let mut logs = Vec::new();
        for i in 0..self.peers.len() {
            let Some(p) = self.peers.get_mut(i) else {
                continue;
            };
            let Some(r) = p.reopen_at else { continue };
            let start = r - 1;
            if own_pushed < start {
                continue;
            }
            if start < base {
                if !p.reopen_logged {
                    p.reopen_logged = true;
                    logs.push(format!(
                        "cannot resend set {start} to player {}: history starts at {base}",
                        p.id.0
                    ));
                }
                continue;
            }
            let mut link = Link::new(start, start);
            for seq in start..own_pushed {
                if let Some(s) = self.history.get((seq - base) as usize) {
                    link.push_command(s.clone());
                }
            }
            p.link = Some(link);
            p.reopen_at = None;
        }
        for l in logs {
            self.log(l);
        }
    }

    // ------------------------------------------------------------ rejoin wind

    fn wind_step(&mut self, now: Instant, engine: &mut impl Engine) {
        let Some(r) = self.wind.as_ref().map(|w| w.at) else {
            return;
        };
        let mut n = 0;
        while self.scene + 1 < r && n < MAX_TICKS_PER_FRAME_REJOIN {
            let t = self.scene + 1;
            let mut recorded = Vec::new();
            if let Some(w) = self.wind.as_mut() {
                while w.ticks.front().is_some_and(|x| x.tick.0 < t) {
                    w.ticks.pop_front();
                }
                if w.ticks.front().is_some_and(|x| x.tick.0 == t) {
                    if let Some(x) = w.ticks.pop_front() {
                        recorded = x.sets;
                    }
                }
            }
            let sets: Vec<(PlayerId, Vec<u8>)> = self
                .peers
                .iter()
                .rev()
                .map(|p| {
                    let s = recorded
                        .iter()
                        .find(|(q, _)| *q == p.id)
                        .map(|(_, s)| s.clone())
                        .unwrap_or_default();
                    (p.id, s)
                })
                .collect();
            if self.record {
                self.log.record(Tick(t), &sets);
            }
            engine.step(Tick(t), &sets);
            self.scene = t;
            for (issuer, set) in &sets {
                self.on_tick_ran(now, *issuer, set, true);
            }
            n += 1;
        }
        if self.scene + 1 >= r {
            self.finish_wind(now);
        }
    }

    fn finish_wind(&mut self, now: Instant) {
        let Some(w) = self.wind.take() else { return };
        let start = w.at - 1;
        let mut removed = Vec::new();
        for p in &mut self.peers {
            p.buffer.clear();
            p.pushed = start;
            p.last_heard = p.last_heard.or(Some(now));
            if let Some(f) = p.dropped_from {
                p.link = None;
                removed.push(p.id);
                while p.pushed + 1 < f {
                    p.buffer.push_back(Vec::new());
                    p.pushed += 1;
                }
            }
        }
        for id in removed {
            self.hashes.remove_source(id);
        }
        if let Some(s) = w.speed {
            self.chosen = s.max(1);
        }
        self.eff = f64::from(self.chosen);
        self.acc_us = 0;
        if self.is_dropped(self.local) {
            self.log("the rejoin bundle leaves this player dropped".to_string());
        }
        self.events.push(Event::Rejoined { at: Tick(w.at) });
    }

    // ------------------------------------------------------------ pacing

    /// Projected scene time of a remote (1.6 step 3), optionally capped.
    fn projected(&self, p: &Peer, now: Instant, cap: Option<Duration>) -> Option<u32> {
        let r = p.report?;
        if r.run.paused || r.run.stalled {
            return Some(r.est);
        }
        let mut e = now.0.saturating_sub(r.at.0);
        if let Some(c) = cap {
            e = e.min(c);
        }
        let ticks = e.as_micros() as u64 * u64::from(r.run.speed) / 1000 / TICK_US;
        Some(
            r.est
                .saturating_add(u32::try_from(ticks).unwrap_or(u32::MAX)),
        )
    }

    /// The drift gate (1.6): this frame's tick cost in microseconds.
    fn tick_cost_us(&self, now: Instant) -> u64 {
        let local = i64::from(self.scene);
        let mut sum = local;
        let mut n = 1i64;
        for p in &self.peers {
            if p.id == self.local || p.dropped_from.is_some() || p.link.is_none() {
                continue;
            }
            if let Some(t) = self.projected(p, now, None) {
                sum += i64::from(t);
                n += 1;
            }
        }
        let avg = sum / n;
        let g = (1.0 + 0.03 * (avg - local) as f64).clamp(0.75, 1.25);
        (TICK_US as f64 / g).round() as u64
    }

    /// Remote capacities that limit: below the reporter's own chosen speed.
    fn remote_capacities(&self) -> impl Iterator<Item = (PlayerId, u16)> + '_ {
        self.peers
            .iter()
            .filter(|p| p.id != self.local && p.dropped_from.is_none())
            .filter_map(|p| p.report.map(|r| (p.id, r.run)))
            .filter(|(_, r)| r.capacity < r.chosen)
            .map(|(p, r)| (p, r.capacity))
    }

    fn update_effective_speed(&mut self, elapsed: Duration) {
        let target = self
            .remote_capacities()
            .map(|(_, c)| c)
            .fold(self.chosen.min(self.capacity), u16::min);
        let target = f64::from(target);
        if target < self.eff || self.speed_raised {
            self.eff = target;
        } else {
            self.eff = (self.eff + GOVERNOR_RECOVERY_PER_S * elapsed.as_secs_f64()).min(target);
        }
        self.speed_raised = false;
    }

    /// The governor (1.7): the speed this machine can sustain.
    fn governor(&mut self, ran: u32, lost: u64, blocked: bool, paused: bool) {
        if paused {
            return;
        }
        let chosen = f64::from(self.chosen);
        let mut cap = chosen;
        let owed = u64::from(ran) + if self.prev_lost { lost } else { 0 };
        if !blocked && owed > 0 {
            cap = cap.min(chosen * f64::from(ran) / owed as f64);
        }
        if let Some(c) = self.tick_cost_ms {
            if c > 0.0 {
                cap = cap.min(f64::from(TICK_MS) / c * 1000.0);
            }
        }
        let cap = cap.min(chosen).max(f64::from(GOVERNOR_FLOOR));
        self.capacity = cap.round() as u16;
        self.prev_lost = lost > 0;
    }

    // ------------------------------------------------------------ liveness

    fn silence(&self, p: &Peer, now: Instant) -> Duration {
        let since = p.last_heard.or(self.started).unwrap_or(now);
        now.0.saturating_sub(since.0)
    }

    fn in_grace(p: &Peer, now: Instant) -> bool {
        p.grace_until.is_some_and(|g| now < g)
    }

    /// 5.3 with the 5.5 deviation: this peer issues if every undropped player below
    /// it (other than the lost one) is itself silent past the timeout.
    fn may_issue_drop(&self, lost: PlayerId, now: Instant) -> bool {
        for p in &self.peers {
            if p.id == lost || p.dropped_from.is_some() {
                continue;
            }
            if p.id == self.local {
                return true;
            }
            if Self::in_grace(p, now) || self.silence(p, now) < self.drop_timeout {
                return false;
            }
        }
        false
    }

    fn liveness(&mut self, now: Instant) {
        if self.drop_timeout.is_zero() {
            return;
        }
        let mut countdown: Option<u32> = None;
        let mut counted = Vec::new();
        let mut issue = Vec::new();
        for p in &self.peers {
            if p.id == self.local || p.dropped_from.is_some() || !self.stall.waiting.contains(&p.id)
            {
                continue;
            }
            if Self::in_grace(p, now) {
                continue;
            }
            let silence = self.silence(p, now);
            if silence >= self.drop_timeout {
                if !p.drop_issued && self.may_issue_drop(p.id, now) {
                    issue.push(p.id);
                }
            } else {
                let n = (self.drop_timeout - silence).as_secs() as u32 + 1;
                countdown = Some(countdown.map_or(n, |c| c.min(n)));
                counted.push(p.id);
            }
        }
        for player in issue {
            let reported = self
                .peers
                .iter()
                .filter_map(|p| p.report.map(|r| r.run.scene_time))
                .max()
                .unwrap_or(0);
            let own_pushed = self.peers.get(self.local_idx()).map_or(0, |p| p.pushed);
            let from = self.scene.max(own_pushed).max(reported) + DROP_MARGIN;
            self.pending.push_back(Command::Dropped {
                player,
                from: Tick(from),
            });
            if let Some(i) = self.idx(player) {
                if let Some(p) = self.peers.get_mut(i) {
                    p.drop_issued = true;
                }
            }
            self.events.push(Event::DropIssued {
                player,
                from: Tick(from),
            });
        }
        let stalled_for = self
            .stall
            .since
            .map_or(Duration::ZERO, |s| now.0.saturating_sub(s.0));
        self.countdown_players = counted.clone();
        if stalled_for >= STALL_CAPTION_DELAY && countdown.is_some() && countdown != self.countdown
        {
            self.events.push(Event::DropCountdown {
                players: counted,
                seconds: countdown.unwrap_or(0),
            });
        }
        if stalled_for >= STALL_CAPTION_DELAY {
            self.countdown = countdown;
        }
    }

    // ------------------------------------------------------------ send

    fn flush(&mut self, now: Instant) {
        let header = Header {
            sender: self.local,
            run: RunState {
                scene_time: self.scene,
                speed: self.effective_speed(),
                chosen: self.chosen,
                paused: self.pause.paused,
                stalled: self.last_blocked,
                capacity: self.capacity,
            },
            pause: self.pause,
        };
        let mut logs = Vec::new();
        for p in &mut self.peers {
            let (Some(link), Some(to)) = (p.link.as_mut(), p.endpoint) else {
                continue;
            };
            if !link.due(now) {
                continue;
            }
            let built = link.build(now, header);
            match built.error {
                Some(BuildError::SetTooLarge { seq, size }) if !p.too_large_logged => {
                    p.too_large_logged = true;
                    logs.push(format!(
                        "set {seq} for player {} is {size} bytes and can never be sent",
                        p.id.0
                    ));
                }
                Some(BuildError::Wire(e)) => logs.push(format!("cannot encode packet: {e}")),
                _ => {}
            }
            if !built.bytes.is_empty() {
                self.outgoing.push(Outgoing {
                    to,
                    bytes: built.bytes,
                });
            }
        }
        for l in logs {
            self.log(l);
        }
    }

    // ------------------------------------------------------------ overlay

    fn peer_stats(&self, p: &Peer, now: Instant) -> PeerStats {
        let link = p.link.as_ref();
        let rtt = link.map(|l| l.rtt());
        let latest = rtt.and_then(|r| r.latest_ms()).unwrap_or(0);
        let no_ack_bound_ms = rtt.and_then(|r| r.oldest_unacked_age(now)).and_then(|age| {
            let bound = latest.max(ms(age).saturating_sub(100));
            (bound > latest + 100).then_some(bound)
        });
        let tick_delta = self
            .projected(p, now, Some(Duration::from_millis(200)))
            .map_or(0, |t| i64::from(t) - i64::from(self.scene));
        PeerStats {
            player: p.id,
            name: p.name.clone(),
            dropped: p.dropped_from.is_some(),
            quiet_ms: ms(self.silence(p, now)),
            tick_delta,
            unacked: link.map_or(0, Link::unacked_commands),
            rtt_ms: rtt.map_or(0, |r| r.smoothed_ms()),
            jitter_ms: rtt.map_or(0, |r| r.dev_ms()),
            rtt_min_max: rtt.and_then(|r| r.window_min_max()),
            no_ack_bound_ms,
            buffered: p.buffer.len(),
        }
    }

    fn sample_peers(&mut self, now: Instant) {
        let samples: Vec<PeerSample> = self
            .peers
            .iter()
            .filter(|p| p.id != self.local)
            .map(|p| {
                let s = self.peer_stats(p, now);
                PeerSample {
                    player: s.player,
                    rtt_ms: s.rtt_ms,
                    quiet_ms: s.quiet_ms,
                    buffered: s.buffered,
                }
            })
            .collect();
        for s in samples {
            self.sampler.observe_peer(s);
        }
    }

    /// The centred caption, if any (1.5, 1.7, 5.2).
    pub fn caption(&self, now: Instant) -> Option<Caption> {
        if let Some(since) = self.stall.since {
            if now.0.saturating_sub(since.0) >= STALL_CAPTION_DELAY {
                return Some(Caption::Waiting {
                    players: self.stall.waiting.clone(),
                    dropping_in: self.countdown,
                });
            }
        }
        let eff = self.effective_speed();
        if eff < self.chosen {
            let mut players: Vec<PlayerId> = self
                .remote_capacities()
                .filter(|(_, c)| *c <= eff)
                .map(|(p, _)| p)
                .collect();
            if self.capacity <= eff {
                players.insert(0, self.local);
            }
            if !players.is_empty() {
                players.sort();
                return Some(Caption::Slowed { players });
            }
        }
        None
    }

    /// The overlay snapshot (6).
    pub fn stats(&self, now: Instant) -> Stats {
        let (rtt, dev) = self.worst_rtt();
        let d = self.order_delay();
        let current = self.stall.since.map(|s| now.0.saturating_sub(s.0));
        Stats {
            tick: Tick(self.scene),
            ticks_per_s: self.sampler.ticks_per_s(),
            expected_ticks_per_s: 30.0 * f64::from(self.chosen) / 1000.0,
            paused: self.pause.paused,
            chosen_speed: self.chosen,
            effective_speed: self.effective_speed(),
            capacity: self.capacity,
            order_delay: d,
            order_delay_ms: d * TICK_MS,
            rtt_ms: rtt,
            jitter_ms: dev,
            stalls: self.stall.count,
            longest_stall_ms: self.stall.longest_ms,
            stalled_total_ms: self.stall.total.as_millis() as u64,
            stalled_ms: current.filter(|d| *d >= COUNTED_STALL).map(ms),
            waiting_for: self.stall.waiting.clone(),
            last_stall_waited_for: self.stall.last_waited.clone(),
            no_remote_players: !self.has_remotes,
            lost_to_cap: self.lost_to_cap,
            caption: self.caption(now),
            peers: self
                .peers
                .iter()
                .filter(|p| p.id != self.local)
                .map(|p| self.peer_stats(p, now))
                .collect(),
            history: self.sampler.history(),
        }
    }
}
