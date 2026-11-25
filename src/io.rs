//! The I/O driver: real sockets and a real clock around the sans-IO parts.
//!
//! A [`Node`] is one machine taking part in one game. It owns the discovery and game
//! sockets (SPEC 2.1) through a [`Transport`] and drives, in phases ([`Phase`]):
//!
//! 1. **Traversal**: STUN from both sockets ([`crate::nat::traversal::Traversal`]), skipped
//!    with [`Stun::Off`]. A guest joining through a relay code connects to the relay here
//!    instead. A guest joining an address or a code skips this phase: its lobby probes the
//!    host while STUN runs (2.6). Traversal keeps running (keepalive, address drift, 2.4)
//!    until game start, and on the host through the game.
//! 2. **Lobby**: a [`HostLobby`] or a [`GuestLobby`], with punching
//!    ([`crate::nat::punch::Puncher`]) on the game socket; or, for [`Role::Browse`], LAN
//!    discovery ([`crate::nat::lan`]) listing the games heard.
//! 3. **Loading**: SPEC 3.7. The lobby is torn down, the game socket is closed and bound
//!    again on the same port, and the load handshake ([`load::LoadHandshake`]) runs.
//! 4. **Game**: the [`Lockstep`].
//!
//! Drive it with [`Node::pump`] (read every pending datagram, route each by its first
//! bytes, poll every state machine, send what they produced) and [`Node::wait`] (sleep
//! until the earliest deadline, at most 5 ms). The only threads are short-lived name
//! lookups ([`Lookup`]): a typed host name and the default STUN servers are resolved
//! off the caller's thread, and the answer is picked up by a later pump.
//!
//! Routing: on the discovery socket a datagram that passes the STUN shape test goes to the
//! traversal first; the fixed LAN probe goes to the host lobby; everything else is lobby
//! traffic. On the game socket: STUN, then the fixed punch datagram, then the load
//! handshake or the lockstep.
//!
//! Every user-visible message of SPEC section 9 comes out as an [`Event`] whose
//! [`fmt::Display`] is the sentence to show.
//!
//! # Loading and rejoining
//!
//! Once the lobby is over the node reports [`Event::Loading`] and, from the next pump on,
//! calls [`Engine::load`] with the agreed seed until it returns `true`; only then does it
//! tell the others it is ready (3.7).
//!
//! The host keeps its discovery socket open during the game and serves rejoins
//! ([`crate::session::rejoin`]). A dropped player runs the same join again; the host
//! answers its lobby traffic with "in game", the node asks for the seat of its name back,
//! and the host, once the lockstep has dropped that player, offers the seat at a rejoin
//! tick R and later sends the game so far. The returning node loads the engine and
//! fast-forwards (`Lockstep::rejoin`) without a load handshake, then plays on.
//!
//! # The transport seam, and the relay
//!
//! All socket access goes through the [`Transport`] trait. [`UdpTransport`] is the direct
//! path, and it also carries the relay: [`Transport::open_relay`] gives it a
//! [`RelayLink`] and a third socket. From then on a datagram for a *synthetic* endpoint
//! (`0.0.0.(k+1)`, [`crate::relay::peer_endpoint`]) is wrapped and sent to the relay, and a
//! relayed datagram comes out of [`Transport::recv`] with the sender's synthetic endpoint,
//! tagged with the local socket it was addressed to (the game socket when the destination
//! port is the local game port, otherwise the discovery socket). The lobby, the load
//! handshake and the lockstep never know. [`Transport::max_datagram_to`] tells the node to
//! cap lockstep packets for relayed peers at the relay's `max_payload` (see
//! [`crate::lockstep::Config::max_datagram`]).
//!
//! When the relay is used ([`crate::relay::FallbackPolicy`]):
//!
//! * a host with [`NodeConfig::relay`] set opens a relay room when traversal fails, when a
//!   peer it expects is not heard directly within the grace period, when
//!   [`NodeConfig::relay_always`] is set, or when the host types `/relay`; it then shows
//!   a version-2 invite code ([`Event::RelayCode`]);
//! * a guest accepts a version-1 or version-2 code ([`crate::relay::code::decode_any`]);
//!   with a version-2 code it joins the room and finds the host at the synthetic endpoint
//!   of member 0.
//!
//! Mixed rooms: once the host has a relay room, it announces it, and every guest joins it
//! too, even one that reached the host directly. Each peer reports its member index and
//! the seats it has heard punch it ([`crate::session::PathTable`]). The host freezes that
//! table when the launch starts, so every peer addresses every pair the same way: directly
//! if the two heard each other's punches, otherwise through the relay. The host cannot
//! start while some pair has neither path.
//!
//! Another transport (an in-memory network for tests, a different relay) implements the
//! same trait and is passed to [`Node::with_transport`].

pub mod load;
pub mod lookup;
pub mod rng;
pub mod toy;
pub mod transport;

use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

pub use load::{LoadEvent, LoadHandshake, LoadTimeout};
pub use lookup::Lookup;
pub use rng::Rng;
pub use transport::{Datagram, Socket, Transport, TransportError, TransportEvent, UdpTransport};

use crate::invite;
use crate::lockstep::{
    self, Caption, ChatError, Desync, Lockstep, PlayerConfig, Stats, SubmitError,
};
use crate::nat::lan::{self, HeardAnnouncements, Prober, TypedTarget};
use crate::nat::punch::{self, PunchEvent, Puncher};
use crate::nat::stun;
use crate::nat::traversal::{Status, Traversal, TraversalEvent, TraversalFailure, Tx};
use crate::relay::code::{self as relay_code, AnyInvite, RelayInvite, RelayRef};
use crate::relay::{peer_endpoint, FallbackPolicy, FallbackReason, RelayEvent, RelayLink, RoomId};
use crate::session::rejoin::{
    self, ClientEvent, Rejoin, RejoinClient, RejoinRefused, RejoinServer, ServerEvent,
};
use crate::session::{
    self, build_compatible, display_build, GameStart, GuestConfig, GuestEvent, GuestLobby,
    GuestStatus, HeardGame, HostConfig, HostError, HostEvent, HostLobby, JoinError, LobbyView,
    MapInfo, PendingRequest, SeatKind, Step,
};
use crate::types::{Endpoint, Engine, Instant, Outgoing, PlayerId, Tick};
use crate::wire::{ChatLabel, MAX_DATAGRAM};

/// The longest [`Node::wait`] sleeps.
pub const MAX_WAIT: Duration = Duration::from_millis(5);
/// Datagrams read per [`Node::pump`] at most, so a flood cannot stall the loop.
pub const MAX_READS_PER_PUMP: usize = 512;
/// A guest that has a reply code shows it if the host is still silent this long after
/// the lobby opened (2.6).
pub const REPLY_CODE_AFTER: Duration = Duration::from_secs(2);
/// A game list says "No games found" after this long without one.
pub const NO_GAMES_AFTER: Duration = Duration::from_secs(3);

/// Maps `std::time::Instant` to [`crate::types::Instant`].
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    origin: std::time::Instant,
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }

    pub fn now(&self) -> Instant {
        Instant(self.origin.elapsed())
    }
}

/// Which STUN servers to ask (2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stun {
    /// No traversal: the local address is used (LAN play, tests).
    Off,
    /// The default public servers ([`stun::DEFAULT_SERVERS`]), resolved at start.
    Default,
    /// These servers.
    Servers(Vec<Endpoint>),
}

/// Everything a [`Node`] needs.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Display name (at most 20 bytes).
    pub name: String,
    /// Build identity (3.4).
    pub build_id: Vec<u8>,
    /// The local address to bind (normally 0.0.0.0).
    pub bind_ip: Ipv4Addr,
    /// Discovery / lobby port; 0 picks a free one.
    pub discovery_port: u16,
    /// Game port; 0 picks a free one.
    pub game_port: u16,
    /// The port LAN announcements and game-list probes go to (normally 1338).
    pub lan_port: u16,
    pub stun: Stun,
    /// Host: the room password. Guest: the password to answer with.
    pub password: Option<String>,
    /// Host: the game label.
    pub game_label: String,
    /// The map the host plays; a guest has exactly this map.
    pub map: MapInfo,
    /// Lockstep drop timeout (5.1).
    pub drop_timeout: Duration,
    /// Guest: tick the ready box as soon as the host seats this peer.
    pub auto_ready: bool,
    /// The relay to fall back to (host).
    pub relay: Option<Endpoint>,
    /// Host: use the relay from the start.
    pub relay_always: bool,
}

impl NodeConfig {
    /// Defaults: ports 1338 / 1337, default STUN servers, the map "demo", auto-ready.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            build_id: b"unknown".to_vec(),
            bind_ip: Ipv4Addr::UNSPECIFIED,
            discovery_port: session::DISCOVERY_PORT,
            game_port: session::GAME_PORT,
            lan_port: lan::DISCOVERY_PORT,
            stun: Stun::Default,
            password: None,
            game_label: format!("{name}'s game"),
            map: MapInfo {
                name: "demo".to_owned(),
                identity: String::new(),
            },
            drop_timeout: lockstep::DEFAULT_DROP_TIMEOUT,
            auto_ready: true,
            relay: None,
            relay_always: false,
        }
    }
}

/// What this node does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// Open a room.
    Host,
    /// Join the room at an address (`ip[:port]`, host name) or an invite code (v1 or v2).
    Join(String),
    /// List the games on the LAN (and at an optional typed address).
    Browse(Option<String>),
}

/// Where the node is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Traversal,
    Lobby,
    Loading,
    Game,
    Ended,
}

/// A game heard by a game list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedGame {
    /// Where to join it (the host's discovery endpoint).
    pub host: Endpoint,
    pub label: String,
    pub host_name: String,
    pub players: usize,
    pub open_seats: usize,
    pub launching: bool,
    pub password: bool,
    /// ". Version X, not Y: cannot join." when the build is incompatible.
    pub incompatible: Option<String>,
}

impl fmt::Display for ListedGame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {}, hosted by {}, {} player(s), {} open seat(s)",
            self.label, self.host, self.host_name, self.players, self.open_seats
        )?;
        if self.password {
            write!(f, ", password")?;
        }
        if self.launching {
            write!(f, ", starting")?;
        }
        if let Some(v) = &self.incompatible {
            write!(f, "{v}")?;
        }
        Ok(())
    }
}

/// Why the node stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The join failed or the guest was sent back to the list.
    Join(JoinError),
    /// The load handshake timed out (3.7).
    LoadTimedOut(LoadTimeout),
    /// The simulations diverged (4.3). Fatal.
    Desync(Box<Desync>),
    /// The typed host name did not resolve to an IPv4 address.
    HostNotFound(String),
    /// Anything else that stops the game.
    Failed(String),
    /// The local player left.
    Left,
}

impl fmt::Display for Ended {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Join(e) => write!(f, "{e}"),
            Self::LoadTimedOut(t) => write!(f, "{t}"),
            Self::HostNotFound(s) => write!(f, "Cannot find the computer called {s}"),
            Self::Desync(d) => write!(f, "{}", d.report(None)),
            Self::Failed(s) => write!(f, "{s}"),
            Self::Left => write!(f, "You left the game"),
        }
    }
}

/// Something to show or log. [`fmt::Display`] is the sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The status line changed.
    Status(String),
    /// A line for the user, answering their own action.
    Notice(String),
    /// A diagnostic line.
    Log(String),
    /// "Invite code: X", with help lines.
    InviteCode(String),
    /// "Your address changed. New invite code: X"
    InviteCodeChanged(String),
    /// "No answer yet. Reply code Y; send it to the host if needed."
    ReplyCode(String),
    /// The room is reachable through a relay with this version-2 code.
    RelayCode {
        code: String,
        relay: Endpoint,
    },
    /// The relay could not be used.
    RelayFailed(String),
    TraversalFailed(TraversalFailure),
    /// A host room line.
    Host(HostEvent),
    /// A guest room line or status.
    Guest(GuestEvent),
    /// Guest side: the first punch arrived from this seated player.
    Reachable {
        name: String,
    },
    /// The room's seats changed: one line per occupied seat.
    Roster(Vec<String>),
    /// A game list heard a game, or a listed game changed.
    GameListed(ListedGame),
    /// A listed game was not heard for 3.5 s.
    GameUnlisted {
        host: Endpoint,
        label: String,
    },
    /// "No games found on this network."
    NoGamesFound,
    /// The lobby is over; waiting for the others to load (3.7).
    Loading {
        seed: u64,
        me: PlayerId,
        players: Vec<(PlayerId, String)>,
    },
    /// A remote finished loading.
    PlayerLoaded {
        name: String,
    },
    /// A seat's address moved (2.8).
    AddressMoved {
        seat: PlayerId,
        from: Endpoint,
        to: Endpoint,
    },
    /// Everyone loaded; ticks are running.
    GameRunning,
    /// The centred in-game caption changed ("WAITING FOR A, B", "SLOWED FOR A").
    Caption(Option<String>),
    /// "DROPPING IN n".
    DropCountdown {
        names: Vec<String>,
        seconds: u32,
    },
    /// "<name> has left the game".
    PlayerLeft {
        name: String,
    },
    /// "<name> has rejoined the game".
    PlayerRejoined {
        name: String,
    },
    /// "Rejoined the game".
    Rejoined,
    /// An in-game chat line (including this player's own, shown at once).
    Chat {
        from: String,
        text: String,
        label: ChatLabel,
    },
    /// The node stopped; see [`Ended`].
    Ended(Ended),
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(s) | Self::Notice(s) | Self::Log(s) => write!(f, "{s}"),
            Self::InviteCode(c) => write!(
                f,
                "Invite code: {c}\n\
                 Send it to the player who wants to join; they paste it to join.\n\
                 If the game does not appear for them, they get a reply code: type it here.\n\
                 A code is good for this session only."
            ),
            Self::InviteCodeChanged(c) => write!(f, "Your address changed. New invite code: {c}"),
            Self::ReplyCode(c) => {
                write!(
                    f,
                    "No answer yet. Reply code {c}; send it to the host if needed."
                )
            }
            Self::RelayCode { code, relay } => write!(
                f,
                "Relay invite code: {code}\nThe game goes through the relay at {relay}."
            ),
            Self::RelayFailed(s) => write!(f, "The relay cannot be used: {s}"),
            Self::TraversalFailed(t) => write!(f, "{t}"),
            Self::Host(e) => write!(f, "{e}"),
            Self::Guest(e) => write!(f, "{e}"),
            Self::Reachable { name } => write!(f, "{name} is reachable directly"),
            Self::Roster(lines) => write!(f, "Room: {}", lines.join(", ")),
            Self::GameListed(g) => write!(f, "Game: {g}"),
            Self::GameUnlisted { host, label } => write!(f, "Game gone: {label} at {host}"),
            Self::NoGamesFound => write!(f, "No games found on this network."),
            Self::Loading { players, .. } => {
                let names: Vec<&str> = players.iter().map(|(_, n)| n.as_str()).collect();
                write!(
                    f,
                    "Starting game with {}. Waiting for every player to load...",
                    names.join(", ")
                )
            }
            Self::PlayerLoaded { name } => write!(f, "{name} has loaded"),
            Self::AddressMoved { seat, from, to } => {
                write!(f, "Player {} moved from {from} to {to}", seat.0)
            }
            Self::GameRunning => write!(f, "Everyone has loaded. The game is running."),
            Self::Caption(Some(c)) => write!(f, "{c}"),
            Self::Caption(None) => write!(f, "(caption cleared)"),
            Self::DropCountdown { names, seconds } => {
                write!(f, "DROPPING IN {seconds}: {}", names.join(", "))
            }
            Self::PlayerLeft { name } => write!(f, "{name} has left the game"),
            Self::PlayerRejoined { name } => write!(f, "{name} has rejoined the game"),
            Self::Rejoined => write!(f, "Rejoined the game"),
            Self::Chat { from, text, label } => match label {
                ChatLabel::None => write!(f, "<{from}> {text}"),
                ChatLabel::Allies => write!(f, "<{from}> (allies) {text}"),
                ChatLabel::Enemies => write!(f, "<{from}> (enemies) {text}"),
            },
            Self::Ended(e) => write!(f, "{e}"),
        }
    }
}

/// Why a [`Node`] could not be made.
#[derive(Debug)]
pub enum NodeError {
    /// A socket could not be bound.
    Transport(TransportError),
    /// The typed address is neither an address, a host name nor a valid code.
    InvalidAddress(String),
    /// The host name did not resolve to an IPv4 address.
    HostNotFound(String),
    /// IPv6 addresses are not supported.
    Ipv6,
    /// The relay code names a relay by index and this build knows no relay table.
    UnknownRelay,
    Host(HostError),
    Join(JoinError),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "{e}"),
            Self::InvalidAddress(s) => write!(f, "Invalid TCP/IP Address: {s}"),
            Self::HostNotFound(s) => write!(f, "Cannot find the computer called {s}"),
            Self::Ipv6 => write!(f, "IPv6 addresses are not supported; use an IPv4 address"),
            Self::UnknownRelay => write!(
                f,
                "That code names a relay this program does not know; ask for a code that \
                 names the relay's address"
            ),
            Self::Host(e) => write!(f, "{e}"),
            Self::Join(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<TransportError> for NodeError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

/// How a guest reaches its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JoinVia {
    Direct { host: Endpoint, via_code: bool },
    Relay { relay: Endpoint, room: RoomId },
}

/// What the user typed to join.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Typed {
    Via(JoinVia),
    /// A host name, to look up off the caller's thread.
    Name {
        host: String,
        port: u16,
    },
}

/// A name lookup in flight, and what it is for.
struct NameLookup {
    lookup: Lookup,
    host: String,
    port: u16,
}

/// A game list.
struct Browser {
    prober: Prober,
    targets: Vec<Endpoint>,
    heard: HeardAnnouncements<u64>,
    games: Vec<(u64, ListedGame)>,
    started: Instant,
    said_none: bool,
}

enum Lobby {
    None,
    Host(Box<HostLobby>),
    Guest(Box<GuestLobby>),
    Browse(Box<Browser>),
    /// A dropped player asking the host for its seat back (session::rejoin).
    Rejoin(Box<RejoinClient>),
}

/// Where the engine is with [`Engine::load`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EngineLoad {
    Idle,
    /// The setup was reported; load from the next pump on.
    Announced(u64),
    Loading(u64),
    Loaded,
}

/// The host's record of one rejoin it speaks for: the rejoin tick R and, once cut, the
/// encoded catch-up bundle.
struct Speaking {
    seat: PlayerId,
    at: Tick,
    bundle: Option<Vec<u8>>,
}

/// One machine in one game. See the module documentation.
pub struct Node<T: Transport = UdpTransport> {
    cfg: NodeConfig,
    role: Role,
    transport: T,
    clock: Clock,
    rng: Rng,
    phase: Phase,
    join: Option<JoinVia>,
    lobby: Lobby,
    traversal: Option<Traversal>,
    outside: Option<(Endpoint, Endpoint)>,
    invite_code: Option<String>,
    reply_code: Option<String>,
    reply_shown: bool,
    lobby_opened: Option<Instant>,
    fallback: FallbackPolicy,
    expected_ip: Option<Ipv4Addr>,
    relay_code: Option<String>,
    puncher: Puncher,
    roster: Vec<String>,
    start: Option<GameStart>,
    load: Option<LoadHandshake>,
    lockstep: Option<Lockstep>,
    caption: Option<String>,
    events: Vec<Event>,
    sends: Vec<(Socket, Outgoing)>,
    send_errors: HashSet<Endpoint>,
    recv_errors: u64,
    /// The path-table part last given to the lobby: (relay member, heard mask).
    paths_sent: Option<(Option<u8>, u16)>,
    /// A guest joined the room's relay room (or tried to).
    joined_room_relay: bool,
    engine_load: EngineLoad,
    /// Host, in the game: answers lobby traffic and serves rejoins.
    rejoin_server: Option<RejoinServer>,
    speaking: Vec<Speaking>,
    /// A returning player: the catch-up to fast-forward through once loaded.
    pending_rejoin: Option<(lockstep::Bundle, Tick)>,
    rejoin_status: Option<String>,
    /// The default STUN servers being looked up.
    stun_lookup: Option<Lookup>,
    /// The typed host name being looked up (join or game list).
    name_lookup: Option<NameLookup>,
}

impl Node<UdpTransport> {
    /// Bind the sockets and start. A host or guest binds both sockets; a game list binds
    /// only the discovery socket, on the LAN port if it is free (else any port).
    pub fn new(cfg: NodeConfig, role: Role) -> Result<Self, NodeError> {
        let transport = match &role {
            Role::Browse(_) => match UdpTransport::bind(cfg.bind_ip, Some(cfg.lan_port), None) {
                Ok(t) => t,
                Err(_) => UdpTransport::bind(cfg.bind_ip, Some(0), None)?,
            },
            _ => UdpTransport::bind(cfg.bind_ip, Some(cfg.discovery_port), Some(cfg.game_port))?,
        };
        Self::with_transport(cfg, role, transport, Rng::from_entropy())
    }
}

impl<T: Transport> Node<T> {
    /// Start with a given transport and random source.
    pub fn with_transport(
        cfg: NodeConfig,
        role: Role,
        transport: T,
        rng: Rng,
    ) -> Result<Self, NodeError> {
        let clock = Clock::new();
        let now = clock.now();
        let mut node = Self {
            cfg,
            role: role.clone(),
            transport,
            clock,
            rng,
            phase: Phase::Traversal,
            join: None,
            lobby: Lobby::None,
            traversal: None,
            outside: None,
            invite_code: None,
            reply_code: None,
            reply_shown: false,
            lobby_opened: None,
            fallback: FallbackPolicy::new(),
            expected_ip: None,
            relay_code: None,
            puncher: Puncher::new(),
            roster: Vec::new(),
            start: None,
            load: None,
            lockstep: None,
            caption: None,
            events: Vec::new(),
            sends: Vec::new(),
            send_errors: HashSet::new(),
            recv_errors: 0,
            paths_sent: None,
            joined_room_relay: false,
            engine_load: EngineLoad::Idle,
            rejoin_server: None,
            speaking: Vec::new(),
            pending_rejoin: None,
            rejoin_status: None,
            stun_lookup: None,
            name_lookup: None,
        };
        match role {
            Role::Browse(target) => node.open_browser(now, target.as_deref())?,
            Role::Join(text) => match parse_join(&text, node.cfg.lan_port)? {
                Typed::Via(via) => node.begin_join(now, via)?,
                Typed::Name { host, port } => {
                    node.events
                        .push(Event::Status(format!("Looking up {host}...")));
                    node.lookup_name(host, port)?;
                }
            },
            Role::Host => {
                if !node.start_traversal(now) {
                    node.open_host(now)?;
                }
            }
        }
        node.flush_sends();
        Ok(node)
    }

    // ------------------------------------------------------------------ read access

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn role(&self) -> &Role {
        &self.role
    }

    pub fn now(&self) -> Instant {
        self.clock.now()
    }

    /// The local port of a socket.
    pub fn local_port(&self, socket: Socket) -> Option<u16> {
        self.transport.local_port(socket)
    }

    /// The invite code, once STUN has answered (host).
    pub fn invite_code(&self) -> Option<&str> {
        self.invite_code.as_deref()
    }

    /// The reply code, once STUN has answered (guest).
    pub fn reply_code(&self) -> Option<&str> {
        self.reply_code.as_deref()
    }

    /// The version-2 relay invite code, once the relay room is open (host).
    pub fn relay_code(&self) -> Option<&str> {
        self.relay_code.as_deref()
    }

    pub fn host_lobby(&self) -> Option<&HostLobby> {
        match &self.lobby {
            Lobby::Host(h) => Some(h),
            _ => None,
        }
    }

    pub fn guest_lobby(&self) -> Option<&GuestLobby> {
        match &self.lobby {
            Lobby::Guest(g) => Some(g),
            _ => None,
        }
    }

    /// The host's waiting join requests.
    pub fn pending_requests(&self) -> Vec<PendingRequest> {
        self.host_lobby()
            .map(HostLobby::pending_requests)
            .unwrap_or_default()
    }

    /// Host: why Start is not possible yet.
    pub fn start_blocker(&self) -> Option<String> {
        self.host_lobby()
            .and_then(|h| h.start_blocker())
            .map(|b| b.to_string())
    }

    /// The agreed game, once the lobby is over.
    pub fn game_start(&self) -> Option<&GameStart> {
        self.start.as_ref()
    }

    pub fn lockstep(&self) -> Option<&Lockstep> {
        self.lockstep.as_ref()
    }

    /// Ticks run so far (0 before the game).
    pub fn scene_time(&self) -> Tick {
        self.lockstep.as_ref().map_or(Tick(0), Lockstep::scene_time)
    }

    /// The overlay snapshot (section 6), during the game.
    pub fn stats(&self) -> Option<Stats> {
        let now = self.clock.now();
        self.lockstep.as_ref().map(|l| l.stats(now))
    }

    /// A player's name.
    pub fn player_name(&self, p: PlayerId) -> String {
        self.start
            .as_ref()
            .and_then(|g| g.seats.get(usize::from(p.0)))
            .filter(|s| !s.name.is_empty())
            .map_or_else(|| format!("player {}", p.0), |s| s.name.clone())
    }

    /// Datagrams that failed to parse or were from strangers, in the game phases.
    pub fn recv_errors(&self) -> u64 {
        self.recv_errors
    }

    /// The transport (for its relay link, say).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    // ------------------------------------------------------------------ actions

    /// Host: press Start.
    pub fn start(&mut self) -> Result<(), HostError> {
        let now = self.clock.now();
        let seed = self.rng.next_u64();
        let Lobby::Host(h) = &mut self.lobby else {
            return Err(HostError::NotRunning);
        };
        let step = h.start(now, seed)?;
        self.absorb_host(now, step);
        self.flush_sends();
        Ok(())
    }

    /// Host: accept the oldest join request, or the oldest from `name`.
    pub fn accept(&mut self, name: Option<&str>) {
        let now = self.clock.now();
        if let Lobby::Host(h) = &mut self.lobby {
            let step = match h.accept(now, name) {
                Ok(s) => s,
                Err(e) => Step {
                    send: Vec::new(),
                    events: vec![HostEvent::AcceptFailed(e)],
                },
            };
            self.absorb_host(now, step);
        }
        self.flush_sends();
    }

    /// Host: open a relay room now (the `/relay` command).
    pub fn use_relay(&mut self) {
        let now = self.clock.now();
        self.open_host_relay(now);
        self.flush_sends();
    }

    /// Queue a game command for this player's next set.
    pub fn submit_command(&mut self, command: Vec<u8>) -> Result<(), SubmitError> {
        match self.lockstep.as_mut() {
            Some(l) => l.submit(command),
            None => Err(SubmitError::QueueFull),
        }
    }

    /// Send an in-game chat line to every remote player.
    pub fn chat(&mut self, text: &str) -> Result<(), ChatError> {
        let me = self.my_seat();
        let Some(l) = self.lockstep.as_mut() else {
            return Err(ChatError::NoSuchPlayer);
        };
        let recipients: Vec<PlayerId> = self
            .start
            .as_ref()
            .map(|g| {
                g.peers
                    .iter()
                    .map(|(p, _)| *p)
                    .filter(|p| !l.is_dropped(*p))
                    .collect()
            })
            .unwrap_or_default();
        l.send_chat(text, &recipients, ChatLabel::None)?;
        let from = me.map_or_else(|| self.cfg.name.clone(), |p| self.player_name(p));
        self.events.push(Event::Chat {
            from,
            text: lockstep::sanitize_chat(text.as_bytes()),
            label: ChatLabel::None,
        });
        Ok(())
    }

    /// A line the user typed. Host lobby: `/start`, `/accept [name]`, `/relay`, a pasted
    /// reply code (never said to the room), or room chat. Guest lobby: `/ready`,
    /// `/unready`, or room chat. Game: chat. Problems come back as [`Event::Notice`].
    pub fn submit_line(&mut self, line: &str) {
        let now = self.clock.now();
        let t = line.trim();
        if t.is_empty() {
            return;
        }
        let word = t
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match self.phase {
            Phase::Lobby | Phase::Traversal => match &mut self.lobby {
                Lobby::Host(_) => {
                    if word == "/start" {
                        if let Err(e) = self.start() {
                            self.events.push(Event::Notice(e.to_string()));
                        }
                    } else if word == "/relay" {
                        self.open_host_relay(now);
                    } else if word == "/invite" {
                        let msg = match &self.invite_code {
                            Some(c) => Event::InviteCode(c.clone()),
                            None => Event::Notice(
                                "There is no invite code: internet traversal is off or failed."
                                    .to_owned(),
                            ),
                        };
                        self.events.push(msg);
                    } else if let Ok(ep) = invite::decode_reply(t) {
                        self.pre_approve(now, ep);
                    } else if let Lobby::Host(h) = &mut self.lobby {
                        let step = h.submit_line(now, t);
                        self.absorb_host(now, step);
                    }
                }
                Lobby::Guest(g) => {
                    let step = match word.as_str() {
                        "/ready" => g.set_ready(now, true),
                        "/unready" => g.set_ready(now, false),
                        _ if t.starts_with('/') => {
                            self.events
                                .push(Event::Notice(format!("Unknown command: {t}")));
                            Step::default()
                        }
                        _ => g.say(now, t),
                    };
                    self.absorb_guest(now, step);
                }
                Lobby::Browse(_) | Lobby::Rejoin(_) | Lobby::None => {}
            },
            Phase::Game => {
                if t.starts_with('/') {
                    self.events
                        .push(Event::Notice(format!("Unknown command: {t}")));
                } else if let Err(e) = self.chat(t) {
                    self.events.push(Event::Notice(e.to_string()));
                }
            }
            Phase::Loading | Phase::Ended => {
                self.events.push(Event::Notice(
                    "Chat works again once everyone has loaded.".to_owned(),
                ));
            }
        }
        self.flush_sends();
    }

    /// Leave: a guest in the lobby tells the host. Ends the node.
    pub fn leave(&mut self) {
        let now = self.clock.now();
        if let Lobby::Guest(g) = &mut self.lobby {
            let step = g.leave(now);
            for o in step.send {
                self.sends.push((Socket::Discovery, o));
            }
        }
        self.flush_sends();
        self.end(Ended::Left);
    }

    // ------------------------------------------------------------------ the loop

    /// One loop step: read every pending datagram, route it, poll every state machine
    /// and send what they produced. Returns the events since the last call.
    pub fn pump(&mut self, engine: &mut impl Engine) -> Vec<Event> {
        let now = self.clock.now();
        if self.phase != Phase::Ended {
            self.read_all(now);
            self.poll_all(now, engine);
            self.flush_sends();
        }
        // The caller now has the setup (Event::Loading): the engine loads from the next
        // pump on.
        if let EngineLoad::Announced(seed) = self.engine_load {
            self.engine_load = EngineLoad::Loading(seed);
        }
        std::mem::take(&mut self.events)
    }

    /// Sleep until the earliest deadline of any part, at most [`MAX_WAIT`].
    pub fn wait(&mut self) {
        let now = self.clock.now();
        let mut deadlines = vec![self.transport.next_deadline()];
        if let Some(t) = &self.traversal {
            deadlines.push(t.next_deadline());
        }
        if self.phase == Phase::Lobby {
            deadlines.push(self.puncher.next_deadline());
        }
        if let Some(l) = &self.load {
            deadlines.push(Some(l.next_deadline()));
        }
        let mut d = MAX_WAIT;
        for at in deadlines.into_iter().flatten() {
            d = d.min(at.0.saturating_sub(now.0));
        }
        if !d.is_zero() {
            self.transport.wait(d);
        }
    }

    // ------------------------------------------------------------------ phases

    /// Start joining the host the user named.
    fn begin_join(&mut self, now: Instant, via: JoinVia) -> Result<(), NodeError> {
        self.join = Some(via);
        match via {
            JoinVia::Relay { relay, room } => {
                let nonce = self.rng.bytes::<8>();
                self.transport
                    .open_relay(RelayLink::guest(relay, room, nonce, now))?;
                self.events.push(Event::Status(format!(
                    "Connecting to the relay at {relay}..."
                )));
            }
            JoinVia::Direct { host, .. } => {
                self.events
                    .push(Event::Status(format!("Connecting to {host}...")));
                // STUN and the probes run in parallel (2.6): the lobby opens now and gets
                // this machine's outside addresses once STUN answers.
                self.start_traversal(now);
                self.open_guest(now)?;
            }
        }
        Ok(())
    }

    /// Look a typed host name up off this thread; a later pump picks the answer up. If no
    /// thread can be started, look it up here.
    fn lookup_name(&mut self, host: String, port: u16) -> Result<(), NodeError> {
        match Lookup::spawn(vec![(host.clone(), port)]) {
            Ok(lookup) => {
                self.name_lookup = Some(NameLookup { lookup, host, port });
                Ok(())
            }
            Err(_) => match lookup::resolve_v4(&host, port) {
                Some(ep) => {
                    let now = self.clock.now();
                    self.on_name_found(now, &host, Some(ep));
                    Ok(())
                }
                None => Err(NodeError::HostNotFound(host)),
            },
        }
    }

    /// Answers of the name lookups in flight.
    fn poll_lookups(&mut self, now: Instant) {
        if let Some(found) = self.stun_lookup.as_mut().and_then(Lookup::poll) {
            self.stun_lookup = None;
            let servers: Vec<Endpoint> = found.into_iter().flatten().collect();
            if !self.begin_traversal(now, &servers) {
                self.after_traversal(now);
            }
        }
        if let Some(found) = self.name_lookup.as_mut().and_then(|n| n.lookup.poll()) {
            if let Some(n) = self.name_lookup.take() {
                let ep = found
                    .first()
                    .copied()
                    .flatten()
                    .map(|e| SocketAddrV4::new(*e.ip(), n.port));
                self.on_name_found(now, &n.host, ep);
            }
        }
    }

    /// A typed host name resolved (or did not).
    fn on_name_found(&mut self, now: Instant, host: &str, ep: Option<Endpoint>) {
        match (&mut self.lobby, ep) {
            (Lobby::Browse(b), Some(ep)) => {
                if !b.targets.contains(&ep) {
                    b.targets.push(ep);
                    b.prober.set_targets(&b.targets);
                }
            }
            (Lobby::Browse(_), None) => self.events.push(Event::Notice(format!(
                "Cannot find the computer called {host}"
            ))),
            (_, Some(ep)) => {
                let via = JoinVia::Direct {
                    host: ep,
                    via_code: false,
                };
                if let Err(e) = self.begin_join(now, via) {
                    self.end(Ended::Failed(e.to_string()));
                }
            }
            (_, None) => self.end(Ended::HostNotFound(host.to_owned())),
        }
    }

    /// Start STUN if configured. Returns whether traversal is now running, or waiting for
    /// the default servers' names to be looked up (off this thread).
    fn start_traversal(&mut self, now: Instant) -> bool {
        if self.cfg.stun == Stun::Off {
            return false;
        }
        self.events.push(Event::Status(
            "Finding this computer's internet address...".to_owned(),
        ));
        let servers = match &self.cfg.stun {
            Stun::Off => return false,
            Stun::Servers(s) => s.clone(),
            Stun::Default => {
                let names = stun::DEFAULT_SERVERS
                    .iter()
                    .map(|(h, p)| ((*h).to_owned(), *p))
                    .collect();
                match Lookup::spawn(names) {
                    Ok(l) => {
                        self.stun_lookup = Some(l);
                        return true;
                    }
                    Err(_) => resolve_default_servers(),
                }
            }
        };
        self.begin_traversal(now, &servers)
    }

    /// Start STUN with these servers. Returns whether traversal is now running.
    fn begin_traversal(&mut self, now: Instant, servers: &[Endpoint]) -> bool {
        let rng = &mut self.rng;
        match Traversal::start(servers, now, &mut || rng.bytes::<12>()) {
            Ok(t) => {
                self.traversal = Some(t);
                true
            }
            Err(f) => {
                self.fallback.note_traversal(&Status::Failed(f.clone()));
                self.events.push(Event::TraversalFailed(f));
                false
            }
        }
    }

    fn open_host(&mut self, now: Instant) -> Result<(), NodeError> {
        let game_port = self.transport.local_port(Socket::Game).unwrap_or(0);
        let mut hc = HostConfig::new(
            &self.cfg.name,
            &self.cfg.game_label,
            &self.cfg.build_id,
            self.rng.next_u64(),
            self.rng.bytes::<32>(),
        );
        hc.game_port = game_port;
        hc.discovery_port = self.cfg.lan_port;
        hc.password = self.cfg.password.clone();
        hc.game_addr = self.outside.map(|(_, g)| g);
        // Handing out an invite code turns on approval (2.9).
        hc.require_approval = self.outside.is_some();
        let mut h = HostLobby::new(hc, now).map_err(NodeError::Host)?;
        let step = h
            .set_map(now, Some(self.cfg.map.clone()))
            .map_err(NodeError::Host)?;
        self.lobby = Lobby::Host(Box::new(h));
        self.phase = Phase::Lobby;
        self.lobby_opened = Some(now);
        self.absorb_host(now, step);
        if let Some((d, _)) = self.outside {
            match invite::encode(d) {
                Ok(code) => {
                    self.invite_code = Some(code.clone());
                    self.events.push(Event::InviteCode(code));
                }
                Err(e) => self
                    .events
                    .push(Event::Notice(format!("Cannot make an invite code: {e}"))),
            }
        }
        if let Some(port) = self.transport.local_port(Socket::Discovery) {
            self.events.push(Event::Status(format!(
                "Hosting on UDP ports {port} (lobby) and {game_port} (game). Type /start when \
                 everyone is ready."
            )));
        }
        if self.cfg.relay_always {
            self.open_host_relay(now);
        }
        Ok(())
    }

    /// The lobby configuration of a guest joining through `self.join`.
    fn guest_config(&mut self) -> Option<GuestConfig> {
        let (host, via_code, relayed) = match self.join? {
            JoinVia::Direct { host, via_code } => (host, via_code, false),
            JoinVia::Relay { .. } => (peer_endpoint(0, session::DISCOVERY_PORT), false, true),
        };
        let mut gc = GuestConfig::new(
            &self.cfg.name,
            &self.cfg.build_id,
            host,
            self.rng.bytes::<16>(),
        );
        gc.game_port = self.transport.local_port(Socket::Game).unwrap_or(0);
        gc.password = self.cfg.password.clone();
        gc.maps = vec![self.cfg.map.clone()];
        gc.via_code = via_code;
        gc.approval = via_code || relayed;
        if !relayed {
            gc.game_addr = self.outside.map(|(_, g)| g);
            gc.stun_addr = self.outside.map(|(d, _)| d);
        }
        Some(gc)
    }

    fn open_guest(&mut self, now: Instant) -> Result<(), NodeError> {
        let Some(gc) = self.guest_config() else {
            return Ok(());
        };
        let via_code = gc.via_code;
        let g = GuestLobby::new(gc, now).map_err(NodeError::Join)?;
        self.lobby = Lobby::Guest(Box::new(g));
        self.phase = Phase::Lobby;
        self.lobby_opened = Some(now);
        if via_code {
            self.fallback.expect_contact(now);
        }
        let step = match &mut self.lobby {
            Lobby::Guest(g) => g.poll(now),
            _ => Step::default(),
        };
        self.absorb_guest(now, step);
        Ok(())
    }

    fn open_browser(&mut self, now: Instant, target: Option<&str>) -> Result<(), NodeError> {
        let mut targets = vec![
            lan::broadcast_target(self.cfg.lan_port),
            lan::loopback_target(self.cfg.lan_port),
        ];
        if let Some(t) = target {
            match parse_join(t, self.cfg.lan_port)? {
                Typed::Via(JoinVia::Direct { host, .. }) => targets.push(host),
                Typed::Via(JoinVia::Relay { .. }) => {}
                Typed::Name { host, port } => self.lookup_name(host, port)?,
            }
        }
        let mut prober = Prober::new();
        prober.set_targets(&targets);
        self.lobby = Lobby::Browse(Box::new(Browser {
            prober,
            targets,
            heard: HeardAnnouncements::new(),
            games: Vec::new(),
            started: now,
            said_none: false,
        }));
        self.phase = Phase::Lobby;
        if self.transport.local_port(Socket::Discovery) != Some(self.cfg.lan_port) {
            self.events.push(Event::Log(format!(
                "UDP port {} is in use, so only games that answer a probe are listed.",
                self.cfg.lan_port
            )));
        }
        self.events.push(Event::Status(
            "Looking for games on this network...".to_owned(),
        ));
        Ok(())
    }

    /// Host: open a relay room (once).
    fn open_host_relay(&mut self, now: Instant) {
        if self.transport.relay_link().is_some() || !matches!(self.lobby, Lobby::Host(_)) {
            return;
        }
        let Some(relay) = self.cfg.relay else {
            self.events.push(Event::Notice(
                "No relay is configured, so only direct connections can work.".to_owned(),
            ));
            return;
        };
        let nonce = self.rng.bytes::<8>();
        match self
            .transport
            .open_relay(RelayLink::host(relay, nonce, now))
        {
            Ok(()) => self.events.push(Event::Status(format!(
                "Opening a room on the relay at {relay}..."
            ))),
            Err(e) => self.events.push(Event::RelayFailed(e.to_string())),
        }
    }

    fn pre_approve(&mut self, now: Instant, ep: Endpoint) {
        if let Lobby::Host(h) = &mut self.lobby {
            let step = h.pre_approve(now, ep);
            if step
                .events
                .iter()
                .any(|e| matches!(e, HostEvent::ReplyCodeAccepted(_)))
            {
                self.expected_ip = Some(*ep.ip());
                self.fallback.expect_contact(now);
            }
            self.absorb_host(now, step);
        }
    }

    /// SPEC 3.7 step 3: tear down the lobby, rebind the game port, start loading.
    ///
    /// The host keeps its discovery socket (and its STUN keepalive, 2.4, so the invite code
    /// stays valid) for rejoins (session::rejoin); a guest closes it.
    fn begin_game(&mut self, now: Instant, gs: GameStart) {
        self.flush_sends();
        self.puncher = Puncher::new();
        self.lobby = Lobby::None;
        if self.role == Role::Host {
            self.rejoin_server = Some(RejoinServer::new(
                &self.cfg.build_id,
                gs.session,
                self.rng.bytes::<32>(),
                self.cfg.password.clone(),
            ));
        } else {
            self.traversal = None;
            self.transport.close_discovery();
        }
        if let Err(e) = self.transport.rebind_game() {
            self.end(Ended::Failed(e.to_string()));
            return;
        }
        let load = LoadHandshake::new(gs.my_seat, &gs.peers, now);
        self.engine_load = EngineLoad::Announced(gs.simulation_seed());
        let players: Vec<(PlayerId, String)> = gs
            .human_players()
            .into_iter()
            .map(|(p, n)| (p, n.to_owned()))
            .collect();
        self.events.push(Event::Loading {
            seed: gs.simulation_seed(),
            me: gs.my_seat,
            players,
        });
        self.load = Some(load);
        self.start = Some(gs);
        self.phase = Phase::Loading;
    }

    /// The lockstep configuration for the agreed game, with each remote at `endpoint_of`.
    fn lockstep_config(
        &self,
        gs: &GameStart,
        endpoint_of: impl Fn(PlayerId) -> Option<Endpoint>,
    ) -> lockstep::Config {
        let players: Vec<PlayerConfig> = gs
            .human_players()
            .into_iter()
            .map(|(id, name)| PlayerConfig {
                id,
                name: name.to_owned(),
                endpoint: if id == gs.my_seat {
                    None
                } else {
                    endpoint_of(id)
                },
            })
            .collect();
        let mut cfg = lockstep::Config::new(gs.my_seat, players.clone());
        cfg.drop_timeout = self.cfg.drop_timeout;
        for p in &players {
            if let Some(ep) = p.endpoint {
                let cap = self.transport.max_datagram_to(ep);
                if cap < MAX_DATAGRAM {
                    cfg.max_datagram.push((p.id, cap));
                }
            }
        }
        cfg
    }

    fn begin_lockstep(&mut self) {
        let (Some(gs), Some(load)) = (&self.start, self.load.take()) else {
            return;
        };
        let book = load.addresses();
        let cfg = self.lockstep_config(gs, |p| book.get(p));
        match Lockstep::new(cfg) {
            Ok(l) => {
                self.lockstep = Some(l);
                self.phase = Phase::Game;
                self.events.push(Event::GameRunning);
            }
            Err(e) => self.end(Ended::Failed(format!("Cannot start the game: {e}"))),
        }
    }

    /// A returning player's catch-up arrived (session::rejoin): set up the game as if it had
    /// just started, but skip the load handshake; once the engine has loaded,
    /// fast-forward with `Lockstep::rejoin` (SPEC 5.6 steps 9-12).
    fn begin_rejoin(&mut self, now: Instant, r: Rejoin) {
        let bundle = match lockstep::Bundle::decode(&r.bundle) {
            Ok(b) => b,
            Err(e) => {
                self.end(Ended::Failed(format!(
                    "The catch-up from the host could not be read: {e}"
                )));
                return;
            }
        };
        let gs = r.start;
        self.flush_sends();
        self.traversal = None;
        self.puncher = Puncher::new();
        self.lobby = Lobby::None;
        self.transport.close_discovery();
        let me = gs.my_seat.0;
        let needs_relay = gs
            .human_players()
            .iter()
            .any(|(p, _)| gs.paths.relayed(me, p.0));
        if let (Some((relay, room)), true, None) =
            (gs.paths.relay, needs_relay, self.transport.relay_link())
        {
            let nonce = self.rng.bytes::<8>();
            if let Err(e) = self
                .transport
                .open_relay(RelayLink::guest(relay, room, nonce, now))
            {
                self.events.push(Event::RelayFailed(e.to_string()));
            }
        }
        let players: Vec<(PlayerId, String)> = gs
            .human_players()
            .into_iter()
            .map(|(p, n)| (p, n.to_owned()))
            .collect();
        self.events.push(Event::Loading {
            seed: gs.simulation_seed(),
            me: gs.my_seat,
            players,
        });
        self.events.push(Event::Status(format!(
            "Catching up to tick {} before rejoining...",
            r.at.0.saturating_sub(1)
        )));
        self.engine_load = EngineLoad::Announced(gs.simulation_seed());
        self.pending_rejoin = Some((bundle, r.at));
        self.start = Some(gs);
        self.phase = Phase::Loading;
    }

    fn begin_rejoin_lockstep(&mut self) {
        let (Some(gs), Some((bundle, at))) = (&self.start, self.pending_rejoin.take()) else {
            return;
        };
        let cfg = self.lockstep_config(gs, |p| gs.endpoint_of(p));
        match Lockstep::rejoin(cfg, bundle, at) {
            Ok(l) => {
                self.lockstep = Some(l);
                self.phase = Phase::Game;
            }
            Err(e) => self.end(Ended::Failed(format!("Cannot rejoin the game: {e}"))),
        }
    }

    fn end(&mut self, why: Ended) {
        if self.phase == Phase::Ended {
            return;
        }
        self.phase = Phase::Ended;
        self.events.push(Event::Ended(why));
    }

    fn my_seat(&self) -> Option<PlayerId> {
        self.start.as_ref().map(|g| g.my_seat)
    }

    // ------------------------------------------------------------------ receive

    fn read_all(&mut self, now: Instant) {
        for _ in 0..MAX_READS_PER_PUMP {
            match self.transport.recv(now) {
                Ok(Some(d)) => self.route(now, d),
                Ok(None) => break,
                Err(e) => {
                    self.recv_errors += 1;
                    if self.recv_errors <= 3 {
                        self.events.push(Event::Log(e.to_string()));
                    }
                    break;
                }
            }
        }
    }

    fn route(&mut self, now: Instant, d: Datagram) {
        let Datagram {
            socket,
            from,
            bytes,
        } = d;
        if stun::looks_like_stun(&bytes) {
            if let Some(t) = self.traversal.as_mut() {
                if let Some(evs) = t.handle(socket, now, from, &bytes) {
                    for e in evs {
                        self.on_traversal(now, e);
                    }
                    return;
                }
            }
        }
        match socket {
            Socket::Discovery => self.route_lobby(now, from, &bytes),
            Socket::Game => self.route_game(now, from, &bytes),
        }
    }

    fn route_lobby(&mut self, now: Instant, from: Endpoint, bytes: &[u8]) {
        if Some(*from.ip()) == self.expected_ip {
            self.fallback.note_direct_contact();
        }
        match &mut self.lobby {
            Lobby::Host(h) => {
                // Our own broadcast or loopback announcement coming back.
                if session::read_announcement(from, bytes)
                    .is_some_and(|a| a.view.session == h.view().session)
                {
                    return;
                }
                // The fixed LAN probe means the same as the lobby's own probe.
                let step = if lan::is_probe(bytes) {
                    h.on_datagram(now, from, &session::probe_datagram(&self.cfg.build_id))
                } else {
                    h.on_datagram(now, from, bytes)
                };
                self.absorb_host(now, step);
            }
            Lobby::Guest(g) => {
                // The host is in the game already: ask for a dropped seat back.
                if let Some((session, challenge)) = rejoin::read_in_game(bytes) {
                    if let Some(gc) = self.guest_config().filter(|c| c.host.ip() == from.ip()) {
                        self.events.push(Event::Status(
                            "The game is under way. Asking the host to rejoin it...".to_owned(),
                        ));
                        let nonce = u32::from_le_bytes(self.rng.bytes::<4>());
                        let c = RejoinClient::new(gc, session, challenge, nonce, now);
                        self.lobby = Lobby::Rejoin(Box::new(c));
                        self.poll_rejoin_client(now);
                    }
                    return;
                }
                let step = g.on_datagram(now, from, bytes);
                self.absorb_guest(now, step);
            }
            Lobby::Rejoin(c) => {
                let step = c.on_datagram(now, from, bytes);
                self.absorb_rejoin_client(now, step);
            }
            Lobby::Browse(b) => {
                if let Some(heard) = session::read_announcement(from, bytes) {
                    let ev = b.hear(now, from, &heard, &self.cfg.build_id);
                    self.events.extend(ev);
                }
            }
            Lobby::None => {
                if let Some(srv) = self.rejoin_server.as_mut() {
                    let step = srv.on_datagram(now, from, bytes);
                    self.absorb_rejoin_server(now, step);
                }
            }
        }
    }

    // ------------------------------------------------------------------ rejoin

    fn poll_rejoin_client(&mut self, now: Instant) {
        if let Lobby::Rejoin(c) = &mut self.lobby {
            let step = c.poll(now);
            self.absorb_rejoin_client(now, step);
        }
    }

    fn rejoin_status(&mut self, s: String) {
        if self.rejoin_status.as_ref() != Some(&s) {
            self.rejoin_status = Some(s.clone());
            self.events.push(Event::Status(s));
        }
    }

    fn absorb_rejoin_client(&mut self, now: Instant, step: Step<ClientEvent>) {
        for o in step.send {
            self.sends.push((Socket::Discovery, o));
        }
        for e in step.events {
            match e {
                ClientEvent::Waiting => self.rejoin_status(
                    "Waiting for the game to let your old connection go...".to_owned(),
                ),
                ClientEvent::Offered { seat, at } => self.rejoin_status(format!(
                    "The host offers seat {} back, from tick {}. Receiving the game so far...",
                    seat.0, at.0
                )),
                ClientEvent::Progress { have, total } => self
                    .events
                    .push(Event::Log(format!("Catch-up: {have} of {total} bytes"))),
                ClientEvent::Refused(r) => self.end(Ended::Failed(r.to_string())),
                ClientEvent::HostSilent => self.end(Ended::Join(JoinError::HostLeft)),
                ClientEvent::Corrupt => self.end(Ended::Failed(
                    "The catch-up from the host could not be read".to_owned(),
                )),
                ClientEvent::Ready(r) => {
                    self.begin_rejoin(now, *r);
                    return;
                }
            }
        }
    }

    fn absorb_rejoin_server(&mut self, now: Instant, step: Step<ServerEvent>) {
        for o in step.send {
            self.sends.push((Socket::Discovery, o));
        }
        for e in step.events {
            match e {
                ServerEvent::Asked { nonce, name, from } => {
                    self.events.push(Event::Log(format!(
                        "{name} at {from} asks to rejoin the game"
                    )));
                    let step = self.answer_rejoin(now, nonce, &name);
                    // Answers produce sends only, never further events.
                    for o in step.send {
                        self.sends.push((Socket::Discovery, o));
                    }
                }
                ServerEvent::Delivered { seat } => self.events.push(Event::Log(format!(
                    "{} has the game so far and is catching up",
                    self.player_name(seat)
                ))),
                ServerEvent::GaveUp { seat } => {
                    let who = seat.map_or_else(|| "a player".to_owned(), |p| self.player_name(p));
                    self.events.push(Event::Log(format!(
                        "Stopped waiting for {who} to rejoin: nothing heard"
                    )));
                }
            }
        }
    }

    /// Host: answer a request for the seat of the player called `name`.
    fn answer_rejoin(&mut self, now: Instant, nonce: u32, name: &str) -> Step<ServerEvent> {
        let seat = self.start.as_ref().and_then(|g| {
            g.seats
                .iter()
                .find(|s| s.kind == SeatKind::Network && s.name.eq_ignore_ascii_case(name))
                .map(|s| PlayerId(s.index))
        });
        let Some(seat) = seat else {
            return match self.rejoin_server.as_mut() {
                Some(srv) => srv.refuse(nonce, RejoinRefused::NoSuchPlayer),
                None => Step::default(),
            };
        };
        let Some(srv) = self.rejoin_server.as_mut() else {
            return Step::default();
        };
        // Already speaking for this seat (an earlier attempt): offer the same tick.
        if let Some(sp) = self.speaking.iter().find(|s| s.seat == seat) {
            let mut step = srv.offer(nonce, seat, sp.at);
            if let (Some(b), Some(gs)) = (&sp.bundle, &self.start) {
                let more = srv.provide(now, seat, gs, &self.cfg.name, &self.cfg.game_label, b);
                step.send.extend(more.send);
            }
            return step;
        }
        let Some(l) = self.lockstep.as_mut() else {
            return srv.wait(nonce);
        };
        if !l.is_dropped(seat) {
            return srv.wait(nonce);
        }
        match l.request_rejoin(seat) {
            Ok(at) => {
                let step = srv.offer(nonce, seat, at);
                self.speaking.push(Speaking {
                    seat,
                    at,
                    bundle: None,
                });
                let name = self.player_name(seat);
                self.events.push(Event::Log(format!(
                    "Letting {name} back in at tick {}",
                    at.0
                )));
                step
            }
            Err(lockstep::RejoinRefusal::NotSpeaker) => {
                srv.refuse(nonce, RejoinRefused::NotSpeaker)
            }
            Err(lockstep::RejoinRefusal::NotRecording) => {
                srv.refuse(nonce, RejoinRefused::NotRecording)
            }
            Err(_) => srv.wait(nonce),
        }
    }

    /// Host: the lockstep reached R-1 for a rejoin it speaks for; send the catch-up.
    fn on_bundle_ready(&mut self, now: Instant, player: PlayerId) {
        let Some(l) = self.lockstep.as_ref() else {
            return;
        };
        let bytes = match l.cut_bundle(player) {
            Ok(b) => b.encode(),
            Err(e) => {
                self.events.push(Event::Log(format!(
                    "Cannot let {} back in: {e}",
                    self.player_name(player)
                )));
                return;
            }
        };
        if let (Some(srv), Some(gs)) = (self.rejoin_server.as_mut(), &self.start) {
            let step = srv.provide(
                now,
                player,
                gs,
                &self.cfg.name,
                &self.cfg.game_label,
                &bytes,
            );
            for o in step.send {
                self.sends.push((Socket::Discovery, o));
            }
        }
        if let Some(sp) = self.speaking.iter_mut().find(|s| s.seat == player) {
            sp.bundle = Some(bytes);
        }
    }

    fn route_game(&mut self, now: Instant, from: Endpoint, bytes: &[u8]) {
        if punch::is_punch(bytes) {
            if self.phase != Phase::Lobby {
                return;
            }
            let evs = self.puncher.handle(from, bytes);
            match &mut self.lobby {
                Lobby::Host(h) => {
                    if let Some(e) = h.note_punch(from) {
                        self.events.push(Event::Host(e));
                    }
                }
                Lobby::Guest(_) => self.on_punch_events(evs),
                _ => {}
            }
            return;
        }
        match self.phase {
            Phase::Loading => {
                let Some(load) = self.load.as_mut() else {
                    return;
                };
                for e in load.handle(from, bytes) {
                    match e {
                        LoadEvent::Ready(p) => {
                            let name = self.player_name(p);
                            self.events.push(Event::PlayerLoaded { name });
                        }
                        LoadEvent::Moved { seat, from, to } => {
                            self.events.push(Event::AddressMoved { seat, from, to });
                        }
                    }
                }
            }
            Phase::Game => {
                if let Some(l) = self.lockstep.as_mut() {
                    if l.handle_datagram(now, from, bytes).is_err() {
                        self.recv_errors += 1;
                    }
                }
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------ poll

    fn poll_all(&mut self, now: Instant, engine: &mut impl Engine) {
        self.poll_lookups(now);
        for e in self.transport.poll(now) {
            self.on_transport(now, e);
        }
        if let Some(t) = self.traversal.as_mut() {
            let mut txs: Vec<Tx> = Vec::new();
            let rng = &mut self.rng;
            let evs = t.poll(now, &mut || rng.bytes::<12>(), &mut txs);
            self.sends
                .extend(txs.into_iter().map(|tx| (tx.socket, tx.out)));
            for e in evs {
                self.on_traversal(now, e);
            }
        }
        if let Some(reason) = self.fallback.poll(now) {
            self.on_fallback(now, reason);
        }
        match &mut self.lobby {
            Lobby::Host(h) => {
                let step = h.poll(now);
                self.absorb_host(now, step);
            }
            Lobby::Guest(g) => {
                let step = g.poll(now);
                self.absorb_guest(now, step);
                self.maybe_show_reply_code(now);
            }
            Lobby::Rejoin(_) => self.poll_rejoin_client(now),
            Lobby::Browse(b) => {
                let mut out = Vec::new();
                b.prober.poll(now, &mut out);
                let probe = session::probe_datagram(&self.cfg.build_id);
                for mut o in out {
                    o.bytes.clone_from(&probe);
                    self.sends.push((Socket::Discovery, o));
                }
                let ev = b.expire(now);
                self.events.extend(ev);
            }
            Lobby::None => {}
        }
        if self.phase == Phase::Lobby {
            self.update_punch_targets();
            let mut out = Vec::new();
            self.puncher.poll(now, &mut out);
            self.sends
                .extend(out.into_iter().map(|o| (Socket::Game, o)));
            self.update_paths(now);
            self.update_roster();
        }
        if let Some(srv) = self.rejoin_server.as_mut() {
            let step = srv.poll(now);
            self.absorb_rejoin_server(now, step);
        }
        if self.phase == Phase::Loading {
            self.poll_engine_load(engine);
        }
        if self.phase == Phase::Loading && self.pending_rejoin.is_some() {
            if self.engine_load == EngineLoad::Loaded {
                self.begin_rejoin_lockstep();
            }
        } else if self.phase == Phase::Loading {
            let mut out = Vec::new();
            let result = match self.load.as_mut() {
                Some(l) => l.poll(now, &mut out),
                None => Ok(()),
            };
            self.sends
                .extend(out.into_iter().map(|o| (Socket::Game, o)));
            match result {
                Err(t) => self.end(Ended::LoadTimedOut(t)),
                Ok(()) => {
                    if self.load.as_ref().is_some_and(LoadHandshake::is_complete) {
                        self.begin_lockstep();
                    }
                }
            }
        }
        if self.phase == Phase::Game {
            self.poll_lockstep(now, engine);
        }
    }

    /// Call [`Engine::load`] until it reports the engine loaded.
    fn poll_engine_load(&mut self, engine: &mut impl Engine) {
        if let EngineLoad::Loading(seed) = self.engine_load {
            if engine.load(seed) {
                self.engine_load = EngineLoad::Loaded;
                if let Some(l) = self.load.as_mut() {
                    l.set_loaded();
                }
            }
        }
    }

    fn poll_lockstep(&mut self, now: Instant, engine: &mut impl Engine) {
        let Some(l) = self.lockstep.as_mut() else {
            return;
        };
        let out = l.poll(now, engine);
        let caption = l.caption(now);
        self.sends
            .extend(out.outgoing.into_iter().map(|o| (Socket::Game, o)));
        for e in out.events {
            if let lockstep::Event::RejoinBundleReady { player, .. } = &e {
                self.on_bundle_ready(now, *player);
            }
            if let lockstep::Event::PlayerRejoined { player, .. } = &e {
                self.speaking.retain(|s| s.seat != *player);
            }
            self.on_lockstep(e);
        }
        let caption = caption.map(|c| self.caption_text(&c));
        if caption != self.caption {
            self.caption.clone_from(&caption);
            self.events.push(Event::Caption(caption));
        }
    }

    fn names(&self, players: &[PlayerId]) -> Vec<String> {
        players.iter().map(|p| self.player_name(*p)).collect()
    }

    fn caption_text(&self, c: &Caption) -> String {
        match c {
            Caption::Waiting {
                players,
                dropping_in,
            } => {
                let mut s = format!("WAITING FOR {}", self.names(players).join(", "));
                if let Some(n) = dropping_in {
                    s.push_str(&format!(". DROPPING IN {n}"));
                }
                s
            }
            Caption::Slowed { players } => {
                format!("SLOWED FOR {}", self.names(players).join(", "))
            }
        }
    }

    fn on_lockstep(&mut self, e: lockstep::Event) {
        let ev = match e {
            lockstep::Event::Desync(d) => {
                self.end(Ended::Desync(Box::new(d)));
                return;
            }
            lockstep::Event::DropCountdown { players, seconds } => Event::DropCountdown {
                names: self.names(&players),
                seconds,
            },
            lockstep::Event::DropIssued { player, from } => Event::Log(format!(
                "Dropping {} from tick {}",
                self.player_name(player),
                from.0
            )),
            lockstep::Event::PlayerLeft { player, .. } => Event::PlayerLeft {
                name: self.player_name(player),
            },
            lockstep::Event::PlayerRejoined { player, .. } => Event::PlayerRejoined {
                name: self.player_name(player),
            },
            lockstep::Event::RejoinBundleReady { player, at } => Event::Log(format!(
                "A catch-up bundle for {} is ready (tick {})",
                self.player_name(player),
                at.0
            )),
            lockstep::Event::Rejoined { .. } => Event::Rejoined,
            lockstep::Event::Chat { from, text, label } => Event::Chat {
                from: self.player_name(from),
                text,
                label,
            },
            lockstep::Event::Log(s) => Event::Log(s),
        };
        self.events.push(ev);
    }

    fn on_transport(&mut self, now: Instant, e: TransportEvent) {
        match e {
            TransportEvent::Log(s) => self.events.push(Event::Log(s)),
            TransportEvent::Relay(RelayEvent::Joined { room, me }) => {
                if let (Lobby::Host(h), Some(relay)) = (&mut self.lobby, self.cfg.relay) {
                    // Every human peer joins this room too (session::PathTable).
                    let step = h.set_relay(now, Some((relay, room)), Some(me));
                    self.absorb_host(now, step);
                    let inv = RelayInvite {
                        relay: RelayRef::Endpoint(relay),
                        room,
                    };
                    match relay_code::encode(&inv) {
                        Ok(code) => {
                            self.relay_code = Some(code.clone());
                            self.events.push(Event::RelayCode { code, relay });
                        }
                        Err(e) => self.events.push(Event::RelayFailed(e.to_string())),
                    }
                } else if let Some(JoinVia::Relay { relay, .. }) = self.join {
                    self.events.push(Event::Log(format!(
                        "Joined the relay at {relay} as member {me}"
                    )));
                    if matches!(self.lobby, Lobby::None) && self.phase == Phase::Traversal {
                        if let Err(e) = self.open_guest(now) {
                            self.end(Ended::Failed(e.to_string()));
                        }
                    }
                } else {
                    self.events.push(Event::Log(format!(
                        "Joined the room's relay as member {me}, for the players who cannot                          be reached directly"
                    )));
                }
            }
            TransportEvent::Relay(RelayEvent::Members(m)) => self.events.push(Event::Log(format!(
                "Relay room members: {}",
                m.count_ones()
            ))),
            TransportEvent::Relay(RelayEvent::Warning(r)) => {
                self.events.push(Event::Log(format!("Relay warning: {r}")));
            }
            TransportEvent::Relay(RelayEvent::Failed(e)) => {
                self.events.push(Event::RelayFailed(e.to_string()));
                if let Lobby::Host(h) = &mut self.lobby {
                    // No relay room any more: every pair is direct again.
                    let step = h.set_relay(now, None, None);
                    self.absorb_host(now, step);
                }
                if matches!(self.join, Some(JoinVia::Relay { .. })) {
                    self.end(Ended::Failed(e.to_string()));
                }
            }
        }
    }

    fn on_fallback(&mut self, now: Instant, reason: FallbackReason) {
        let why = match &reason {
            FallbackReason::Traversal(f) => f.message(),
            FallbackReason::NoDirectContact => "the other player was not heard directly".to_owned(),
        };
        match &self.lobby {
            Lobby::Host(_) if self.cfg.relay.is_some() => {
                self.events
                    .push(Event::Log(format!("Using the relay because {why}.")));
                self.open_host_relay(now);
            }
            Lobby::Guest(g) if g.view().is_none() => self.events.push(Event::Notice(format!(
                "The host cannot be reached directly ({why}). Ask the host for a relay code."
            ))),
            _ => {}
        }
    }

    fn on_traversal(&mut self, now: Instant, e: TraversalEvent) {
        if let Some(t) = &self.traversal {
            self.fallback.note_traversal(t.status());
        }
        match e {
            TraversalEvent::Ready { discovery, game } => {
                self.outside = Some((discovery, game));
                self.events.push(Event::Log(format!(
                    "Internet address: {discovery} (lobby), {game} (game)"
                )));
                self.after_traversal(now);
            }
            TraversalEvent::Failed(f) => {
                self.events.push(Event::TraversalFailed(f));
                self.after_traversal(now);
            }
            TraversalEvent::DiscoveryChanged(ep) => match &self.lobby {
                Lobby::Host(_) | Lobby::None if self.role == Role::Host => {
                    if let Ok(code) = invite::encode(ep) {
                        self.invite_code = Some(code.clone());
                        self.events.push(Event::InviteCodeChanged(code));
                    }
                    self.outside = self.outside.map(|(_, g)| (ep, g));
                }
                Lobby::Guest(_) => {
                    self.outside = self.outside.map(|(_, g)| (ep, g));
                    if let Ok(code) = invite::encode_reply(ep) {
                        self.events
                            .push(Event::Log(format!("New reply code: {code}")));
                        self.reply_code = Some(code);
                    }
                    self.push_guest_addrs(now);
                }
                _ => {}
            },
            TraversalEvent::GameChanged(ep) => {
                self.outside = self.outside.map(|(d, _)| (d, ep));
                match &mut self.lobby {
                    Lobby::Host(h) => {
                        let step = h.set_outside_addr(now, Some(ep));
                        self.absorb_host(now, step);
                    }
                    Lobby::Guest(_) => self.push_guest_addrs(now),
                    _ => {}
                }
            }
        }
    }

    fn push_guest_addrs(&mut self, now: Instant) {
        let (game, stun) = (self.outside.map(|(_, g)| g), self.outside.map(|(d, _)| d));
        if let Lobby::Guest(g) = &mut self.lobby {
            let step = g.set_addrs(now, game, stun);
            self.absorb_guest(now, step);
        }
    }

    /// Traversal settled (or failed): open the lobby if it is not open yet. A guest's lobby
    /// is already probing (2.6); it gets the outside addresses for its claims now.
    fn after_traversal(&mut self, now: Instant) {
        if let Some((d, _)) = self.outside {
            if self.join.is_some() {
                self.reply_code = invite::encode_reply(d).ok();
            }
        }
        if self.phase != Phase::Traversal {
            if self.outside.is_some() && matches!(self.lobby, Lobby::Guest(_)) {
                self.push_guest_addrs(now);
            }
            return;
        }
        let opened = match self.role {
            Role::Host => self.open_host(now),
            Role::Join(_) => self.open_guest(now),
            Role::Browse(_) => Ok(()),
        };
        if let Err(e) = opened {
            self.end(Ended::Failed(e.to_string()));
        }
    }

    fn maybe_show_reply_code(&mut self, now: Instant) {
        if self.reply_shown {
            return;
        }
        let (Some(code), Some(opened), Lobby::Guest(g)) =
            (&self.reply_code, self.lobby_opened, &self.lobby)
        else {
            return;
        };
        if g.view().is_none() && now.0.saturating_sub(opened.0) >= REPLY_CODE_AFTER {
            self.reply_shown = true;
            self.events.push(Event::ReplyCode(code.clone()));
        }
    }

    fn absorb_host(&mut self, now: Instant, step: Step<HostEvent>) {
        for o in step.send {
            self.sends.push((Socket::Discovery, o));
        }
        for e in step.events {
            match e {
                HostEvent::Started(gs) => {
                    self.begin_game(now, *gs);
                    return;
                }
                other => self.events.push(Event::Host(other)),
            }
        }
    }

    fn absorb_guest(&mut self, now: Instant, step: Step<GuestEvent>) {
        let mut queue = vec![step];
        while let Some(step) = queue.pop() {
            for o in step.send {
                self.sends.push((Socket::Discovery, o));
            }
            for e in step.events {
                match e {
                    GuestEvent::Started(gs) => {
                        self.begin_game(now, *gs);
                        return;
                    }
                    GuestEvent::Failed(e) => {
                        self.end(Ended::Join(e));
                        return;
                    }
                    GuestEvent::Updated => self.fallback.note_direct_contact(),
                    GuestEvent::Seated(p) => {
                        self.events.push(Event::Guest(GuestEvent::Seated(p)));
                        if self.cfg.auto_ready {
                            if let Lobby::Guest(g) = &mut self.lobby {
                                queue.push(g.set_ready(now, true));
                            }
                        }
                    }
                    // A new setup epoch cleared the ready box (3.3): tick it again.
                    GuestEvent::Status(GuestStatus::NotReady) if self.cfg.auto_ready => {
                        self.events
                            .push(Event::Guest(GuestEvent::Status(GuestStatus::NotReady)));
                        if let Lobby::Guest(g) = &mut self.lobby {
                            queue.push(g.set_ready(now, true));
                        }
                    }
                    other => self.events.push(Event::Guest(other)),
                }
            }
        }
    }

    fn lobby_view(&self) -> Option<&LobbyView> {
        match &self.lobby {
            Lobby::Host(h) => Some(h.view()),
            Lobby::Guest(g) => g.view(),
            _ => None,
        }
    }

    fn update_roster(&mut self) {
        let Some(view) = self.lobby_view() else {
            return;
        };
        let lines: Vec<String> = view
            .seats
            .iter()
            .filter(|s| s.kind != SeatKind::Open)
            .map(|s| {
                let who = match s.kind {
                    SeatKind::Host => format!("{} (host)", s.name),
                    SeatKind::Computer => format!("computer {}", s.personality),
                    _ => s.name.clone(),
                };
                let ready = if s.ready { "" } else { ", not ready" };
                format!("seat {} {who}{ready}", s.index)
            })
            .collect();
        if lines != self.roster {
            self.roster.clone_from(&lines);
            self.events.push(Event::Roster(lines));
        }
    }

    /// Punch the game address of every seated remote human (2.5).
    fn update_punch_targets(&mut self) {
        let mine = self.guest_lobby().and_then(GuestLobby::my_seat);
        let Some(view) = self.lobby_view() else {
            return;
        };
        let host_side = matches!(self.lobby, Lobby::Host(_));
        let targets: Vec<Endpoint> = view
            .seats
            .iter()
            .filter(|s| {
                if host_side {
                    s.kind == SeatKind::Network
                } else {
                    s.kind.is_human() && Some(PlayerId(s.index)) != mine
                }
            })
            .filter_map(|s| s.addr)
            .filter(|a| !crate::relay::is_synthetic(*a))
            .collect();
        let evs = self.puncher.set_targets(&targets);
        if !host_side {
            self.on_punch_events(evs);
        }
    }

    /// Keep this peer's part of the path table current (session::PathTable): join the
    /// room's relay room when the host has one, and report the relay member index and the
    /// seats heard punching.
    fn update_paths(&mut self, now: Instant) {
        let room = match &self.lobby {
            Lobby::Guest(g) => g.view().and_then(|v| v.paths.relay),
            _ => None,
        };
        if let (Some((relay, room)), false) = (room, self.joined_room_relay) {
            self.joined_room_relay = true;
            if self.transport.relay_link().is_none() {
                let nonce = self.rng.bytes::<8>();
                match self
                    .transport
                    .open_relay(RelayLink::guest(relay, room, nonce, now))
                {
                    Ok(()) => self.events.push(Event::Log(format!(
                        "The host has a relay room; joining it at {relay}"
                    ))),
                    Err(e) => self.events.push(Event::RelayFailed(e.to_string())),
                }
            }
        }
        let member = self.transport.relay_link().and_then(RelayLink::me);
        let heard = self.heard_mask();
        if self.paths_sent == Some((member, heard)) {
            return;
        }
        self.paths_sent = Some((member, heard));
        match &mut self.lobby {
            Lobby::Host(h) => {
                let step = h.set_heard(now, heard);
                self.absorb_host(now, step);
            }
            Lobby::Guest(g) => {
                let step = g.set_paths(now, member, heard);
                self.absorb_guest(now, step);
            }
            _ => {}
        }
    }

    /// A bit per remote human seat whose game address a punch arrived from.
    fn heard_mask(&self) -> u16 {
        let mine = match &self.lobby {
            Lobby::Host(_) => Some(0),
            Lobby::Guest(g) => g.my_seat().map(|p| p.0),
            _ => None,
        };
        let Some(view) = self.lobby_view() else {
            return 0;
        };
        let sources = self.puncher.sources();
        view.seats
            .iter()
            .filter(|s| s.kind.is_human() && Some(s.index) != mine && s.index < 16)
            .filter(|s| s.addr.is_some_and(|a| sources.contains(&a)))
            .fold(0u16, |m, s| m | (1 << s.index))
    }

    fn on_punch_events(&mut self, evs: Vec<PunchEvent>) {
        for e in evs {
            if let PunchEvent::Reachable { target, .. } = e {
                let name = self.lobby_view().and_then(|v| {
                    v.seats
                        .iter()
                        .find(|s| s.addr == Some(target))
                        .map(|s| s.name.clone())
                });
                if let Some(name) = name {
                    self.events.push(Event::Reachable { name });
                }
            }
        }
    }

    // ------------------------------------------------------------------ send

    fn flush_sends(&mut self) {
        for (socket, out) in std::mem::take(&mut self.sends) {
            if let Err(e) = self.transport.send(socket, &out) {
                // Say each unreachable destination once (a broadcast on a machine without
                // a network, a relayed peer before the relay answers).
                if self.send_errors.insert(out.to) {
                    self.events
                        .push(Event::Log(format!("Could not send to {}: {e}", out.to)));
                }
            }
        }
    }
}

impl Browser {
    fn hear(
        &mut self,
        now: Instant,
        from: Endpoint,
        heard: &HeardGame,
        build: &[u8],
    ) -> Vec<Event> {
        let key = heard.view.session;
        self.heard.hear(key, now);
        let v = &heard.view;
        let game = ListedGame {
            host: from,
            label: v.label.clone(),
            host_name: v.host_name.clone(),
            players: v.seats.iter().filter(|s| s.kind != SeatKind::Open).count(),
            open_seats: v.seats.iter().filter(|s| s.kind == SeatKind::Open).count(),
            launching: v.launching,
            password: heard.password,
            incompatible: (!build_compatible(build, &heard.build_id)).then(|| {
                format!(
                    ". Version {}, not {}: cannot join.",
                    display_build(&heard.build_id),
                    display_build(build)
                )
            }),
        };
        let mut game = game;
        if let Some((_, g)) = self.games.iter().find(|(k, _)| *k == key) {
            // Heard on several addresses (LAN and loopback): keep the first.
            game.host = g.host;
        }
        match self.games.iter_mut().find(|(k, _)| *k == key) {
            Some((_, g)) if *g == game => Vec::new(),
            Some((_, g)) => {
                *g = game.clone();
                vec![Event::GameListed(game)]
            }
            None => {
                self.games.push((key, game.clone()));
                vec![Event::GameListed(game)]
            }
        }
    }

    fn expire(&mut self, now: Instant) -> Vec<Event> {
        let mut events = Vec::new();
        for gone in self.heard.expire(now) {
            if let Some(i) = self.games.iter().position(|(k, _)| *k == gone) {
                let (_, g) = self.games.remove(i);
                events.push(Event::GameUnlisted {
                    host: g.host,
                    label: g.label,
                });
            }
        }
        if !self.said_none
            && self.games.is_empty()
            && now.0.saturating_sub(self.started.0) >= NO_GAMES_AFTER
        {
            self.said_none = true;
            events.push(Event::NoGamesFound);
        }
        if !self.games.is_empty() {
            self.said_none = false;
        }
        events
    }
}

/// Resolve the default STUN servers to IPv4, skipping the ones that do not resolve.
/// This blocks for the lookups; a [`Node`] does them on a [`Lookup`] thread instead.
pub fn resolve_default_servers() -> Vec<Endpoint> {
    stun::DEFAULT_SERVERS
        .iter()
        .filter_map(|(host, port)| lookup::resolve_v4(host, *port))
        .collect()
}

/// How to reach the host, from what the user typed. Host names are not looked up here.
fn parse_join(text: &str, default_port: u16) -> Result<Typed, NodeError> {
    let t = text.trim();
    // A relay code first: it is longer than any address.
    if let Ok(AnyInvite::Relay(inv)) = relay_code::decode_any(t) {
        let relay = match inv.relay {
            RelayRef::Endpoint(e) => e,
            RelayRef::Index(_) => return Err(NodeError::UnknownRelay),
        };
        return Ok(Typed::Via(JoinVia::Relay {
            relay,
            room: inv.room,
        }));
    }
    match lan::parse_target(t, default_port) {
        Ok(TypedTarget::Ipv4(host)) => Ok(Typed::Via(JoinVia::Direct {
            host,
            via_code: false,
        })),
        Ok(TypedTarget::Code(host)) => Ok(Typed::Via(JoinVia::Direct {
            host,
            via_code: true,
        })),
        Ok(TypedTarget::Ipv6(_)) => Err(NodeError::Ipv6),
        Ok(TypedTarget::Name { host, port }) => Ok(Typed::Name { host, port }),
        Err(_) => Err(NodeError::InvalidAddress(t.to_owned())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_join_targets() {
        let lan = 1338;
        assert_eq!(
            parse_join("10.0.0.2:5000", lan).unwrap(),
            Typed::Via(JoinVia::Direct {
                host: "10.0.0.2:5000".parse().unwrap(),
                via_code: false
            })
        );
        assert_eq!(
            parse_join("10.0.0.2", lan).unwrap(),
            Typed::Via(JoinVia::Direct {
                host: "10.0.0.2:1338".parse().unwrap(),
                via_code: false
            })
        );
        let ep: Endpoint = "81.2.69.160:40000".parse().unwrap();
        let code = invite::encode(ep).unwrap();
        assert_eq!(
            parse_join(&code, lan).unwrap(),
            Typed::Via(JoinVia::Direct {
                host: ep,
                via_code: true
            })
        );
        let inv = RelayInvite {
            relay: RelayRef::Endpoint("81.2.69.161:3479".parse().unwrap()),
            room: 0x1234_5678_9abc,
        };
        let code = relay_code::encode(&inv).unwrap();
        assert_eq!(
            parse_join(&code, lan).unwrap(),
            Typed::Via(JoinVia::Relay {
                relay: "81.2.69.161:3479".parse().unwrap(),
                room: 0x1234_5678_9abc
            })
        );
        assert!(matches!(
            parse_join("not an address!", lan),
            Err(NodeError::InvalidAddress(_))
        ));
        assert!(matches!(parse_join("::1", lan), Err(NodeError::Ipv6)));
        // Names are looked up later, off the caller's thread.
        assert_eq!(
            parse_join("game-host.example:4000", lan).unwrap(),
            Typed::Name {
                host: "game-host.example".to_owned(),
                port: 4000
            }
        );
    }

    #[test]
    fn event_sentences() {
        assert_eq!(
            Event::ReplyCode("BTM-X".into()).to_string(),
            "No answer yet. Reply code BTM-X; send it to the host if needed."
        );
        assert_eq!(
            Event::Host(HostEvent::HearingFrom("1.2.3.4:5".parse().unwrap())).to_string(),
            "Hearing from 1.2.3.4:5"
        );
        assert_eq!(
            Event::InviteCodeChanged("C".into()).to_string(),
            "Your address changed. New invite code: C"
        );
        assert_eq!(
            Event::NoGamesFound.to_string(),
            "No games found on this network."
        );
    }
}
