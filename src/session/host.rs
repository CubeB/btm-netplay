//! The host side of the lobby (3.1 to 3.8, 2.9).

use std::collections::VecDeque;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use super::codec::{
    self, encode_announce, encode_refuse, Announce, Claim, Leave, Msg, Refuse, RefuseReason,
};
use super::sha256::{ct_eq, Sha256};
use super::{
    build_compatible, clean, display_build, option_valid, password_proof, resolve_addr, since,
    ChatLine, Endpoint, GameStart, HostError, Instant, LobbyView, MapInfo, ModDiff, ModSet,
    PlayerId, SeatInfo, SeatKind, StartBlocker, Step, ANNOUNCE_CHANGE_GAP, ANNOUNCE_PERIOD,
    CLAIM_EXPIRY, DEFAULT_RESOURCE, DISCOVERY_PORT, LAUNCH_WINDOW, MAX_ANNOUNCED_CHAT, MAX_LABEL,
    MAX_NAME, MAX_OPTIONS, MAX_PENDING, MAX_RESOURCE, MAX_TRANSCRIPT, SEATS,
};

const MAX_CLAIMS: usize = 64;
const MAX_REMEMBERED: usize = 256;
const MAX_HEARD_IPS: usize = 32;
const MAX_PRE_APPROVED: usize = 16;
const MAX_REPLY_TRACK: usize = 64;
const REPLY_GAP: std::time::Duration = std::time::Duration::from_millis(250);
const LAUNCH_PUSH_GAP: std::time::Duration = std::time::Duration::from_millis(250);

/// Everything the host needs to open a room. Randomness comes from the caller.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// A random session id (shown as 16 hex digits).
    pub session: u64,
    /// Random bytes: the password challenge is derived from them.
    pub entropy: [u8; 32],
    /// Host display name (at most 20 bytes).
    pub host_name: String,
    /// Game label.
    pub game_label: String,
    /// Opaque build identity (see [`super::build_compatible`]).
    pub build_id: Vec<u8>,
    /// The game port guests should punch and play on.
    pub game_port: u16,
    /// The discovery port announcements are sent to.
    pub discovery_port: u16,
    /// The host's outside game address if it is traversing a NAT.
    pub game_addr: Option<Endpoint>,
    /// Optional password; never sent, see the module docs.
    pub password: Option<String>,
    /// The host's resolved mod set.
    pub mods: ModSet,
    /// Every claim needs an Accept (the host typed `/invite`, 2.9).
    pub require_approval: bool,
    /// Extra unicast announcement targets (broadcast and loopback are always included).
    pub announce_targets: Vec<Endpoint>,
}

impl HostConfig {
    /// A configuration with the default ports, no password, no mods, no approval.
    pub fn new(
        host_name: &str,
        game_label: &str,
        build_id: &[u8],
        session: u64,
        entropy: [u8; 32],
    ) -> Self {
        Self {
            session,
            entropy,
            host_name: host_name.to_owned(),
            game_label: game_label.to_owned(),
            build_id: build_id.to_vec(),
            game_port: super::GAME_PORT,
            discovery_port: DISCOVERY_PORT,
            game_addr: None,
            password: None,
            mods: ModSet::default(),
            require_approval: false,
            announce_targets: Vec::new(),
        }
    }
}

/// Why an accept did not happen (2.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptError {
    Launching,
    NoneWaiting,
    NoMatch,
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Launching => write!(
                f,
                "Cannot accept a join request while the game is starting."
            ),
            Self::NoneWaiting => write!(f, "No join requests are waiting."),
            Self::NoMatch => write!(f, "No join request from that name is waiting."),
        }
    }
}

impl std::error::Error for AcceptError {}

/// A join request waiting for the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRequest {
    pub token: u32,
    pub name: String,
    pub from: Endpoint,
}

/// Things the host shows in the room (section 9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEvent {
    Joined {
        seat: PlayerId,
        name: String,
    },
    Left {
        seat: PlayerId,
        name: String,
    },
    Removed {
        seat: PlayerId,
        name: String,
    },
    /// Said once per token; two room lines.
    BuildRefused {
        name: String,
        theirs: String,
        mine: String,
    },
    PasswordRefused {
        name: String,
    },
    ModsRefused {
        name: String,
        diff: ModDiff,
    },
    JoinRequest {
        token: u32,
        name: String,
    },
    Accepted {
        name: String,
    },
    Declined {
        name: String,
    },
    AcceptFailed(AcceptError),
    /// First datagram from this IP.
    HearingFrom(Endpoint),
    /// A pasted reply code was accepted.
    ReplyCodeAccepted(Endpoint),
    /// The reply code's address equals the host's own outside address.
    CodeOnThisRouter,
    /// A punch arrived from a seated player's IP.
    Reachable {
        name: String,
    },
    Chat(ChatLine),
    /// A slash command this lobby does not know.
    UnknownCommand(String),
    /// The room cannot be advertised (the announcement does not fit one datagram).
    NotAdvertised,
    Starting,
    Started(Box<GameStart>),
}

impl fmt::Display for HostEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Joined { name, .. } => write!(f, "{name} has joined"),
            Self::Left { name, .. } => write!(f, "{name} has left"),
            Self::Removed { name, .. } => write!(f, "{name} was removed"),
            Self::BuildRefused { name, theirs, mine } => {
                write!(
                    f,
                    "{name} cannot join: it is version {theirs}\nThis is version {mine}"
                )
            }
            Self::PasswordRefused { name } => write!(f, "{name} cannot join: incorrect password"),
            Self::ModsRefused { name, diff } => {
                write!(f, "{name} cannot join: the mods differ: {diff}")
            }
            Self::JoinRequest { name, .. } => {
                write!(f, "{name} wants to join. Click Accept or type /accept.")
            }
            Self::Accepted { name } => write!(f, "Accepted {name}'s join request."),
            Self::Declined { name } => write!(f, "Declined {name}'s join request."),
            Self::AcceptFailed(e) => write!(f, "{e}"),
            Self::HearingFrom(e) => write!(f, "Hearing from {e}"),
            Self::ReplyCodeAccepted(e) => {
                write!(f, "Reply code accepted ({e}). Waiting for that player...")
            }
            Self::CodeOnThisRouter => {
                write!(
                    f,
                    "That code is on this router. It joins from the LAN list."
                )
            }
            Self::Reachable { name } => write!(f, "{name} is reachable directly"),
            Self::Chat(l) => write!(f, "{l}"),
            Self::UnknownCommand(c) => write!(f, "Unknown command: {c}"),
            Self::NotAdvertised => write!(f, "The room is too large to advertise"),
            Self::Starting => write!(f, "Starting game..."),
            Self::Started(_) => write!(f, "Game started"),
        }
    }
}

#[derive(Clone, Debug)]
struct ClaimRec {
    token: u32,
    from: Endpoint,
    name: String,
    seat: u8,
    last_choice: (u8, u8, i8),
    game_port: u16,
    game_addr: Option<Endpoint>,
    stun_addr: Option<Endpoint>,
    approval: bool,
    last_heard: Instant,
    last_chat_seq: u32,
    seated: Option<u8>,
}

/// The host's lobby.
pub struct HostLobby {
    cfg: HostConfig,
    challenge: Option<[u8; 16]>,
    view: LobbyView,
    claims: Vec<ClaimRec>,
    pending: Vec<u32>,
    approved: Vec<u32>,
    removed: Vec<(u32, Instant)>,
    said: Vec<u32>,
    pre_approved: Vec<Endpoint>,
    targets: Vec<Endpoint>,
    heard: VecDeque<Ipv4Addr>,
    reachable: Vec<Ipv4Addr>,
    outside_ip: Option<Ipv4Addr>,
    transcript: VecDeque<ChatLine>,
    next_seq: u32,
    fingerprint: [u8; 32],
    last_bytes: Option<Vec<u8>>,
    last_send: Option<Instant>,
    last_launch_push: Option<Instant>,
    replies: Vec<(Endpoint, Instant)>,
    launch: Option<(Instant, u64)>,
    finished: bool,
    warned: bool,
}

impl HostLobby {
    /// Open a room. Seat 0 is the host.
    pub fn new(cfg: HostConfig, _now: Instant) -> Result<Self, HostError> {
        let host_name = clean(&cfg.host_name, MAX_NAME);
        if host_name.is_empty() {
            return Err(HostError::NameRequired);
        }
        let label = clean(&cfg.game_label, MAX_LABEL);
        if label.is_empty() {
            return Err(HostError::GameNameRequired);
        }
        let mut seats: Vec<SeatInfo> = (0..SEATS as u8).map(SeatInfo::open).collect();
        if let Some(s) = seats.first_mut() {
            s.kind = SeatKind::Host;
            s.name = host_name.clone();
            s.addr = cfg.game_addr;
            s.ready = true;
        }
        let password = cfg.password.as_deref().filter(|p| !p.is_empty());
        let challenge = password.map(|_| {
            let mut h = Sha256::new();
            h.update(&cfg.entropy);
            h.update(b"btm-lobby-challenge");
            h.update(&cfg.session.to_le_bytes());
            let d = h.finish();
            let mut c = [0u8; 16];
            c.copy_from_slice(&d[..16]);
            c
        });
        let mut targets = vec![
            SocketAddrV4::new(Ipv4Addr::BROADCAST, cfg.discovery_port),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, cfg.discovery_port),
        ];
        for t in &cfg.announce_targets {
            if !targets.contains(t) {
                targets.push(*t);
            }
        }
        let view = LobbyView {
            session: cfg.session,
            label,
            host_name,
            map: None,
            options: Vec::new(),
            seats,
            epoch: 1,
            launching: false,
            approval_required: cfg.require_approval,
            chat: Vec::new(),
        };
        let mut me = Self {
            challenge,
            view,
            claims: Vec::new(),
            pending: Vec::new(),
            approved: Vec::new(),
            removed: Vec::new(),
            said: Vec::new(),
            pre_approved: Vec::new(),
            targets,
            heard: VecDeque::new(),
            reachable: Vec::new(),
            outside_ip: cfg.game_addr.map(|a| *a.ip()),
            transcript: VecDeque::new(),
            next_seq: 1,
            fingerprint: [0; 32],
            last_bytes: None,
            last_send: None,
            last_launch_push: None,
            replies: Vec::new(),
            launch: None,
            finished: false,
            warned: false,
            cfg,
        };
        me.fingerprint = me.compute_fingerprint();
        Ok(me)
    }

    // ----- read access -------------------------------------------------------------

    /// The room as announced.
    pub fn view(&self) -> &LobbyView {
        &self.view
    }

    /// Join requests waiting for Accept, oldest first.
    pub fn pending_requests(&self) -> Vec<PendingRequest> {
        self.pending
            .iter()
            .filter_map(|t| self.claims.iter().find(|c| c.token == *t))
            .map(|c| PendingRequest {
                token: c.token,
                name: c.name.clone(),
                from: c.from,
            })
            .collect()
    }

    /// Why Start is not possible yet, if so (3.3).
    pub fn start_blocker(&self) -> Option<StartBlocker> {
        if self.view.map.is_none() {
            return Some(StartBlocker::NoMap);
        }
        if let Some(s) = self
            .view
            .seats
            .iter()
            .find(|s| s.kind == SeatKind::Network && !s.ready)
        {
            return Some(StartBlocker::WaitingForReady(s.name.clone()));
        }
        if !self.view.seats.iter().any(|s| s.kind == SeatKind::Network) {
            return Some(StartBlocker::WaitingForPlayer);
        }
        None
    }

    /// The help line of the room (3.3, section 9).
    pub fn help_line(&self) -> String {
        if self.launch.is_some() {
            return "Starting game...".to_owned();
        }
        match self.start_blocker() {
            Some(b) => b.to_string(),
            None => "Ready. Press Start.".to_owned(),
        }
    }

    pub fn is_launching(&self) -> bool {
        self.launch.is_some()
    }

    // ----- time and datagrams ------------------------------------------------------

    /// Run timers: expire claims, finish the launch window, announce.
    pub fn poll(&mut self, now: Instant) -> Step<super::HostEvent> {
        let mut step = Step::default();
        if self.finished {
            return step;
        }
        if let Some((at, seed)) = self.launch {
            if now >= at {
                self.finished = true;
                if let Some(gs) = GameStart::from_view(&self.view, 0, seed, self.cfg.game_port) {
                    step.events.push(HostEvent::Started(Box::new(gs)));
                }
                return step;
            }
        } else {
            self.expire(now, &mut step);
        }
        self.finish(now, &mut step);
        step
    }

    /// Handle a datagram from the discovery socket.
    pub fn on_datagram(&mut self, now: Instant, from: Endpoint, bytes: &[u8]) -> Step<HostEvent> {
        let mut step = Step::default();
        if self.finished {
            return step;
        }
        if !self.heard.contains(from.ip()) {
            if self.heard.len() >= MAX_HEARD_IPS {
                self.heard.pop_front();
            }
            self.heard.push_back(*from.ip());
            step.events.push(HostEvent::HearingFrom(from));
        }
        match codec::decode(bytes) {
            Ok(Msg::Claim(c)) => self.on_claim(now, from, c, &mut step),
            Ok(Msg::Probe) => self.reply_announce(now, from, &mut step),
            Ok(Msg::Leave(l)) => self.on_leave(now, from, l, &mut step),
            _ => {}
        }
        step
    }

    /// A punch datagram arrived on the game port from `from` (2.5): report the first one
    /// from a seated player's IP.
    pub fn note_punch(&mut self, from: Endpoint) -> Option<HostEvent> {
        let ip = *from.ip();
        let seat = self
            .view
            .seats
            .iter()
            .find(|s| s.kind == SeatKind::Network && s.addr.is_some_and(|a| *a.ip() == ip))?;
        if self.reachable.contains(&ip) {
            return None;
        }
        self.reachable.push(ip);
        Some(HostEvent::Reachable {
            name: seat.name.clone(),
        })
    }

    // ----- UI actions --------------------------------------------------------------

    fn editable(&self) -> Result<(), HostError> {
        if self.finished {
            Err(HostError::NotRunning)
        } else if self.launch.is_some() {
            Err(HostError::AlreadyLaunching)
        } else {
            Ok(())
        }
    }

    /// Choose the map.
    pub fn set_map(
        &mut self,
        now: Instant,
        map: Option<MapInfo>,
    ) -> Result<Step<HostEvent>, HostError> {
        self.editable()?;
        self.view.map = map
            .map(|m| MapInfo {
                name: clean(&m.name, super::MAX_MAP_NAME),
                identity: clean(&m.identity, super::MAX_MAP_IDENTITY),
            })
            .filter(|m| !m.name.is_empty());
        Ok(self.done(now))
    }

    /// Set (or replace) an option. Known names must carry a valid value.
    pub fn set_option(
        &mut self,
        now: Instant,
        name: &str,
        value: &str,
    ) -> Result<Step<HostEvent>, HostError> {
        self.editable()?;
        if !option_valid(name, value) {
            return Err(HostError::BadOption);
        }
        if let Some((_, v)) = self.view.options.iter_mut().find(|(n, _)| n == name) {
            *v = value.to_owned();
        } else if self.view.options.len() >= MAX_OPTIONS {
            return Err(HostError::TooManyOptions);
        } else {
            self.view.options.push((name.to_owned(), value.to_owned()));
        }
        Ok(self.done(now))
    }

    /// Remove an option.
    pub fn clear_option(&mut self, now: Instant, name: &str) -> Result<Step<HostEvent>, HostError> {
        self.editable()?;
        self.view.options.retain(|(n, _)| n != name);
        Ok(self.done(now))
    }

    /// Turn an open or computer seat into a computer player.
    pub fn set_computer(
        &mut self,
        now: Instant,
        seat: u8,
        personality: &str,
    ) -> Result<Step<HostEvent>, HostError> {
        self.editable()?;
        let colour = self.free_colour(seat, seat);
        let s = self.seat_mut(seat)?;
        if !matches!(s.kind, SeatKind::Open | SeatKind::Computer) || seat == 0 {
            return Err(HostError::SeatNotEditable(seat));
        }
        if s.kind == SeatKind::Open {
            s.colour = colour;
        }
        s.kind = SeatKind::Computer;
        s.personality = clean(personality, super::MAX_PERSONALITY);
        s.ready = true;
        Ok(self.done(now))
    }

    /// Turn a computer seat back into an open seat.
    pub fn open_seat(&mut self, now: Instant, seat: u8) -> Result<Step<HostEvent>, HostError> {
        self.editable()?;
        let s = self.seat_mut(seat)?;
        if s.kind != SeatKind::Computer {
            return Err(HostError::SeatNotEditable(seat));
        }
        *s = SeatInfo::open(seat);
        Ok(self.done(now))
    }

    /// Change side, colour and team of the host's own seat or a computer seat.
    pub fn set_seat_choice(
        &mut self,
        now: Instant,
        seat: u8,
        side: u8,
        colour: u8,
        team: i8,
    ) -> Result<Step<HostEvent>, HostError> {
        self.editable()?;
        if colour < SEATS as u8 && self.colour_held_by_other(seat, colour) {
            return Err(HostError::ColourTaken(colour));
        }
        let s = self.seat_mut(seat)?;
        if !matches!(s.kind, SeatKind::Host | SeatKind::Computer) {
            return Err(HostError::SeatNotEditable(seat));
        }
        s.side = side;
        s.colour = colour;
        s.team = team.clamp(-1, 4);
        Ok(self.done(now))
    }

    /// Starting resources of the host's own seat or a computer seat.
    pub fn set_seat_resources(
        &mut self,
        now: Instant,
        seat: u8,
        metal: u32,
        energy: u32,
    ) -> Result<Step<HostEvent>, HostError> {
        self.editable()?;
        let s = self.seat_mut(seat)?;
        if !matches!(s.kind, SeatKind::Host | SeatKind::Computer) {
            return Err(HostError::SeatNotEditable(seat));
        }
        s.metal = metal.min(MAX_RESOURCE);
        s.energy = energy.min(MAX_RESOURCE);
        Ok(self.done(now))
    }

    /// The host says something in the room.
    pub fn say(&mut self, now: Instant, text: &str) -> Step<HostEvent> {
        let mut step = Step::default();
        if self.finished {
            return step;
        }
        let name = self.view.host_name.clone();
        if let Some(line) = self.push_chat(&name, text) {
            step.events.push(HostEvent::Chat(line));
        }
        self.finish(now, &mut step);
        step
    }

    /// A line typed in the room box. `/accept [name]` and `/community` are handled here and
    /// never sent as chat; other slash commands are reported as unknown (the caller handles
    /// `/invite` itself before calling). Anything else is chat.
    pub fn submit_line(&mut self, now: Instant, text: &str) -> Step<HostEvent> {
        let t = text.trim();
        let Some(cmd) = t.strip_prefix('/') else {
            return self.say(now, t);
        };
        let (word, arg) = match cmd.split_once(char::is_whitespace) {
            Some((w, a)) => (w, a.trim()),
            None => (cmd, ""),
        };
        match word.to_ascii_lowercase().as_str() {
            "accept" => match self.accept(now, (!arg.is_empty()).then_some(arg)) {
                Ok(step) => step,
                Err(e) => Step {
                    send: Vec::new(),
                    events: vec![HostEvent::AcceptFailed(e)],
                },
            },
            "community" => {
                let next = if self.view.option("community") == Some("on") {
                    "off"
                } else {
                    "on"
                };
                self.set_option(now, "community", next).unwrap_or_default()
            }
            _ => Step {
                send: Vec::new(),
                events: vec![HostEvent::UnknownCommand(t.to_owned())],
            },
        }
    }

    /// Accept the oldest pending request, or the oldest whose name matches (case
    /// insensitive). The Accept button is `accept(now, None)`.
    pub fn accept(
        &mut self,
        now: Instant,
        name: Option<&str>,
    ) -> Result<Step<HostEvent>, AcceptError> {
        if self.launch.is_some() || self.finished {
            return Err(AcceptError::Launching);
        }
        if self.pending.is_empty() {
            return Err(AcceptError::NoneWaiting);
        }
        let token = match name {
            None => self.pending.first().copied(),
            Some(n) => {
                let n = n.to_lowercase();
                self.pending.iter().copied().find(|t| {
                    self.claims
                        .iter()
                        .any(|c| c.token == *t && c.name.to_lowercase() == n)
                })
            }
        }
        .ok_or(AcceptError::NoMatch)?;
        self.accept_token(now, token)
    }

    /// Accept one request by its claim token (approval belongs to the token, not the name).
    pub fn accept_token(
        &mut self,
        now: Instant,
        token: u32,
    ) -> Result<Step<HostEvent>, AcceptError> {
        if self.launch.is_some() || self.finished {
            return Err(AcceptError::Launching);
        }
        if !self.pending.contains(&token) {
            return Err(AcceptError::NoneWaiting);
        }
        let name = self
            .claims
            .iter()
            .find(|c| c.token == token)
            .map(|c| c.name.clone())
            .unwrap_or_default();
        self.pending.retain(|t| *t != token);
        self.approved.push(token);
        let mut step = Step::default();
        step.events.push(HostEvent::Accepted { name });
        self.try_seat(now, token, &mut step);
        self.finish(now, &mut step);
        Ok(step)
    }

    /// Decline a pending request. The guest is told; its token is not heard again.
    pub fn refuse_token(
        &mut self,
        now: Instant,
        token: u32,
    ) -> Result<Step<HostEvent>, AcceptError> {
        if !self.pending.contains(&token) {
            return Err(AcceptError::NoneWaiting);
        }
        let mut step = Step::default();
        self.pending.retain(|t| *t != token);
        if let Some(i) = self.claims.iter().position(|c| c.token == token) {
            let rec = self.claims.remove(i);
            step.events.push(HostEvent::Declined { name: rec.name });
            self.refuse(
                rec.from,
                token,
                RefuseReason::Declined,
                ModDiff::default(),
                &mut step,
            );
        }
        self.remember_removed(token, now);
        self.finish(now, &mut step);
        Ok(step)
    }

    /// Pre-approve a claim whose source or announced discovery endpoint is `ep` (a pasted
    /// reply code, 2.6). `ep` also becomes an announcement target.
    pub fn pre_approve(&mut self, now: Instant, ep: Endpoint) -> Step<HostEvent> {
        let mut step = Step::default();
        if self.finished {
            return step;
        }
        if self.outside_ip == Some(*ep.ip()) {
            step.events.push(HostEvent::CodeOnThisRouter);
            return step;
        }
        if !self.pre_approved.contains(&ep) && self.pre_approved.len() < MAX_PRE_APPROVED {
            self.pre_approved.push(ep);
        }
        if !self.targets.contains(&ep) {
            self.targets.push(ep);
        }
        step.events.push(HostEvent::ReplyCodeAccepted(ep));
        // A matching request may already be waiting.
        let waiting: Vec<u32> = self
            .pending
            .iter()
            .copied()
            .filter(|t| {
                self.claims
                    .iter()
                    .any(|c| c.token == *t && (c.from == ep || c.stun_addr == Some(ep)))
            })
            .collect();
        for t in waiting {
            self.pending.retain(|p| *p != t);
            self.approved.push(t);
            self.try_seat(now, t, &mut step);
        }
        self.finish(now, &mut step);
        step
    }

    /// Tell the lobby the host's own outside address (it changed, or STUN just answered).
    pub fn set_outside_addr(&mut self, now: Instant, addr: Option<Endpoint>) -> Step<HostEvent> {
        self.outside_ip = addr.map(|a| *a.ip());
        self.cfg.game_addr = addr;
        if let Some(s) = self.view.seats.first_mut() {
            s.addr = addr;
        }
        self.done(now)
    }

    /// Add an unicast announcement target.
    pub fn add_announce_target(&mut self, ep: Endpoint) {
        if !self.targets.contains(&ep) {
            self.targets.push(ep);
        }
    }

    /// Require (or stop requiring) approval for every claim.
    pub fn set_require_approval(&mut self, now: Instant, on: bool) -> Step<HostEvent> {
        self.cfg.require_approval = on;
        self.view.approval_required = on;
        self.done(now)
    }

    /// Remove a seated guest (3.2).
    pub fn remove_seat(&mut self, now: Instant, seat: u8) -> Result<Step<HostEvent>, HostError> {
        self.editable()?;
        let s = self
            .view
            .seats
            .get(usize::from(seat))
            .ok_or(HostError::NoSuchSeat(seat))?;
        if s.kind != SeatKind::Network {
            return Err(HostError::SeatNotEditable(seat));
        }
        let (token, name) = (s.token, s.name.clone());
        let mut step = Step::default();
        self.free_seat(seat);
        self.remember_removed(token, now);
        if let Some(i) = self.claims.iter().position(|c| c.token == token) {
            let rec = self.claims.remove(i);
            self.refuse(
                rec.from,
                token,
                RefuseReason::Removed,
                ModDiff::default(),
                &mut step,
            );
        }
        step.events.push(HostEvent::Removed {
            seat: PlayerId(seat),
            name,
        });
        self.finish(now, &mut step);
        Ok(step)
    }

    /// Press Start. On success the launching flag goes out for 2.5 s and
    /// [`HostEvent::Started`] follows from [`HostLobby::poll`]. `seed` is the random seed for
    /// the game.
    pub fn start(&mut self, now: Instant, seed: u64) -> Result<Step<HostEvent>, HostError> {
        self.editable()?;
        if let Some(b) = self.start_blocker() {
            return Err(HostError::StartBlocked(b));
        }
        self.launch = Some((Instant(now.0 + LAUNCH_WINDOW), seed));
        self.view.launching = true;
        self.pending.clear();
        self.last_send = None;
        let mut step = Step::default();
        step.events.push(HostEvent::Starting);
        self.finish(now, &mut step);
        Ok(step)
    }

    // ----- internals ---------------------------------------------------------------

    fn done(&mut self, now: Instant) -> Step<HostEvent> {
        let mut step = Step::default();
        self.finish(now, &mut step);
        step
    }

    fn seat_mut(&mut self, seat: u8) -> Result<&mut SeatInfo, HostError> {
        self.view
            .seats
            .get_mut(usize::from(seat))
            .ok_or(HostError::NoSuchSeat(seat))
    }

    fn colour_held_by_other(&self, seat: u8, colour: u8) -> bool {
        self.view
            .seats
            .iter()
            .any(|s| s.index != seat && s.kind != SeatKind::Open && s.colour == colour)
    }

    /// `pref` if no other active seat holds it, else the first colour nobody holds.
    fn free_colour(&self, seat: u8, pref: u8) -> u8 {
        if usize::from(pref) < SEATS && !self.colour_held_by_other(seat, pref) {
            return pref;
        }
        (0..SEATS as u8)
            .find(|c| !self.colour_held_by_other(seat, *c))
            .unwrap_or(pref)
    }

    fn free_seat(&mut self, seat: u8) {
        if let Some(s) = self.view.seats.get_mut(usize::from(seat)) {
            *s = SeatInfo::open(seat);
        }
        for c in &mut self.claims {
            if c.seated == Some(seat) {
                c.seated = None;
            }
        }
    }

    fn remember_removed(&mut self, token: u32, now: Instant) {
        if self.removed.len() >= MAX_REMEMBERED {
            self.removed.remove(0);
        }
        self.removed.push((token, now));
    }

    fn say_once(&mut self, token: u32, ev: HostEvent, step: &mut Step<HostEvent>) {
        if self.said.contains(&token) {
            return;
        }
        if self.said.len() >= MAX_REMEMBERED {
            self.said.remove(0);
        }
        self.said.push(token);
        step.events.push(ev);
    }

    fn refuse(
        &self,
        to: Endpoint,
        token: u32,
        reason: RefuseReason,
        diff: ModDiff,
        step: &mut Step<HostEvent>,
    ) {
        step.send.push(super::Outgoing {
            to,
            bytes: encode_refuse(&Refuse {
                build: self.cfg.build_id.clone(),
                session: self.cfg.session,
                token,
                reason,
                diff,
            }),
        });
    }

    fn push_chat(&mut self, from: &str, text: &str) -> Option<ChatLine> {
        let text = clean(text, super::MAX_CHAT_LINE);
        if text.is_empty() {
            return None;
        }
        let line = ChatLine {
            seq: self.next_seq,
            from: clean(from, MAX_NAME),
            text,
        };
        self.next_seq = self.next_seq.wrapping_add(1);
        if self.transcript.len() >= MAX_TRANSCRIPT {
            self.transcript.pop_front();
        }
        self.transcript.push_back(line.clone());
        Some(line)
    }

    fn is_pre_approved(&self, rec: &ClaimRec) -> bool {
        self.pre_approved
            .iter()
            .any(|e| *e == rec.from || Some(*e) == rec.stun_addr)
    }

    /// Hash over what 3.3 calls the setup: map, options, and each seat's index, kind, side,
    /// colour, team, resources and (for computers) personality.
    fn compute_fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        let s = |h: &mut Sha256, t: &str| {
            h.update(&(t.len() as u32).to_le_bytes());
            h.update(t.as_bytes());
        };
        if let Some(m) = &self.view.map {
            s(&mut h, &m.name);
            s(&mut h, &m.identity);
        }
        let mut opts: Vec<&(String, String)> = self.view.options.iter().collect();
        opts.sort();
        for (n, v) in opts {
            s(&mut h, n);
            s(&mut h, v);
        }
        for seat in &self.view.seats {
            let kind = match seat.kind {
                SeatKind::Open => 0u8,
                SeatKind::Host => 1,
                SeatKind::Network => 2,
                SeatKind::Computer => 3,
            };
            h.update(&[seat.index, kind, seat.side, seat.colour]);
            h.update(&seat.team.to_le_bytes());
            h.update(&seat.metal.to_le_bytes());
            h.update(&seat.energy.to_le_bytes());
            if seat.kind == SeatKind::Computer {
                s(&mut h, &seat.personality);
            }
        }
        h.finish()
    }

    /// A changed setup bumps the epoch and clears every ready flag (3.3); the host and
    /// computer seats are always ready, an open seat never.
    fn refresh_epoch(&mut self) {
        let fp = self.compute_fingerprint();
        let changed = fp != self.fingerprint;
        if changed {
            self.fingerprint = fp;
            self.view.epoch = self.view.epoch.wrapping_add(1);
        }
        for s in &mut self.view.seats {
            s.ready = match s.kind {
                SeatKind::Host | SeatKind::Computer => true,
                SeatKind::Open => false,
                SeatKind::Network => s.ready && !changed,
            };
        }
    }

    fn finish(&mut self, now: Instant, step: &mut Step<HostEvent>) {
        self.refresh_epoch();
        self.view.chat = self
            .transcript
            .iter()
            .skip(self.transcript.len().saturating_sub(MAX_ANNOUNCED_CHAT))
            .cloned()
            .collect();
        self.flush(now, step);
    }

    fn announce_msg(&self) -> Announce {
        let mut seats = self.view.seats.clone();
        for s in &mut seats {
            if !s.kind.is_human() {
                s.name.clear();
            }
        }
        let (launching, seed) = match self.launch {
            Some((_, seed)) => (true, seed),
            None => (false, 0),
        };
        Announce {
            build: self.cfg.build_id.clone(),
            session: self.cfg.session,
            label: self.view.label.clone(),
            host_name: self.view.host_name.clone(),
            game_port: self.cfg.game_port,
            map: self.view.map.clone(),
            challenge: self.challenge,
            epoch: self.view.epoch,
            launching,
            seed,
            approval: self.cfg.require_approval,
            seats,
            options: self.view.options.clone(),
            chat: self.view.chat.clone(),
            mods_hash: *self.cfg.mods.hash(),
        }
    }

    /// Announce when due: every second, or at once (at most every 100 ms) when the
    /// announcement changed. During the launch window the seated guests are also told
    /// directly every 250 ms.
    fn flush(&mut self, now: Instant, step: &mut Step<HostEvent>) {
        if self.finished {
            return;
        }
        let Some(bytes) = encode_announce(&self.announce_msg()) else {
            if !self.warned {
                self.warned = true;
                step.events.push(HostEvent::NotAdvertised);
            }
            return;
        };
        let changed = self.last_bytes.as_deref() != Some(bytes.as_slice());
        let due = match self.last_send {
            None => true,
            Some(t) => {
                let el = since(now, t);
                el >= ANNOUNCE_PERIOD || (changed && el >= ANNOUNCE_CHANGE_GAP)
            }
        };
        if due {
            for to in &self.targets {
                step.send.push(super::Outgoing {
                    to: *to,
                    bytes: bytes.clone(),
                });
            }
            self.last_send = Some(now);
            self.last_bytes = Some(bytes.clone());
        }
        if self.launch.is_some()
            && self
                .last_launch_push
                .is_none_or(|t| since(now, t) >= LAUNCH_PUSH_GAP)
        {
            self.last_launch_push = Some(now);
            for c in self.claims.iter().filter(|c| c.seated.is_some()) {
                step.send.push(super::Outgoing {
                    to: c.from,
                    bytes: bytes.clone(),
                });
            }
        }
    }

    /// Unicast the announcement to a prober or claimant, at most once per 250 ms each.
    fn reply_announce(&mut self, now: Instant, to: Endpoint, step: &mut Step<HostEvent>) {
        self.replies.retain(|(_, t)| since(now, *t) < REPLY_GAP);
        if self.replies.iter().any(|(e, _)| *e == to) || self.replies.len() >= MAX_REPLY_TRACK {
            return;
        }
        self.refresh_epoch();
        if let Some(bytes) = encode_announce(&self.announce_msg()) {
            self.replies.push((to, now));
            step.send.push(super::Outgoing { to, bytes });
        }
    }

    fn expire(&mut self, now: Instant, step: &mut Step<HostEvent>) {
        self.removed.retain(|(_, t)| since(now, *t) <= CLAIM_EXPIRY);
        let gone: Vec<ClaimRec> = self
            .claims
            .iter()
            .filter(|c| since(now, c.last_heard) > CLAIM_EXPIRY)
            .cloned()
            .collect();
        for rec in gone {
            self.claims.retain(|c| c.token != rec.token);
            self.pending.retain(|t| *t != rec.token);
            self.approved.retain(|t| *t != rec.token);
            self.said.retain(|t| *t != rec.token);
            if let Some(seat) = rec.seated {
                self.free_seat(seat);
                step.events.push(HostEvent::Left {
                    seat: PlayerId(seat),
                    name: rec.name,
                });
            }
        }
    }

    fn on_leave(&mut self, now: Instant, from: Endpoint, l: Leave, step: &mut Step<HostEvent>) {
        if l.session != self.cfg.session {
            return;
        }
        let Some(i) = self.claims.iter().position(|c| c.token == l.token) else {
            return;
        };
        if self.claims.get(i).is_some_and(|c| c.from.ip() != from.ip()) || self.launch.is_some() {
            return;
        }
        let rec = self.claims.remove(i);
        self.pending.retain(|t| *t != l.token);
        self.approved.retain(|t| *t != l.token);
        // The token must not be re-seated by a claim still in flight.
        self.remember_removed(l.token, now);
        if let Some(seat) = rec.seated {
            self.free_seat(seat);
            step.events.push(HostEvent::Left {
                seat: PlayerId(seat),
                name: rec.name,
            });
        }
        self.finish(now, step);
    }

    fn on_claim(&mut self, now: Instant, from: Endpoint, c: Claim, step: &mut Step<HostEvent>) {
        if c.session != self.cfg.session {
            return;
        }
        if let Some(r) = self.removed.iter_mut().find(|(t, _)| *t == c.token) {
            r.1 = now;
            return;
        }
        let token = c.token;
        let name = clean(&c.name, MAX_NAME);
        if name.is_empty() {
            return;
        }
        // Identity checks come first, for seated and new guests alike (3.4, 3.6, 3.9).
        if !build_compatible(&self.cfg.build_id, &c.build) {
            let ev = HostEvent::BuildRefused {
                name,
                theirs: display_build(&c.build),
                mine: display_build(&self.cfg.build_id),
            };
            self.say_once(token, ev, step);
            self.refuse(from, token, RefuseReason::Build, ModDiff::default(), step);
            return;
        }
        if let Some(ch) = self.challenge {
            let ok = match (c.proof, self.cfg.password.as_deref()) {
                (Some(p), Some(pw)) => ct_eq(&p, &password_proof(pw, self.cfg.session, &ch, token)),
                _ => false,
            };
            if !ok {
                self.say_once(token, HostEvent::PasswordRefused { name }, step);
                self.refuse(
                    from,
                    token,
                    RefuseReason::Password,
                    ModDiff::default(),
                    step,
                );
                return;
            }
        }
        if let Some(diff) = self.cfg.mods.diff(&c.mods) {
            let ev = HostEvent::ModsRefused {
                name,
                diff: diff.clone(),
            };
            self.say_once(token, ev, step);
            self.refuse(from, token, RefuseReason::Mods, diff, step);
            return;
        }

        let idx = match self.claims.iter().position(|r| r.token == token) {
            Some(i) => i,
            None => {
                if self.claims.len() >= MAX_CLAIMS {
                    return;
                }
                self.claims.push(ClaimRec {
                    token,
                    from,
                    name: name.clone(),
                    seat: c.seat,
                    last_choice: (c.side, c.colour, c.team),
                    game_port: c.game_port,
                    game_addr: c.game_addr,
                    stun_addr: c.stun_addr,
                    approval: c.approval,
                    last_heard: now,
                    last_chat_seq: 0,
                    seated: None,
                });
                self.claims.len() - 1
            }
        };
        let seated = {
            let Some(rec) = self.claims.get_mut(idx) else {
                return;
            };
            rec.from = from;
            rec.last_heard = now;
            rec.seat = c.seat;
            rec.game_port = c.game_port;
            rec.game_addr = c.game_addr;
            rec.stun_addr = c.stun_addr;
            rec.approval = c.approval;
            if rec.seated.is_none() {
                rec.name = name;
            }
            rec.seated
        };
        match seated {
            Some(seat) => self.update_seated(idx, seat, &c, from),
            None => self.try_seat(now, token, step),
        }
        self.take_chat(idx, &c.chat, step);
        self.finish(now, step);
        self.reply_announce(now, from, step);
        // A claim that could not be seated because the room is full or launching.
        let seated_now = self.claims.get(idx).is_some_and(|r| r.seated.is_some());
        if !seated_now {
            if self.launch.is_some() {
                self.refuse(
                    from,
                    token,
                    RefuseReason::Launching,
                    ModDiff::default(),
                    step,
                );
            } else if self.view.first_open_seat().is_none() {
                self.refuse(from, token, RefuseReason::Full, ModDiff::default(), step);
            }
        }
    }

    /// Follow an address change, apply a changed choice, and take ready if its epoch is
    /// current (3.2, 3.3).
    fn update_seated(&mut self, idx: usize, seat: u8, c: &Claim, from: Endpoint) {
        let new_choice = (c.side, c.colour, c.team);
        let changed = match self.claims.get_mut(idx) {
            Some(rec) => {
                let changed = rec.last_choice != new_choice;
                rec.last_choice = new_choice;
                changed
            }
            None => return,
        };
        let colour_ok = usize::from(c.colour) < SEATS && !self.colour_held_by_other(seat, c.colour);
        let epoch = self.view.epoch;
        let Some(s) = self.view.seats.get_mut(usize::from(seat)) else {
            return;
        };
        s.addr = Some(resolve_addr(from, c.game_addr, c.game_port));
        if changed {
            s.side = c.side;
            if (-1..=4).contains(&c.team) {
                s.team = c.team;
            }
            if colour_ok {
                s.colour = c.colour;
            }
        }
        if c.epoch.is_none_or(|e| e == epoch) {
            s.ready = c.ready;
        }
    }

    fn take_chat(&mut self, idx: usize, lines: &[(u32, String)], step: &mut Step<HostEvent>) {
        let Some(rec) = self.claims.get(idx) else {
            return;
        };
        if rec.seated.is_none() {
            return;
        }
        let (name, mut last) = (rec.name.clone(), rec.last_chat_seq);
        let start = last;
        for (seq, text) in lines {
            if *seq > last {
                last = *seq;
                if let Some(line) = self.push_chat(&name, text) {
                    step.events.push(HostEvent::Chat(line));
                }
            }
        }
        if last != start {
            if let Some(rec) = self.claims.get_mut(idx) {
                rec.last_chat_seq = last;
            }
        }
    }

    /// Try to seat a heard claim: approval first (2.9), then the requested seat (3.2).
    fn try_seat(&mut self, now: Instant, token: u32, step: &mut Step<HostEvent>) {
        let _ = now;
        let Some(rec) = self.claims.iter().find(|c| c.token == token).cloned() else {
            return;
        };
        if self.launch.is_some() || self.view.first_open_seat().is_none() {
            return;
        }
        if (self.cfg.require_approval || rec.approval) && !self.approved.contains(&token) {
            if self.is_pre_approved(&rec) {
                self.approved.push(token);
            } else {
                if !self.pending.contains(&token) && self.pending.len() < MAX_PENDING {
                    self.pending.push(token);
                    step.events.push(HostEvent::JoinRequest {
                        token,
                        name: rec.name.clone(),
                    });
                }
                return;
            }
        }
        let seat = rec.seat;
        let open = seat != 0
            && self
                .view
                .seats
                .get(usize::from(seat))
                .is_some_and(|s| s.kind == SeatKind::Open);
        if !open {
            return;
        }
        let (side, pref_colour, team) = rec.last_choice;
        let colour = self.free_colour(seat, pref_colour);
        let addr = resolve_addr(rec.from, rec.game_addr, rec.game_port);
        if let Some(s) = self.view.seats.get_mut(usize::from(seat)) {
            *s = SeatInfo {
                index: seat,
                kind: SeatKind::Network,
                side,
                colour,
                team: if (-1..=4).contains(&team) { team } else { -1 },
                name: rec.name.clone(),
                addr: Some(addr),
                metal: DEFAULT_RESOURCE,
                energy: DEFAULT_RESOURCE,
                personality: String::new(),
                ready: false,
                token,
            };
        }
        self.pending.retain(|t| *t != token);
        self.approved.retain(|t| *t != token);
        if let Some(r) = self.claims.iter_mut().find(|c| c.token == token) {
            r.seated = Some(seat);
        }
        step.events.push(HostEvent::Joined {
            seat: PlayerId(seat),
            name: rec.name,
        });
    }
}
