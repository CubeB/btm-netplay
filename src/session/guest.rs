//! The guest side of the lobby (3.2, 3.7, 2.9).

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddrV4;

use super::codec::{
    self, encode_claim, encode_leave, encode_probe, Announce, Claim, Leave, Msg, Refuse,
    RefuseReason,
};
use super::sha256::Sha256;
use super::{
    build_compatible, clean, display_build, password_proof, resolve_addr, since, ChatLine,
    Endpoint, GameStart, Instant, JoinError, LobbyView, MapInfo, ModSet, Outgoing, PlayerId,
    SeatInfo, SeatKind, Step, ANNOUNCE_CHANGE_GAP, ANNOUNCE_PERIOD, CHOICE_HOLD, HOST_GONE,
    HOST_NO_ANSWER, MAX_CHAT_LINE, MAX_CLAIM_CHAT, MAX_NAME, SEATS,
};

/// What a guest needs to join one host.
#[derive(Clone, Debug)]
pub struct GuestConfig {
    /// Display name (at most 20 bytes); must not be empty.
    pub name: String,
    /// Opaque build identity.
    pub build_id: Vec<u8>,
    /// Where the host listens (its discovery endpoint).
    pub host: Endpoint,
    /// The password the player typed, if any.
    pub password: Option<String>,
    /// Random bytes; claim tokens are derived from them (a fresh one per retry).
    pub token_seed: [u8; 16],
    /// This peer's game port.
    pub game_port: u16,
    /// This peer's outside game address, if traversing a NAT.
    pub game_addr: Option<Endpoint>,
    /// This peer's STUN discovery address, if it has a reply code.
    pub stun_addr: Option<Endpoint>,
    /// Joined through an invite code: believe the host's announced game address (22).
    pub via_code: bool,
    /// Ask for the host's approval (joined through an invite code, 2.9).
    pub approval: bool,
    /// The maps this machine has.
    pub maps: Vec<MapInfo>,
    /// This peer's resolved mod set.
    pub mods: ModSet,
    /// Initial side, colour and team.
    pub side: u8,
    pub colour: u8,
    pub team: i8,
}

impl GuestConfig {
    /// A configuration with the default game port and no extras.
    pub fn new(name: &str, build_id: &[u8], host: Endpoint, token_seed: [u8; 16]) -> Self {
        Self {
            name: name.to_owned(),
            build_id: build_id.to_vec(),
            host,
            password: None,
            token_seed,
            game_port: super::GAME_PORT,
            game_addr: None,
            stun_addr: None,
            via_code: false,
            approval: false,
            maps: Vec::new(),
            mods: ModSet::default(),
            side: 0,
            colour: 0,
            team: -1,
        }
    }
}

/// The status line of the guest room (section 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestStatus {
    Asking,
    WaitingForApproval,
    NotReady,
    Ready,
    Starting,
    Closed,
}

impl fmt::Display for GuestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asking => write!(f, "Asking the host for a seat..."),
            Self::WaitingForApproval => {
                write!(f, "Waiting for the host to accept your join request...")
            }
            Self::NotReady => write!(f, "Click the box beside your name when you are ready."),
            Self::Ready => write!(f, "You are ready. Waiting for the host to start."),
            Self::Starting => write!(f, "Starting game..."),
            Self::Closed => write!(f, ""),
        }
    }
}

/// What the guest tells its UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestEvent {
    /// The host seated this peer.
    Seated(PlayerId),
    /// The mirrored room changed; read [`GuestLobby::view`].
    Updated,
    /// The status line changed.
    Status(GuestStatus),
    /// A room chat line.
    Chat(ChatLine),
    /// The join failed or ended; the guest is closed.
    Failed(JoinError),
    /// The game starts: every peer received the same seat table.
    Started(Box<GameStart>),
}

impl fmt::Display for GuestEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seated(p) => write!(f, "You have seat {}", p.0),
            Self::Updated => write!(f, "The room changed"),
            Self::Status(s) => write!(f, "{s}"),
            Self::Chat(l) => write!(f, "{l}"),
            Self::Failed(e) => write!(f, "{e}"),
            Self::Started(_) => write!(f, "Game started"),
        }
    }
}

/// A guest in one host's lobby.
pub struct GuestLobby {
    cfg: GuestConfig,
    name: String,
    token: u32,
    token_n: u32,
    wanted: Option<u8>,
    session: Option<u64>,
    challenge: Option<[u8; 16]>,
    view: Option<LobbyView>,
    last_heard: Option<Instant>,
    born: Instant,
    waiting_since: Instant,
    accepted: bool,
    approval_in_play: bool,
    ready: bool,
    ready_epoch: u32,
    choice: (u8, u8, i8),
    hold_until: Option<Instant>,
    outbox: VecDeque<(u32, String)>,
    next_chat: u32,
    chat_seen: u32,
    last_send: Option<Instant>,
    dirty: bool,
    closed: bool,
    started: bool,
    last_status: Option<GuestStatus>,
}

fn derive_token(seed: &[u8; 16], n: u32) -> u32 {
    let mut h = Sha256::new();
    h.update(b"btm-lobby-token");
    h.update(seed);
    h.update(&n.to_le_bytes());
    let d = h.finish();
    match u32::from_le_bytes([d[0], d[1], d[2], d[3]]) {
        0 => 1,
        t => t,
    }
}

impl GuestLobby {
    /// Start joining. Fails with [`JoinError::NameRequired`] when the name is empty.
    pub fn new(cfg: GuestConfig, now: Instant) -> Result<Self, JoinError> {
        let name = clean(&cfg.name, MAX_NAME);
        if name.is_empty() {
            return Err(JoinError::NameRequired);
        }
        Ok(Self {
            token: derive_token(&cfg.token_seed, 0),
            token_n: 0,
            choice: (cfg.side, cfg.colour, cfg.team),
            approval_in_play: cfg.approval,
            name,
            cfg,
            wanted: None,
            session: None,
            challenge: None,
            view: None,
            last_heard: None,
            born: now,
            waiting_since: now,
            accepted: false,
            ready: false,
            ready_epoch: 0,
            hold_until: None,
            outbox: VecDeque::new(),
            next_chat: 1,
            chat_seen: 0,
            last_send: None,
            dirty: false,
            closed: false,
            started: false,
            last_status: None,
        })
    }

    /// The mirrored room, once the host has been heard.
    pub fn view(&self) -> Option<&LobbyView> {
        self.view.as_ref()
    }

    /// This peer's seat once the host has accepted it.
    pub fn my_seat(&self) -> Option<PlayerId> {
        if !self.accepted {
            return None;
        }
        self.my_seat_index().map(PlayerId)
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// The side, colour and team shown for this peer (its own click is held for 2 s).
    pub fn choice(&self) -> (u8, u8, i8) {
        self.choice
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn status(&self) -> GuestStatus {
        if self.started {
            return GuestStatus::Starting;
        }
        if self.closed {
            return GuestStatus::Closed;
        }
        if !self.accepted {
            return if self.last_heard.is_some() && self.approval_in_play {
                GuestStatus::WaitingForApproval
            } else {
                GuestStatus::Asking
            };
        }
        if self.view.as_ref().is_some_and(|v| v.launching) {
            GuestStatus::Starting
        } else if self.ready {
            GuestStatus::Ready
        } else {
            GuestStatus::NotReady
        }
    }

    /// Replace the list of maps this machine has.
    pub fn set_local_maps(&mut self, maps: Vec<MapInfo>) {
        self.cfg.maps = maps;
    }

    /// The addresses to put in claims changed (STUN refresh, new reply code).
    pub fn set_addrs(
        &mut self,
        now: Instant,
        game: Option<Endpoint>,
        stun: Option<Endpoint>,
    ) -> Step<GuestEvent> {
        self.cfg.game_addr = game;
        self.cfg.stun_addr = stun;
        self.dirty = true;
        self.done(now)
    }

    // ----- UI actions --------------------------------------------------------------

    /// Click the ready box. Ignored until the host has seated this peer.
    pub fn set_ready(&mut self, now: Instant, ready: bool) -> Step<GuestEvent> {
        if self.accepted && !self.closed && self.ready != ready {
            self.ready = ready;
            self.dirty = true;
        }
        self.done(now)
    }

    /// Change side, colour and team; shown at once, sent in the next claim, and the host's
    /// word wins after 2 s.
    pub fn set_choice(&mut self, now: Instant, side: u8, colour: u8, team: i8) -> Step<GuestEvent> {
        if self.accepted && !self.closed {
            self.choice = (side, colour, team);
            self.hold_until = Some(Instant(now.0 + CHOICE_HOLD));
            self.dirty = true;
        }
        self.done(now)
    }

    /// Say something in the room (sent in the next claims; shown when the host echoes it).
    pub fn say(&mut self, now: Instant, text: &str) -> Step<GuestEvent> {
        let text = clean(text, MAX_CHAT_LINE);
        if self.accepted && !self.closed && !text.is_empty() {
            if self.outbox.len() >= MAX_CLAIM_CHAT {
                self.outbox.pop_front();
            }
            self.outbox.push_back((self.next_chat, text));
            self.next_chat = self.next_chat.wrapping_add(1);
            self.dirty = true;
        }
        self.done(now)
    }

    /// Leave the room. The host frees the seat at once (or after 3.5 s if this is lost).
    pub fn leave(&mut self, now: Instant) -> Step<GuestEvent> {
        let mut step = Step::default();
        if !self.closed {
            self.send_leave(&mut step);
            self.closed = true;
        }
        self.status_event(now, &mut step);
        step
    }

    // ----- time and datagrams ------------------------------------------------------

    /// Run timers and send the claim (or a probe before the host has answered).
    pub fn poll(&mut self, now: Instant) -> Step<GuestEvent> {
        let mut step = Step::default();
        if self.closed {
            return step;
        }
        if let Some(h) = self.last_heard {
            if since(now, h) > HOST_GONE {
                self.fail(JoinError::HostLeft, &mut step);
            } else if !self.accepted
                && !self.approval_in_play
                && since(now, self.waiting_since) > HOST_NO_ANSWER
            {
                self.fail(JoinError::HostDidNotAnswer, &mut step);
            }
        } else if !self.cfg.approval && since(now, self.born) > HOST_NO_ANSWER {
            self.fail(JoinError::HostDidNotAnswer, &mut step);
        }
        self.flush(now, &mut step);
        self.status_event(now, &mut step);
        step
    }

    /// Handle a datagram from the discovery socket.
    pub fn on_datagram(&mut self, now: Instant, from: Endpoint, bytes: &[u8]) -> Step<GuestEvent> {
        let mut step = Step::default();
        if self.closed || from.ip() != self.cfg.host.ip() {
            return step;
        }
        match codec::decode(bytes) {
            Ok(Msg::Announce(a)) => self.on_announce(now, from, a, &mut step),
            Ok(Msg::Refuse(r)) => self.on_refuse(r, &mut step),
            _ => {}
        }
        self.flush(now, &mut step);
        self.status_event(now, &mut step);
        step
    }

    // ----- internals ---------------------------------------------------------------

    fn done(&mut self, now: Instant) -> Step<GuestEvent> {
        let mut step = Step::default();
        self.flush(now, &mut step);
        self.status_event(now, &mut step);
        step
    }

    fn status_event(&mut self, _now: Instant, step: &mut Step<GuestEvent>) {
        let s = self.status();
        if self.last_status != Some(s) {
            self.last_status = Some(s);
            step.events.push(GuestEvent::Status(s));
        }
    }

    fn my_seat_index(&self) -> Option<u8> {
        self.view
            .as_ref()?
            .seats
            .iter()
            .find_map(|s| (s.kind == SeatKind::Network && s.token == self.token).then_some(s.index))
    }

    fn fail(&mut self, e: JoinError, step: &mut Step<GuestEvent>) {
        if self.closed {
            return;
        }
        if self.session.is_some()
            && matches!(
                e,
                JoinError::NoMap(_) | JoinError::MapMismatch(_) | JoinError::CouldNotLoadMap(_)
            )
        {
            self.send_leave(step);
        }
        self.closed = true;
        step.events.push(GuestEvent::Failed(e));
    }

    fn send_leave(&self, step: &mut Step<GuestEvent>) {
        if let Some(session) = self.session {
            step.send.push(Outgoing {
                to: self.cfg.host,
                bytes: encode_leave(
                    &self.cfg.build_id,
                    &Leave {
                        session,
                        token: self.token,
                    },
                ),
            });
        }
    }

    fn map_problem(&self, map: &Option<MapInfo>) -> Option<JoinError> {
        let host = map.as_ref()?;
        let Some(local) = self.cfg.maps.iter().find(|m| m.name == host.name) else {
            return Some(JoinError::NoMap(host.name.clone()));
        };
        // Map identity is checked when the host gave one (3.5).
        (!host.identity.is_empty() && !local.identity.is_empty() && local.identity != host.identity)
            .then(|| JoinError::MapMismatch(host.name.clone()))
    }

    fn on_refuse(&mut self, r: Refuse, step: &mut Step<GuestEvent>) {
        if Some(r.session) != self.session || r.token != self.token {
            return;
        }
        let err = match r.reason {
            RefuseReason::Removed => JoinError::Removed,
            _ if self.accepted => return,
            RefuseReason::Build => JoinError::VersionMismatch {
                theirs: display_build(&r.build),
                mine: display_build(&self.cfg.build_id),
            },
            RefuseReason::Password => JoinError::IncorrectPassword,
            RefuseReason::Mods => JoinError::ModMismatch(r.diff),
            RefuseReason::Full => JoinError::GameFull,
            RefuseReason::Launching => JoinError::AlreadyStarted,
            RefuseReason::Declined => JoinError::Declined,
        };
        self.fail(err, step);
    }

    fn build_view(&self, from: Endpoint, a: &Announce) -> LobbyView {
        let mut seats: Vec<SeatInfo> = (0..SEATS as u8).map(SeatInfo::open).collect();
        for s in &a.seats {
            if let Some(slot) = seats.get_mut(usize::from(s.index)) {
                *slot = s.clone();
            }
        }
        // The host's own game address (2.8, 22): believed only when joined by a code.
        if let Some(s) = seats.first_mut() {
            if s.kind == SeatKind::Host {
                s.addr = Some(if self.cfg.via_code {
                    resolve_addr(from, s.addr, a.game_port)
                } else {
                    SocketAddrV4::new(*from.ip(), a.game_port)
                });
            }
        }
        LobbyView {
            session: a.session,
            label: a.label.clone(),
            host_name: a.host_name.clone(),
            map: a.map.clone(),
            options: a.options.clone(),
            seats,
            epoch: a.epoch,
            launching: a.launching,
            approval_required: a.approval,
            chat: a.chat.clone(),
        }
    }

    fn on_announce(
        &mut self,
        now: Instant,
        from: Endpoint,
        a: Announce,
        step: &mut Step<GuestEvent>,
    ) {
        if self.session.is_some_and(|s| s != a.session) {
            return;
        }
        let first = self.session.is_none();
        self.session = Some(a.session);
        self.challenge = a.challenge;
        self.last_heard = Some(now);
        self.approval_in_play = self.cfg.approval || a.approval;
        let view = self.build_view(from, &a);

        // The checks of 3.2, in order, until the host has seated this peer.
        if !self.accepted {
            let problem = if a.launching {
                Some(JoinError::AlreadyStarted)
            } else if !build_compatible(&self.cfg.build_id, &a.build) {
                Some(JoinError::VersionMismatch {
                    theirs: display_build(&a.build),
                    mine: display_build(&self.cfg.build_id),
                })
            } else if a.challenge.is_some()
                && self.cfg.password.as_deref().is_none_or(str::is_empty)
            {
                Some(JoinError::IncorrectPassword)
            } else {
                self.map_problem(&a.map)
            };
            if let Some(e) = problem {
                self.view = Some(view);
                return self.fail(e, step);
            }
        } else if let Some(e) = self.map_problem(&a.map) {
            self.view = Some(view);
            return self.fail(e, step);
        }

        if first {
            self.ready_epoch = a.epoch;
        }
        self.view = Some(view);
        self.update_claim_state(now, step);
        if self.closed {
            return;
        }

        // Ready is tied to the setup epoch: a new epoch clears this peer's ready (3.3).
        if a.epoch != self.ready_epoch {
            self.ready_epoch = a.epoch;
            if self.ready {
                self.ready = false;
                self.dirty = true;
            }
        }

        // The host's word wins over this peer's own choice after 2 s (3.2).
        if let Some(seat) = self
            .my_seat_index()
            .and_then(|i| self.view.as_ref().and_then(|v| v.seats.get(usize::from(i))))
        {
            let theirs = (seat.side, seat.colour, seat.team);
            if theirs == self.choice {
                self.hold_until = None;
            } else if self.hold_until.is_none_or(|h| now >= h) {
                self.choice = theirs;
                self.hold_until = None;
                self.dirty = true;
            }
        }

        for line in &a.chat {
            if line.seq > self.chat_seen {
                self.chat_seen = line.seq;
                step.events.push(GuestEvent::Chat(line.clone()));
            }
        }
        step.events.push(GuestEvent::Updated);

        if a.launching && self.accepted {
            self.try_start(a.seed, step);
        }
    }

    /// Waiting / Accepted / Lost, from how the host shows this peer's seat (3.2).
    fn update_claim_state(&mut self, now: Instant, step: &mut Step<GuestEvent>) {
        let mine = self.my_seat_index();
        if let Some(seat) = mine {
            if !self.accepted {
                self.accepted = true;
                self.dirty = true;
                step.events.push(GuestEvent::Seated(PlayerId(seat)));
            }
            return;
        }
        if self.accepted {
            return self.fail(JoinError::Removed, step);
        }
        let open_wanted = self.wanted.is_some_and(|w| {
            self.view
                .as_ref()
                .and_then(|v| v.seats.get(usize::from(w)))
                .is_some_and(|s| s.kind == SeatKind::Open)
        });
        if open_wanted {
            return;
        }
        // Not yet claimed, or lost: take the lowest open seat. An approved token must survive
        // when approval is in play; otherwise a lost claim gets a fresh token.
        let Some(next) = self.view.as_ref().and_then(LobbyView::first_open_seat) else {
            return self.fail(JoinError::GameFull, step);
        };
        if self.wanted.is_some() && !self.approval_in_play {
            self.token_n += 1;
            self.token = derive_token(&self.cfg.token_seed, self.token_n);
        }
        self.wanted = Some(next);
        self.waiting_since = now;
        self.hold_until = Some(Instant(now.0 + CHOICE_HOLD));
        self.dirty = true;
    }

    fn try_start(&mut self, seed: u64, step: &mut Step<GuestEvent>) {
        let Some(view) = &self.view else { return };
        if let Some(map) = &view.map {
            let loaded = self.cfg.maps.iter().any(|m| m.name == map.name);
            if !loaded {
                return self.fail(JoinError::CouldNotLoadMap(map.name.clone()), step);
            }
        }
        let Some(my) = self.my_seat_index() else {
            return;
        };
        match GameStart::from_view(view, my, seed, self.cfg.game_port) {
            Some(gs) => {
                self.closed = true;
                self.started = true;
                step.events.push(GuestEvent::Started(Box::new(gs)));
            }
            None => self.fail(JoinError::CouldNotLoadMap(String::new()), step),
        }
    }

    fn claim(&self) -> Option<Claim> {
        let session = self.session?;
        let proof = match (&self.challenge, &self.cfg.password) {
            (Some(ch), Some(pw)) if !pw.is_empty() => {
                Some(password_proof(pw, session, ch, self.token))
            }
            _ => None,
        };
        Some(Claim {
            build: self.cfg.build_id.clone(),
            session,
            token: self.token,
            name: self.name.clone(),
            seat: self.wanted?,
            side: self.choice.0,
            colour: self.choice.1,
            team: self.choice.2,
            ready: self.ready,
            epoch: Some(self.ready_epoch),
            game_port: self.cfg.game_port,
            game_addr: self.cfg.game_addr,
            stun_addr: self.cfg.stun_addr,
            approval: self.cfg.approval,
            chat: self.outbox.iter().cloned().collect(),
            proof,
            mods: self.cfg.mods.clone(),
        })
    }

    /// A probe each second until the host answers, then a claim each second and at once
    /// (at most every 100 ms) after a change.
    fn flush(&mut self, now: Instant, step: &mut Step<GuestEvent>) {
        if self.closed {
            return;
        }
        let due = match self.last_send {
            None => true,
            Some(t) => {
                let el = since(now, t);
                el >= ANNOUNCE_PERIOD || (self.dirty && el >= ANNOUNCE_CHANGE_GAP)
            }
        };
        if !due {
            return;
        }
        let bytes = match self.claim() {
            Some(c) => match encode_claim(&c) {
                Some(b) => b,
                None => return self.fail(JoinError::BadConfig, step),
            },
            None => encode_probe(&self.cfg.build_id),
        };
        self.last_send = Some(now);
        self.dirty = false;
        step.send.push(Outgoing {
            to: self.cfg.host,
            bytes,
        });
    }
}
