//! One peer link: three reliable streams (commands, hashes, chat) with cumulative
//! acks and full resend of everything unacked in every packet (8.1, 8.3), the
//! heartbeat and submit rate limit, and RTT estimation (8.4).

use std::collections::VecDeque;
use std::time::Duration;

use super::codec::{
    chat_size, encode_message, seal, set_size, update_header_size, ChatLine, Chunk, Message, Relay,
    RunState, SharedPause, Update, WireError, CHUNK_OVERHEAD, HASH_SIZE, MAX_DATAGRAM, MAX_PAYLOAD,
    RELAY_OVERHEAD,
};
use crate::types::{Instant, PlayerId};

/// One packet to each peer at least this often (8.1).
pub const HEARTBEAT: Duration = Duration::from_millis(100);
/// Immediate packets are rate-limited to one per this interval per peer.
pub const SUBMIT_GAP: Duration = Duration::from_millis(10);
/// Max sets or hashes buffered per peer (8.6).
pub const MAX_BUFFERED: usize = 900;
/// Max unacknowledged chat lines per peer (8.6).
pub const MAX_UNACKED_CHAT: usize = 32;
/// RTT min/max window (8.6).
pub const RTT_WINDOW: usize = 50;
/// Bound on outstanding RTT probes (one per packet that carried a new set).
const MAX_RTT_PENDING: usize = 4096;

/// The send side of one stream: items from sequence `base` not yet acknowledged.
#[derive(Clone, Debug)]
pub struct OutStream<T> {
    base: u32,
    items: VecDeque<T>,
}

impl<T> OutStream<T> {
    /// A stream whose next item will be number `base`.
    pub fn new(base: u32) -> Self {
        OutStream {
            base,
            items: VecDeque::new(),
        }
    }

    /// Sequence number of the oldest unacknowledged item.
    pub fn base(&self) -> u32 {
        self.base
    }

    /// Sequence number the next pushed item will get.
    pub fn end(&self) -> u32 {
        self.base.saturating_add(self.items.len() as u32)
    }

    pub fn unacked(&self) -> usize {
        self.items.len()
    }

    /// Appends an item and returns its sequence number.
    pub fn push(&mut self, item: T) -> u32 {
        let seq = self.end();
        self.items.push_back(item);
        seq
    }

    /// Applies a cumulative ack (the next number the peer expects). An ack beyond
    /// what was sent is ignored and reported.
    pub fn ack(&mut self, next_expected: u32) -> Result<(), AckBeyond> {
        if next_expected > self.end() {
            return Err(AckBeyond {
                ack: next_expected,
                sent: self.end(),
            });
        }
        while self.base < next_expected {
            self.items.pop_front();
            self.base += 1;
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }
}

/// An ack named a sequence number never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckBeyond {
    pub ack: u32,
    pub sent: u32,
}

/// Round-trip estimation (8.4). Whole milliseconds.
#[derive(Clone, Debug, Default)]
pub struct Rtt {
    smoothed: Option<f64>,
    dev: f64,
    latest: Option<u32>,
    window: VecDeque<u32>,
    pending: VecDeque<(u32, Instant)>,
    last_recorded: Option<u32>,
}

impl Rtt {
    /// Notes that a packet left at `now` whose last set ends before `seq`.
    pub fn on_send(&mut self, seq: u32, now: Instant) {
        if self.last_recorded.is_some_and(|l| seq <= l) {
            return;
        }
        self.last_recorded = Some(seq);
        if self.pending.len() >= MAX_RTT_PENDING {
            self.pending.pop_front();
        }
        self.pending.push_back((seq, now));
    }

    /// Takes a cumulative command ack and the peer's reported ack delay.
    pub fn on_ack(&mut self, ack: u32, now: Instant, ack_delay: Duration) {
        while self.pending.front().is_some_and(|&(s, _)| s < ack) {
            self.pending.pop_front();
        }
        if let Some(&(s, sent)) = self.pending.front() {
            if s == ack {
                self.pending.pop_front();
                let elapsed = now.0.saturating_sub(sent.0).saturating_sub(ack_delay);
                self.sample(u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX));
            }
        }
    }

    fn sample(&mut self, ms: u32) {
        let x = f64::from(ms);
        match self.smoothed {
            None => {
                self.smoothed = Some(x);
                self.dev = x / 2.0;
            }
            Some(s) => {
                self.dev = 0.75 * self.dev + 0.25 * (x - s).abs();
                self.smoothed = Some(0.9 * s + 0.1 * x);
            }
        }
        self.latest = Some(ms);
        if self.window.len() >= RTT_WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(self.smoothed_ms());
    }

    /// Smoothed RTT in ms (0 before any sample).
    pub fn smoothed_ms(&self) -> u32 {
        self.smoothed.map_or(0, |s| s.round() as u32)
    }

    /// Smoothed deviation in ms.
    pub fn dev_ms(&self) -> u32 {
        self.dev.round() as u32
    }

    /// The latest raw sample.
    pub fn latest_ms(&self) -> Option<u32> {
        self.latest
    }

    /// Min and max smoothed RTT over the last 50 samples.
    pub fn window_min_max(&self) -> Option<(u32, u32)> {
        let min = self.window.iter().copied().min()?;
        let max = self.window.iter().copied().max()?;
        Some((min, max))
    }

    /// Age of the oldest packet still awaiting its ack.
    pub fn oldest_unacked_age(&self, now: Instant) -> Option<Duration> {
        self.pending
            .front()
            .map(|&(_, t)| now.0.saturating_sub(t.0))
    }

    pub fn has_sample(&self) -> bool {
        self.smoothed.is_some()
    }
}

/// How much the receiver can take from one update.
#[derive(Clone, Copy, Debug)]
pub struct Room {
    /// Command sets the receiver can still buffer for this peer.
    pub commands: usize,
    /// Hashes the receiver can still queue for this peer.
    pub hashes: usize,
    /// False while a rejoining peer winds forward: commands are neither taken nor acked.
    pub accept_commands: bool,
}

/// What one update delivered, in stream order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Incoming {
    pub commands: Vec<Vec<u8>>,
    pub hashes: Vec<u32>,
    pub chat: Vec<ChatLine>,
    pub notes: Vec<LinkNote>,
}

/// Things worth logging that do not stop the packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkNote {
    AckBeyond {
        stream: &'static str,
        ack: u32,
        sent: u32,
    },
    Gap {
        stream: &'static str,
        first: u32,
        expected: u32,
    },
    BadSet {
        seq: u32,
    },
    Full {
        stream: &'static str,
    },
}

/// The fields of an update that are not stream data.
#[derive(Clone, Debug)]
pub struct Header {
    pub sender: PlayerId,
    pub run: RunState,
    pub pause: SharedPause,
    /// Sets held per player (always sent).
    pub held: Vec<(PlayerId, u32)>,
    /// Sets offered for relay; the longest prefix that fits after the streams goes.
    pub relay: Option<Relay>,
}

impl Header {
    pub fn new(sender: PlayerId, run: RunState, pause: SharedPause) -> Self {
        Header {
            sender,
            run,
            pause,
            held: Vec::new(),
            relay: None,
        }
    }
}

/// Why `Link::build` could not produce a packet carrying the oldest set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The oldest unacked set alone does not fit a datagram; it can never be sent.
    SetTooLarge {
        seq: u32,
        size: usize,
    },
    Wire(WireError),
}

/// A packet ready to send, with anything worth logging.
#[derive(Clone, Debug)]
pub struct Built {
    pub bytes: Vec<u8>,
    pub error: Option<BuildError>,
}

/// Why a chat line could not be queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatFull;

/// The state of one peer link.
#[derive(Clone, Debug)]
pub struct Link {
    commands: OutStream<Vec<u8>>,
    hashes: OutStream<u32>,
    chat: OutStream<ChatLine>,
    cmd_in: u32,
    hash_in: u32,
    chat_in: u32,
    rtt: Rtt,
    last_sent: Option<Instant>,
    dirty: bool,
    packet_id: u32,
    last_new_commands: Option<Instant>,
    /// Largest encoded update this link builds (before the CRC).
    max_payload: usize,
}

impl Link {
    /// A link whose command and hash streams start at `cmd_seq` / `hash_seq` in both
    /// directions; chat starts at 0.
    pub fn new(cmd_seq: u32, hash_seq: u32) -> Self {
        Link {
            commands: OutStream::new(cmd_seq),
            hashes: OutStream::new(hash_seq),
            chat: OutStream::new(0),
            cmd_in: cmd_seq,
            hash_in: hash_seq,
            chat_in: 0,
            rtt: Rtt::default(),
            last_sent: None,
            dirty: true,
            packet_id: 0,
            last_new_commands: None,
            max_payload: MAX_PAYLOAD,
        }
    }

    /// Cap the datagrams this link builds at `max_datagram` bytes including the CRC (for
    /// example a relay's `max_payload`). Values above [`MAX_DATAGRAM`] are clamped; the
    /// default is [`MAX_DATAGRAM`].
    pub fn with_max_datagram(mut self, max_datagram: usize) -> Self {
        self.max_payload = max_datagram.min(MAX_DATAGRAM).saturating_sub(4);
        self
    }

    /// The datagram cap, including the CRC.
    pub fn max_datagram(&self) -> usize {
        self.max_payload + 4
    }

    pub fn push_command(&mut self, set: Vec<u8>) -> u32 {
        self.dirty = true;
        self.commands.push(set)
    }

    pub fn push_hash(&mut self, hash: u32) -> u32 {
        self.dirty = true;
        self.hashes.push(hash)
    }

    /// Queues a chat line, refused if 32 are already unacknowledged (7).
    pub fn push_chat(&mut self, line: ChatLine) -> Result<u32, ChatFull> {
        if self.chat.unacked() >= MAX_UNACKED_CHAT {
            return Err(ChatFull);
        }
        self.dirty = true;
        Ok(self.chat.push(line))
    }

    pub fn chat_full(&self) -> bool {
        self.chat.unacked() >= MAX_UNACKED_CHAT
    }

    /// The next own command sequence number.
    pub fn commands_end(&self) -> u32 {
        self.commands.end()
    }

    /// The next own hash sequence number.
    pub fn hashes_end(&self) -> u32 {
        self.hashes.end()
    }

    /// Own sets sent but not yet acknowledged.
    pub fn unacked_commands(&self) -> usize {
        self.commands.unacked()
    }

    /// Marks the peer's sets before `next` as received (they came by relay), so
    /// the direct copies are skipped and acknowledged.
    pub fn skip_commands_to(&mut self, next: u32) {
        if next > self.cmd_in {
            self.cmd_in = next;
            self.dirty = true;
        }
    }

    /// The next command sequence number expected from the peer.
    pub fn commands_expected(&self) -> u32 {
        self.cmd_in
    }

    pub fn rtt(&self) -> &Rtt {
        &self.rtt
    }

    /// True if a packet should go now: the heartbeat is due, or something new
    /// was queued and the rate limit allows.
    pub fn due(&self, now: Instant) -> bool {
        match self.last_sent {
            None => true,
            Some(t) => {
                let since = now.0.saturating_sub(t.0);
                since >= HEARTBEAT || (self.dirty && since >= SUBMIT_GAP)
            }
        }
    }

    /// Builds the next packet: as many unacked sets as fit, then hashes, then chat.
    pub fn build(&mut self, now: Instant, header: Header) -> Built {
        let ack_delay_ms = self.last_new_commands.map_or(0, |t| {
            u32::try_from(now.0.saturating_sub(t.0).as_millis()).unwrap_or(u32::MAX)
        });
        let mut update = Update {
            sender: header.sender,
            packet_id: self.packet_id,
            run: header.run,
            pause: header.pause,
            ack_delay_ms,
            commands: Chunk {
                first: self.commands.base(),
                ack: self.cmd_in,
                items: Vec::new(),
            },
            hashes: Chunk {
                first: self.hashes.base(),
                ack: self.hash_in,
                items: Vec::new(),
            },
            chat: Chunk {
                first: self.chat.base(),
                ack: self.chat_in,
                items: Vec::new(),
            },
            held: header.held,
            relay: None,
        };
        let mut budget = self
            .max_payload
            .saturating_sub(update_header_size(&update))
            .saturating_sub(3 * CHUNK_OVERHEAD)
            .saturating_sub(RELAY_OVERHEAD);
        let mut error = None;

        for (i, set) in self.commands.iter().enumerate() {
            let size = set_size(set);
            if size > budget {
                if i == 0 {
                    error = Some(BuildError::SetTooLarge {
                        seq: self.commands.base(),
                        size,
                    });
                }
                break;
            }
            budget -= size;
            update.commands.items.push(set.clone());
        }
        for h in self.hashes.iter() {
            if HASH_SIZE > budget {
                break;
            }
            budget -= HASH_SIZE;
            update.hashes.items.push(*h);
        }
        for line in self.chat.iter() {
            let size = chat_size(line);
            if size > budget {
                break;
            }
            budget -= size;
            update.chat.items.push(line.clone());
        }
        if let Some(offer) = header.relay {
            let mut sets = Vec::new();
            for s in offer.sets {
                let size = set_size(&s);
                if size > budget {
                    break;
                }
                budget -= size;
                sets.push(s);
            }
            if !sets.is_empty() {
                update.relay = Some(Relay {
                    player: offer.player,
                    first: offer.first,
                    sets,
                });
            }
        }

        let past_last = update
            .commands
            .first
            .saturating_add(update.commands.items.len() as u32);
        if !update.commands.items.is_empty() {
            self.rtt.on_send(past_last, now);
        }
        self.packet_id = self.packet_id.wrapping_add(1);
        self.last_sent = Some(now);
        self.dirty = false;

        let bytes = match seal(encode_message(&Message::Update(update))) {
            Ok(b) => b,
            Err(e) => {
                error = Some(BuildError::Wire(e));
                Vec::new()
            }
        };
        Built { bytes, error }
    }

    /// Applies a received update: acks, then each stream's new data within `room`.
    /// `valid_set` decodes a command set; if any new set fails, none is taken.
    pub fn receive(
        &mut self,
        now: Instant,
        u: &Update,
        room: Room,
        valid_set: impl Fn(&[u8]) -> bool,
    ) -> Incoming {
        let mut inc = Incoming::default();
        let delay = Duration::from_millis(u64::from(u.ack_delay_ms));

        // Acks.
        if u.commands.ack <= self.commands.end() {
            self.rtt.on_ack(u.commands.ack, now, delay);
        }
        if let Err(e) = self.commands.ack(u.commands.ack) {
            inc.notes.push(LinkNote::AckBeyond {
                stream: "commands",
                ack: e.ack,
                sent: e.sent,
            });
        }
        if let Err(e) = self.hashes.ack(u.hashes.ack) {
            inc.notes.push(LinkNote::AckBeyond {
                stream: "hashes",
                ack: e.ack,
                sent: e.sent,
            });
        }
        if let Err(e) = self.chat.ack(u.chat.ack) {
            inc.notes.push(LinkNote::AckBeyond {
                stream: "chat",
                ack: e.ack,
                sent: e.sent,
            });
        }

        // Commands.
        if room.accept_commands {
            if let Some(new) = new_items(&u.commands, self.cmd_in, "commands", &mut inc.notes) {
                let mut bad = None;
                for (i, s) in new.iter().enumerate() {
                    if !valid_set(s) {
                        bad = Some(self.cmd_in.saturating_add(i as u32));
                        break;
                    }
                }
                if let Some(seq) = bad {
                    inc.notes.push(LinkNote::BadSet { seq });
                } else {
                    let take = new.len().min(room.commands);
                    if take < new.len() {
                        inc.notes.push(LinkNote::Full { stream: "commands" });
                    }
                    if take > 0 {
                        inc.commands.extend(new.iter().take(take).cloned());
                        self.cmd_in = self.cmd_in.saturating_add(take as u32);
                        self.last_new_commands = Some(now);
                        self.dirty = true;
                    }
                }
            }
        }

        // Hashes.
        if let Some(new) = new_items(&u.hashes, self.hash_in, "hashes", &mut inc.notes) {
            let take = new.len().min(room.hashes);
            if take < new.len() {
                inc.notes.push(LinkNote::Full { stream: "hashes" });
            }
            inc.hashes.extend(new.iter().take(take).copied());
            self.hash_in = self.hash_in.saturating_add(take as u32);
        }

        // Chat.
        if let Some(new) = new_items(&u.chat, self.chat_in, "chat", &mut inc.notes) {
            inc.chat.extend(new.iter().cloned());
            self.chat_in = self.chat_in.saturating_add(new.len() as u32);
            if !new.is_empty() {
                self.dirty = true;
            }
        }
        inc
    }
}

/// The part of a chunk past what was already received, or None on a gap.
fn new_items<'a, T>(
    chunk: &'a Chunk<T>,
    expected: u32,
    stream: &'static str,
    notes: &mut Vec<LinkNote>,
) -> Option<&'a [T]> {
    if chunk.first > expected {
        if !chunk.items.is_empty() {
            notes.push(LinkNote::Gap {
                stream,
                first: chunk.first,
                expected,
            });
        }
        return None;
    }
    let skip = (expected - chunk.first) as usize;
    chunk.items.get(skip..)
}
