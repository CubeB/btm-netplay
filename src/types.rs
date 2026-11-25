//! Types shared by every part. Change them only by agreement.

use std::net::SocketAddrV4;
use std::time::Duration;

/// A player slot, 0..=9. The lobby's seat index is the player id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlayerId(pub u8);

/// A simulation tick. The first tick run is 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Tick(pub u32);

/// Monotonic time since an arbitrary start, supplied by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Instant(pub Duration);

/// A UDP endpoint. The spec is IPv4-only.
pub type Endpoint = SocketAddrV4;

/// A datagram to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub to: Endpoint,
    pub bytes: Vec<u8>,
}

/// The game, as lockstep drives it. Implemented by the engine.
pub trait Engine {
    /// Run one tick with every player's commands, in player-id order.
    fn step(&mut self, tick: Tick, commands: &[(PlayerId, Vec<u8>)]);
    /// The state hash after the last tick run.
    fn state_hash(&self) -> u32;
    /// A dump of the state for a desync report.
    fn dump(&self) -> String;

    /// Prepare a new game before its first tick. The driver ([`crate::io::Node`]) calls it
    /// once the lobby is over (or a returning player's catch-up has arrived), with the
    /// agreed simulation seed, starting on the pump after the one that reported the
    /// game's setup (`io::Event::Loading`, and `Node::game_start`). It keeps calling it,
    /// once per pump, until it returns `true`; until then this peer tells the others it is
    /// still loading (SPEC 3.7). A returning player fast-forwards from the loaded state.
    ///
    /// The default returns `true` at once and changes nothing, for an engine that is set
    /// up by other means. Added for rejoin; the only change to this trait.
    fn load(&mut self, seed: u64) -> bool {
        let _ = seed;
        true
    }
}
