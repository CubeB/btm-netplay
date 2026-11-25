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
}
