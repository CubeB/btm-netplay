//! Easy multiplayer for Byte Tactics. The behaviour is specified in `SPEC.md`.
//!
//! Every protocol part is **sans-IO**: a state machine fed with received datagrams and
//! the current time, which returns the datagrams to send and the events for the game.
//! Sockets and clocks live only in [`io`], so every part is testable deterministically.

#![forbid(unsafe_code)]

pub mod types;

pub mod invite;
pub mod io;
pub mod lockstep;
pub mod nat;
pub mod relay;
pub mod session;
pub mod wire;
