# btm-netplay

Easy multiplayer for Byte Tactics ([ozgb/btm](https://github.com/ozgb/btm)), so that friends can set up a game out of the box:

- deterministic lockstep at 30 ticks a second;
- invite codes with STUN NAT hole-punching, with no server needed, and a relay fallback for the cases punching can't reach;
- LAN discovery and a 10-seat lobby;
- a lobby that refuses mismatched builds and mod sets;
- desync detection that names the first tick that differs;
- dropping a lost player on an agreed tick, and rejoining by replay fast-forward;
- a network overlay: round trip, stalls, and who is being waited for.

It is a host-side package: it never touches game logic, and it drives any engine through a small trait (step a tick with everyone's inputs, return a state hash, save and load state).

## Provenance

This is a clean-room implementation, under MIT. Its behaviour comes from a written spec (`SPEC.md`) of [RWE-B4](https://github.com/CubeB/RWE-B4)'s multiplayer, which is GPLv3 and field-proven. The spec was written by someone who read RWE. The code was written only from the spec, by someone who never read RWE's source. No RWE code is in this repository.

## Status

Work in progress. See `SPEC.md` and the issues.
