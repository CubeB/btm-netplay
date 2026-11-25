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

## Try it: the demo

`btm-netplay-demo` runs a toy deterministic game, so you can test the connection with a friend before the engine exists.

```sh
cargo build --release
# Machine A
target/release/btm-netplay-demo host --name A        # prints an invite code: BTM-XXXX-XXXX-XXXXX
# Machine B
target/release/btm-netplay-demo join BTM-XXXX-XXXX-XXXXX --name B
```

- If B hears nothing within about 2 s, it prints a **reply code**. Type it on A, which approves B. Otherwise A types `/accept`.
- A types `/start`. Every second, each side prints the tick, the round trip, the input delay, stalls, and who is being waited for. Lines typed on stdin are sent as chat.
- **On one LAN:** use `--no-stun` and `join <ip>`. `btm-netplay-demo lan` lists the games it finds.
- **If punching fails** (symmetric NAT): run `btm-relay --bind 0.0.0.0:PORT` somewhere reachable, pass `--relay ip:port` to the host, and the host shows a relay code instead. See `RELAY.md`.
- **Rejoining:** a guest whose game dropped it runs the same `join` again. The host offers the seat back, sends the game so far, and the guest fast-forwards and plays on.
- **Mods:** build with `--features mods` and pass `--mods <dir>` (repeat it for each mod directory) to `host` and `join`. The directories are resolved with [btm-mod](https://github.com/CubeB/btm-mod), and the resolved set is the lobby's mod set. A guest whose set differs is refused, and the refusal names the mods that differ. `--engine V` (default 0.4.0), `--interface NAME=V` and `--phases A,B` describe the engine the mods resolve against. The library itself stays std-only; btm-mod is an optional dependency used only by the demo.
- **Testing the failure paths:**
  - `--ticks N` ends the game after N ticks.
  - `--build-id X` triggers the mismatch refusal.
  - `--desync-at T` forces a desync report at tick T.

## Status

Work in progress. Not yet wired into an engine. Known gaps:

- IPv6 isn't supported.
- Codes aren't copied to the clipboard (that would need a dependency). Each code is printed on a line of its own instead.
- Rejoin goes through the host, so a dropped host can't come back. The returning machine is found again by address following, so it has to keep its /16 (as a machine that just restarted does), or the pair has to go through the relay.
- Name lookups aren't cached. Each node does at most one host-name lookup plus one for the STUN servers.
