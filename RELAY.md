# Relay fallback

STUN punching (SPEC 2.3–2.7) cannot connect every pair of machines. Symmetric NAT
gives a new outside port for each destination. Some carrier NATs and same-router setups
drop or never hairpin the punched traffic. When that happens nothing reaches the host,
the lobby included, because the lobby runs over the punched discovery socket.

The relay is the fallback. It is a dumb UDP datagram forwarder that carries the lobby
datagrams and the game datagrams unchanged, so `session` and `lockstep` don't know it
is there. This is an original design (SPEC section 10 item 1: the reference had no relay).

- Server: `src/relay/server.rs` (`RelayServer`, sans-IO), run by `src/bin/btm-relay.rs`.
- Client: `src/relay/client.rs` (`RelayLink`, sans-IO).
- Relay invite codes (invite version 2): `src/relay/code.rs`.
- When to fall back: `relay::FallbackPolicy`.

## 1. Model

| Term | Meaning |
|---|---|
| Room | A set of at most 10 members, keyed by a random non-zero 64-bit **room id**. |
| Member | One machine in a room, with an index 0..=9 (the host who allocated the room is 0) and a random non-zero 64-bit **secret**. |
| Verified source | The registered address of an admitted member. Every other source is *unverified*. |
| Cookie | 16 bytes: `HMAC-SHA-256(server key, purpose ‖ period ‖ source IP ‖ source port ‖ nonce ‖ room)` truncated. The server keeps no state for it. |
| Synthetic endpoint | `0.0.0.(k+1):port`: what the client shows the lobby and game as "relay member k". |

The relay never parses payloads. It copies the two port fields without reading them.

## 2. Frames

All integers are big-endian. Every frame starts with this header:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 2 | magic | `B7 52` (`0xB7 'R'`) |
| 2 | 1 | version | 1 |
| 3 | 1 | kind | see below |

### 2.1 Client to relay

| Kind | Name | Body after the header | Total length |
|---|---|---|---|
| `0x01` | ALLOCATE | nonce 8, cookie 16 (zero on first try), room 8 (zero), zero padding | **exactly 64** |
| `0x02` | JOIN | nonce 8, cookie 16 (zero on first try), room 8 (non-zero), zero padding | **exactly 64** |
| `0x03` | DATA | room 8, secret 8, to (member) 1, src port 2, dst port 2, payload | 25 + payload (payload ≤ 1400) |
| `0x04` | PING | room 8, secret 8, ping id 4, cookie 16 (a rebind cookie being echoed, else zero) | exactly 40 |
| `0x05` | LEAVE | room 8, secret 8 | exactly 20 |

### 2.2 Relay to client

| Kind | Name | Body after the header | Total length | Sent to |
|---|---|---|---|---|
| `0x81` | CHALLENGE | nonce 8, cookie 16 | 28 | any source (≤ the 64-byte hello) |
| `0x82` | WELCOME | nonce 8, room 8, secret 8, member 1, members bitmap 2, max payload 2 | 33 | a source whose cookie was verified |
| `0x83` | DELIVER | recipient's secret 8, from (member) 1, src port 2, dst port 2, payload | 17 + payload | a member's registered address |
| `0x84` | PONG | secret 8, ping id 4, members bitmap 2, rebind cookie 16 (zero unless rebinding) | 34 | the member, or (rebind) the pinging source (≤ the 40-byte ping) |
| `0x85` | REFUSE | echo 8, reason 1 | 13 | see 2.4 |

`echo` is the hello's nonce, or the secret the client sent. A DELIVER carries the
recipient's own secret. Neither can be forged by an off-path attacker who spoofs the
relay's address.

### 2.3 Exchanges

| Step | Client | Relay |
|---|---|---|
| 1 | ALLOCATE or JOIN with a zero cookie, from a random nonce | CHALLENGE with a cookie bound to (source, nonce, room, period). It stores nothing and doesn't look up the room. |
| 2 | The same hello, echoing the cookie | Cookie valid: checks its limits, then sends WELCOME (new room / new member) or REFUSE. Cookie invalid: sends a new CHALLENGE. |
| 3 | A hello repeated from an admitted address | WELCOME again (the first one was lost). No new room or member. |
| 4 | DATA to member `k` | DELIVER to `k`'s registered address, with the sender's index and the two ports unchanged |
| 5 | PING every 4 s | PONG (keepalive, RTT, member bitmap) |
| 6 | PING with a valid secret from a **new** address (NAT rebinding) | PONG with a rebind cookie for the new address. Nothing moves yet. |
| 7 | PING echoing that cookie from the new address | Moves the member to the new address. PONG. |
| 8 | LEAVE | Removes the member. The room closes when it is empty. |

Cookies are valid in the period they were made and the next one (10 s periods, so
10–20 s). The client resends a hello every 500 ms, answers a challenge at once, and gives
up after 10 s. It declares the relay lost after 15 s with no pong or delivery.

### 2.4 Refusals

| Code | Reason | Fatal for the client | When |
|---|---|---|---|
| 1 | ServerFull | yes | allocate, max rooms reached |
| 2 | TooManyRooms | yes | allocate, this IPv4 address already owns `max_rooms_per_ip` rooms |
| 3 | RoomFull | yes | join, 10 members (or the configured maximum) |
| 4 | NoSuchRoom | yes | join, unknown room id (only told after the cookie round trip) |
| 5 | NotMember | yes | PING with an unknown room or secret (for example after idle expiry). 13 bytes in answer to 40. |
| 6 | NoSuchMember | no | DATA to an absent member or to itself |
| 7 | TooLarge | no | DATA payload above the configured limit |
| 8 | RateLimited | no | DATA or PING over the member's budget |

Non-fatal refusals go only to the member's registered address, at most one per second
per member. DATA, LEAVE or garbage from an unverified source is dropped without an
answer.

## 3. Limits

| Limit | Default | Flag / field |
|---|---|---|
| Rooms held | 1024 | `--max-rooms`, `RelayConfig::max_rooms` |
| Rooms owned per IPv4 address | 4 | `max_rooms_per_ip` |
| Members per room | 10 (ten seats; also the protocol maximum) | `max_members` |
| Payload | 1400 bytes (also the protocol maximum) | `max_payload` |
| Per-member packets | 600/s, one second of burst | `member_packets_per_sec` |
| Per-member payload bytes | 256 KiB/s, one second of burst | `member_bytes_per_sec` |
| Idle expiry | 30 s without any frame from a member. An empty room is closed. | `idle_expiry` |
| Cookie period | 10 s | `cookie_period` |
| Refusal gap | 1 s per member | `refusal_gap` |

The packet budget is sized for the lockstep (SPEC 8.1): a 100 ms heartbeat plus
submits rate-limited to one per 10 ms per peer. A member sends one DATA per destination,
so a full room needs roughly 9 × (10 + 30) ≈ 360 packets/s at worst.

**Payload limit vs. the game wire.** Lobby datagrams are at most 1400 bytes (SPEC 3.1)
and fit. Lockstep datagrams may be up to 1500 bytes (SPEC 8.1). Over a relay the game
must cap them at `RelayLink::max_payload()` (1400). `RelayLink::wrap` refuses a larger
datagram with `WrapError::TooLarge` rather than fragmenting it. See open decision 2.

## 4. Threat model

| Threat | Defence |
|---|---|
| **Amplification / reflection** (spoofed source, to flood a victim) | A source that isn't an admitted member gets at most one reply per datagram, and that reply is never larger than the datagram (64-byte hellos get 28-byte challenges and 13-byte refusals; 40-byte pings get 34-byte pongs or 13-byte refusals). The code enforces this centrally (`send_unverified` drops anything larger), the frame sizes are checked at compile time, and a fuzz test checks it over 20,000 random frames. Forwarded traffic only goes to admitted members' addresses. |
| **Spoofed joins** (creating state for an address the attacker doesn't own) | No room or member is created until the hello echoes a cookie that was sent to that address (stateless return-routability check). Cookies are keyed MACs bound to address, port, nonce, room and period, so they can't be forged, reused from another address, or kept for long. |
| **Spoofed data** (injecting into a room) | DATA must carry the sender's 64-bit secret **and** come from its registered address. A known secret from another address is dropped. The address moves only after a cookie round trip to the new address (2.3, steps 6–7). Secrets are compared in constant time. |
| **Forged relay replies** (off-path, spoofing the relay's address to a client) | DELIVER and PONG carry the recipient's secret. REFUSE echoes the nonce or secret. The client ignores frames that don't match, and anything not from the relay's address. |
| **Room guessing** | Room ids are 64-bit outputs of HMAC-SHA-256 under the server seed. An unverified source can't even learn whether a room exists, because the challenge comes before the lookup. Each guess costs a real address and a round trip. At any plausible rate, finding one of 1024 live rooms takes on the order of 2^54 attempts. A guessed room id still only buys a seat that the lobby itself then gates (approval, password, build and mod checks). |
| **Open-relay abuse** (using it as a free tunnel for other traffic) | Rooms are capped server-wide and per address. Members are capped per room, with per-member packet and byte budgets and idle expiry. Payloads are capped at 1400 bytes. There is no broadcast and no forwarding to non-members. The relay is still a generic forwarder: anyone can allocate a room and push up to the budget between machines they control. A hosted instance needs abuse monitoring (the minute summaries) or authentication (open decision 3). |
| **Privacy** | The relay sees every lobby and game payload in clear (the lockstep has no encryption anyway, SPEC 10 item 5) and the members' addresses. `info` logging writes no addresses and no payloads. `debug` logs addresses. |
| **Resource exhaustion** | All state is bounded: rooms × 10 members, a few dozen bytes each. Malformed frames are dropped after bounds-checked decoding, and no input can panic (fuzzed). The receive loop survives every error. |

Out of scope: an on-path attacker who can read the traffic can read secrets and
payloads. That is the same position as against the direct path.

## 5. Client integration

The caller runs one extra UDP socket for the relay, on any local port.

| Step | What to do |
|---|---|
| Host | When `FallbackPolicy` says so, create `RelayLink::host(relay, random nonce, now)`. On `RelayEvent::Joined { room, .. }`, show `relay::code::encode(&RelayInvite { relay, room })` instead of the version-1 invite code. Keep `HostConfig::game_addr = None`. |
| Guest | `relay::code::decode_any(text)` reads either kind of code. For `AnyInvite::Relay`, create `RelayLink::guest(relay, room, nonce, now)`. Once joined, start the lobby with `GuestConfig::host = relay::peer_endpoint(0, DISCOVERY_PORT)`, `game_addr = None`. |
| Sending | Pass each `Step::send` (lobby) or game datagram list through `link.wrap_all(local_port_it_would_use, sends, &mut relayed)`. Send `relayed` from the relay socket to `link.relay()`. The returned remainder (broadcast, loopback, real addresses) goes direct as before. |
| Receiving | For each datagram on the relay socket, call `link.handle(now, from, bytes)`. `Received::Datagram(d)`: deliver `d.payload` from `d.from` to the game if `d.to_port` is the local game port, otherwise to the lobby. |
| Timers | `link.poll(now, &mut out)` at `link.next_deadline()`. `RelayEvent::Failed` ends the link. `link.rtt()` is the round trip to the relay (for the overlay). |

What it means for the rest of the crate:

- The host records each guest's game address as `0.0.0.(k+1):<game port>`. Every
  `GameStart::peers` entry is therefore a synthetic endpoint, and it means the same
  member on every machine. Guest-to-guest traffic goes through the relay too, which
  also covers SPEC 10 item 8 (three or more players across NATs).
- All synthetic endpoints share one /16, so the address following of SPEC 2.8 may move a
  seat between synthetic endpoints. This is no worse than the direct case, which has no
  authentication either.
- Punching (2.5) is pointless in a relayed room. The puncher's datagrams to synthetic
  endpoints are relayed harmlessly, or the caller can skip punching.
- The game-port handover (2.1) doesn't apply. The relay socket stays open from the lobby
  into the game.

## 6. When to use it

`FallbackPolicy` decides once, and its `poll` returns the reason.

| Condition | Decision |
|---|---|
| Traversal `Failed(Symmetric)`, `Failed(NoReply)`, `Failed(NoServers)`, `Failed(Setup)` | relay now |
| Traversal `Failed(PortInUse)` | no (a relay doesn't fix a busy local port) |
| `expect_contact(now)` was called (host: a reply code was pasted; guest: it started probing a code) and nothing arrived directly (`note_direct_contact`) within **10 s** | relay |

Only the host can switch, because it owns the room. A guest whose policy fires can only
tell the player to ask the host for a relay code.

## 7. Relay invite code (invite version 2)

This uses the same Crockford base32, the same `BTM` prefix, the same forgiving reading
(case, separators, O/I/L, optional prefix, 64-character input limit) and the same CRC-8
(polynomial 0x07, init 0, over every byte before the check) as version 1. The version-1
code and `invite.rs` are unchanged.

| Form (low nibble) | Bytes | Characters | Display |
|---|---|---|---|
| 0: relay by index | `0x20, index, room(8), crc8` = 11 | 18 | `BTM-XXXX-XXXX-XXXXX-XXXXX` |
| 1: relay by endpoint | `0x21, ip(4), port(2), room(8), crc8` = 16 | 26 | `BTM-XXXX-XXXX-XXXX-XXXX-XXXXX-XXXXX` |

The two bits left over in the last character are zero padding. CRC-8 catches every burst
of 8 bits or fewer, so every single-character slip is caught (tested exhaustively). The
three lengths (13, 18, 26) tell the codes apart, and version-2 codes begin with `4`
where version-1 codes begin with `2`.

Refusal order: too long, wrong length, bad prefix, bad character, padding bit, version,
form (must match the length), checksum, room 0, endpoint rules (port 0, unspecified,
multicast). As in version 1, a code has no expiry. It is single-use in practice because
the room expires 30 s after its last member goes quiet.

Form 0 indexes `relay::code::KNOWN_RELAYS`, which is empty until a hosted relay exists.
Both ends must ship the same table. `relay::code::resolve` maps either form to an
endpoint.

## 8. Self-hosting

```sh
cargo build --release --bin btm-relay
./target/release/btm-relay --bind 0.0.0.0:3479 --max-rooms 256 --log info
```

| Flag | Default | Meaning |
|---|---|---|
| `--bind ADDR:PORT` | `0.0.0.0:3479` | IPv4 only |
| `--max-rooms N` | 1024 | rooms held at once |
| `--log quiet\|info\|debug` | `info` | `quiet`: start-up and errors only. `info`: rooms opened and closed, plus a stats line every minute, with no addresses. `debug`: every event, with addresses. |

- Open UDP 3479 (or your port) inbound on the firewall or router. Nothing else is needed.
- Bandwidth: each relayed byte is received once and sent once. A 4-player game
  is typically tens of KB/s. The per-member budget caps any member at 256 KiB/s.
- The server seed comes from the operating system's randomness (through the standard
  library's hash keys), the time and the process id. It is not stored, so a restart drops
  all rooms, and clients see `Lost` after 15 s.
- One process is single-threaded and std-only. Run it under a service manager (systemd,
  NSSM, Docker) for restarts.
- Players reach your relay with form-1 codes (relay by endpoint), so no table is needed.

## 9. Open decisions for the maintainer

1. **Hosted instance** (MODDING-PLAN 2.6 #6). Whether the project runs a public relay,
   who pays, where it runs, and what goes in `KNOWN_RELAYS`. Until then form-0 codes
   can't be resolved and players self-host.
2. **Game datagrams over 1400 bytes.** The lockstep may build packets up to 1496 bytes.
   Either the wire layer caps packets at the relay's `max_payload` when a peer is
   synthetic, or the relay limit is raised to 1500 (about 1525-byte frames, so IP
   fragmentation on 1500-MTU paths).
3. **Authentication of allocations.** The relay is open: anyone can allocate. For a
   hosted instance, consider an allocation token (for example, signed by the launcher) or
   a proof-of-work cookie.
4. **Member index reuse.** A freed index goes to the next joiner. That is fine for the
   lobby, which identifies guests by claim token, but a rejoin protocol may want indices
   that are never reused.
5. **Both codes at once.** A host currently shows either a direct code or a relay code.
   Advertising both, by trying direct first and relaying after 10 s, would avoid the
   relay hop for guests who could punch.
6. **Encryption.** The relay sees payloads in clear, like the direct path. A per-room key
   carried in the code would need a longer code.
