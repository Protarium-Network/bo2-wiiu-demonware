# open-bitdemon-emulator — Wii U / Black Ops II fork

A fork of [Laupetin/open-bitdemon-emulator](https://github.com/Laupetin/open-bitdemon-emulator)
that adds the pieces **Call of Duty: Black Ops II on Wii U** needs to get online.
Upstream is a general Demonware/BitDemon backend with no Wii U support; everything
below was added here.

Licensed **AGPL-3.0**, same as upstream. The network clause matters for a project
like this: if you run this server for other people, you owe them the source of
whatever you are running.

## What this fork adds

**Wii U authentication** (`libbitdemon/src/auth/auth_handler/wiiu.rs`)
The console authenticates with a Nintendo service token rather than the flows
upstream implements. The handler pulls the longest base64 run out of the request,
decodes it, and extracts the PID. PIDs are remembered per source address so that
several consoles can be online at once, each with its own identity.

Two identifiers are involved and they are not interchangeable: the **PID** is the
auth identity, while the **DWID** (`0xBD00 << 32 | PID`) is the storage identity.
Mixing them up makes the title spam EventLog asserts and never finish loading
stats.

**Matchmaking** (`libbitdemon/src/lobby/matchmaking.rs`)
A session store: consoles register a lobby, refresh it, and find each other's.
Task ids and the wire format were recovered from the game module itself — see the
comments in that file, which cite the address of every function they came from.
Answering `CreateSession` with no results at all leaves the console without a
session id, so nothing it hosts can ever be joined.

**Messaging and stats services** (`libbitdemon/src/lobby/messaging_service.rs`,
`stats_service.rs`)
Minimal implementations. Without them the lobby replies "unavailable service" and
the title stalls on its loading path.

**Assorted fixes** to the LSG, DML, counter, group and storage handlers so the
Wii U build gets through its start-up sequence. The DML operation id in the
hierarchical reply and the group-count aggregation were both wrong for this title.

## What is not in here, on purpose

- `db/` — SQLite databases holding player profiles and their uploaded files.
- `storage/` — publisher files. These are **Activision game assets**
  (`online_tu9_*.wad`, `*_ffotd_*.ff`, heatmaps) and are not ours to redistribute.
  You have to supply them yourself from your own copy of the game.
- `config.json` — deployment-specific hostname.

## The UDP side is separate

Lobby traffic is TCP, but the console also speaks three UDP protocols on the same
port before it will consider itself online:

| Protocol | Request | Reply |
|---|---|---|
| bdIPDiscovery | `0x1E` | `0x1E` |
| bdNATTypeDiscovery | `0x14` | **`0x15`** |
| bdNATTraversal | `0x0A` (to the introducer) | `0x0B` INTRO, `0x0C` INTRO_REPLY |

The NAT-type reply type being `0x15` while the request is `0x14` is worth
calling out: `bdNATTypeDiscoveryClient::receiveReplies` drops anything else
silently, with no log, so a `0x14` reply looks exactly like no reply at all and
the console loops the first test forever.

## Building

```
cargo build --release
```

Run `dw-server`. Nothing here is specific to one deployment beyond `config.json`.

## Credit

All of the groundwork is upstream's. This fork only teaches it about one console
and one title.
