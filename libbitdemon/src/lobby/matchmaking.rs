use crate::lobby::LobbyHandler;
use crate::lobby::response::task_reply::TaskReply;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_reader::BdReader;
use crate::messaging::bd_response::{BdResponse, ResponseCreator};
use crate::messaging::bd_serialization::BdSerialize;
use crate::messaging::bd_writer::BdWriter;
use crate::networking::bd_session::BdSession;
use log::{info, warn};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// bdMatchMaking (LobbyServiceId::Matchmaking = 21).
///
/// Task ids come from the Wii U module, where every bdMatchMaking method calls
/// bdRemoteTaskManager::initTaskBuffer(buffer, 0x15, <task id>):
///
/// |  1 | createSession        | RPL 0x02a65534 |
/// |  2 | updateSession        | RPL 0x02a65690 |
/// |  3 | deleteSession        | RPL 0x02a65904 |
/// |  5 | findSessions         | RPL 0x02a65d9c |
/// | 12 | updateSessionPlayers | RPL 0x02a657cc |
/// | 13 | findSessionsPaged    | RPL 0x02a65f9c |
///
/// Wire format, from MatchMakingInfo::serialize (RPL 0x02258124) and confirmed
/// against a real CreateSession captured off the wire:
///
///   blob(37)   bdCommonAddr - local addr, four empty slots, public addr, flags
///   u32, u32                - 0 and 18 (max players)
///   u64                     - GAME_SECURITY_ID
///   blob(16)                - security key
///   8 x i32                 - 1000, 1, 2079 (netcode version), ...
///   f32                     - skill
///   4 x i32
///
/// bdMatchMakingInfo::deserialize (RPL 0x02a67e84) gives the shape of a result
/// row: the payload blob, then the session id, then three u32s. And
/// bdSessionID::deserialize (RPL 0x02a6854c) reads a blob capped at 8 bytes, so
/// an id is exactly 8 bytes wide.
///
/// Answering CreateSession with no results at all - which this handler used to
/// do - leaves the console without a session id, so nothing it hosts can ever be
/// joined ("Unable to join game session").
pub struct MatchmakingHandler;

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, FromPrimitive, ToPrimitive)]
#[repr(u8)]
enum MatchmakingTaskId {
    CreateSession = 1,
    UpdateSession = 2,
    DeleteSession = 3,
    FindSessions = 5,
    UpdateSessionPlayers = 12,
    FindSessionsPaged = 13,
    FindSessionsByEntityIds = 14,
    FindSessionsFromIds = 15,
}

/// How long a lobby survives without any traffic from its host. Generous on
/// purpose: the console only re-announces every couple of minutes, so a short
/// window drops live lobbies while someone is still searching for them.
const SESSION_TTL: Duration = Duration::from_secs(240);

/// Optional allowlist of addresses FindSessions may hand real lobbies back to,
/// read once from `BO2_MM_ROW_ALLOWLIST` as a comma-separated list.
///
/// Unset or empty - the normal case - means every caller gets results. The knob
/// exists because a console once took a DSI after being handed a lobby, and
/// being able to narrow delivery to one opted-in machine is how you debug that
/// without faulting bystanders. Addresses belong in the environment, never in
/// the source: they are players' home IPs.
///
/// What has been ruled out about that crash, so nobody re-treads it:
///   - Field order. Checked instruction by instruction against
///     MatchMakingInfo::deserialize (RPL 0x0225831c); it matches.
///   - Tagged vs raw encoding. bdByteBuffer has setTypeCheck/readDataType/
///     writeDataType (RPL 0x029f9aa8 / 0x029f6a48 / 0x029f65a8), so it is the
///     type-checked buffer after all and writing tagged values is right.
///   - Blob overruns. The payload lands in a 256-byte field capped at 0xff and
///     we send 37; the id is capped at 8 and the key at 0x10, both exact.
/// A console has since parsed a row, run its QoS probe and asked for a NAT
/// introduction without faulting, so the encoding is believed sound.
static ROW_ALLOWLIST: LazyLock<Vec<String>> = LazyLock::new(|| {
    std::env::var("BO2_MM_ROW_ALLOWLIST")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
});

/// What CreateSession answers with: `id` (default) returns the 8-byte session
/// id, `none` returns no results at all.
///
/// The switch exists because of a measurement that cuts against the obvious
/// reading. On a day when CreateSession answered with nothing, consoles went on
/// to send UpdateSessionPlayers and DeleteSession; on a day when it answered
/// with an id, they sent neither, all day. If the id makes
/// bdRemoteTask::deserializeTaskReply (RPL 0x02a70ec0) fail, the task never
/// completes, Session_CreateHostSessionSuccess never copies the security id into
/// sessionData+0x11, and Session_QoSListenStart_Platform (RPL 0x026b800c) then
/// registers the QoS listener under the wrong id - after which no joiner's probe
/// can ever match and every lobby reads as "0/1 good games".
///
/// That chain is plausible, not proven; this makes it an A/B rather than an
/// argument. Set BO2_MM_CREATE_SESSION_REPLY=none to test it.
fn create_session_reply_has_id() -> bool {
    !std::env::var("BO2_MM_CREATE_SESSION_REPLY")
        .map(|v| v.eq_ignore_ascii_case("none"))
        .unwrap_or(false)
}

/// Hand out an all-zero GAME_SECURITY_ID in FindSessions rows instead of the
/// host's real one, when BO2_MM_ZERO_SEC_ID is set.
///
/// Measured on console: a host advertises a real id (probe read
/// g_matchmakingInfo + 0x120 and it matched this server's record byte for byte)
/// but registers its QoS listener with eight zero bytes - the party security
/// block at partyData + 0x93ac, which Session_QoSListenStart_Platform feeds to
/// bdQoSProbe::listen, is never populated. bdQoSProbe::handleRequest then fails
/// to find the probed id and answers nothing at all, which every joiner reads as
/// "0/1 good games" no matter how good its connection is.
///
/// Handing out zeroes makes joiners probe for the id the host actually listens
/// on. It is a workaround for a client-side bug, not a fix, and it is worth
/// keeping behind a flag: the right repair is to make the console register the
/// id it advertises.
fn zero_out_sec_id() -> bool {
    std::env::var("BO2_MM_ZERO_SEC_ID").is_ok()
}

/// The r36 advertise patch makes every console announce on entering a playlist,
/// so both sides become hosts and neither joins ("waiting for the host" on both
/// screens). BO2_MM_ASYMMETRIC breaks the tie: FindSessions returns rows only to
/// the console that should be the *joiner*, leaving the other as host.
///
/// The joiner is picked by reachability, not by IP. A session whose advertised
/// public UDP port equals its bind port (3074, or 30000 when the port patch is
/// on) is directly reachable and makes a good host; one behind a remapping NAT
/// (shared IPv4 / CGNAT - the public port differs) does not. So:
///   - a console whose own session is reachable keeps its rows withheld -> host
///   - a console whose own session is not reachable gets every candidate -> join
///   - if neither side is reachable, fall back to an IP-string sort so exactly
///     one of them still joins
fn asymmetric_matching() -> bool {
    std::env::var("BO2_MM_ASYMMETRIC").is_ok()
}

/// Bind ports bdNet can be on: stock, and the shared-IPv4 rebind (r37).
const BDNET_BIND_PORTS: [u16; 2] = [3074, 30000];

/// The public UDP port a session's bdCommonAddr advertises, if any. Layout is
/// six bdAddr (4 IP bytes + u16 LE port) then a flag byte; slot 0 is the local
/// address, and the first non-empty slot after it is the public one.
fn advertised_public_port(blob: &[u8]) -> Option<u16> {
    let mut ports = blob
        .chunks(6)
        .take(6)
        .filter(|c| c.len() == 6 && !(c[0] == 0 && c[1] == 0xff && c[2] == 0 && c[3] == 0xff))
        .map(|c| u16::from_le_bytes([c[4], c[5]]));
    ports.next(); // local
    ports.next() // public
}

/// A directly reachable host: its public port was not remapped away from a bind
/// port.
fn is_reachable_host(info: &SessionInfo) -> bool {
    matches!(advertised_public_port(&info.common_addr), Some(p) if BDNET_BIND_PORTS.contains(&p))
}

/// Diagnostic (BO2_MM_STAGE1_SINK=<ip:port>): rewrite every populated address
/// slot of the bdCommonAddr handed out in FindSessions rows so that the joiner's
/// stage-1 punch lands on this server instead of on the real peer.
///
/// bdNATTravClient::sendStage1 (RPL 0x02a20280) builds a type 0x0d traversal
/// packet for each address in the peer's bdCommonAddr - every local address plus
/// the public one - and sends them all directly. Those packets are peer to peer,
/// so nothing here ever sees them, which is why "does the console really send the
/// punch?" has stayed unanswerable. Pointing them at a port the bdNet responder
/// binds makes them visible, and answers two questions at once: whether the punch
/// is sent at all (r47's nat-open stub is supposed to have unblocked it - in the
/// module, sendStage1 only takes the SIMULATED path when this+0x5c is set AND
/// connectionAllowed returns false), and what source port the sender's NAT
/// assigns towards a destination port it has never used, which is exactly the
/// symmetric-NAT question behind a stale advertised port.
///
/// It breaks joining for whoever it applies to, so scope it with
/// BO2_MM_SINK_FOR=<caller ip>. The store keeps the real addresses untouched;
/// only the serialised row is rewritten.
static STAGE1_SINK: LazyLock<Option<[u8; 6]>> = LazyLock::new(|| {
    let spec = std::env::var("BO2_MM_STAGE1_SINK").ok()?;
    let (ip, port) = spec.rsplit_once(':')?;
    let ip: std::net::Ipv4Addr = ip.parse().ok()?;
    let port: u16 = port.parse().ok()?;
    let mut slot = [0u8; 6];
    slot[..4].copy_from_slice(&ip.octets());
    slot[4..].copy_from_slice(&port.to_le_bytes());
    Some(slot)
});

static STAGE1_SINK_FOR: LazyLock<Option<String>> =
    LazyLock::new(|| std::env::var("BO2_MM_SINK_FOR").ok());

fn stage1_sink(peer: Option<IpAddr>) -> Option<[u8; 6]> {
    let slot = (*STAGE1_SINK)?;
    match &*STAGE1_SINK_FOR {
        Some(only) => match peer {
            Some(p) if p.to_string() == *only => Some(slot),
            _ => None,
        },
        None => Some(slot),
    }
}

/// Replace every populated bdAddr slot with `slot`, leaving the empty ones
/// (0.255.0.255:0) and the trailing flag byte alone.
fn redirect_common_addr(blob: &[u8], slot: [u8; 6]) -> Vec<u8> {
    let mut out = blob.to_vec();
    for i in 0..6 {
        let o = i * 6;
        if o + 6 > out.len() {
            break;
        }
        if out[o] == 0 && out[o + 1] == 0xff && out[o + 2] == 0 && out[o + 3] == 0xff {
            continue;
        }
        out[o..o + 6].copy_from_slice(&slot);
    }
    out
}

fn may_receive_rows(peer: Option<IpAddr>) -> bool {
    if ROW_ALLOWLIST.is_empty() {
        return true;
    }
    match peer {
        Some(ip) => {
            let ip = ip.to_string();
            ROW_ALLOWLIST.iter().any(|allowed| *allowed == ip)
        }
        None => false,
    }
}

#[derive(Clone, Debug)]
struct SessionInfo {
    common_addr: Vec<u8>,
    field_a: u32,
    max_players: u32,
    security_id: u64,
    security_key: Vec<u8>,
    ints: Vec<i32>,
    skill: f32,
    tail: Vec<i32>,
}

#[derive(Clone, Debug)]
struct StoredSession {
    id: u64,
    owner: Option<IpAddr>,
    info: SessionInfo,
    updated: Instant,
    /// Playlist number of this lobby. Read from the session blob's ints[5]
    /// (ints[4] is the playlist version, seen live 2026-09-07), falling back to
    /// the owner's last FindSessions query playlist when the blob carries 0.
    playlist: Option<i32>,
    /// Set once the owner sends UpdateSessionPlayers - i.e. someone actually
    /// joined. A lobby with players wins host election over a fresh one, so a
    /// console that leaves and re-searches is pointed back at the same game
    /// instead of being elected a lone host of nothing.
    has_players: bool,
}

/// Playlist number carried in a session blob: ints[5], with ints[4] the version.
/// 0 or out of the concrete-playlist range means "not set" - fall back to the
/// owner's last searched playlist.
fn session_playlist(info: &SessionInfo, owner: Option<IpAddr>) -> Option<i32> {
    match info.ints.get(5).copied() {
        Some(p) if (1..PLAYLIST_GROUPING_MIN).contains(&p) => Some(p),
        _ => owner.and_then(|ip| LAST_QUERY_PLAYLIST.lock().unwrap().get(&ip).copied()),
    }
}

static SESSIONS: LazyLock<Mutex<HashMap<u64, StoredSession>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_SESSION_ID: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(1));

/// Last playlist number each console asked for in a FindSessions query, so the
/// session it goes on to host can be tagged with it (CreateSession itself
/// carries no playlist we've decoded). Keyed by peer IP.
static LAST_QUERY_PLAYLIST: LazyLock<Mutex<HashMap<IpAddr, i32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Playlist numbers at or above this are "grouping" ids (parking playlist 9000,
/// dev slots), not a concrete public playlist to filter on.
const PLAYLIST_GROUPING_MIN: i32 = 1000;

/// Pull the requested playlist number out of a raw FindSessions message.
///
/// MatchMakingQuery::serialize (RPL 0x02258848, QueryId 2) writes a run of
/// tag-checked scalars. Decoded from live TDM vs Ground War captures
/// (2026-09-07): after `15 03 05` (FullType, task 5) come three u32s
/// (QueryId, 0, maxResults) then i32s `A, netcode(2079), C, playlist_version,
/// playlist_number, ...`. `C` is `2` in the strict query and the wildcard tag
/// 0x14 in the relaxed one, so anchor on netcode and count forward.
///
/// Tags (RE_REFERENCE): 0x07 i32, 0x08 u32, 0x0a u64, 0x0d f32, 0x13 blob,
/// 0x14 NaN/"don't care" (no payload), 0x00 terminator, 0x15 FullType, 0x03 u8.
/// Returns None on any parse surprise or a grouping/parking id - callers then
/// fall back to the older max_players heuristic rather than over-filtering.
fn parse_query_playlist(raw: &[u8]) -> Option<i32> {
    let mut i = 0usize;
    // scalar slots, in order; a wildcard slot is recorded as None
    let mut slots: Vec<Option<i64>> = Vec::new();
    while i < raw.len() && slots.len() < 12 {
        match raw[i] {
            0x15 => i += 1,        // FullType marker, no payload
            0x03 => i += 2,        // u8 tag + its one value byte (the task id)
            0x07 | 0x08 => {
                let v = raw.get(i + 1..i + 5)?;
                let n = i32::from_le_bytes([v[0], v[1], v[2], v[3]]);
                slots.push(Some(n as i64));
                i += 5;
            }
            0x0d => {
                slots.push(Some(i64::MIN)); // an f32 slot, not a number we compare
                i += 5;
            }
            0x0a => {
                slots.push(Some(i64::MIN));
                i += 9;
            }
            0x14 => {
                slots.push(None); // "don't care"
                i += 1;
            }
            0x00 => break,
            _ => return None,
        }
    }
    // slots so far: [taskId? no - consumed], QueryId, 0, maxResults, A,
    // netcode, C, playlist_version, playlist_number, ...
    let netcode_pos = slots.iter().position(|s| *s == Some(2079))?;
    let playlist = (*slots.get(netcode_pos + 3)?)?; // C, plver, plnum
    let playlist = i32::try_from(playlist).ok()?;
    if !(0..PLAYLIST_GROUPING_MIN).contains(&playlist) {
        return None;
    }
    Some(playlist)
}

/// Render a bdCommonAddr blob as the addresses it carries, so the log says who
/// is actually hosting. Layout is six bdAddr (four raw IP bytes then a u16 port,
/// little endian) followed by a flag byte; unset slots read back as
/// 0.255.0.255:0, which is what a default-constructed bdAddr looks like.
fn describe_common_addr(blob: &[u8]) -> String {
    let mut parts = Vec::new();
    for chunk in blob.chunks(6).take(6) {
        if chunk.len() < 6 {
            break;
        }
        if chunk[0] == 0 && chunk[1] == 0xff && chunk[2] == 0 && chunk[3] == 0xff {
            continue;
        }
        let port = u16::from_le_bytes([chunk[4], chunk[5]]);
        parts.push(format!(
            "{}.{}.{}.{}:{port}",
            chunk[0], chunk[1], chunk[2], chunk[3]
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn parse_session_info(reader: &mut BdReader) -> Result<SessionInfo, Box<dyn Error>> {
    let common_addr = reader.read_blob()?;
    let field_a = reader.read_u32()?;
    let max_players = reader.read_u32()?;
    let security_id = reader.read_u64()?;
    let security_key = reader.read_blob()?;
    let mut ints = Vec::with_capacity(8);
    for _ in 0..8 {
        ints.push(reader.read_i32()?);
    }
    let skill = reader.read_f32()?;
    let mut tail = Vec::with_capacity(4);
    for _ in 0..4 {
        tail.push(reader.read_i32()?);
    }
    Ok(SessionInfo {
        common_addr,
        field_a,
        max_players,
        security_id,
        security_key,
        ints,
        skill,
        tail,
    })
}

/// One row of a FindSessions reply, in the order bdMatchMakingInfo::deserialize
/// reads it: payload blob, session id, three u32s, then the T6 tail.
struct SessionRow {
    id: u64,
    info: SessionInfo,
    /// Set only by the BO2_MM_STAGE1_SINK diagnostic.
    sink: Option<[u8; 6]>,
}

impl BdSerialize for SessionRow {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        let common_addr = match self.sink {
            Some(slot) => redirect_common_addr(&self.info.common_addr, slot),
            None => self.info.common_addr.clone(),
        };
        writer.write_blob(&common_addr)?;
        writer.write_blob(&self.id.to_le_bytes())?;
        writer.write_u32(0)?;
        writer.write_u32(self.info.field_a)?;
        writer.write_u32(self.info.max_players)?;
        let advertised_sec_id = if zero_out_sec_id() { 0 } else { self.info.security_id };
        writer.write_u64(advertised_sec_id)?;
        writer.write_blob(&self.info.security_key)?;
        for v in &self.info.ints {
            writer.write_i32(*v)?;
        }
        writer.write_f32(self.info.skill)?;
        for v in &self.info.tail {
            writer.write_i32(*v)?;
        }
        Ok(())
    }
}

/// The eight bytes bdSessionID::deserialize expects back from CreateSession.
struct SessionIdResult {
    id: u64,
}

impl BdSerialize for SessionIdResult {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        writer.write_blob(&self.id.to_le_bytes())
    }
}

fn read_session_id(reader: &mut BdReader) -> Option<u64> {
    let blob = reader.read_blob().ok()?;
    if blob.len() < 8 {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&blob[..8]);
    Some(u64::from_le_bytes(b))
}

impl MatchmakingHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MatchmakingHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl LobbyHandler for MatchmakingHandler {
    fn handle_message(
        &self,
        session: &mut BdSession,
        mut message: BdMessage,
    ) -> Result<BdResponse, Box<dyn Error>> {
        let task_id_value = message.reader.read_u8()?;
        let peer = session.peer_ip();
        let task_id = MatchmakingTaskId::from_u8(task_id_value);

        // Diagnostic only (2026-09-05): FindSessionsByEntityIds/FindSessionsFromIds
        // fall through to the empty-success stub below - neither has ever been
        // observed on the wire, so the id format they carry (session id? entity/
        // profile id? how many, what encoding?) is unknown. This dump exists to
        // capture that format the next time a console's "join friend's session"
        // button sends one, so a real handler can be written. Remove once done.
        if task_id_value == 14 || task_id_value == 15 {
            let raw = message.reader.get_buffer().to_vec();
            let hex_str: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
            warn!(
                "Matchmaking task={task_id_value} ({task_id:?}) from {peer:?} RAW DUMP ({} bytes): {}",
                raw.len(),
                hex_str
            );
        }

        {
            let mut store = SESSIONS.lock().unwrap();
            store.retain(|_, s| s.updated.elapsed() < SESSION_TTL);
            // Observed on the wire: a console sitting in its lobby sends no
            // UpdateSession at all - it just re-announces with CreateSession every
            // couple of minutes. Keying liveness on update tasks therefore expired
            // live lobbies mid-search. Any traffic from the owner is proof enough
            // that it is still there.
            if peer.is_some() {
                for s in store.values_mut() {
                    if s.owner == peer {
                        s.updated = Instant::now();
                    }
                }
            }
        }

        match task_id {
            Some(MatchmakingTaskId::CreateSession) => {
                match parse_session_info(&mut message.reader) {
                    Ok(info) => {
                        let id = {
                            let mut next = NEXT_SESSION_ID.lock().unwrap();
                            let id = *next;
                            *next += 1;
                            id
                        };
                        // sec_id is what a joiner puts in its QoS probe, shrunk
                        // to 32 bits: bdQoSProbe::shrinkSecId (RPL 0x02a281b4)
                        // keeps the first four bytes of the bdSecurityID, read
                        // little-endian, i.e. the low half. The host only answers
                        // probes carrying an id it registered, and answers nothing
                        // at all otherwise - so a stale id here is indistinguishable
                        // from an unreachable host.
                        info!(
                            "Matchmaking CreateSession: id={id} host={} max_players={} netcode={:?} sec_id={:#018x} qos_sec_id={:#010x}",
                            describe_common_addr(&info.common_addr),
                            info.max_players,
                            info.ints.get(2),
                            info.security_id,
                            info.security_id as u32
                        );
                        // DIAG 2026-09-07: full session blob so the playlist/mode
                        // field can be located (which int changes between TDM and
                        // Ground War). Remove once FindSessions filters by playlist.
                        info!(
                            "Matchmaking CreateSession DIAG: field_a={} ints={:?} skill={} tail={:?}",
                            info.field_a, info.ints, info.skill, info.tail
                        );
                        let playlist = session_playlist(&info, peer);
                        info!("Matchmaking CreateSession: id={id} tagged playlist={playlist:?}");
                        {
                            let mut store = SESSIONS.lock().unwrap();
                            // Re-announcing replaces the previous lobby instead of
                            // adding a second one, so a joiner is never handed a
                            // stale address for a host that has already moved on.
                            // Carry has_players across the replace: a re-announce
                            // from a host mid-game must not demote it to "fresh".
                            let had_players = peer
                                .map(|p| store.values().any(|s| s.owner == Some(p) && s.has_players))
                                .unwrap_or(false);
                            if peer.is_some() {
                                store.retain(|_, s| s.owner != peer);
                            }
                            store.insert(
                                id,
                                StoredSession {
                                    id,
                                    owner: peer,
                                    info,
                                    updated: Instant::now(),
                                    playlist,
                                    has_players: had_players,
                                },
                            );
                        }
                        let results: Vec<Box<dyn BdSerialize>> = if create_session_reply_has_id()
                        {
                            vec![Box::new(SessionIdResult { id })]
                        } else {
                            Vec::new()
                        };
                        info!(
                            "Matchmaking CreateSession: replying with {} result(s)",
                            results.len()
                        );
                        return TaskReply::with_results(task_id_value, results).to_response();
                    }
                    Err(e) => {
                        warn!("Matchmaking CreateSession: could not parse session info: {e}");
                    }
                }
            }
            Some(MatchmakingTaskId::UpdateSession)
            | Some(MatchmakingTaskId::UpdateSessionPlayers) => {
                if let Some(id) = read_session_id(&mut message.reader) {
                    let mut store = SESSIONS.lock().unwrap();
                    if let Some(existing) = store.get_mut(&id) {
                        existing.updated = Instant::now();
                        let owner = existing.owner;
                        if let Ok(info) = parse_session_info(&mut message.reader) {
                            existing.playlist = session_playlist(&info, owner).or(existing.playlist);
                            existing.info = info;
                        }
                        // UpdateSessionPlayers means the roster changed - someone
                        // is in this lobby. Marks it as a real game for election.
                        if matches!(task_id, Some(MatchmakingTaskId::UpdateSessionPlayers)) {
                            existing.has_players = true;
                        }
                        info!("Matchmaking {task_id:?}: refreshed session id={id}");
                    } else {
                        info!("Matchmaking {task_id:?}: unknown session id={id}");
                    }
                }
            }
            Some(MatchmakingTaskId::DeleteSession) => {
                if let Some(id) = read_session_id(&mut message.reader) {
                    SESSIONS.lock().unwrap().remove(&id);
                    info!("Matchmaking DeleteSession: removed session id={id}");
                }
            }
            Some(MatchmakingTaskId::FindSessions) | Some(MatchmakingTaskId::FindSessionsPaged) => {
                // DIAG 2026-09-07: dump the raw query so the requested playlist/
                // mode field can be located (diff a TDM search vs a Ground War
                // search). MatchMakingQuery::serialize wire format is undocumented;
                // this is the capture step before a real playlist filter. The
                // buffer is the whole message incl. the task-id byte already read.
                let query_playlist = parse_query_playlist(message.reader.get_buffer());
                {
                    let raw = message.reader.get_buffer();
                    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
                    info!(
                        "Matchmaking FindSessions DIAG from {peer:?} playlist={query_playlist:?} ({} bytes): {hex}",
                        raw.len()
                    );
                }
                // Remember what this console is searching for, so the lobby it
                // hosts next (CreateSession carries no decoded playlist) inherits
                // it. Only a concrete playlist - the parking/grouping form leaves
                // the last real value in place on purpose.
                if let (Some(ip), Some(pl)) = (peer, query_playlist) {
                    LAST_QUERY_PLAYLIST.lock().unwrap().insert(ip, pl);
                }

                // Never hand a console back its own lobby - it would try to join
                // itself. Everything else currently registered is fair game; the
                // console applies its own filters to what it receives.
                let store = SESSIONS.lock().unwrap();
                let caller_own = store.values().find(|s| peer.is_some() && s.owner == peer);

                // Only match within the caller's own playlist/mode. Use the
                // playlist from this query, or - for the relaxed "any core
                // playlist" query form - the last concrete playlist this console
                // searched. Both known -> must be equal; either unknown -> don't
                // exclude (a relaxed search is the client asking to widen, and
                // over-filtering it is what left a console unable to re-find a
                // lobby it had just left). The old max_players fallback keyed on
                // the caller's own stale/fresh session and wrongly dropped valid
                // rejoin candidates.
                // This query's playlist, else the one this console is currently
                // hosting in (what it's actually sitting in - the relevant value
                // when it re-searches from inside a lobby), else the last one it
                // searched for. A stale last-searched value was filtering a
                // console in a custom lobby out of every candidate in that same
                // lobby's playlist.
                let caller_pl = query_playlist
                    .or_else(|| caller_own.and_then(|s| s.playlist))
                    .or_else(|| {
                        peer.and_then(|ip| LAST_QUERY_PLAYLIST.lock().unwrap().get(&ip).copied())
                    });
                let same_playlist = |s: &&StoredSession| match (caller_pl, s.playlist) {
                    (Some(q), Some(sp)) => q == sp,
                    _ => true,
                };

                // The pool the election is drawn from includes the caller's own
                // session - excluding it (as the row list below correctly does,
                // a console can't join itself) silently broke the whole feature:
                // whoever *should* have won the election could never recognize
                // themselves as the winner, since they never appeared in their
                // own candidate list, and so every console - including the best
                // host available - kept trying to join someone else instead of
                // sitting still (04/09 live test: the best-reachable console was still
                // sending 0x0a at another candidate instead of staying quiet). `suppress` below is what actually
                // keeps a winner silent; this pool only decides who wins.
                let pool: Vec<&StoredSession> = store.values().filter(same_playlist).collect();

                // Elect exactly one host for the whole group instead of deciding
                // per pair: with 3+ consoles, a pairwise reachability check lets
                // two reachable hosts each treat the other as joinable, so both
                // keep advertising and everyone ends up punching everyone else
                // at once instead of converging on one lobby (04/09 live test:
                // four simultaneous 0x0a loops instead of one).
                //
                // Sorting by owner IP (not session id) keeps the election
                // stable across time and observers: session `id` is assigned
                // fresh on every re-announce, so "lowest id" among reachable
                // candidates used to drift depending on exactly when each
                // console happened to call FindSessions - two callers a few
                // seconds apart got told two DIFFERENT elected hosts. A
                // console's owner IP never changes, so every caller converges
                // on the same answer regardless of timing.
                // Election key, best first: a lobby that already has players
                // beats a fresh one; then a directly reachable host beats one
                // behind a remapping NAT; then lowest owner IP breaks ties.
                // has_players comes first on purpose - since allowAllNAT lets a
                // joiner punch to an unreachable host too, the running game
                // should stay the target even if its host's port was remapped,
                // so a console that leaves and re-searches lands back in it
                // instead of an empty reachable lobby (2026-09-07: "can't
                // rejoin", then "join in progress hits an empty lobby").
                fn elect_key(s: &&StoredSession) -> (bool, bool, Option<IpAddr>) {
                    (!s.has_players, !is_reachable_host(&s.info), s.owner)
                }
                let elected = asymmetric_matching()
                    .then(|| pool.iter().min_by_key(|s| elect_key(s)).copied())
                    .flatten();

                // We ARE the elected host: stay quiet and let everyone else's
                // rows point at us instead. Compare owners, not ids - a fresh
                // re-announce between computing `elected` and `caller_own`
                // would otherwise give the same console two different ids and
                // make this false-negative.
                let suppress = matches!((elected, caller_own), (Some(host), Some(own)) if host.owner == own.owner);

                // Rows are still drawn from the self-excluded list - a console
                // can't be handed its own lobby - just not the election itself.
                let candidates: Vec<&StoredSession> = pool
                    .iter()
                    .filter(|s| peer.is_none() || s.owner != peer)
                    .copied()
                    .collect();

                let sink = stage1_sink(peer);
                if let Some(slot) = sink {
                    warn!(
                        "Matchmaking FindSessions: STAGE1 SINK ACTIVE for {:?} - rows point at {}.{}.{}.{}:{} instead of the real peer",
                        peer, slot[0], slot[1], slot[2], slot[3],
                        u16::from_le_bytes([slot[4], slot[5]])
                    );
                }
                // When electing a host, hand out only that one row - never the
                // whole candidate list - so a non-reachable console punches
                // toward exactly the lobby it's meant to join, not every
                // reachable host at once.
                let visible: Vec<&StoredSession> = match elected {
                    Some(host) => vec![host],
                    None => candidates.clone(),
                };
                let rows: Vec<Box<dyn BdSerialize>> = if !suppress && may_receive_rows(peer) {
                    visible
                        .iter()
                        .map(|s| {
                            Box::new(SessionRow {
                                id: s.id,
                                info: s.info.clone(),
                                sink,
                            }) as Box<dyn BdSerialize>
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                info!(
                    "Matchmaking FindSessions: {} session(s) held, {} match(es) for {:?}, returning {}",
                    store.len(),
                    candidates.len(),
                    peer,
                    rows.len()
                );
                return TaskReply::with_results(task_id_value, rows).to_response();
            }
            _ => {}
        }

        match task_id {
            Some(id) => info!("Matchmaking task={task_id_value} ({id:?}): returning empty success"),
            None => info!("Matchmaking task={task_id_value} (unknown): returning empty success"),
        }
        TaskReply::with_results(task_id_value, Vec::new()).to_response()
    }
}

#[cfg(test)]
mod tests {
    use super::parse_query_playlist;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // Live captures 2026-09-07, strict + relaxed forms.
    const TDM_STRICT: &str = "1503050802000000080000000008320000000701000000071f0800000702000000074f0000000701000000070000000007010000000d000000000d0ad7233c07000000000700000000070000000007000000000dcdcc4c3f0d9a99193f0dcdcccc3e0dcdcc4c3e0007070707";
    const GW_STRICT: &str = "1503050802000000080000000008320000000701000000071f0800000702000000074f0000000705000000070000000007010000000d000000000d0ad7233c07000000000700000000070000000007000000000dcdcc4c3f0d9a99193f0dcdcccc3e0dcdcc4c3e0019191919";
    const RELAXED: &str = "1503050802000000080000000008320000000701000000071f08000014074f0000000728230000070100000007010000000d000000000d0000000007000000000700000000070000000007000000000dcdcc4c3f0d9a99193f0dcdcccc3e0dcdcc4c3e00";

    #[test]
    fn decodes_playlist_number() {
        assert_eq!(parse_query_playlist(&hex(TDM_STRICT)), Some(1));
        assert_eq!(parse_query_playlist(&hex(GW_STRICT)), Some(5));
        // relaxed / parking form: playlist slot is 9000 -> no concrete filter
        assert_eq!(parse_query_playlist(&hex(RELAXED)), None);
        // garbage in -> None, never a panic
        assert_eq!(parse_query_playlist(&[0xff, 0x00, 0x12]), None);
        assert_eq!(parse_query_playlist(&[]), None);
    }
}
