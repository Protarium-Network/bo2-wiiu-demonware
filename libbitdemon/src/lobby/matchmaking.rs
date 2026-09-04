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
}

static SESSIONS: LazyLock<Mutex<HashMap<u64, StoredSession>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_SESSION_ID: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(1));

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
}

impl BdSerialize for SessionRow {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        writer.write_blob(&self.info.common_addr)?;
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
                        {
                            let mut store = SESSIONS.lock().unwrap();
                            // Re-announcing replaces the previous lobby instead of
                            // adding a second one, so a joiner is never handed a
                            // stale address for a host that has already moved on.
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
                        if let Ok(info) = parse_session_info(&mut message.reader) {
                            existing.info = info;
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
                // Never hand a console back its own lobby - it would try to join
                // itself. Everything else currently registered is fair game; the
                // console applies its own filters to what it receives.
                let store = SESSIONS.lock().unwrap();
                let candidates: Vec<&StoredSession> = store
                    .values()
                    .filter(|s| peer.is_none() || s.owner != peer)
                    .collect();

                // Asymmetry: only the console that should be the joiner gets
                // rows; the other stays host.
                let suppress = asymmetric_matching() && {
                    let caller_own =
                        store.values().find(|s| peer.is_some() && s.owner == peer);
                    let caller_reachable = caller_own.is_some_and(|s| is_reachable_host(&s.info));
                    // Among what the caller could join, is there a reachable one?
                    let reachable_candidate = candidates.iter().any(|s| is_reachable_host(&s.info));

                    if caller_reachable && !reachable_candidate {
                        // Caller is the best host available -> keep it hosting.
                        !candidates.is_empty()
                    } else if !caller_reachable && reachable_candidate {
                        // Caller can't host well but someone else can -> let it join.
                        false
                    } else {
                        // Both comparable (both reachable, or neither): IP sort,
                        // higher address joins.
                        match (peer, candidates.iter().filter_map(|s| s.owner).min()) {
                            (Some(c), Some(o)) if c != o => c.to_string() < o.to_string(),
                            _ => false,
                        }
                    }
                };

                let rows: Vec<Box<dyn BdSerialize>> = if !suppress && may_receive_rows(peer) {
                    candidates
                        .iter()
                        .map(|s| {
                            Box::new(SessionRow {
                                id: s.id,
                                info: s.info.clone(),
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
