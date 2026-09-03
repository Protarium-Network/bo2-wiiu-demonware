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
        writer.write_u64(self.info.security_id)?;
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
                        info!(
                            "Matchmaking CreateSession: id={id} host={} max_players={} netcode={:?}",
                            describe_common_addr(&info.common_addr),
                            info.max_players,
                            info.ints.get(2)
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
                        return TaskReply::with_results(
                            task_id_value,
                            vec![Box::new(SessionIdResult { id })],
                        )
                        .to_response();
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
                let rows: Vec<Box<dyn BdSerialize>> = if may_receive_rows(peer) {
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
