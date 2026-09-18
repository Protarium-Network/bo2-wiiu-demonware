use crate::auth::auth_handler::wiiu::recall_pid;
use crate::lobby::LobbyHandler;
use crate::lobby::response::task_reply::TaskReply;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_response::{BdResponse, ResponseCreator};
use crate::messaging::bd_serialization::BdSerialize;
use crate::messaging::bd_writer::BdWriter;
use crate::networking::bd_session::BdSession;
use log::{info, warn};
use std::error::Error;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Minimal legacy bdMessaging implementation.
///
/// BO2 calls operation 1 while entering multiplayer to poll its mailbox.  An
/// empty successful result is the correct state for a new account with no
/// messages.  Returning ServiceNotAvailable makes the title abort online init.
pub struct MessagingHandler;

/// dwInstantSendMessage's task id (bdMessaging::sendGlobalInstantMessages) -
/// the join-friend flow (Live_JoinSessionInProgress / Invite_Add) calls
/// through here. dwInstantSendMessage itself doesn't wait on our reply (RE'd
/// 2026-09-16: sendGlobalInstantMessages constructs and starts a task
/// locally, returning a valid handle regardless of network outcome) - the
/// actual delivery is async, via whatever the RECIPIENT's own next mailbox
/// poll (op 1) turns up.
const INSTANT_MESSAGE_SEND: u8 = 18;
const MAILBOX_POLL: u8 = 1;

/// How long an undelivered message is kept before being dropped, so a player
/// who never logs in again doesn't pin memory forever.
const MESSAGE_TTL: Duration = Duration::from_secs(120);

/// Demonware's DWID format for a Wii U Nintendo Network PID: the high 4
/// bytes are always this constant, the low 4 bytes are the raw PID (see
/// `auth/auth_handler/wiiu.rs`'s `remember_pid`/`recall_pid`).
const DWID_PREFIX: [u8; 4] = [0x00, 0xbd, 0x00, 0x00];

/// Pull every recipient XUID out of a serialized op-18 body.
///
/// RE'd 2026-09-17 from the retail dedicated-server binary
/// (`CoDMPServer_WIIU.exe` + its matching `.pdb`, official Treyarch symbols
/// via Ghidra headless + PDB Universal Analyzer): `bdMessaging::
/// sendGlobalInstantMessages` writes the message blob first via
/// `bdByteBuffer::writeBlob`, then one `bdByteBuffer::writeUInt64` per
/// recipient. On the wire each of those shows up as `[0x0a tag][8-byte
/// little-endian XUID]`, high 4 bytes always `0000bd00`. Confirmed against
/// every op-18 capture in the journal so far (`journalctl -u bo2-demonware`)
/// - always exactly one recipient tag, 17 bytes from the end of a 140-byte
/// message - but we scan instead of hardcoding that offset in case a future
/// capture has more than one recipient (dwInstantSendMessage supports up to
/// 18 in a single call).
fn extract_recipient_xuids(body: &[u8]) -> Vec<u64> {
    let mut xuids = Vec::new();
    if body.len() < 9 {
        return xuids;
    }
    for i in 0..=body.len() - 9 {
        if body[i] == 0x0a && body[i + 5..i + 9] == DWID_PREFIX {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&body[i + 1..i + 9]);
            xuids.push(u64::from_le_bytes(buf));
        }
    }
    xuids
}

struct PendingMessage {
    sender_ip: Option<IpAddr>,
    recipient_xuids: Vec<u64>,
    body: Vec<u8>,
    queued_at: Instant,
}

/// Per-XUID mailbox now that `extract_recipient_xuids` can read the real
/// destination out of the wire format. A message whose recipient couldn't be
/// parsed (empty `recipient_xuids` - shouldn't happen anymore, kept as a
/// safety net) still falls back to the previous broadcast-to-whoever-polls-
/// next-and-isn't-the-sender behaviour.
static PENDING: LazyLock<Mutex<Vec<PendingMessage>>> = LazyLock::new(|| Mutex::new(Vec::new()));

struct RawBlobResult {
    body: Vec<u8>,
}

impl BdSerialize for RawBlobResult {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        writer.write_blob(&self.body)
    }
}

impl MessagingHandler {
    pub fn new() -> Self {
        Self
    }
}

impl LobbyHandler for MessagingHandler {
    fn handle_message(
        &self,
        session: &mut BdSession,
        mut message: BdMessage,
    ) -> Result<BdResponse, Box<dyn Error>> {
        let operation_id = message.reader.read_u8()?;
        let peer = session.peer_ip();

        // Diagnostic-only (2026-09-16): dump the full raw payload for anything
        // but the known mailbox-poll op 1, to capture the real wire format.
        // Remove once the join-friend flow is confirmed working end-to-end.
        if operation_id != MAILBOX_POLL {
            let raw = message.reader.get_buffer().to_vec();
            let hex_str: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
            warn!(
                "Messaging RAW DUMP operation={operation_id} from {peer:?} ({} bytes): {hex_str}",
                raw.len()
            );
        }

        if operation_id == INSTANT_MESSAGE_SEND {
            let body = message.reader.get_buffer().to_vec();
            let recipient_xuids = extract_recipient_xuids(&body);
            let mut pending = PENDING.lock().unwrap();
            pending.retain(|m| m.queued_at.elapsed() < MESSAGE_TTL);
            let xuid_strs: Vec<String> = recipient_xuids
                .iter()
                .map(|x| format!("{:016x}", x))
                .collect();
            info!(
                "Messaging operation={operation_id}: queued instant message from {peer:?} for xuids {xuid_strs:?} ({} pending)",
                pending.len() + 1
            );
            pending.push(PendingMessage {
                sender_ip: peer,
                recipient_xuids,
                body,
                queued_at: Instant::now(),
            });
            return TaskReply::with_results(operation_id, Vec::new()).to_response();
        }

        if operation_id == MAILBOX_POLL {
            let my_dwid = peer.as_ref().and_then(recall_pid).map(|pid| (0xbd00u64 << 32) | pid);

            let mut pending = PENDING.lock().unwrap();
            pending.retain(|m| m.queued_at.elapsed() < MESSAGE_TTL);

            let mut deliver = Vec::new();
            pending.retain(|m| {
                let is_mine = if m.recipient_xuids.is_empty() {
                    // Couldn't parse a recipient - fall back to the old
                    // broadcast-to-anyone-but-the-sender behaviour.
                    m.sender_ip != peer
                } else {
                    my_dwid.is_some_and(|d| m.recipient_xuids.contains(&d))
                };
                if is_mine {
                    deliver.push(m.body.clone());
                    false // delivered, remove from queue
                } else {
                    true // not for this poller, leave queued
                }
            });
            drop(pending);

            if !deliver.is_empty() {
                let dwid_str = my_dwid
                    .map(|d| format!("{:016x}", d))
                    .unwrap_or_else(|| "unknown".to_string());
                info!(
                    "Messaging operation={operation_id}: delivering {} queued instant message(s) to {peer:?} (dwid {dwid_str})",
                    deliver.len()
                );
                let results: Vec<Box<dyn BdSerialize>> = deliver
                    .into_iter()
                    .map(|body| Box::new(RawBlobResult { body }) as Box<dyn BdSerialize>)
                    .collect();
                return TaskReply::with_results(operation_id, results).to_response();
            }
        }

        info!("Messaging operation={operation_id}: returning an empty mailbox");
        TaskReply::with_results(operation_id, Vec::new()).to_response()
    }
}
