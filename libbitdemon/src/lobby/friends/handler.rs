use crate::lobby::LobbyHandler;
use crate::lobby::response::task_reply::TaskReply;
use crate::messaging::BdErrorCode;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_response::{BdResponse, ResponseCreator};
use crate::networking::bd_session::BdSession;
use log::warn;
use std::error::Error;

// Diagnostic-only (2026-09-05): service 9 (Friends) was never implemented at all -
// bdFriends::setRichPresence/getRichPresence/getFriendsAndRichPresence (task 0x10/
// 0x11/0x1a, confirmed by decompiling the Wii U RPL) always fell through to the
// generic ServiceNotAvailable stub in LobbyServer::handle_message. This is very
// likely why every friend shows as "not joinable" - IsPlayerJoinable reads a local
// cache that getFriendsAndRichPresence (0x1a) is supposed to fill, and that call
// has never once succeeded. This handler just makes every request visible (full
// hex dump) so the real request/reply wire format can be captured from a live
// console opening its friends list, before writing real logic.
pub struct FriendsHandler {}

impl Default for FriendsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl FriendsHandler {
    pub fn new() -> FriendsHandler {
        FriendsHandler {}
    }
}

impl LobbyHandler for FriendsHandler {
    fn handle_message(
        &self,
        session: &mut BdSession,
        message: BdMessage,
    ) -> Result<BdResponse, Box<dyn Error>> {
        let raw = message.reader.get_buffer().to_vec();
        let hex_str: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        let task_id_value = raw.first().copied().unwrap_or(0);
        let known = match task_id_value {
            0x10 => " (SetRichPresence)",
            0x11 => " (GetRichPresence)",
            0x1a => " (GetFriendsAndRichPresence)",
            _ => "",
        };
        warn!(
            "Friends service RAW DUMP task=0x{:02x}{} from {:?} ({} bytes): {}",
            task_id_value,
            known,
            session.peer_ip(),
            raw.len(),
            hex_str
        );

        TaskReply::with_only_error_code(BdErrorCode::NoError, task_id_value).to_response()
    }
}
