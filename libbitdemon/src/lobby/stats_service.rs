use crate::lobby::LobbyHandler;
use crate::lobby::response::task_reply::TaskReply;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_response::{BdResponse, ResponseCreator};
use crate::networking::bd_session::BdSession;
use log::info;
use std::error::Error;

/// Minimal bdStats stub (LobbyServiceId::Stats = 4).
///
/// BO2 calls Stats operation 1 during multiplayer online-init (leaderboard /
/// stats-session setup). Without a registered handler the lobby answers
/// "unavailable service" and the title aborts to "the server is not
/// available". An empty successful TaskReply lets init continue - the game's
/// own stats blob is persisted separately through bdStorage
/// (`mpstatsCompressed`), so nothing here needs to return real data.
pub struct StatsHandler;

impl StatsHandler {
    pub fn new() -> Self {
        Self
    }
}

impl LobbyHandler for StatsHandler {
    fn handle_message(
        &self,
        _session: &mut BdSession,
        mut message: BdMessage,
    ) -> Result<BdResponse, Box<dyn Error>> {
        let operation_id = message.reader.read_u8()?;
        info!("Stats operation={operation_id}: returning empty success");

        TaskReply::with_results(operation_id, Vec::new()).to_response()
    }
}
