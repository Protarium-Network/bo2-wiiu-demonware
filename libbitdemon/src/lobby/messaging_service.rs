use crate::lobby::LobbyHandler;
use crate::lobby::response::task_reply::TaskReply;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_response::{BdResponse, ResponseCreator};
use crate::networking::bd_session::BdSession;
use log::info;
use std::error::Error;

/// Minimal legacy bdMessaging implementation.
///
/// BO2 calls operation 1 while entering multiplayer to poll its mailbox.  An
/// empty successful result is the correct state for a new account with no
/// messages.  Returning ServiceNotAvailable makes the title abort online init.
pub struct MessagingHandler;

impl MessagingHandler {
    pub fn new() -> Self {
        Self
    }
}

impl LobbyHandler for MessagingHandler {
    fn handle_message(
        &self,
        _session: &mut BdSession,
        mut message: BdMessage,
    ) -> Result<BdResponse, Box<dyn Error>> {
        let operation_id = message.reader.read_u8()?;
        info!("Messaging operation={operation_id}: returning an empty mailbox");

        TaskReply::with_results(operation_id, Vec::new()).to_response()
    }
}
