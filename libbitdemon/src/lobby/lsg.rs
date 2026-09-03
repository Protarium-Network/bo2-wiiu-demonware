use crate::auth::auth_proof::ClientOpaqueAuthProof;
use crate::auth::authentication::SessionAuthentication;
use crate::auth::key_store::ThreadSafeBackendPrivateKeyStorage;
use crate::domain::title::Title;
use crate::lobby::LobbyHandler;
use crate::lobby::response::lsg_reply::ConnectionIdResponse;
use crate::messaging::StreamMode::BitMode;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_response::{BdResponse, ResponseCreator};
use crate::networking::bd_session::BdSession;
use log::info;
use num_traits::FromPrimitive;
use snafu::{OptionExt, Snafu, ensure};
use std::error::Error;
use std::sync::Arc;

pub struct LsgHandler {
    key_store: Arc<ThreadSafeBackendPrivateKeyStorage>,
}

impl LsgHandler {
    pub fn new(key_store: Arc<ThreadSafeBackendPrivateKeyStorage>) -> LsgHandler {
        LsgHandler { key_store }
    }
}

#[derive(Debug, Snafu)]
enum LobbyServiceError {
    #[snafu(display("The title id is unknown (value={title_id})"))]
    UnknownTitle { title_id: u32 },
    #[snafu(display(
        "The specified title id does not match (specified_title={specified_title:?} authenticated_title={authenticated_title:?})"
    ))]
    InvalidTitle {
        specified_title: Title,
        authenticated_title: Title,
    },
    #[snafu(display("The authentication expired (expires={expires} now={now})"))]
    AuthenticationExpired { expires: i64, now: i64 },
}

impl LobbyHandler for LsgHandler {
    fn handle_message(
        &self,
        session: &mut BdSession,
        mut message: BdMessage,
    ) -> Result<BdResponse, Box<dyn Error>> {
        message.reader.set_mode(BitMode);
        message.reader.read_type_checked_bit()?;

        let title_id = message.reader.read_u32()?;
        let title = Title::from_u32(title_id).with_context(|| UnknownTitleSnafu { title_id })?;
        let _iv_seed = message.reader.read_u32()?;

        let mut auth_proof: [u8; 128] = [0; 128];
        message.reader.read_bytes(&mut auth_proof)?;
        let proof_hex: String = auth_proof
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        info!("WiiU opaque proof received by LSG: {proof_hex}");

        let auth_proof = if auth_proof.iter().all(|byte| *byte == 0) && title == Title::T6WiiU {
            // BO2 Wii U sends an all-zero 128-byte LSG proof after the
            // WiiUForMmpReply2 exchange. Its actual session key was delivered
            // inside bdAuthTicket. This temporary compatibility path mirrors
            // that key so the next encrypted packet can validate its HMAC.
            info!("Using BO2 Wii U zero-proof compatibility path");
            // Recover the PID that authenticated from this same client address a
            // moment ago; only fall back to the historical hard-coded value if the
            // auth exchange never produced one.
            let pid = session
                .peer_ip()
                .and_then(|ip| crate::auth::auth_handler::wiiu::recall_pid(&ip))
                .unwrap_or(1768140980);
            info!("LSG zero-proof resolved to PID {pid}");
            ClientOpaqueAuthProof {
                title,
                time_expires: chrono::Utc::now().timestamp() + 300,
                license_id: pid,
                // The title addresses its own storage by the Demonware ID, not the
                // raw Nintendo PID: bdAuthUtility::createDWIDForWiiU builds it as
                //     DWID = 0xBD00 << 32 | PID
                // (0xBD00 being the Wii U platform prefix). Observed live:
                // PID 1768140980 (0x6963b0b4) -> DWID 207809465790644 (0xbd006963b0b4).
                // Reporting the PID here made the game upload its files under one
                // owner id while reading them back under another, so it never found
                // its own mpstatsCompressed / mpClassSets and its stats stayed empty.
                user_id: 0x0000_BD00_0000_0000u64 | pid,
                session_key: [
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                    0x55, 0xAA, 0x55, 0xAA, 0x33, 0xCC, 0x33, 0xCC,
                ],
                username: format!("WiiUUser{pid}"),
            }
        } else {
            ClientOpaqueAuthProof::deserialize(&mut auth_proof, self.key_store.as_ref())?
        };

        let now = chrono::Utc::now().timestamp();
        ensure!(
            auth_proof.time_expires >= now,
            AuthenticationExpiredSnafu {
                expires: auth_proof.time_expires,
                now
            }
        );

        ensure!(
            auth_proof.title == title,
            InvalidTitleSnafu {
                specified_title: title,
                authenticated_title: auth_proof.title
            }
        );

        info!(
            "Authenticated with opaque data user_id={} username={}",
            auth_proof.user_id, auth_proof.username
        );

        session.set_authentication(SessionAuthentication {
            user_id: auth_proof.user_id,
            username: auth_proof.username,
            session_key: auth_proof.session_key,
            title: auth_proof.title,
        });

        ConnectionIdResponse::new(session.id).to_response()
    }

    fn requires_authentication(&self) -> bool {
        false
    }
}
