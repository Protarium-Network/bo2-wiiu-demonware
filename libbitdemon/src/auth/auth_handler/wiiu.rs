use crate::auth::auth_handler::{AuthHandler, AuthMessageType};
use crate::auth::auth_proof::ClientOpaqueAuthProof;
use crate::auth::key_store::ThreadSafeBackendPrivateKeyStorage;
use crate::auth::response::AuthResponse;
use crate::auth::result::auth_ticket::{AuthTicket, BdAuthTicketType};
use crate::crypto::{encrypt_buffer_in_place, generate_iv_from_seed, generate_iv_seed};
use crate::domain::title::Title;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_serialization::BdSerialize;
use crate::messaging::bd_writer::BdWriter;
use crate::messaging::{BdErrorCode, StreamMode};
use crate::networking::bd_session::BdSession;
use chrono::Utc;
use des::cipher::BlockSizeUser;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use log::{info, warn};
use num_traits::FromPrimitive;
use std::error::Error;
use std::sync::Arc;
use tiger::{Digest, Tiger};

pub struct WiiUAuthHandler {
    key_store: Arc<ThreadSafeBackendPrivateKeyStorage>,
    reply_type: AuthMessageType,
}

// chrono::Utc::timestamp() is expressed in seconds.
const TICKET_ISSUE_LENGTH: i64 = 5 * 60;

struct WiiUAuthResponse {
    reply_type: AuthMessageType,
    ticket: AuthTicket,
    serialized_proof_data: [u8; 128],
    iv_seed: u32,
    token_encryption_key: [u8; 24],
}

impl AuthResponse for WiiUAuthResponse {
    fn message_type(&self) -> AuthMessageType {
        self.reply_type
    }

    fn error_code(&self) -> BdErrorCode {
        BdErrorCode::AuthNoError
    }

    fn write_auth_data(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        let seed = generate_iv_seed();
        writer.write_u32(seed)?;

        let mut ticket_buf = Vec::new();
        {
            let mut ticket_writer = BdWriter::new(&mut ticket_buf);
            self.ticket.serialize(&mut ticket_writer)?;
        }

        let iv = generate_iv_from_seed(seed);
        // Retail BO2's handleWiiUReply2 passes a fixed 0x98-byte encrypted
        // blob to handleWiiUReplies.  The first 0x80 bytes are bdAuthTicket;
        // the remaining 0x18 bytes are reply-info padding/session material.
        // Sending only bdAuthTicket makes readBits fail before decryption.
        let required_len = if self.reply_type == AuthMessageType::WiiUForMmpReply2 {
            0x98
        } else {
            0x80
        };
        ticket_buf.resize(required_len, 0);

        encrypt_buffer_in_place(&mut ticket_buf, &self.token_encryption_key, &iv);
        // BO2's bdAuthService::handleWiiUReplies reads a fixed 128-byte RSA
        // signature before it reads and decrypts the user ticket.
        writer.write_bytes(&self.serialized_proof_data)?;
        writer.write_bytes(ticket_buf.as_slice())?;

        Ok(())
    }
}

impl WiiUAuthHandler {
    pub fn new(
        key_store: Arc<ThreadSafeBackendPrivateKeyStorage>,
        reply_type: AuthMessageType,
    ) -> Self {
        WiiUAuthHandler {
            key_store,
            reply_type,
        }
    }
}

/// Remembers which Nintendo PID authenticated from which client address.
pub static PID_BY_ADDR: LazyLock<Mutex<HashMap<IpAddr, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn remember_pid(addr: IpAddr, pid: u64) {
    if let Ok(mut map) = PID_BY_ADDR.lock() {
        map.insert(addr, pid);
    }
}

pub fn recall_pid(addr: &IpAddr) -> Option<u64> {
    PID_BY_ADDR.lock().ok().and_then(|m| m.get(addr).copied())
}

/// Locate the base64 service token inside the raw auth payload.
///
/// The previous implementation searched for the literal bytes "aW", which are
/// just the first two base64 characters of one particular PID: it matched a
/// single account and silently fell back to a hard-coded PID for everyone else.
/// Take the longest run of base64 characters instead - the token is by far the
/// longest such run (~80 chars).
fn find_service_token(raw: &[u8]) -> Option<&[u8]> {
    fn is_b64(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
    }
    let mut best: Option<(usize, usize)> = None;
    let mut run_start: Option<usize> = None;
    for (i, &b) in raw.iter().enumerate() {
        if is_b64(b) {
            run_start.get_or_insert(i);
        } else if let Some(st) = run_start.take() {
            let len = i - st;
            if best.map_or(true, |(_, bl)| len > bl) {
                best = Some((st, len));
            }
        }
    }
    if let Some(st) = run_start {
        let len = raw.len() - st;
        if best.map_or(true, |(_, bl)| len > bl) {
            best = Some((st, len));
        }
    }
    best.filter(|&(_, len)| len >= 40)
        .map(|(st, len)| &raw[st..st + len])
}

fn decode_b64(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;

    for &b in input {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => continue,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// The Wii U Demonware client derives its ticket cipher key by hashing the
// Nintendo principal ID as a big-endian u32 with Tiger192. This mirrors
// bdAuthService::makeAuthForWiiU2 in the retail BO2 RPL.
fn token_key_from_pid(pid: u32) -> [u8; 24] {
    let mut tiger = Tiger::new();
    tiger.update(pid.to_be_bytes());
    tiger.finalize().into()
}

impl AuthHandler for WiiUAuthHandler {
    fn handle_message(
        &self,
        session: &mut BdSession,
        mut message: BdMessage,
    ) -> Result<Box<dyn AuthResponse>, Box<dyn Error>> {
        let raw = message.reader.get_buffer().to_vec();
        let hex_str: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        info!("WiiUAuthHandler received {} bytes: {}", raw.len(), hex_str);

        message.reader.set_mode(StreamMode::BitMode);
        let _ = message.reader.read_type_checked_bit();

        let mut iv_seed = generate_iv_seed();
        if let Ok(seed) = message.reader.read_u32() {
            iv_seed = seed;
        }

        let mut title = Title::T6WiiU;
        if let Ok(title_id) = message.reader.read_u32() {
            if let Some(t) = Title::from_u32(title_id) {
                title = t;
            }
        }

        // Default fallback key
        let mut user_id = 1768140980u64;
        let mut token_key = token_key_from_pid(user_id as u32);

        // Locate the base64 service token anywhere in the raw message buffer.
        let mut token_found = false;
        if let Some(token_slice) = find_service_token(raw.as_slice()) {
            if let Ok(token_str) = std::str::from_utf8(token_slice) {
                info!("Found base64 Service Token: {}", token_str);
                if let Some(decoded) = decode_b64(token_slice) {
                    info!("Decoded Service Token: {} bytes", decoded.len());
                    if decoded.len() >= 4 {
                        let pid =
                            u32::from_be_bytes([decoded[0], decoded[1], decoded[2], decoded[3]]);
                        user_id = pid as u64;
                        token_key = token_key_from_pid(pid);
                        token_found = true;
                        info!("Extracted PID from token: {}", pid);
                        if let Some(ip) = session.peer_ip() {
                            remember_pid(ip, user_id);
                        }
                    }
                }
            }
        }
        if !token_found {
            warn!(
                "No service token found in auth payload; falling back to PID {}",
                user_id
            );
        }

        let username = format!("WiiUUser{}", user_id);
        let session_key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x55, 0xAA, 0x55, 0xAA, 0x33, 0xCC, 0x33, 0xCC,
        ];

        info!(
            "Handling WiiU Auth request: session={} iv_seed={:x} title={:?} user_id={}",
            session.id, iv_seed, title, user_id
        );

        let now = Utc::now();
        let issued = (now.timestamp() % (u32::MAX as i64)) as u32;
        let expires_i64 = now.timestamp() + TICKET_ISSUE_LENGTH;
        let expires = ((expires_i64) % (u32::MAX as i64)) as u32;

        let ticket = AuthTicket {
            ticket_type: BdAuthTicketType::UserToService,
            title,
            time_issued: issued,
            time_expires: expires,
            license_id: user_id,
            user_id,
            username: username.clone(),
            session_key,
        };

        let proof = ClientOpaqueAuthProof {
            title: ticket.title,
            time_expires: expires_i64,
            license_id: ticket.license_id,
            user_id: ticket.user_id,
            session_key: ticket.session_key,
            username,
        };
        let serialized_proof_data = proof.serialize(self.key_store.as_ref());
        let proof_hex: String = serialized_proof_data
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        info!("WiiU opaque proof sent: {proof_hex}");

        info!("Sending WiiU Auth Reply {:?} to session={}", self.reply_type, session.id);

        Ok(Box::new(WiiUAuthResponse {
            reply_type: self.reply_type,
            ticket,
            serialized_proof_data,
            iv_seed,
            token_encryption_key: token_key,
        }))
    }
}
