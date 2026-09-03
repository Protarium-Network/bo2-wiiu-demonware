use crate::domain::title::Title;
use crate::messaging::StreamMode;
use crate::messaging::bd_serialization::BdSerialize;
use crate::messaging::bd_writer::BdWriter;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::ToPrimitive;
use snafu::{Snafu, ensure};
use std::error::Error;
use tiger::{Digest, Tiger};

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum BdAuthTicketType {
    UserToService = 0x0,
    HostToService = 0x1,
    UserToHost = 0x2,
}

pub struct AuthTicket {
    pub ticket_type: BdAuthTicketType,
    pub title: Title,
    pub time_issued: u32,
    pub time_expires: u32,
    pub license_id: u64,
    pub user_id: u64,
    pub username: String,
    pub session_key: [u8; 24],
}

const MAGIC_NUMBER: u32 = 0xEFBDADDE;
const NAME_MAX_LEN: usize = 64;

#[derive(Debug, Snafu)]
#[snafu(display("Name too long when serializing auth ticket (len={name_len} max={NAME_MAX_LEN})"))]
struct UsernameTooLongError {
    name_len: usize,
}

impl BdSerialize for AuthTicket {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        writer.set_type_checked(false);
        writer.set_mode(StreamMode::ByteMode);

        ensure!(
            self.username.len() <= NAME_MAX_LEN,
            UsernameTooLongSnafu {
                name_len: self.username.len()
            }
        );

        // Retail bdAuthTicket is exactly 128 bytes. All integer fields are
        // serialized little-endian, followed by the fixed Wii U trailer and
        // the first four bytes of Tiger192(ticket[0..121]).
        let mut ticket = Vec::with_capacity(128);
        ticket.extend_from_slice(&MAGIC_NUMBER.to_le_bytes());
        ticket.push(self.ticket_type.to_u8().unwrap());
        ticket.extend_from_slice(&self.title.to_u32().unwrap().to_le_bytes());
        ticket.extend_from_slice(&self.time_issued.to_le_bytes());
        ticket.extend_from_slice(&self.time_expires.to_le_bytes());
        ticket.extend_from_slice(&self.license_id.to_le_bytes());
        ticket.extend_from_slice(&self.user_id.to_le_bytes());
        ticket.extend_from_slice(self.username.as_bytes());
        ticket.resize(ticket.len() + (NAME_MAX_LEN - self.username.len()), 0);
        ticket.extend_from_slice(&self.session_key);
        debug_assert_eq!(ticket.len(), 121);
        let checksum = Tiger::digest(&ticket);
        ticket.extend_from_slice(&[0x55, 0x33, 0x22]);
        debug_assert_eq!(ticket.len(), 124);
        ticket.extend_from_slice(&checksum[..4]);
        debug_assert_eq!(ticket.len(), 128);

        writer.write_bytes(&ticket)?;
        Ok(())
    }
}
