use crate::auth::authentication::SessionAuthentication;
use std::io;
use std::io::BufReader;
use std::net::{SocketAddr, TcpStream};

pub type SessionId = u64;

pub struct BdSession {
    pub id: SessionId,
    authentication: Option<SessionAuthentication>,
    stream: BufReader<TcpStream>,
}

impl BdSession {
    /// Address of the connected console.
    ///
    /// BO2 authenticates on one TCP session and then opens a second one for the
    /// LSG handshake, which carries no identity of its own. Matching the two by
    /// peer address is what lets the LSG side recover the PID that just
    /// authenticated instead of assuming a single hard-coded player.
    pub fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.stream.get_ref().peer_addr().ok().map(|a| a.ip())
    }
}

impl io::Read for BdSession {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl io::Write for BdSession {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.get_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.get_mut().flush()
    }
}

impl BdSession {
    pub fn new(stream: TcpStream) -> Self {
        let reader = BufReader::new(stream);

        BdSession {
            id: 0,
            authentication: None,
            stream: reader,
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.get_ref().peer_addr()
    }

    pub fn authentication(&self) -> Option<&SessionAuthentication> {
        self.authentication.as_ref()
    }

    pub fn set_authentication(&mut self, authentication: SessionAuthentication) {
        debug_assert!(self.authentication.is_none());
        self.authentication = Some(authentication);
    }
}
