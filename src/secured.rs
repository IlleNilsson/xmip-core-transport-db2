//! DRDA over the estate's TLS, behind the `tls` feature.
//!
//! A DB2 server that speaks TLS does so on a port of its own
//! (`SSL_SVCENAME`) from the first byte: there is no request to turn it on
//! as FTP or PostgreSQL have. The client makes the TCP connection, hands it
//! to TLS (`xmip-core-library-tls`, ADR-0033), checks the server's
//! certificate, and logs in over it — which is what keeps the password of
//! security mechanism 3 off the wire in the clear.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use tls::duplex::split;
use transport::error::{Result, classify};
use transport::{Login, socket};

use crate::session::Session;
use crate::wire::Wire;

/// How a client guards its connection: the trust its server's certificate
/// is checked against, and the name it is checked for.
#[derive(Clone)]
pub struct Secured {
    /// The name the certificate must carry; the address's host where `None`.
    name: Option<String>,
    /// The trust a caller holds; the operating system's store where `None`.
    config: Option<Arc<tls::ClientConfig>>,
}

impl Secured {
    /// Checked against the operating system's trust store, for the
    /// address's host.
    #[must_use]
    pub const fn native() -> Self {
        Self {
            name: None,
            config: None,
        }
    }

    /// Checked against the trust `config` holds.
    #[must_use]
    pub fn trusting(config: Arc<tls::ClientConfig>) -> Self {
        Self {
            name: None,
            config: Some(config),
        }
    }

    /// Checked for `name` rather than the address's host.
    #[must_use]
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// A guarded connection to `server`.
    ///
    /// # Errors
    /// Where the server could not be reached or the handshake failed, the
    /// server's certificate among the reasons.
    pub fn wire(&self, server: &str, timeout: Option<Duration>) -> Result<Wire> {
        let socket = socket::connect_tcp(server, timeout)?;
        let name = self
            .name
            .as_deref()
            .unwrap_or_else(|| net::authority::host_of(server));
        let under = clone(&socket)?;
        let guarded = match &self.config {
            Some(config) => tls::client_with(name, socket, Arc::clone(config))?,
            None => tls::client(name, socket)?,
        };
        let halves = split(guarded)?;
        Ok(Wire::new(
            Box::new(halves.reading),
            Box::new(halves.writing),
            under,
        ))
    }
}

/// Accept one client on `listener` over TLS with `config`, and log it in
/// as [`Session::accept`] does.
///
/// # Errors
/// As [`Session::accept`], and where the handshake failed.
pub fn accept(
    listener: &TcpListener,
    login: &Login,
    timeout: Option<Duration>,
    config: &Arc<tls::ServerConfig>,
) -> Result<Session> {
    let (socket, peer): (TcpStream, SocketAddr) = socket::accept_tcp(listener, timeout)?;
    let under = clone(&socket)?;
    let halves = split(tls::server(socket, Arc::clone(config))?)?;
    let wire = Wire::new(Box::new(halves.reading), Box::new(halves.writing), under);
    Session::over(wire, peer, login)
}

fn clone(socket: &TcpStream) -> Result<TcpStream> {
    socket
        .try_clone()
        .map_err(|e| classify("cloning the connection", &e))
}
