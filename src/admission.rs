//! The far end's side of the login: the server attributes, the security
//! mechanism, the check of one expected user and password, and the
//! database opened — what [`crate::login`] asks, answered as a DB2 server
//! on Intel answers it.

use std::net::SocketAddr;

use transport::Login;
use transport::error::{Result, TransportError, protocol_error};

use crate::codepoint::{
    ACCRDB, ACCRDBRM, ACCSEC, ACCSECRD, EXCSAT, EXCSATRD, MGRLVLLS, PASSWORD, PRDID, RDBNAM,
    SECCHK, SECCHKCD, SECCHKRM, SECMEC, SRVCLSNM, SRVNAM, SRVRLSLV, SVRCOD, TYPDEFNAM, USRID,
};
use crate::ddm::Object;
use crate::ebcdic;
use crate::login::{REPRESENTATION, USRIDPWD};
use crate::wire::{Chain, Dss, REPLY, Wire};

/// What this far end says it is.
pub const SERVER_VERSION: &str = "SQL11059";

/// Who logged in, and to what.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Admitted {
    pub user: String,
    pub database: String,
}

/// Answer the login of the client on `wire`, from `peer`, demanding
/// `login`.
///
/// # Errors
/// Where the client did not speak DRDA, or gave another user, password or
/// mechanism — which is told to the client before this returns.
pub fn admit(wire: &mut Wire, peer: SocketAddr, login: &Login) -> Result<Admitted> {
    let mut admitted = Admitted::default();
    let mut reply = Chain::new();
    for dss in chain(wire, "the server attributes")? {
        for object in &dss.objects {
            reply = match object.codepoint {
                EXCSAT => reply.reply(REPLY, dss.correlation, &attributes(object)?),
                ACCSEC => reply.reply(REPLY, dss.correlation, &mechanism()),
                _ => return Err(protocol_error("no EXCSAT and ACCSEC opened the login")),
            };
        }
    }
    wire.send(&reply)?;
    let mut reply = Chain::new();
    for dss in chain(wire, "the security check")? {
        for object in &dss.objects {
            reply = match object.codepoint {
                SECCHK => {
                    let text = |codepoint| object.parameter(codepoint).map(|v| ebcdic::decode(&v));
                    admitted.user = text(USRID).unwrap_or_default();
                    let password = text(PASSWORD).unwrap_or_default();
                    let mechanism = object.parameter(SECMEC).unwrap_or_default();
                    let code = if mechanism != USRIDPWD.to_be_bytes() {
                        0x01
                    } else if admitted.user != login.user {
                        0x13
                    } else if password != login.password {
                        0x0F
                    } else {
                        reply = reply.reply(REPLY, dss.correlation, &security(0, 0));
                        continue;
                    };
                    wire.send(&reply.reply(REPLY, dss.correlation, &security(8, code)))?;
                    return Err(TransportError::permanent(format!(
                        "the login of {:?} from {} was refused (SECCHKCD {code:#04x})",
                        admitted.user,
                        peer.ip()
                    )));
                }
                ACCRDB => {
                    let name = object.parameter(RDBNAM).unwrap_or_default();
                    admitted.database = ebcdic::decode(&name).trim_end().to_string();
                    reply.reply(REPLY, dss.correlation, &accessed()?)
                }
                _ => return Err(protocol_error("no SECCHK and ACCRDB followed")),
            };
        }
    }
    wire.send(&reply)?;
    Ok(admitted)
}

/// `EXCSATRD`: this far end's name and release, and the levels asked for.
///
/// # Errors
/// Never in practice: every name is ASCII.
pub fn attributes(asked: &Object) -> Result<Object> {
    let name = ebcdic::encode("xmip")?;
    let class = ebcdic::encode("QDB2/XMIP")?;
    let release = ebcdic::encode(SERVER_VERSION)?;
    let levels = asked.parameter(MGRLVLLS).unwrap_or_default();
    Ok(Object::of(
        EXCSATRD,
        &[
            (SRVCLSNM, &class),
            (SRVNAM, &name),
            (SRVRLSLV, &release),
            (MGRLVLLS, &levels),
        ],
    ))
}

/// `ACCSECRD`: mechanism 3, the one this far end checks.
fn mechanism() -> Object {
    Object::of(ACCSECRD, &[(SECMEC, &USRIDPWD.to_be_bytes())])
}

/// `SECCHKRM` of `severity` and `code`.
fn security(severity: u16, code: u8) -> Object {
    Object::of(
        SECCHKRM,
        &[(SVRCOD, &severity.to_be_bytes()), (SECCHKCD, &[code])],
    )
}

/// `ACCRDBRM`: the database open, this far end's product and order.
fn accessed() -> Result<Object> {
    let product = ebcdic::encode(SERVER_VERSION)?;
    let representation = ebcdic::encode(REPRESENTATION)?;
    Ok(Object::of(
        ACCRDBRM,
        &[
            (SVRCOD, &[0, 0]),
            (PRDID, &product),
            (TYPDEFNAM, &representation),
        ],
    ))
}

fn chain(wire: &mut Wire, waiting_for: &str) -> Result<Vec<Dss>> {
    wire.receive()?
        .ok_or_else(|| protocol_error(format!("the client closed before {waiting_for}")))
}
