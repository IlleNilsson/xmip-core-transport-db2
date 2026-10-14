//! The login: what a client says before its first statement, and what it
//! makes of the answers (DRDA Version 5, Volume 3, *EXCSAT*, *ACCSEC*,
//! *SECCHK*, *ACCRDB*).
//!
//! Two chains. The first exchanges server attributes — the managers and
//! the levels this client speaks them at, Unicode among them — and asks
//! for security mechanism 3, a user ID and a password (`USRIDPWD`). The
//! second checks the user and opens the database: `SECCHK` and `ACCRDB`,
//! the client's numbers in Intel byte order (`QTDSQLX86`) and its strings
//! in UTF-8 (code set 1208), as DB2's own clients on Intel ask.
//!
//! Mechanism 3 sends the password as it is, so the wire protects it: TLS,
//! through the estate's own (`xmip-core-library-tls`, ADR-0033), where a
//! Location says `tls = true`. The mechanisms that encrypt the password
//! in DRDA itself (`EUSRIDPWD`, 9) rest on DES or AES keyed by an anonymous
//! Diffie-Hellman exchange that authenticates neither side; IBM marks the
//! server's side of them (`SERVER_ENCRYPT`) deprecated and recommends TLS.
//! A server that refuses mechanism 3 is told which one this client speaks.
//!
//! DDM's own names travel in EBCDIC code page 500 here, as DB2's clients
//! send them before Unicode is agreed; the package a statement runs in is
//! named in ASCII. Both are what a pure-protocol DB2 client tested against
//! DB2 for Linux, UNIX and Windows sends.

use transport::Login;
use transport::error::{Result, TransportError, protocol_error};

use crate::codepoint::{
    ACCRDB, ACCRDBRM, ACCSEC, ACCSECRD, AGENT, CCSIDDBC, CCSIDMBC, CCSIDMGR, CCSIDSBC, CMNTCPIP,
    CRRTKN, EXCSAT, EXTNAM, MGRLVLLS, PASSWORD, PRDID, RDB, RDBACCCL, RDBNAM, SECCHK, SECCHKCD,
    SECCHKRM, SECMEC, SECMGR, SQLAM, SRVCLSNM, SRVNAM, SRVRLSLV, TYPDEFNAM, TYPDEFOVR, UNICODEMGR,
    USRID,
};
use crate::ddm::Object;
use crate::ebcdic;
use crate::sqlca::Endian;
use crate::wire::{Chain, Wire};

/// Security mechanism 3: a user ID and a password.
pub const USRIDPWD: u16 = 3;
/// Unicode: UTF-8, the code set every string after the login is in.
pub const UTF8: u16 = 1208;
/// UTF-16, the double-byte code set.
const UTF16: u16 = 1200;
/// The managers this client speaks and the level of each.
pub const LEVELS: [(u16, u16); 6] = [
    (AGENT, 10),
    (SQLAM, 11),
    (CMNTCPIP, 5),
    (RDB, 12),
    (SECMGR, 9),
    (UNICODEMGR, UTF8),
];
/// The product a requester names itself as: DB2 for Linux, UNIX and
/// Windows at 12.1, whose behavior a DB2 server keys its answers on.
const PRODUCT: &str = "SQL12010";
/// The representation this client's numbers are in.
pub const REPRESENTATION: &str = "QTDSQLX86";
/// How long a database name a fixed-form `RDBNAM` holds.
pub const NAME: usize = 18;

/// What the server said of itself at the login.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accessed {
    /// The order the server's numbers come in.
    pub endian: Endian,
    /// Its product and release: `SQL11059` say.
    pub product: String,
}

/// `database` blank-padded to the eighteen characters a fixed-form name
/// holds.
///
/// # Errors
/// A longer name, which this client does not send.
pub fn padded(database: &str) -> Result<String> {
    if database.chars().count() > NAME {
        return Err(TransportError::permanent(format!(
            "{database:?} is longer than the {NAME} characters a DRDA database name holds here"
        )));
    }
    Ok(format!("{database:<NAME$}"))
}

/// `EXCSAT` naming `levels`, and this client where `named`.
///
/// # Errors
/// Never in practice: every name is ASCII.
pub fn excsat(levels: &[(u16, u16)], named: bool) -> Result<Object> {
    let listed: Vec<u8> = levels
        .iter()
        .flat_map(|(manager, level)| [manager.to_be_bytes(), level.to_be_bytes()].concat())
        .collect();
    if !named {
        return Ok(Object::of(EXCSAT, &[(MGRLVLLS, &listed)]));
    }
    let name = ebcdic::encode("xmip")?;
    let release = ebcdic::encode(env!("CARGO_PKG_VERSION"))?;
    Ok(Object::of(
        EXCSAT,
        &[
            (EXTNAM, &name),
            (SRVNAM, &name),
            (SRVRLSLV, &release),
            (MGRLVLLS, &listed),
            (SRVCLSNM, &name),
        ],
    ))
}

/// Log in to `database` as `login` on `wire`, and say Unicode is spoken
/// from here on.
///
/// # Errors
/// Where the server refused the mechanism, the user, the password or the
/// database, or answered what is not DRDA.
pub fn log_in(wire: &mut Wire, database: &str, login: &Login) -> Result<Accessed> {
    let name = ebcdic::encode(&padded(database)?)?;
    let mechanism = USRIDPWD.to_be_bytes();
    let attributes = excsat(&LEVELS, true)?;
    let security = Object::of(ACCSEC, &[(SECMEC, &mechanism), (RDBNAM, &name)]);
    wire.send(&Chain::new().request(&attributes).request(&security))?;
    let answered = replies(wire, "the security mechanism")?;
    for object in &answered {
        if object.codepoint == ACCSECRD {
            mechanisms(object)?;
        }
    }
    judged(&answered, Endian::default())?;
    let user = ebcdic::encode(&login.user)?;
    let password = ebcdic::encode(&login.password)?;
    let check = Object::of(
        SECCHK,
        &[
            (SECMEC, &mechanism),
            (RDBNAM, &name),
            (USRID, &user),
            (PASSWORD, &password),
        ],
    );
    let access = access(&name)?;
    wire.send(&Chain::new().request(&check).request(&access))?;
    let mut accessed = Accessed::default();
    let answered = replies(wire, "the login's answer")?;
    for object in &answered {
        match object.codepoint {
            SECCHKRM => checked(object)?,
            ACCRDBRM => accessed = opened(object),
            _ => {}
        }
    }
    judged(&answered, accessed.endian)?;
    wire.send(&Chain::new().request(&excsat(&[(CCSIDMGR, UTF8)], false)?))?;
    judged(&replies(wire, "the code set's answer")?, accessed.endian)?;
    Ok(accessed)
}

/// `ACCRDB` for the database `name` names, as SQL.
fn access(name: &[u8]) -> Result<Object> {
    let product = ebcdic::encode(PRODUCT)?;
    let representation = ebcdic::encode(REPRESENTATION)?;
    let token = [
        &ebcdic::encode("NF000001.XMIP")?[..],
        &codec::random::array::<6>(),
    ]
    .concat();
    let mut sets = Vec::new();
    for (set, value) in [(CCSIDSBC, UTF8), (CCSIDDBC, UTF16), (CCSIDMBC, UTF8)] {
        crate::ddm::put(&mut sets, set, &value.to_be_bytes());
    }
    Ok(Object::of(
        ACCRDB,
        &[
            (RDBNAM, name),
            (RDBACCCL, &SQLAM.to_be_bytes()),
            (PRDID, &product),
            (TYPDEFNAM, &representation),
            (CRRTKN, &token),
            (TYPDEFOVR, &sets),
        ],
    ))
}

/// Every object of the server's next chain.
fn replies(wire: &mut Wire, waiting_for: &str) -> Result<Vec<Object>> {
    let chain = wire
        .receive()?
        .ok_or_else(|| protocol_error(format!("the server closed before {waiting_for}")))?;
    Ok(chain.into_iter().flat_map(|dss| dss.objects).collect())
}

/// The first failure `objects` report, as the error.
fn judged(objects: &[Object], endian: Endian) -> Result<()> {
    crate::client::failure(objects, endian).map_or(Ok(()), Err)
}

/// The mechanisms `ACCSECRD` offers, refused where `USRIDPWD` is not one.
fn mechanisms(reply: &Object) -> Result<()> {
    let offered: Vec<u16> = reply
        .parameter(SECMEC)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect();
    if offered.contains(&USRIDPWD) {
        return Ok(());
    }
    Err(TransportError::permanent(format!(
        "the server offers security mechanisms {offered:?}, and this transport speaks {USRIDPWD} \
         (USRIDPWD) only: set the server's authentication to SERVER and guard the wire with TLS"
    )))
}

/// The login's verdict, refused where `SECCHKCD` is not zero.
fn checked(reply: &Object) -> Result<()> {
    let code = reply
        .parameter(SECCHKCD)
        .and_then(|value| value.first().copied())
        .unwrap_or(0);
    let reason = match code {
        0 => return Ok(()),
        0x01 => "the security mechanism is not supported",
        0x0E => "the password expired",
        0x0F => "the password is invalid",
        0x10 => "the password is missing",
        0x12 => "the user ID is missing",
        0x13 => "the user ID is invalid",
        0x14 => "the user ID is revoked",
        _ => "the security check failed",
    };
    Err(TransportError::permanent(format!(
        "the server refused the login: {reason} (SECCHKCD {code:#04x})"
    )))
}

/// What `ACCRDBRM` says of the server.
fn opened(reply: &Object) -> Accessed {
    let text = |codepoint| reply.parameter(codepoint).map(|v| ebcdic::decode(&v));
    Accessed {
        endian: text(TYPDEFNAM).map_or(Endian::Little, |name| Endian::of(&name)),
        product: text(PRDID).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_padded_and_the_answers_are_judged() {
        assert_eq!(padded("SAMPLE").expect("short"), "SAMPLE            ");
        assert!(padded(&"D".repeat(19)).is_err());
        let offered = Object::of(ACCSECRD, &[(SECMEC, &[0, 9, 0, 3])]);
        assert!(mechanisms(&offered).is_ok());
        let refused = Object::of(ACCSECRD, &[(SECMEC, &[0, 9])]);
        assert!(
            mechanisms(&refused)
                .expect_err("9 only")
                .message
                .contains("[9]")
        );
        let wrong = Object::of(SECCHKRM, &[(SECCHKCD, &[0x0F])]);
        assert!(
            checked(&wrong)
                .expect_err("refused")
                .message
                .contains("password is invalid")
        );
        let server = Object::of(
            ACCRDBRM,
            &[
                (PRDID, &ebcdic::encode("SQL11059").expect("ascii")),
                (TYPDEFNAM, &ebcdic::encode("QTDSQL370").expect("ascii")),
            ],
        );
        assert_eq!(
            opened(&server),
            Accessed {
                endian: Endian::Big,
                product: "SQL11059".into()
            }
        );
    }
}
