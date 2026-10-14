//! The client's side of one connection to a DB2 server: the login, a query
//! and its rows, a statement and its count, each unit of work committed
//! (DRDA Version 5, Volume 1, *SQL Application Manager*).
//!
//! Every statement runs as dynamic SQL in the package every DB2 database
//! binds for its command-line and call-level clients, `NULLID.SYSSH200`,
//! section 65. A query is prepared and opened in one chain — `PRPSQLSTT`,
//! its `SQLSTT`, `OPNQRY` — and continued with `CNTQRY` under the limited
//! block protocol until the server ends it; a statement is `EXCSQLIMM`
//! with `RDBCMM` chained behind it. DRDA has no autocommit: a query is
//! committed after its last block, so neither holds a lock past its call.

use std::time::Duration;

use transport::error::{Result, TransportError, protocol_error};
use transport::pool::{Pooled, alive};
use transport::{Login, socket};

use crate::codepoint::{
    CNTQRY, ENDQRYRM, EXCSQLIMM, MAXBLKEXT, OPNQRY, OPNQRYRM, PKGNAMCSN, PRPSQLSTT, QRYBLKSZ,
    QRYCLSIMP, QRYDSC, QRYDTA, QRYINSID, QRYNOPRM, RDBCMM, RDBCMTOK, RTNEXTDTA, RTNSQLDA, SQLCARD,
    SQLDARD, SRVDGN,
};
use crate::ddm::Object;
use crate::login::{Accessed, log_in, padded};
use crate::row::{Row, describe, rows};
use crate::sqlca::{Endian, Sqlca};
use crate::statement::statement;
use crate::wire::{Chain, Dss, Wire};

/// The collection, package and consistency token dynamic SQL runs in.
const PACKAGE: (&str, &str, &str) = ("NULLID", "SYSSH200", "SYSLVL01");
/// The section of that package every statement uses.
const SECTION: u16 = 65;
/// The most one query block holds.
const BLOCK: u32 = 65_535;
/// `TRUE` as a DDM boolean.
const TRUE: u8 = 0xF1;

/// What a query came back with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryResult {
    /// Each row, each column as text or NULL.
    pub rows: Vec<Row>,
}

/// One logged-in connection, kept between statements while the server
/// keeps it open.
pub struct Client {
    wire: Wire,
    package: Vec<u8>,
    accessed: Accessed,
}

impl Client {
    /// Connect to `server` in the clear and log in to `database` as
    /// `login`.
    ///
    /// # Errors
    /// Where the server could not be reached or refused the login.
    pub fn connect(
        server: &str,
        database: &str,
        login: &Login,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let stream = socket::connect_tcp(server, timeout)?;
        Self::over(Wire::plain(stream)?, database, login)
    }

    /// Log in to `database` as `login` over a connection already made —
    /// guarded by TLS, or not.
    ///
    /// # Errors
    /// Where the server refused the login.
    pub fn over(mut wire: Wire, database: &str, login: &Login) -> Result<Self> {
        let accessed = log_in(&mut wire, database, login)?;
        let named = format!(
            "{}{:<18}{:<18}{}",
            padded(database)?,
            PACKAGE.0,
            PACKAGE.1,
            PACKAGE.2
        );
        let mut package = named.into_bytes();
        package.extend_from_slice(&SECTION.to_be_bytes());
        Ok(Self {
            wire,
            package,
            accessed,
        })
    }

    /// What the server said it was: `SQL11059` say.
    #[must_use]
    pub fn server_version(&self) -> &str {
        &self.accessed.product
    }

    /// Run `sql` and take its rows.
    ///
    /// # Errors
    /// Where the server went away, answered with an error, or sent a
    /// column of a type this transport does not read.
    pub fn query(&mut self, sql: &str) -> Result<QueryResult> {
        let prepare = Object::of(
            PRPSQLSTT,
            &[(PKGNAMCSN, &self.package), (RTNSQLDA, &[TRUE])],
        );
        let open = Object::of(
            OPNQRY,
            &[
                (PKGNAMCSN, &self.package),
                (QRYBLKSZ, &BLOCK.to_be_bytes()),
                (MAXBLKEXT, &(-1i16).to_be_bytes()),
                (QRYCLSIMP, &[1]),
            ],
        );
        let chain = Chain::new()
            .request(&prepare)
            .object(&statement(sql))
            .request(&open);
        self.wire.send(&chain)?;
        let (mut columns, mut data, mut instance) = (Vec::new(), Vec::new(), None);
        let mut failed = None;
        loop {
            let mut ended = false;
            let endian = self.accessed.endian;
            for object in self
                .replies("the query's answer")?
                .into_iter()
                .flat_map(|d| d.objects)
            {
                // The end of a query, or a query the server already closed:
                // either way there is nothing more to ask for.
                if matches!(object.codepoint, ENDQRYRM | QRYNOPRM) {
                    ended = true;
                    continue;
                }
                failed = failed.or_else(|| failure(std::slice::from_ref(&object), endian));
                match object.codepoint {
                    OPNQRYRM => instance = Some(object.parameter(QRYINSID).unwrap_or_default()),
                    QRYDSC => columns.extend(describe(&object.data)?),
                    QRYDTA => data.extend(object.data),
                    _ => {}
                }
            }
            let Some(open) = instance.as_deref().filter(|_| !ended && failed.is_none()) else {
                break;
            };
            let more = Object::of(
                CNTQRY,
                &[
                    (PKGNAMCSN, &self.package),
                    (QRYBLKSZ, &BLOCK.to_be_bytes()),
                    (QRYINSID, open),
                    (RTNEXTDTA, &[0x02]),
                ],
            );
            self.wire.send(&Chain::new().request(&more))?;
        }
        self.commit()?;
        if let Some(failed) = failed {
            return Err(failed);
        }
        if instance.is_none() {
            return Err(protocol_error("the server opened no query"));
        }
        let (rows, end) = rows(&data, &columns, self.accessed.endian)?;
        match end.and_then(|area| area.error()) {
            Some(failed) => Err(failed),
            None => Ok(QueryResult { rows }),
        }
    }

    /// Run `sql` for its effect and commit it; the rows the server said it
    /// touched.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn execute(&mut self, sql: &str) -> Result<u64> {
        let immediate = Object::of(
            EXCSQLIMM,
            &[(PKGNAMCSN, &self.package), (RDBCMTOK, &[TRUE])],
        );
        let chain = Chain::new()
            .request(&immediate)
            .object(&statement(sql))
            .request(&Object::new(RDBCMM, Vec::new()));
        self.wire.send(&chain)?;
        let mut touched = 0;
        let answered = self.replies("the statement's answer")?;
        for dss in &answered {
            for object in dss.objects.iter().filter(|o| o.codepoint == SQLCARD) {
                if dss.correlation == 1
                    && let Some(area) = self.area(&object.data)?
                {
                    touched = area.rows();
                }
            }
        }
        let objects: Vec<Object> = answered.into_iter().flat_map(|dss| dss.objects).collect();
        failure(&objects, self.accessed.endian).map_or(Ok(touched), Err)
    }

    /// End the unit of work.
    ///
    /// # Errors
    /// Where the server went away or could not commit.
    pub fn commit(&mut self) -> Result<()> {
        self.wire
            .send(&Chain::new().request(&Object::new(RDBCMM, Vec::new())))?;
        let objects: Vec<Object> = self
            .replies("the commit's answer")?
            .into_iter()
            .flat_map(|dss| dss.objects)
            .collect();
        failure(&objects, self.accessed.endian).map_or(Ok(()), Err)
    }

    /// Hang up.
    ///
    /// # Errors
    /// Where the socket had already gone.
    pub fn close(self) -> Result<()> {
        self.wire
            .socket()
            .shutdown(std::net::Shutdown::Both)
            .map_err(|e| transport::error::classify("closing the connection", &e))
    }

    fn replies(&mut self, waiting_for: &str) -> Result<Vec<Dss>> {
        self.wire
            .receive()?
            .ok_or_else(|| protocol_error(format!("the server closed before {waiting_for}")))
    }

    fn area(&self, data: &[u8]) -> Result<Option<Sqlca>> {
        Sqlca::read(&mut codec::cursor::Cursor::new(data), self.accessed.endian)
    }
}

impl Pooled for Client {
    /// While the server has not closed the connection. Each exchange is
    /// read to the end of its chain, so nothing of one is left for the next.
    fn usable(&mut self) -> bool {
        alive(self.wire.socket())
    }
}

/// The first failure `objects` report: a communications area with a
/// negative `SQLCODE`, else a reply message of severity 8 or more, named.
#[must_use]
pub fn failure(objects: &[Object], endian: Endian) -> Option<TransportError> {
    let areas = objects
        .iter()
        .filter(|object| matches!(object.codepoint, SQLCARD | SQLDARD));
    for object in areas {
        let read = Sqlca::read(&mut codec::cursor::Cursor::new(&object.data), endian);
        if let Some(failed) = read.ok().flatten().and_then(|area| area.error()) {
            return Some(failed);
        }
    }
    let message = objects.iter().find(|object| object.severity() >= 8)?;
    let diagnosis = message
        .parameter(SRVDGN)
        .map(|text| format!(": {}", String::from_utf8_lossy(&text)))
        .unwrap_or_default();
    Some(TransportError::permanent(format!(
        "the server answered {} ({:#06x}) with severity {}{diagnosis}",
        named(message.codepoint),
        message.codepoint,
        message.severity()
    )))
}

/// What a reply message is called.
fn named(codepoint: u16) -> &'static str {
    use crate::codepoint::{
        CMDNSPRM, MGRLVLRM, OPNQFLRM, PRCCNVRM, RDBAFLRM, RDBNACRM, RDBNFNRM, SQLERRRM, SYNTAXRM,
    };
    match codepoint {
        RDBNFNRM => "database not found",
        RDBAFLRM => "database access failed",
        RDBNACRM => "database not accessed",
        OPNQFLRM => "open query failed",
        QRYNOPRM => "query not open",
        SQLERRRM => "SQL error",
        CMDNSPRM => "command not supported",
        PRCCNVRM => "conversational protocol error",
        SYNTAXRM => "data stream syntax error",
        MGRLVLRM => "manager level conflict",
        _ => "a reply message",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_is_the_area_first_then_the_message() {
        let endian = Endian::Little;
        let area = Object::new(SQLCARD, Sqlca::new(-204, "42704", "T").encode(endian));
        let message = Object::of(
            crate::codepoint::RDBNFNRM,
            &[(crate::codepoint::SVRCOD, &[0, 8])],
        );
        let both = failure(&[message.clone(), area], endian).expect("failed");
        assert!(both.message.contains("-204"));
        let alone = failure(&[message], endian).expect("failed");
        assert!(
            alone.message.contains("database not found"),
            "{}",
            alone.message
        );
        let fine = Object::new(SQLCARD, vec![0xFF]);
        assert!(failure(&[fine], endian).is_none());
    }
}
