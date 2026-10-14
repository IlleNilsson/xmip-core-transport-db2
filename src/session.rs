//! The server's side of one connection: what a test puts at the far end,
//! and what the playground drives.
//!
//! Not a database. One session does the login for one client — security
//! mechanism 3 checked against the one user and password it expects — and
//! answers each statement from a closure or from one fixed table: any
//! SELECT gets the table's rows, every column nullable text, two rows a
//! query block, so a client must continue the query to read them all; an
//! INSERT of one column is recorded as a Stream — a literal's text or bytes
//! in the column's declared form — anything else is completed. Planning,
//! storage and SQL are a database's.

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use sql::{DB2, Verb};
use transport::error::{Result, protocol_error};
use transport::sql::{Answering, Column, Inserted, Rows, next_insert, table};
use transport::{Login, Taken, socket};

pub use crate::admission::SERVER_VERSION;
use crate::admission::{admit, attributes};
use crate::codepoint::{
    CMDNSPRM, CNTQRY, CODPNT, ENDQRYRM, ENDUOWRM, EXCSAT, EXCSQLIMM, LMTBLKPRC, OPNQFLRM, OPNQRY,
    OPNQRYRM, PRPSQLSTT, QRYDSC, QRYDTA, QRYINSID, QRYNOPRM, QRYPRCTYP, RDBCMM, RDBRLLBCK, SQLCARD,
    SQLDARD, SQLSTT, SVRCOD, UOWDSP,
};
use crate::ddm::Object;
use crate::row::{Row, descriptor, encode};
use crate::sqlca::{Endian, NOT_FOUND, Sqlca};
use crate::statement;
use crate::wire::{Chain, OBJECT, REPLY, Wire};

/// How many rows one query block carries here.
const ROWS_A_BLOCK: usize = 2;
/// The order this far end writes numbers in.
const ENDIAN: Endian = Endian::Little;
/// The replies to one command, each with the kind of DSS it travels in.
type Replies = Vec<(u8, Object)>;

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client ran a SELECT; here it is.
    Selected(String),
    /// The client inserted one value; here is the Stream.
    Inserted(Taken),
    /// The client ran something else; here it is.
    Executed(String),
}

impl Inserted for Event {
    fn inserted(self) -> Option<Taken> {
        match self {
            Self::Inserted(arrived) => Some(arrived),
            Self::Selected(_) | Self::Executed(_) => None,
        }
    }
}

/// How a statement is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Rows {
        columns: Vec<String>,
        rows: Vec<Row>,
    },
    /// Done, with this many rows touched.
    Complete(u64),
    Error {
        code: i32,
        state: String,
        message: String,
    },
}

pub struct Session {
    wire: Wire,
    peer: SocketAddr,
    user: String,
    database: String,
    columns: Vec<String>,
    rows: Rows<String>,
    answering: Option<Answering<Answer>>,
    column: Column,
    /// The answer a prepared statement opens with.
    prepared: Option<Answer>,
    /// The rows of the open query not yet sent.
    open: Option<VecDeque<Row>>,
}

impl Session {
    /// Accept one client on `listener` and log it in, demanding `login`'s
    /// user and password.
    ///
    /// # Errors
    /// Where the connection could not be accepted, the client did not
    /// speak DRDA, or gave another user or password — which is told to the
    /// client before this returns.
    pub fn accept(
        listener: &TcpListener,
        login: &Login,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        Self::over(Wire::plain(stream)?, peer, login)
    }

    /// Log in the client on `wire`, from `peer`, demanding `login`.
    ///
    /// # Errors
    /// As [`Session::accept`].
    pub fn over(mut wire: Wire, peer: SocketAddr, login: &Login) -> Result<Self> {
        let admitted = admit(&mut wire, peer, login)?;
        Ok(Self {
            wire,
            peer,
            user: admitted.user,
            database: admitted.database,
            columns: Vec::new(),
            rows: Vec::new(),
            answering: None,
            column: Column::Binary,
            prepared: None,
            open: None,
        })
    }

    /// The user the client logged in as.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The database the client asked for.
    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    /// What the column an INSERT names holds: bytes unless declared
    /// otherwise.
    #[must_use]
    pub const fn holding(mut self, column: Column) -> Self {
        self.column = column;
        self
    }

    /// Answer any SELECT with these `columns` and `rows`.
    #[must_use]
    pub fn with_table(mut self, columns: &[&str], rows: &[&[Option<&str>]]) -> Self {
        (self.columns, self.rows) = table(columns, rows);
        self
    }

    /// Answer statements with `answering` first; what it declines falls to
    /// the table.
    #[must_use]
    pub fn answering(
        mut self,
        answering: impl FnMut(&str) -> Option<Answer> + Send + 'static,
    ) -> Self {
        self.answering = Some(Box::new(answering));
        self
    }

    /// The next value the client inserts, or `None` when it closed.
    /// Everything else is answered on the way.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_insert(&mut self) -> Result<Option<Taken>> {
        next_insert(|| self.next_event())
    }

    /// The next statement the client ran, answered, or `None` when it
    /// hung up. Continuing a query, committing and the code set are
    /// answered on the way.
    ///
    /// # Errors
    /// Where the connection broke or nothing arrived before the timeout.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            let Some(requests) = self.wire.receive()? else {
                return Ok(None);
            };
            let mut reply = Chain::new();
            let mut event = None;
            for (at, dss) in requests.iter().enumerate() {
                let Some(command) = dss.objects.first().filter(|_| dss.kind != OBJECT) else {
                    continue;
                };
                let carried = requests[at + 1..]
                    .iter()
                    .take_while(|next| next.kind == OBJECT && next.correlation == dss.correlation)
                    .flat_map(|next| &next.objects)
                    .find(|object| object.codepoint == SQLSTT)
                    .map(statement::text)
                    .transpose()?;
                let (answered, happened) = self.command(command, carried.as_deref())?;
                for (kind, object) in answered {
                    reply = reply.reply(kind, dss.correlation, &object);
                }
                event = event.or(happened);
            }
            self.wire.send(&reply)?;
            if event.is_some() {
                return Ok(event);
            }
        }
    }

    /// Serve the client until it hangs up; everything it did, in order.
    ///
    /// # Errors
    /// Where the connection broke or nothing arrived before the timeout.
    pub fn serve(mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        while let Some(event) = self.next_event()? {
            events.push(event);
        }
        Ok(events)
    }

    /// The replies to one command, and what the client did by it.
    fn command(&mut self, command: &Object, sql: Option<&str>) -> Result<(Replies, Option<Event>)> {
        let sql = || sql.ok_or_else(|| protocol_error("a statement command without its SQLSTT"));
        Ok(match command.codepoint {
            EXCSAT => (vec![(REPLY, attributes(command)?)], None),
            EXCSQLIMM => {
                let (answer, event) = self.answer(sql()?);
                let area = match answer {
                    Answer::Error {
                        code,
                        state,
                        message,
                    } => Sqlca::new(code, &state, &message),
                    Answer::Complete(touched) => touched_area(touched),
                    Answer::Rows { .. } => touched_area(0),
                };
                (vec![(OBJECT, card(&area))], Some(event))
            }
            PRPSQLSTT => {
                let (answer, event) = self.answer(sql()?);
                let described = match &answer {
                    Answer::Error {
                        code,
                        state,
                        message,
                    } => Sqlca::new(*code, state, message).encode(ENDIAN),
                    _ => vec![0xFF, 0xFF, 0, 0],
                };
                self.prepared = Some(answer);
                (vec![(OBJECT, Object::new(SQLDARD, described))], Some(event))
            }
            OPNQRY => (self.opened()?, None),
            CNTQRY => (self.continued()?, None),
            RDBCMM | RDBRLLBCK => (
                vec![
                    (
                        REPLY,
                        Object::of(ENDUOWRM, &[(SVRCOD, &[0, 4]), (UOWDSP, &[1])]),
                    ),
                    (OBJECT, Object::new(SQLCARD, vec![0xFF])),
                ],
                None,
            ),
            other => (
                vec![(
                    REPLY,
                    Object::of(
                        CMDNSPRM,
                        &[(SVRCOD, &[0, 8]), (CODPNT, &other.to_be_bytes())],
                    ),
                )],
                None,
            ),
        })
    }

    /// The replies to `OPNQRY`: the descriptor and the first block, or why
    /// the prepared statement opens no query.
    fn opened(&mut self) -> Result<Replies> {
        let (columns, rows) = match self.prepared.take() {
            Some(Answer::Rows { columns, rows }) => (columns, rows),
            Some(Answer::Error {
                code,
                state,
                message,
            }) => {
                return Ok(failed_open(&Sqlca::new(code, &state, &message)));
            }
            _ => return Ok(failed_open(&Sqlca::new(-517, "07005", "not a query"))),
        };
        let mut open: VecDeque<Row> = rows.into();
        let data = block(&mut open)?;
        self.open = Some(open);
        let instance = codec::random::array::<8>();
        let message = Object::of(
            OPNQRYRM,
            &[
                (SVRCOD, &[0, 0]),
                (QRYPRCTYP, &LMTBLKPRC.to_be_bytes()),
                (QRYINSID, &instance),
            ],
        );
        Ok(vec![
            (REPLY, message),
            (OBJECT, Object::new(QRYDSC, descriptor(columns.len())?)),
            (OBJECT, Object::new(QRYDTA, data)),
        ])
    }

    /// The replies to `CNTQRY`: the next block, or the end of the query.
    fn continued(&mut self) -> Result<Replies> {
        let Some(open) = self.open.as_mut() else {
            return Ok(vec![(REPLY, Object::of(QRYNOPRM, &[(SVRCOD, &[0, 8])]))]);
        };
        if !open.is_empty() {
            return Ok(vec![(OBJECT, Object::new(QRYDTA, block(open)?))]);
        }
        self.open = None;
        let end = Sqlca::new(NOT_FOUND, "02000", "");
        Ok(vec![
            (OBJECT, Object::new(QRYDTA, end.encode(ENDIAN))),
            (REPLY, Object::of(ENDQRYRM, &[(SVRCOD, &[0, 4])])),
            (OBJECT, card(&end)),
        ])
    }

    fn answer(&mut self, sql: &str) -> (Answer, Event) {
        if let Some(answer) = self.answering.as_mut().and_then(|f| f(sql)) {
            return (answer, Event::Executed(sql.to_string()));
        }
        match Verb::of_statement(sql) {
            Some(Verb::Select) => (
                Answer::Rows {
                    columns: self.columns.clone(),
                    rows: self.rows.clone(),
                },
                Event::Selected(sql.to_string()),
            ),
            Some(Verb::Insert) => match DB2.parse_insert_literal(sql) {
                Some((table, column, value)) => {
                    let origin = format!("db2://{}/{}/{table}/{column}", self.peer, self.database);
                    (
                        Answer::Complete(1),
                        Event::Inserted(Taken::new(origin, self.column.stored(value))),
                    )
                }
                None => (
                    Answer::Error {
                        code: -104,
                        state: "42601".to_string(),
                        message: "only INSERT INTO t (c) VALUES (...) is served here".to_string(),
                    },
                    Event::Executed(sql.to_string()),
                ),
            },
            _ => (Answer::Complete(0), Event::Executed(sql.to_string())),
        }
    }
}

/// The replies when a query does not open: the failure and its area.
fn failed_open(area: &Sqlca) -> Replies {
    vec![
        (REPLY, Object::of(OPNQFLRM, &[(SVRCOD, &[0, 8])])),
        (OBJECT, card(area)),
    ]
}

/// `area` as an `SQLCARD`.
fn card(area: &Sqlca) -> Object {
    Object::new(SQLCARD, area.encode(ENDIAN))
}

/// Success, with `touched` rows.
fn touched_area(touched: u64) -> Sqlca {
    let mut area = Sqlca::new(0, "00000", "");
    area.errd[2] = i32::try_from(touched).unwrap_or(i32::MAX);
    area
}

/// The next block of an open query's rows.
fn block(open: &mut VecDeque<Row>) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    for row in open.drain(..ROWS_A_BLOCK.min(open.len())) {
        data.extend(encode(&row)?);
    }
    Ok(data)
}
