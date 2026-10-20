#![forbid(unsafe_code)]

//! Streams that arrive as rows of an IBM DB2 database. One row is one
//! Stream: the last column of a configured query is what Xmip carries, the
//! first column is where it came from.
//!
//! DB2 is a database the estate's Parties already have — on Linux, UNIX
//! and Windows, on IBM i, on z/OS — and a table in one is the oldest
//! integration surface there is: a producer inserts, an integrator polls.
//! A Receive Location runs its query — `SELECT id, payload FROM inbox ORDER
//! BY id` unless told otherwise — and hands each row up; a Send Location
//! inserts the Stream as one column of one row. What the column holds is
//! the Location's to declare, never the bytes' (ADR-0038): `column =
//! "binary"`, the default, inserts every Stream as a binary string
//! constant `BX'…'` and reads a value back as hex digits, the form a
//! VARBINARY column comes back in here and `HEX(…)` answers; `column =
//! "text"` decodes the Stream strictly in its `encoding` and inserts it as
//! a string literal. The SQL is DB2's as `xmip-core-library-sql` writes it
//! (`sql::DB2`).
//!
//! What is spoken is DRDA, The Open Group's Distributed Relational
//! Database Architecture, on port 50000 unless the address names another:
//! DSS framing (`wire.rs`), DDM objects (`ddm.rs`), the login with security
//! mechanism 3, a user ID and a password (`login.rs`), dynamic SQL in the
//! package every DB2 database binds, rows described and carried in FD:OCA
//! (`row.rs`, `sqlca.rs`). No IBM client library and no ODBC. Mechanism 3
//! sends the password as it is, so a Location that crosses a network says
//! `tls = true`: TLS from the first byte, through `xmip-core-library-tls`
//! (ADR-0033), behind the `tls` feature (`secured.rs`).
//!
//! Rows are artifacts and this transport claims none of them, per
//! ADR-0024: the claim a database has, `SELECT … FOR UPDATE SKIP LOCKED`,
//! holds only inside a unit of work, and one receive commits its own.
//!
//! **A row is consumed by the `accept` statement, after its cycle.** The
//! query only reads. Where the Location declares `accept` — `DELETE FROM
//! inbox WHERE id = ?` — it runs once a row's cycle accepted it, the row's
//! name bound in place of `?` (`transport::sql::accept`) as DB2's string
//! literal, and is committed. A refused row is left where it lies, and not
//! received again while its body is unchanged. A row whose cycle failed is
//! left, and the next receive reads it again; so is a row whose name is
//! NULL. Where `accept` is left out a row's verdict tells the database
//! nothing.
//!
//! The origin URI carries what the row knew: `db2://server/orders?row=41`.
//! A send target is `db2://host:50000/<database>/<table>/<column>`,
//! `host:50000/<database>/<table>/<column>`, or `<table>/<column>` on the
//! configured server and database. The table and column are always quoted,
//! so they name what the catalog holds: `INBOX/PAYLOAD` for a table
//! created as `inbox`.

mod admission;
pub mod client;
pub mod codepoint;
mod configured;
pub mod ddm;
pub mod ebcdic;
pub mod login;
pub mod row;
#[cfg(feature = "tls")]
pub mod secured;
pub mod session;
pub mod sqlca;
pub mod statement;
pub mod wire;

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

pub use client::{Client, QueryResult};
#[cfg(feature = "tls")]
pub use secured::Secured;
pub use session::{Answer, Event, Session};
use sql::DB2;
use transport::ArrivalIdentity;
use transport::claim::{NoNativeClaim, ResourceClaim};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::sql::{Column, accept, destination};
use transport::{Arrived, Directions, Login, Pool, Taken, Transport};

/// The schemes a send target may open with.
const SCHEMES: &[&str] = &["db2"];

/// The port a DB2 server listens on unless told otherwise.
pub const PORT: u16 = 50_000;

/// What a Receive Location runs unless told otherwise.
pub const DEFAULT_QUERY: &str = "SELECT id, payload FROM inbox ORDER BY id";

/// What the loopback pair agrees on: one database, one user with no
/// password, one table and column the payload is inserted into.
const LOOPBACK_DATABASE: &str = "PROBE";
const LOOPBACK_USER: &str = "xmip";
const LOOPBACK_TARGET: &str = "PROBE/PAYLOAD";

#[derive(Clone)]
pub struct Db2Transport {
    server: String,
    database: String,
    login: Login,
    query: String,
    /// The statement run on a row's verdict, its name bound in.
    accept: Option<String>,
    /// The rows refused and left, not received again while unchanged.
    refused: accept::RefusedRows,
    column: Column,
    timeout: Option<Duration>,
    /// How a connection is guarded; in the clear where `None`.
    #[cfg(feature = "tls")]
    secured: Option<Secured>,
    /// The connections a send inserts on and a receive queries on, logged
    /// in once per server and database and kept.
    connections: Pool<Client>,
}

impl Db2Transport {
    /// Speak to the server at `server`, on `database`, as `user` with no
    /// password until one is given.
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        database: impl Into<String>,
        user: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            database: database.into(),
            login: Login::new(user, ""),
            query: DEFAULT_QUERY.to_string(),
            accept: None,
            refused: accept::RefusedRows::default(),
            column: Column::Binary,
            timeout: None,
            #[cfg(feature = "tls")]
            secured: None,
            connections: Pool::new(),
        }
    }

    /// The password the login sends.
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.login.password = password.into();
        self
    }

    /// The query a receive runs: the first column is the row's name, the
    /// last is the Stream.
    #[must_use]
    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self
    }

    /// The statement run once a row's cycle accepted it, the row's name in
    /// place of `?` (`transport::sql::accept`).
    #[must_use]
    pub fn with_accept(mut self, statement: impl Into<String>) -> Self {
        self.accept = Some(statement.into());
        self
    }

    /// What the payload column holds: bytes unless declared otherwise.
    #[must_use]
    pub const fn holding(mut self, column: Column) -> Self {
        self.column = column;
        self
    }

    /// Give up on a server that stops mid-answer.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Every connection guarded by TLS, the server's certificate checked as
    /// `secured` says.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn secured(mut self, secured: Secured) -> Self {
        self.secured = Some(secured);
        self
    }

    /// Log in to the server.
    ///
    /// # Errors
    /// Where the server could not be reached or refused the login.
    pub fn connect(&self) -> Result<Client> {
        self.connect_to(&self.server, &self.database)
    }

    fn connect_to(&self, server: &str, database: &str) -> Result<Client> {
        let server = net::authority::with_default_port(server, PORT);
        #[cfg(feature = "tls")]
        if let Some(secured) = &self.secured {
            return Client::over(secured.wire(&server, self.timeout)?, database, &self.login);
        }
        Client::connect(&server, database, &self.login, self.timeout)
    }

    /// Bind as the far end clients connect to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one client on an already-bound listener, demanding this
    /// transport's user and password.
    ///
    /// # Errors
    /// Where the connection could not be accepted or the login failed.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        Session::accept(listener, &self.login, self.timeout)
            .map(|session| session.holding(self.column))
    }

    fn key(server: &str, database: &str) -> String {
        format!("{server}/{database}")
    }
}

impl Transport for Db2Transport {
    fn name(&self) -> &'static str {
        "db2"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a poll reads again what is not yet told")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Polled("a receive runs the query and returns")
    }

    /// Run the query on the connection kept for the server and database,
    /// logged in on the first receive; each row is a Stream, whole. Its
    /// verdict runs the `accept` statement where one is declared — on
    /// `Accepted`, never on `Refused` or `Failed`.
    fn receive_up_to(&self, most: usize) -> Result<Vec<Arrived>> {
        let result = self.connections.exchange(
            &Self::key(&self.server, &self.database),
            || self.connect(),
            |client| client.query(&self.query),
        )?;
        let shared = Arc::new(self.clone());
        accept::arrivals(
            result.rows,
            most,
            &self.refused,
            |name| format!("db2://{}/{}?row={name}", self.server, self.database),
            Clone::clone,
            |value| self.column.bytes(&value, &DB2),
            |name| {
                let transport = Arc::clone(&shared);
                accept::accepting(&DB2, self.accept.as_deref(), name, move |sql| {
                    transport.connections.exchange(
                        &Self::key(&transport.server, &transport.database),
                        || transport.connect(),
                        |client| client.execute(sql).map(|_| ()),
                    )
                })
            },
        )
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Gathered("an INSERT carries the body as one literal in its statement")
    }

    /// Insert the bytes as one column of one row — a binary string
    /// constant, or a string literal where the column is declared to hold
    /// text — committed, on the connection kept for the server and
    /// database.
    fn send_from(&self, target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        let bytes: &[u8] = &outgoing.gather()?;
        let to = destination(SCHEMES, target, &self.server, &self.database)?;
        let literal = self.column.literal(bytes, &DB2)?;
        let insert = DB2.insert(to.table, to.column, &literal);
        self.connections.exchange(
            &Self::key(to.server, to.database),
            || self.connect_to(to.server, to.database),
            |client| client.execute(&insert).map(|_| ()),
        )
    }

    /// Rows are artifacts, and one receive holds no unit of work to claim
    /// one in.
    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl Db2Transport {
    /// Both ends on this machine: an ephemeral local port, a login with no
    /// password, the loopback timeout.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", LOOPBACK_DATABASE, LOOPBACK_USER)
            .timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for Db2Transport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        // The client keeps its connection for the next insert.
        self.accept_one(listener)?
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))
    }
}

impl Loopback for Db2Transport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::Unnamed(
            "a row names no sender: the database it was read from is in its origin",
        )
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    /// INSERT the payload as one column of one row, as the column is
    /// declared to hold it, from a fresh near end logging in to `address`
    /// as this transport does.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near = Self {
            server: address.to_string(),
            connections: Pool::new(),
            ..self.clone()
        };
        near.send(LOOPBACK_TARGET, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codepoint::{ACCSECRD, EXCSATRD, SECMEC};
    use crate::ddm::Object;
    use crate::wire::{Chain, REPLY};
    use codec::unicode::Form;
    use transport::Configured;
    use transport::error::TransportError;
    use transport::payload::{edge_payloads, sized_payloads};
    use xcore::settings::Applies;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn db2_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(Db2Transport::SETTINGS.problems(), Vec::<String>::new());
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [
            text("database", "ORDERS"),
            text("user", "xmip"),
            text("timeout", "2s"),
        ];
        let built = Db2Transport::open("db:50000", Applies::Receive, &given).expect("built");
        assert_eq!(built.server, "db:50000");
        assert_eq!(built.database, "ORDERS");
        assert_eq!(built.query, DEFAULT_QUERY);
        assert_eq!(built.timeout, Some(secs(2)));
        assert_eq!(built.column, Column::Binary, "bytes unless declared");
        let texts = [
            text("database", "ORDERS"),
            text("user", "xmip"),
            text("column", "text"),
        ];
        let built = Db2Transport::open("db:50000", Applies::Send, &texts).expect("text");
        assert_eq!(built.column, Column::Text(Form::Utf8), "utf-8 unless named");
        let Err(refused) = Db2Transport::open("db:50000", Applies::Send, &given[1..]) else {
            panic!("database is required");
        };
        assert!(
            refused.message.contains("\"database\""),
            "{}",
            refused.message
        );
    }

    #[test]
    fn accept_consumes_an_accepted_row_and_a_refused_one_is_left_unreceived() {
        let far_end = Db2Transport::new("127.0.0.1:0", "ORDERS", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = Db2Transport::new(address, "ORDERS", "xmip")
                .with_accept("DELETE FROM inbox WHERE id = ?")
                .timing_out_after(secs(2));
            let mut arrived = near.receive()?;
            assert_eq!(arrived.len(), 4);
            arrived.remove(0).taken()?;
            arrived
                .remove(0)
                .refused(transport::Refusal::Unacceptable)?;
            arrived.remove(0).failed()?;
            arrived.remove(0).taken()?;
            let again: Vec<_> = near.receive()?.into_iter().map(|a| a.origin_uri).collect();
            assert_eq!(
                again.len(),
                3,
                "the refused row is not received again: {again:?}"
            );
            assert!(
                again.iter().all(|row| !row.ends_with("?row=it's")),
                "{again:?}"
            );
            Ok::<_, TransportError>(())
        });
        let rows: [&[Option<&str>]; 4] = [
            &[Some("41"), Some("61")],
            &[Some("it's"), Some("62")],
            &[Some("43"), Some("63")],
            &[None, Some("64")],
        ];
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(&["ID", "PAYLOAD"], &rows);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("serving") {
            events.push(event);
        }
        receiver.join().expect("thread").expect("receiving");
        assert_eq!(
            events,
            [
                Event::Selected(DEFAULT_QUERY.into()),
                Event::Executed("DELETE FROM inbox WHERE id = '41'".into()),
                Event::Selected(DEFAULT_QUERY.into()),
            ],
            "the refused, the failed and the unnamed row are left"
        );
    }

    #[test]
    fn a_receive_continues_the_query_and_each_row_is_a_stream() {
        let far_end = Db2Transport::new("127.0.0.1:0", "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = || {
                Db2Transport::new(address.clone(), "ORDERS", "xmip")
                    .with_password("secret")
                    .with_query("SELECT id, kind, payload FROM inbox ORDER BY id")
                    .timing_out_after(secs(2))
            };
            let bytes = near()
                .receive()
                .map(|all| all.into_iter().map(Arrived::taken));
            let bytes = bytes.and_then(Iterator::collect::<Result<Vec<_>>>);
            let text = near().holding(Column::Text(Form::Utf8)).receive();
            let text = text.and_then(|all| all.into_iter().map(Arrived::taken).collect());
            (bytes, text)
        });
        let rows: [&[Option<&str>]; 3] = [
            &[Some("41"), Some("order"), Some("4953412a30302a")],
            &[Some("42"), None, Some("FFFE")],
            &[None, Some(""), None],
        ];
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(&["ID", "KIND", "PAYLOAD"], &rows);
        assert_eq!(session.user(), "xmip");
        assert_eq!(session.database(), "ORDERS");
        let event = session.next_event().expect("query").expect("one");
        assert_eq!(
            event,
            Event::Selected("SELECT id, kind, payload FROM inbox ORDER BY id".into())
        );
        assert!(session.next_event().expect("ended").is_none());
        let mut session = far_end
            .accept_one(&listener)
            .expect("the text column")
            .with_table(&["ID", "PAYLOAD"], &[&[Some("43"), Some("fffe")]]);
        while session.next_event().expect("event").is_some() {}
        let (arrived, text): (Result<Vec<Taken>>, Result<Vec<Taken>>) =
            receiver.join().expect("thread");
        assert_eq!(
            text.expect("a text column")[0].bytes,
            b"fffe",
            "text, never hex"
        );
        let arrived = arrived.expect("receiving");
        assert_eq!(arrived.len(), 3, "three rows over two query blocks");
        assert_eq!(arrived[0].bytes, b"ISA*00*");
        assert!(arrived[0].origin_uri.ends_with("/ORDERS?row=41"));
        assert_eq!(arrived[1].bytes, [0xff, 0xfe], "hex digits are the bytes");
        assert!(arrived[2].bytes.is_empty(), "NULL is an empty Stream");
        assert!(arrived[2].origin_uri.ends_with("?row=2"));
    }

    #[test]
    fn a_send_inserts_the_stream_as_one_column_and_the_login_is_checked() {
        let far_end = Db2Transport::new("127.0.0.1:0", "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let near = Db2Transport::new(address.clone(), "ORDERS", "xmip")
                .with_password("secret")
                .timing_out_after(secs(2));
            near.send(
                &format!("db2://{address}/ORDERS/INBOX/PAYLOAD"),
                b"it's \\here",
            )?;
            near.send("OUTBOX/BODY", b"")?;
            near.send(&format!("{address}/ORDERS/INBOX/PAYLOAD"), &[0xff, 0xfe])?;
            let bad_target = near.send("db2://host/only-one", b"x");
            let refused = Db2Transport::new(address.clone(), "ORDERS", "xmip")
                .with_password("wrong")
                .timing_out_after(secs(2))
                .send("INBOX/PAYLOAD", b"x");
            let nobody = Db2Transport::new(address, "ORDERS", "nobody")
                .timing_out_after(secs(2))
                .send("INBOX/PAYLOAD", b"x");
            Ok::<_, TransportError>((bad_target, refused, nobody))
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let first = session.next_insert().expect("first").expect("one");
        assert_eq!(first.bytes, b"it's \\here");
        assert!(first.origin_uri.ends_with("/ORDERS/INBOX/PAYLOAD"));
        let second = session.next_insert().expect("second").expect("one");
        assert_eq!(second.bytes, [] as [u8; 0]);
        assert!(second.origin_uri.ends_with("/ORDERS/OUTBOX/BODY"));
        let binary = session.next_insert().expect("third").expect("one");
        assert_eq!(binary.bytes, [0xff, 0xfe], "a binary column, so BX'…'");
        let error = far_end.accept_one(&listener).err().expect("wrong password");
        assert!(error.message.contains("0x0f"), "{}", error.message);
        let error = far_end.accept_one(&listener).err().expect("wrong user");
        assert!(error.message.contains("\"nobody\""), "{}", error.message);
        let (bad_target, refused, nobody) = sender.join().expect("thread").expect("sending");
        assert!(!bad_target.expect_err("not a column").retryable);
        let refused = refused.expect_err("wrong password");
        assert!(!refused.retryable);
        assert!(
            refused.message.contains("password is invalid"),
            "{}",
            refused.message
        );
        let nobody = nobody.expect_err("wrong user");
        assert!(
            nobody.message.contains("user ID is invalid"),
            "{}",
            nobody.message
        );
        assert!(far_end.claims().is_some(), "rows are artifacts");
        assert_eq!(far_end.name(), "db2");
        assert_eq!(far_end.directions(), Directions::BOTH);
    }

    #[test]
    fn a_thousand_inserts_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const SENDS: usize = 1000;
        let far_end = Db2Transport::new("127.0.0.1:0", "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = Db2Transport::new(address, "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for n in 0..SENDS {
                sending.send("INBOX/PAYLOAD", n.to_string().as_bytes())?;
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond an insert.
            assert!(took < Duration::from_millis(SENDS as u64), "{took:?}");
            sending.send("INBOX/PAYLOAD", b"after the close")
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        for n in 0..SENDS {
            let inserted = session.next_insert().expect("insert").expect("one");
            assert_eq!(inserted.bytes, n.to_string().as_bytes());
        }
        drop(session);
        let mut again = far_end.accept_one(&listener).expect("a new login");
        let last = again.next_insert().expect("insert").expect("one");
        assert_eq!(last.bytes, b"after the close");
        sender.join().expect("thread").expect("sending");
        assert_eq!(near.connections.opened(), 2);
    }

    #[test]
    fn a_thousand_receives_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const RECEIVES: usize = 1000;
        let far_end = Db2Transport::new("127.0.0.1:0", "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = Db2Transport::new(address, "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let receiving = near.clone();
        let receiver = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for _ in 0..RECEIVES {
                assert_eq!(receiving.receive()?.len(), 1);
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond a query,
            // its continuation and its commit.
            assert!(took < Duration::from_millis(RECEIVES as u64), "{took:?}");
            receiving.receive()
        });
        let accept = || {
            far_end
                .accept_one(&listener)
                .expect("a login")
                .with_table(&["ID", "PAYLOAD"], &[&[Some("1"), None]])
        };
        let mut session = accept();
        for _ in 0..RECEIVES {
            let event = session.next_event().expect("query");
            assert!(matches!(event, Some(Event::Selected(_))), "{event:?}");
        }
        drop(session);
        // A query is continued and committed after its event: the new
        // session is served until the near end lets its connection go.
        let again = std::thread::spawn({
            let again = accept();
            move || again.serve()
        });
        assert_eq!(receiver.join().expect("thread").expect("after").len(), 1);
        assert_eq!(near.connections.opened(), 2);
        drop(near);
        let served = again.join().expect("thread").expect("served");
        // The first session was dropped before the last of its thousand
        // queries was continued, so that query went again on the new one.
        assert!(
            matches!(served.as_slice(), [Event::Selected(_), Event::Selected(_)]),
            "{served:?}"
        );
    }

    #[test]
    fn a_text_column_refuses_a_stream_that_is_not_its_encoding() {
        let near =
            Db2Transport::new("127.0.0.1:1", "ORDERS", "xmip").holding(Column::Text(Form::Utf8));
        let refused = near
            .send("INBOX/PAYLOAD", &[0xff, 0xfe])
            .expect_err("not UTF-8");
        assert!(!refused.retryable);
        assert!(
            refused.message.contains("utf-8 text"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_query_the_far_end_errors_is_the_error_and_a_statement_is_its_count() {
        let far_end = Db2Transport::new("127.0.0.1:0", "ORDERS", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let near = std::thread::spawn(move || {
            let near = Db2Transport::new(address, "ORDERS", "xmip").timing_out_after(secs(2));
            let failed = near.receive();
            let mut client = near.connect()?;
            let deleted = client.execute("DELETE FROM inbox WHERE id = 41")?;
            let version = client.server_version().to_string();
            client.close()?;
            Ok::<_, TransportError>((failed, deleted, version))
        });
        let session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .answering(|sql| {
                sql.starts_with("SELECT").then(|| Answer::Error {
                    code: -204,
                    state: "42704".into(),
                    message: "DB2INST1.INBOX".into(),
                })
            });
        assert_eq!(session.serve().expect("served").len(), 1);
        let session = far_end
            .accept_one(&listener)
            .expect("again")
            .answering(|sql| sql.starts_with("DELETE").then_some(Answer::Complete(3)));
        assert_eq!(
            session.serve().expect("served"),
            [Event::Executed("DELETE FROM inbox WHERE id = 41".into())]
        );
        let (failed, deleted, version) = near.join().expect("thread").expect("near");
        let error = failed.expect_err("the table is missing");
        assert!(!error.retryable);
        assert!(
            error
                .message
                .contains("-204 (SQLSTATE 42704): DB2INST1.INBOX")
        );
        assert_eq!(deleted, 3);
        assert_eq!(version, session::SERVER_VERSION);
    }

    #[test]
    fn a_server_offering_another_mechanism_or_speaking_nonsense_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let offer = Chain::new()
            .reply(REPLY, 1, &Object::new(EXCSATRD, Vec::new()))
            .reply(REPLY, 2, &Object::of(ACCSECRD, &[(SECMEC, &[0, 9])]))
            .encode();
        std::thread::spawn(move || {
            for answer in [offer, b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec()] {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut sink = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut sink);
                std::io::Write::write_all(&mut stream, &answer).expect("write");
                let _ = std::io::Read::read(&mut stream, &mut sink);
            }
        });
        let near = Db2Transport::new(address, "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let error = near.connect().err().expect("mechanism 9 only");
        assert!(!error.retryable);
        assert!(error.message.contains("USRIDPWD"), "{}", error.message);
        assert!(near.connect().is_err(), "not the protocol");
    }

    #[test]
    fn the_loopback_inserts_text_and_bytes_through_its_own_session() {
        let pair = Db2Transport::loopback();
        let arrived = pair.round(b"it's \\here").expect("round");
        assert_eq!(arrived.bytes, b"it's \\here");
        assert!(arrived.origin_uri.starts_with("db2://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/PROBE/PROBE/PAYLOAD"));
        let binary = pair.round(&[0xff, 0xfe]).expect("the binary constant");
        assert_eq!(binary.bytes, [0xff, 0xfe]);
        assert_eq!(pair.name(), "db2");
        assert_eq!(pair.ceiling(), None);
    }

    #[test]
    fn the_loopback_returns_the_edge_and_sized_payloads_whole() {
        let pair = Db2Transport::loopback();
        for (name, payload) in edge_payloads().into_iter().chain(sized_payloads()) {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_send_crosses_tls_whole() {
        use provision::{Order, Purpose, Source};
        use provision_self_signed::{SETTINGS, SelfSigned, TECHNOLOGY};
        use xcore::settings::Given;

        let given = [
            ("source".to_string(), Given::Text(TECHNOLOGY.to_string())),
            ("names".to_string(), Given::Text("localhost".to_string())),
            ("lifetime".to_string(), Given::Text("1h".to_string())),
        ];
        let read = provision::read("node", &given, &[SETTINGS]).expect("read");
        let names = vec!["localhost".to_string()];
        let order = Order {
            purpose: Purpose::Node,
            names: &names,
            keep: std::path::Path::new("."),
        };
        let held = SelfSigned::configured(&read.settings)
            .obtain(&order)
            .expect("signed");
        let server =
            tls::server_config(held.chain.as_bytes(), held.key.as_bytes()).expect("server");
        let anchors = held.anchors.as_deref().unwrap_or_default();
        let client = tls::trusting(anchors.as_bytes()).expect("client");
        let far_end = Db2Transport::new("127.0.0.1:0", "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = Db2Transport::new(address, "ORDERS", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5))
            .secured(Secured::trusting(Arc::new(client)).named("localhost"));
        let sender = std::thread::spawn(move || near.send("INBOX/PAYLOAD", b"UNB+UNOC"));
        let login = Login::new("xmip", "secret");
        let mut session = secured::accept(&listener, &login, Some(secs(5)), &Arc::new(server))
            .expect("a guarded login");
        let taken = session.next_insert().expect("insert").expect("one");
        assert_eq!(taken.bytes, b"UNB+UNOC");
        sender.join().expect("thread").expect("sent");
    }
}
