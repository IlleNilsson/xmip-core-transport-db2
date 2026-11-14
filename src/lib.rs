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
//!
//! **The transport is every SQL technology's**, `transport::sql`'s
//! `SqlTransport` over this crate's [`Db2`] wire (2026-11-13): the query
//! and its rows, the `accept` statement after a row's cycle, the INSERT a
//! send writes, the connections kept per server and database, the
//! settings. What is DB2's own is this crate's: its dialect, the port
//! 50000, the TLS a connection is guarded by, and DRDA, both halves.

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
use std::time::Duration;

pub use client::{Client, QueryResult};
pub use session::{Answer, Event, Session};
use sql::{DB2, Dialect};
use transport::error::{Result, protocol_error};
use transport::sql::{Probe, Rows, SqlTransport};
use transport::{Login, Pooled, Taken};
use xcore::settings::{Read, Settings};

/// The port a DB2 server listens on unless told otherwise.
pub const PORT: u16 = 50_000;

/// A Location over an IBM DB2 server.
pub type Db2Transport = SqlTransport<Db2>;

/// DB2's wire: this crate's DRDA client, guarded by TLS where asked for.
#[derive(Clone, Default)]
pub struct Db2 {
    /// How a connection is guarded; in the clear where `None`.
    #[cfg(feature = "tls")]
    secured: Option<tls::ClientSettings>,
}

impl Db2 {
    /// Every connection guarded by TLS, the server's certificate checked as
    /// `secured` says.
    #[cfg(feature = "tls")]
    #[must_use]
    pub const fn secured(secured: tls::ClientSettings) -> Self {
        Self {
            secured: Some(secured),
        }
    }
}

impl transport::sql::Wire for Db2 {
    type Client = Client;

    const NAME: &'static str = "db2";
    const SCHEMES: &'static [&'static str] = &["db2"];
    const SETTINGS: &'static Settings = configured::SETTINGS;
    /// One database, one user with no password.
    const PROBE: Probe = Probe {
        database: "PROBE",
        user: "xmip",
        password: "",
        target: "PROBE/PAYLOAD",
    };

    fn dialect() -> &'static Dialect {
        &DB2
    }

    fn configured(self, settings: &Read) -> Result<Self> {
        configured::wire(settings)
    }

    /// `server`, port 50000 where it names none, guarded where asked for.
    fn connect(
        &self,
        server: &str,
        database: &str,
        login: &Login,
        timeout: Option<Duration>,
    ) -> Result<Client> {
        let server = net::authority::with_default_port(server, PORT);
        #[cfg(feature = "tls")]
        if let Some(settings) = &self.secured {
            return Client::over(secured::wire(settings, &server, timeout)?, database, login);
        }
        Client::connect(&server, database, login, timeout)
    }

    fn usable(client: &mut Client) -> bool {
        client.usable()
    }

    /// Each row's columns as text, the last the Stream.
    fn query(client: &mut Client, sql: &str) -> Result<Rows<String>> {
        Ok(client.query(sql)?.rows)
    }

    fn execute(client: &mut Client, sql: &str) -> Result<()> {
        client.execute(sql).map(|_| ())
    }

    /// The client keeps its connection for the next insert.
    fn take_one(transport: &Db2Transport, listener: &TcpListener) -> Result<Taken> {
        accept_one(transport, listener)?
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))
    }
}

/// Accept one client on a listener `transport` bound, demanding its user
/// and password.
///
/// # Errors
/// Where the connection could not be accepted or the login failed.
pub fn accept_one(transport: &Db2Transport, listener: &TcpListener) -> Result<Session> {
    Session::accept(listener, transport.login(), transport.timeout())
        .map(|session| session.holding(transport.column()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codepoint::{ACCSECRD, EXCSATRD, SECMEC};
    use crate::ddm::Object;
    use crate::wire::{Chain, REPLY};
    use codec::unicode::Form;
    use std::assert_matches;
    #[cfg(feature = "tls")]
    use std::sync::Arc;
    use transport::Configured;
    use transport::error::TransportError;
    use transport::payload::{edge_payloads, sized_payloads};
    use transport::sql::{Column, DEFAULT_QUERY};
    use transport::{Arrived, Directions, Loopback, Transport};
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
        assert_eq!(built.server(), "db:50000");
        assert_eq!(built.database(), "ORDERS");
        assert_eq!(built.query(), DEFAULT_QUERY);
        assert_eq!(built.timeout(), Some(secs(2)));
        assert_eq!(built.column(), Column::Binary, "bytes unless declared");
        let texts = [
            text("database", "ORDERS"),
            text("user", "xmip"),
            text("column", "text"),
        ];
        let built = Db2Transport::open("db:50000", Applies::Send, &texts).expect("text");
        assert_eq!(
            built.column(),
            Column::Text(Form::Utf8),
            "utf-8 unless named"
        );
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
        let mut session = accept_one(&far_end, &listener)
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
        let mut session = accept_one(&far_end, &listener)
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
        let mut session = accept_one(&far_end, &listener)
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
        let mut session = accept_one(&far_end, &listener).expect("accepting");
        let first = session.next_insert().expect("first").expect("one");
        assert_eq!(first.bytes, b"it's \\here");
        assert!(first.origin_uri.ends_with("/ORDERS/INBOX/PAYLOAD"));
        let second = session.next_insert().expect("second").expect("one");
        assert_eq!(second.bytes, [] as [u8; 0]);
        assert!(second.origin_uri.ends_with("/ORDERS/OUTBOX/BODY"));
        let binary = session.next_insert().expect("third").expect("one");
        assert_eq!(binary.bytes, [0xff, 0xfe], "a binary column, so BX'…'");
        let error = accept_one(&far_end, &listener)
            .err()
            .expect("wrong password");
        assert!(error.message.contains("0x0f"), "{}", error.message);
        let error = accept_one(&far_end, &listener).err().expect("wrong user");
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
            for n in 0..SENDS {
                sending.send("INBOX/PAYLOAD", n.to_string().as_bytes())?;
            }
            sending.send("INBOX/PAYLOAD", b"after the close")
        });
        let mut session = accept_one(&far_end, &listener).expect("accepting");
        for n in 0..SENDS {
            let inserted = session.next_insert().expect("insert").expect("one");
            assert_eq!(inserted.bytes, n.to_string().as_bytes());
        }
        drop(session);
        let mut again = accept_one(&far_end, &listener).expect("a new login");
        let last = again.next_insert().expect("insert").expect("one");
        assert_eq!(last.bytes, b"after the close");
        sender.join().expect("thread").expect("sending");
        assert_eq!(near.opened(), 2);
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
            for _ in 0..RECEIVES {
                assert_eq!(receiving.receive()?.len(), 1);
            }
            receiving.receive()
        });
        let accept = || {
            accept_one(&far_end, &listener)
                .expect("a login")
                .with_table(&["ID", "PAYLOAD"], &[&[Some("1"), None]])
        };
        let mut session = accept();
        for _ in 0..RECEIVES {
            let event = session.next_event().expect("query");
            assert_matches!(event, Some(Event::Selected(_)), "{event:?}");
        }
        drop(session);
        // A query is continued and committed after its event: the new
        // session is served until the near end lets its connection go.
        let again = std::thread::spawn({
            let again = accept();
            move || again.serve()
        });
        assert_eq!(receiver.join().expect("thread").expect("after").len(), 1);
        assert_eq!(near.opened(), 2);
        drop(near);
        let served = again.join().expect("thread").expect("served");
        // The first session was dropped before the last of its thousand
        // queries was continued, so that query went again on the new one.
        assert_matches!(
            served.as_slice(),
            [Event::Selected(_), Event::Selected(_)],
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
        let session = accept_one(&far_end, &listener)
            .expect("accepting")
            .answering(|sql| {
                sql.starts_with("SELECT").then(|| Answer::Error {
                    code: -204,
                    state: "42704".into(),
                    message: "DB2INST1.INBOX".into(),
                })
            });
        assert_eq!(session.serve().expect("served").len(), 1);
        let session = accept_one(&far_end, &listener)
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
            .with_wire(Db2::secured(
                tls::ClientSettings::trusting(Arc::new(client)).named("localhost"),
            ));
        let sender = std::thread::spawn(move || near.send("INBOX/PAYLOAD", b"UNB+UNOC"));
        let login = Login::new("xmip", "secret");
        let mut session = secured::accept(&listener, &login, Some(secs(5)), &Arc::new(server))
            .expect("a guarded login");
        let taken = session.next_insert().expect("insert").expect("one");
        assert_eq!(taken.bytes, b"UNB+UNOC");
        sender.join().expect("thread").expect("sent");
    }
}
