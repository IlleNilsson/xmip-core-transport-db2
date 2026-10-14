//! The settings a DB2 Location declares and how the transport is built
//! from them (`xcore::settings`, read through `transport::Configured`,
//! ADR-0064), and whether its connections are guarded by TLS.

use transport::Configured;
use transport::error::Result;
use transport::sql::{COLUMN, Column, ENCODING, accept};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

#[cfg(feature = "tls")]
use crate::Secured;
use crate::{DEFAULT_QUERY, Db2Transport};

impl Configured for Db2Transport {
    /// The address is the server's host and port: where a Location
    /// connects, port 50000 where it names none.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "database",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The database a Location connects to and reads or inserts into.",
                applies: Applies::Both,
            },
            Setting {
                name: "user",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The user a Location logs in as.",
                applies: Applies::Both,
            },
            Setting {
                name: "query",
                kind: Kind::Text,
                presence: Presence::Default(Fixed::Text(DEFAULT_QUERY)),
                meaning: "The query a receive runs: the first column names the row, the last \
                          is the Stream.",
                applies: Applies::Receive,
            },
            accept::ACCEPT,
            COLUMN,
            ENCODING,
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a server that stops mid-answer is waited on; unbounded \
                          when left out.",
                applies: Applies::Both,
            },
            Setting {
                name: "tls",
                kind: Kind::Boolean,
                presence: Presence::Default(Fixed::Boolean(false)),
                meaning: "TLS from the first byte, to the server's TLS port, its certificate \
                          checked against the operating system's trust store; the password \
                          crosses the wire in the clear without it.",
                applies: Applies::Both,
            },
            Setting {
                name: "tls_name",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The name the server's certificate is checked for; the address's \
                          host when left out.",
                applies: Applies::Both,
            },
        ],
    };

    /// The password comes through the Location's credentials, never a
    /// setting.
    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let mut transport = Self::new(address, settings.text("database"), settings.text("user"))
            .guarded_as(
                settings.optional_boolean("tls") == Some(true),
                settings.optional_text("tls_name"),
            )?;
        if let Some(query) = settings.optional_text("query") {
            transport = transport.with_query(query);
        }
        if let Some(statement) = settings.optional_text(accept::ACCEPT.name) {
            transport = transport.with_accept(statement);
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport.holding(Column::configured(settings)?))
    }
}

impl Db2Transport {
    /// TLS where `tls` says, checked for `name` where one is given.
    #[cfg(feature = "tls")]
    #[allow(clippy::unnecessary_wraps)]
    fn guarded_as(self, tls: bool, name: Option<&str>) -> Result<Self> {
        if !tls {
            return Ok(self);
        }
        let secured = name.map_or_else(Secured::native, |name| Secured::native().named(name));
        Ok(self.secured(secured))
    }

    /// In the clear; `tls` refused, since this build carries no TLS.
    #[cfg(not(feature = "tls"))]
    fn guarded_as(self, tls: bool, _name: Option<&str>) -> Result<Self> {
        if tls {
            return Err(transport::TransportError::permanent(
                "TLS needs the db2 transport built with its tls feature",
            ));
        }
        Ok(self)
    }
}
