//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`. Its wire
//! hands it to `transport::sql`'s `Configured`. What every SQL Location
//! declares stays `transport::sql`'s. Whether its connections are guarded by
//! TLS is declared here, read by `configured::wire`.

use transport::sql::accept::ACCEPT;
use transport::sql::{COLUMN, DATABASE, ENCODING, QUERY, TIMEOUT, TLS, TLS_NAME, USER};
use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// Every setting a DB2 Location takes beyond its address, the server's
/// host and port, port 50000 where it names none.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        DATABASE,
        USER,
        QUERY,
        ACCEPT,
        COLUMN,
        ENCODING,
        TIMEOUT,
        Setting {
            name: TLS,
            kind: Kind::Boolean,
            presence: Presence::Default(Fixed::Boolean(false)),
            meaning: "TLS from the first byte, to the server's TLS port, its certificate \
                      checked against the operating system's trust store; the password \
                      crosses the wire in the clear without it.",
            applies: Applies::Both,
        },
        TLS_NAME,
    ],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["db2"];
