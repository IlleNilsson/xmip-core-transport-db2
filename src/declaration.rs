//! What a Location of this technology is configured with: its declaration,
//! which its wire hands `transport::sql`'s `Configured`, built with the
//! crate's `declaration` feature alone and the code behind the default
//! (ADR-0064, amendments 2026-09-26, 2026-10-22 and 2026-11-26), for the
//! library the surfaces load to carry (open problem 48): what every SQL
//! Location declares (`transport::sql`), and whether its connections are
//! guarded by TLS, which `configured::wire` reads.

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

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["db2"];
