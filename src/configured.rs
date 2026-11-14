//! The settings a DB2 Location declares (`xcore::settings`, read through
//! `transport::Configured`, ADR-0064): what every SQL Location declares
//! (`transport::sql`), and whether its connections are guarded by TLS,
//! read by `transport::sql::client_tls`.

use transport::error::Result;
use transport::sql::accept::ACCEPT;
use transport::sql::{COLUMN, DATABASE, ENCODING, QUERY, TIMEOUT, TLS, TLS_NAME, USER};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

use crate::Db2;

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

cfg_select! {
    feature = "tls" => {
        /// The wire `tls` and `tls_name` ask for.
        #[allow(clippy::unnecessary_wraps)]
        pub fn wire(settings: &Read) -> Result<Db2> {
            Ok(transport::sql::client_tls(settings).map_or_else(Db2::default, Db2::secured))
        }
    }
    _ => {
        /// In the clear; `tls` refused, since this build carries no TLS.
        ///
        /// # Errors
        /// `tls` asked of a build that carries no TLS.
        pub fn wire(settings: &Read) -> Result<Db2> {
            if settings.optional_boolean(TLS) == Some(true) {
                return Err(transport::TransportError::permanent(
                    "TLS needs the db2 transport built with its tls feature",
                ));
            }
            Ok(Db2::default())
        }
    }
}
