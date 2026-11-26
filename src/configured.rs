//! How a DB2 Location is configured through its
//! [`declaration`](crate::declaration) (ADR-0064, amendments 2026-09-26 and
//! 2026-11-26): whether its connections are guarded by TLS, `tls` and
//! `tls_name` read by `transport::sql::client_tls`.

use transport::error::Result;
#[cfg(not(feature = "tls"))]
use transport::sql::TLS;
use xcore::settings::Read;

use crate::Db2;

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
