//! The SQL communications area (`SQLCAGRP`): what a server says of a
//! statement — its `SQLCODE`, its `SQLSTATE`, the rows it touched and the
//! tokens of its message — as FD:OCA writes it in an `SQLCARD`, at the
//! head of an `SQLDARD`, and at the end of a query's rows (DRDA Version 5,
//! Volume 1, *SQLCAGRP*).
//!
//! A null area (`0xFF`) is success with nothing to say. Numbers are in the
//! server's byte order, which its `TYPDEFNAM` names; lengths are
//! big-endian. DB2 sends the tokens of a message, not its text, separated
//! by `0xFF`; they are joined here with a comma.

use codec::cursor::Cursor;
use transport::error::{Result, TransportError};

/// What a statement that returned nothing more says: no rows.
pub const NOT_FOUND: i32 = 100;

/// The byte order a server writes numbers in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Endian {
    /// `QTDSQLX86` and `QTDSQLVAX`: an Intel server.
    #[default]
    Little,
    /// `QTDSQL370`, `QTDSQL400` and `QTDSQLASC`: a mainframe, IBM i, AIX.
    Big,
}

impl Endian {
    /// The byte order the representation `typdefnam` names.
    #[must_use]
    pub fn of(typdefnam: &str) -> Self {
        match typdefnam.trim() {
            "QTDSQLX86" | "QTDSQLVAX" => Self::Little,
            _ => Self::Big,
        }
    }

    pub(crate) fn i32(self, cursor: &mut Cursor<'_>) -> Result<i32> {
        Ok(match self {
            Self::Little => cursor.i32_le()?,
            Self::Big => cursor.i32_be()?,
        })
    }

    pub(crate) const fn i32_bytes(self, value: i32) -> [u8; 4] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
}

/// One communications area.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sqlca {
    pub code: i32,
    pub state: String,
    /// `SQLERRD`: the third is the rows a statement touched.
    pub errd: [i32; 6],
    /// The message's tokens, joined.
    pub tokens: String,
}

impl Sqlca {
    /// An area saying `code` and `state`, with `tokens`.
    #[must_use]
    pub fn new(code: i32, state: &str, tokens: &str) -> Self {
        Self {
            code,
            state: state.to_string(),
            errd: [0; 6],
            tokens: tokens.to_string(),
        }
    }

    /// The rows a statement touched.
    #[must_use]
    pub fn rows(&self) -> u64 {
        u64::try_from(self.errd[2]).unwrap_or(0)
    }

    /// The area `cursor` stands at, or `None` where it is null.
    ///
    /// # Errors
    /// Where the bytes end inside the area.
    pub fn read(cursor: &mut Cursor<'_>, endian: Endian) -> Result<Option<Self>> {
        if cursor.byte()? == 0xFF {
            return Ok(None);
        }
        let code = endian.i32(cursor)?;
        let state = String::from_utf8_lossy(cursor.take(5)?).into_owned();
        cursor.skip(8)?;
        let mut area = Self::new(code, &state, "");
        if cursor.byte()? == 0xFF {
            return Ok(Some(area));
        }
        for errd in &mut area.errd {
            *errd = endian.i32(cursor)?;
        }
        cursor.skip(11)?;
        let _database = counted(cursor)?;
        let mixed = counted(cursor)?;
        let single = counted(cursor)?;
        let tokens = if mixed.is_empty() { single } else { mixed };
        area.tokens = tokens
            .split(|&byte| byte == 0xFF)
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join(", ");
        if cursor.peek() == Some(0xFF) {
            cursor.advance(1);
        }
        Ok(Some(area))
    }

    /// This area as FD:OCA writes it, after the null indicator.
    #[must_use]
    pub fn encode(&self, endian: Endian) -> Vec<u8> {
        let mut out = vec![0];
        out.extend_from_slice(&endian.i32_bytes(self.code));
        let mut state = self.state.clone().into_bytes();
        state.resize(5, b' ');
        out.extend_from_slice(&state[..5]);
        out.extend_from_slice(b"XMIPDB2 ");
        out.push(0);
        for errd in self.errd {
            out.extend_from_slice(&endian.i32_bytes(errd));
        }
        out.extend_from_slice(&[b' '; 11]);
        for counted in [&b""[..], self.tokens.as_bytes(), b""] {
            let length = u16::try_from(counted.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(&counted[..usize::from(length)]);
        }
        out.push(0xFF);
        out
    }

    /// The error this area reports, where its code is negative.
    #[must_use]
    pub fn error(&self) -> Option<TransportError> {
        (self.code < 0).then(|| sql_error(self.code, &self.state, &self.tokens))
    }
}

/// Two bytes of length and what they count.
fn counted<'a>(cursor: &mut Cursor<'a>) -> Result<&'a [u8]> {
    let length = cursor.u16_be()?;
    Ok(cursor.take(usize::from(length))?)
}

/// An error the server answered, retryable where its `SQLSTATE` class says
/// the trouble is the connection (08), a rollback a deadlock or a timeout
/// forced (40), or a resource not available now (57) — what a later attempt
/// might not meet.
#[must_use]
pub fn sql_error(code: i32, state: &str, tokens: &str) -> TransportError {
    let text = format!("the server answered SQLCODE {code} (SQLSTATE {state}): {tokens}");
    if matches!(state.get(..2), Some("08" | "40" | "57")) {
        TransportError::retryable(text)
    } else {
        TransportError::permanent(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_area_round_trips_in_either_order_and_null_is_success() {
        let mut area = Sqlca::new(-204, "42704", "");
        area.errd[2] = 3;
        area.tokens = "DB2INST1.INBOX".to_string();
        for endian in [Endian::Little, Endian::Big] {
            let written = area.encode(endian);
            let read = Sqlca::read(&mut Cursor::new(&written), endian).expect("read");
            assert_eq!(read.as_ref(), Some(&area));
            assert_eq!(read.expect("an area").rows(), 3);
        }
        assert_eq!(
            Sqlca::read(&mut Cursor::new(&[0xFF]), Endian::Little).expect("null"),
            None
        );
        let error = area.error().expect("negative");
        assert!(!error.retryable);
        assert!(
            error
                .message
                .contains("-204 (SQLSTATE 42704): DB2INST1.INBOX")
        );
        assert!(Sqlca::new(100, "02000", "").error().is_none());
        assert!(sql_error(-911, "40001", "2").retryable);
        assert!(sql_error(-30081, "08001", "").retryable);
        assert_eq!(Endian::of("QTDSQLX86 "), Endian::Little);
        assert_eq!(Endian::of("QTDSQL370"), Endian::Big);
    }
}
