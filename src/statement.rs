//! The statement object, `SQLSTT`: a statement's text as a command carries
//! it — a nullable mixed-character string with a four-byte length, in
//! UTF-8, then a null single-byte one (DRDA Version 5, Volume 1,
//! *SQLSTTGRP*). Written by the client, read by the far end.

use transport::error::{Result, protocol_error};

use crate::codepoint::SQLSTT;
use crate::ddm::Object;

/// `sql` as the statement object.
#[must_use]
pub fn statement(sql: &str) -> Object {
    let length = u32::try_from(sql.len()).unwrap_or(u32::MAX);
    let mut data = Vec::with_capacity(sql.len() + 6);
    data.push(0);
    data.extend_from_slice(&length.to_be_bytes());
    data.extend_from_slice(sql.as_bytes());
    data.push(0xFF);
    Object::new(SQLSTT, data)
}

/// The text a statement object carries.
///
/// # Errors
/// Where it is not a mixed string of its stated length in UTF-8.
pub fn text(object: &Object) -> Result<String> {
    let data = &object.data;
    let length = data
        .get(1..5)
        .and_then(|four| <[u8; 4]>::try_from(four).ok())
        .map(u32::from_be_bytes)
        .and_then(|length| usize::try_from(length).ok())
        .filter(|_| data.first() == Some(&0))
        .ok_or_else(|| protocol_error("an SQLSTT without its mixed string"))?;
    let text = data
        .get(5..5 + length)
        .ok_or_else(|| protocol_error("an SQLSTT shorter than its length"))?;
    String::from_utf8(text.to_vec()).map_err(|_| protocol_error("an SQLSTT that is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_statement_reads_back_as_written() {
        let written = statement("SELECT 'é'");
        assert_eq!(&written.data[..5], &[0, 0, 0, 0, 11]);
        assert_eq!(written.data.last(), Some(&0xFF));
        assert_eq!(text(&written).expect("text"), "SELECT 'é'");
        assert!(text(&Object::new(SQLSTT, vec![0xFF])).is_err(), "null");
        assert!(text(&Object::new(SQLSTT, vec![0, 0, 0, 0, 9, b'x'])).is_err());
    }
}
