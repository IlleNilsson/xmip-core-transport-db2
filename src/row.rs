//! A query's rows as FD:OCA describes and carries them: the descriptor
//! (`QRYDSC`) names each column's DRDA type and length, and the data
//! (`QRYDTA`) is the rows one after another, each opened by a null
//! communications area, and closed by one that is not — `SQLCODE` 100 at
//! the end, or the error that stopped the query (DRDA Version 5, Volume 1,
//! *FD:OCA* and *Early descriptors*).
//!
//! A value is read as text, as the sibling SQL transports read theirs:
//! characters as UTF-8 — the connection asked for code set 1208 — a number
//! in its decimal form, a date or a time as the server spelled it, and
//! bytes as two hex digits a byte, the DB2 dialect's binary form, so a
//! binary column's Stream is read back whole. A large object, a graphic
//! string or a decimal float is refused with what to cast it to.

use codec::cursor::Cursor;
use codec::hex;
use transport::error::{Result, TransportError, protocol_error};

use crate::sqlca::{Endian, Sqlca};

/// One row: each column as text or NULL.
pub type Row = Vec<Option<String>>;

/// One column as the descriptor names it: its DRDA type, nullable where
/// odd, and two bytes of length — or of precision and scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Described {
    pub kind: u8,
    pub length: [u8; 2],
}

/// The triplet type and identifier of a row's group of columns.
const GROUP: [u8; 2] = [0x76, 0xD0];
/// A nullable mixed-character varying string: what the far end describes
/// every column as.
const NULLABLE_VARMIX: u8 = 0x3F;
/// The triplets that close a descriptor: the row and the answer set laid
/// out, as DB2 sends them.
const LAYOUT: [u8; 12] = [6, 0x71, 0xE4, 0xD0, 0, 1, 6, 0x71, 0xF0, 0xE0, 0, 0];

/// The columns a descriptor names, from every triplet of a row's group.
///
/// # Errors
/// Where a triplet is cut short.
pub fn describe(data: &[u8]) -> Result<Vec<Described>> {
    let mut cursor = Cursor::new(data);
    let mut columns = Vec::new();
    while let Some(length) = cursor.peek() {
        let triplet = cursor.take(usize::from(length))?;
        if triplet.len() < 3 {
            return Err(protocol_error(
                "a descriptor triplet shorter than its header",
            ));
        }
        if triplet[1..3] != GROUP {
            continue;
        }
        for column in triplet[3..].as_chunks::<3>().0 {
            columns.push(Described {
                kind: column[0],
                length: [column[1], column[2]],
            });
        }
    }
    Ok(columns)
}

/// The descriptor of `columns` nullable text columns.
///
/// # Errors
/// More columns than one triplet holds.
pub fn descriptor(columns: usize) -> Result<Vec<u8>> {
    let length = u8::try_from(3 + 3 * columns)
        .map_err(|_| TransportError::permanent("more columns than one descriptor holds"))?;
    let mut out = vec![length, GROUP[0], GROUP[1]];
    for _ in 0..columns {
        out.extend_from_slice(&[NULLABLE_VARMIX, 0x7F, 0xFF]);
    }
    out.extend_from_slice(&LAYOUT);
    Ok(out)
}

/// The rows `data` carries, and the communications area that closed them
/// where it came.
///
/// # Errors
/// Where a value is cut short, of a type this transport does not read, or
/// text that is not UTF-8.
pub fn rows(
    data: &[u8],
    columns: &[Described],
    endian: Endian,
) -> Result<(Vec<Row>, Option<Sqlca>)> {
    let mut cursor = Cursor::new(data);
    let mut rows = Vec::new();
    while let Some(flag) = cursor.peek() {
        if flag != 0xFF {
            return Ok((rows, Sqlca::read(&mut cursor, endian)?));
        }
        cursor.advance(1);
        if cursor.byte()? != 0 {
            continue;
        }
        let mut row = Vec::with_capacity(columns.len());
        for column in columns {
            row.push(value(*column, &mut cursor, endian)?);
        }
        rows.push(row);
    }
    Ok((rows, None))
}

/// One row as the far end sends it: every column nullable text.
///
/// # Errors
/// A value longer than a varying string holds.
pub fn encode(row: &[Option<String>]) -> Result<Vec<u8>> {
    let mut out = vec![0xFF, 0];
    for cell in row {
        let Some(text) = cell else {
            out.push(0xFF);
            continue;
        };
        let length = u16::try_from(text.len())
            .ok()
            .filter(|length| *length <= 0x7FFF)
            .ok_or_else(|| TransportError::permanent("a value longer than VARCHAR holds"))?;
        out.push(0);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(text.as_bytes());
    }
    Ok(out)
}

/// One value as text, or `None` where it is NULL.
fn value(column: Described, cursor: &mut Cursor<'_>, endian: Endian) -> Result<Option<String>> {
    if column.kind & 1 == 1 && cursor.byte()? >= 0x80 {
        return Ok(None);
    }
    let fixed = usize::from(u16::from_be_bytes(column.length) & 0x7FFF);
    let text = match column.kind & !1 {
        0x02 | 0x04 | 0x06 | 0x16 => integer(cursor.take(fixed)?, endian).to_string(),
        0x0A => float(cursor.take(8)?, endian),
        0x0C => float(cursor.take(4)?, endian),
        0x0E => packed(cursor, column.length[0], column.length[1])?,
        0x20 | 0x22 | 0x24 | 0x30 | 0x3C => utf8(cursor.take(fixed)?)?,
        0x32 | 0x34 | 0x3E | 0x40 => {
            let length = cursor.u16_be()?;
            utf8(cursor.take(usize::from(length))?)?
        }
        0x26 | 0xC0 => hex::encode(cursor.take(fixed)?),
        0x28 | 0xC2 => {
            let length = cursor.u16_be()?;
            hex::encode(cursor.take(usize::from(length))?)
        }
        0xBE => (cursor.take(fixed.max(1))?.iter().any(|b| *b != 0)).to_string(),
        other => {
            return Err(TransportError::permanent(format!(
                "a column of DRDA type {other:#04x} — a large object, a graphic string or a \
                 decimal float — is not read by this transport; cast it to VARCHAR or VARBINARY \
                 in the query"
            )));
        }
    };
    Ok(Some(text))
}

/// A signed integer of the bytes' width, in the server's order.
fn integer(bytes: &[u8], endian: Endian) -> i64 {
    let mut ordered = bytes.to_vec();
    if endian == Endian::Little {
        ordered.reverse();
    }
    let negative = ordered.first().is_some_and(|top| top & 0x80 != 0);
    let mut wide = [if negative { 0xFF } else { 0 }; 8];
    let from = 8usize.saturating_sub(ordered.len());
    wide[from..].copy_from_slice(&ordered[ordered.len().saturating_sub(8)..]);
    i64::from_be_bytes(wide)
}

/// A floating-point number of four or eight bytes, in its shortest form.
fn float(bytes: &[u8], endian: Endian) -> String {
    let mut ordered = bytes.to_vec();
    if endian == Endian::Little {
        ordered.reverse();
    }
    match <[u8; 8]>::try_from(ordered.as_slice()) {
        Ok(eight) => f64::from_be_bytes(eight).to_string(),
        Err(_) => <[u8; 4]>::try_from(ordered.as_slice())
            .map(|four| f32::from_be_bytes(four).to_string())
            .unwrap_or_default(),
    }
}

/// A packed decimal of `precision` digits, `scale` of them after the point:
/// a digit a nibble, the last nibble its sign.
fn packed(cursor: &mut Cursor<'_>, precision: u8, scale: u8) -> Result<String> {
    let bytes = cursor.take(usize::from(precision) / 2 + 1)?;
    let mut digits = String::new();
    for byte in bytes {
        digits.push(char::from(b'0' + (byte >> 4)));
        digits.push(char::from(b'0' + (byte & 0x0F)));
    }
    let sign = digits
        .pop()
        .map_or(0, |nibble| u32::from(nibble) - u32::from('0'));
    if digits.bytes().any(|digit| digit > b'9') {
        return Err(protocol_error(
            "a packed decimal with a nibble that is not a digit",
        ));
    }
    let point = digits.len().saturating_sub(usize::from(scale));
    let (whole, fraction) = digits.split_at(point);
    let whole = whole.trim_start_matches('0');
    let mut text = String::new();
    if matches!(sign, 0x0B | 0x0D) {
        text.push('-');
    }
    text.push_str(if whole.is_empty() { "0" } else { whole });
    if !fraction.is_empty() {
        text.push('.');
        text.push_str(fraction);
    }
    Ok(text)
}

fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| TransportError::permanent("a row value that is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(kind: u8, length: [u8; 2]) -> Described {
        Described { kind, length }
    }

    #[test]
    fn the_far_ends_rows_read_back_and_the_end_is_its_area() {
        let described = describe(&descriptor(2).expect("two")).expect("described");
        assert_eq!(described, [column(0x3F, [0x7F, 0xFF]); 2]);
        let rows_sent = [
            vec![Some("41".to_string()), Some("BX'00'".to_string())],
            vec![None, Some(String::new())],
        ];
        let mut data = Vec::new();
        for row in &rows_sent {
            data.extend(encode(row).expect("a row"));
        }
        data.extend(Sqlca::new(100, "02000", "").encode(Endian::Little));
        let (read, end) = rows(&data, &described, Endian::Little).expect("rows");
        assert_eq!(read, rows_sent);
        assert_eq!(end.expect("closed").code, 100);
        assert_eq!(
            rows(
                &encode(&rows_sent[0]).expect("a row"),
                &described,
                Endian::Little
            )
            .expect("open")
            .1,
            None,
            "more to come"
        );
    }

    #[test]
    fn each_type_reads_as_text() {
        let read = |kind, length, bytes: &[u8], endian| {
            value(column(kind, length), &mut Cursor::new(bytes), endian).expect("value")
        };
        let little = Endian::Little;
        assert_eq!(
            read(0x03, [0, 4], &[0, 0xD6, 0xFF, 0xFF, 0xFF], little),
            Some("-42".into())
        );
        assert_eq!(read(0x03, [0, 4], &[0xFF], little), None, "NULL");
        assert_eq!(
            read(0x04, [0, 2], &[0x01, 0x00], Endian::Big),
            Some("256".into())
        );
        assert_eq!(
            read(0x16, [0, 8], &7i64.to_le_bytes(), little),
            Some("7".into())
        );
        assert_eq!(
            read(0x0E, [5, 2], &[0x12, 0x34, 0x5D], little),
            Some("-123.45".into())
        );
        assert_eq!(read(0x0E, [3, 0], &[0x00, 0x7C], little), Some("7".into()));
        assert_eq!(
            read(0x0A, [0, 8], &1.5f64.to_le_bytes(), little),
            Some("1.5".into())
        );
        assert_eq!(read(0x30, [0, 3], b"ab ", little), Some("ab ".into()));
        let text = [0, 0, 3, b'h', 0xC3, 0xA9];
        assert_eq!(read(0x33, [0, 9], &text, little), Some("h\u{e9}".into()));
        assert_eq!(
            read(0x29, [0, 9], &[0, 0, 2, 0xFF, 0x00], little),
            Some("ff00".into())
        );
        assert_eq!(
            read(0x26, [0, 2], &[0x6B, 0xFF], little),
            Some("6bff".into())
        );
        assert_eq!(
            read(0x24, [0, 10], b"2026-10-14", little),
            Some("2026-10-14".into())
        );
        assert_eq!(read(0xBE, [0, 1], &[1], little), Some("true".into()));
        let lob = value(
            column(0xC9, [0x80, 2]),
            &mut Cursor::new(&[0, 0, 0]),
            little,
        );
        assert!(lob.expect_err("a LOB").message.contains("cast it"));
        let bad = value(
            column(0x32, [0, 2]),
            &mut Cursor::new(&[0, 1, 0xFF]),
            little,
        );
        assert!(bad.expect_err("not UTF-8").message.contains("UTF-8"));
    }
}
