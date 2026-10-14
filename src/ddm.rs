//! A DDM object, and the parameters inside one: a two-byte length, a
//! two-byte code point and what it carries (DRDA Version 5, Volume 3).
//!
//! The length counts itself and the code point. One with its high bit set
//! is extended: its low bits less four say how many bytes of length follow
//! the code point — none where the object runs to the end of its DSS, as a
//! server streams `QRYDTA`. A statement longer than 32 763 bytes goes out
//! extended, its length in four bytes.

use codec::cursor::Cursor;
use transport::error::{Result, protocol_error};

/// The most an object's two-byte length says: what does not fit goes
/// extended.
const MOST: usize = 0x7FFF;
/// The length and the code point.
const HEADER: usize = 4;
/// The bit that marks a length extended.
const EXTENDED: u16 = 0x8000;

/// One DDM object: a command, a reply message, reply data, or a parameter
/// inside any of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub codepoint: u16,
    pub data: Vec<u8>,
}

impl Object {
    /// `codepoint` carrying `data`.
    #[must_use]
    pub const fn new(codepoint: u16, data: Vec<u8>) -> Self {
        Self { codepoint, data }
    }

    /// `codepoint` carrying `parameters`, each written as an object of its
    /// own, in order.
    #[must_use]
    pub fn of(codepoint: u16, parameters: &[(u16, &[u8])]) -> Self {
        let mut data = Vec::new();
        for (parameter, value) in parameters {
            put(&mut data, *parameter, value);
        }
        Self::new(codepoint, data)
    }

    /// This object as it travels.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 2 * HEADER);
        put(&mut out, self.codepoint, &self.data);
        out
    }

    /// The parameters this object carries, in order.
    ///
    /// # Errors
    /// Where its data is not a run of whole parameters.
    pub fn parameters(&self) -> Result<Vec<Self>> {
        objects(&self.data)
    }

    /// The value of this object's first `codepoint` parameter, if any; an
    /// object that is not a run of parameters has none.
    #[must_use]
    pub fn parameter(&self, codepoint: u16) -> Option<Vec<u8>> {
        self.parameters()
            .ok()?
            .into_iter()
            .find(|parameter| parameter.codepoint == codepoint)
            .map(|parameter| parameter.data)
    }

    /// The severity a reply message carries (`SVRCOD`): 0 information, 4
    /// warning, 8 error and above.
    #[must_use]
    pub fn severity(&self) -> u16 {
        self.parameter(crate::codepoint::SVRCOD)
            .and_then(|value| Some(u16::from_be_bytes(value.get(..2)?.try_into().ok()?)))
            .unwrap_or(0)
    }
}

/// `data` as an object of `codepoint`, appended to `out`, extended where
/// two bytes cannot say its length.
pub fn put(out: &mut Vec<u8>, codepoint: u16, data: &[u8]) {
    match u16::try_from(data.len() + HEADER) {
        Ok(length) if usize::from(length) <= MOST => {
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(&codepoint.to_be_bytes());
        }
        _ => {
            let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&(EXTENDED | 8).to_be_bytes());
            out.extend_from_slice(&codepoint.to_be_bytes());
            out.extend_from_slice(&length.to_be_bytes());
        }
    }
    out.extend_from_slice(data);
}

/// The objects `bytes` holds, one after another to its end.
///
/// # Errors
/// Where a length is shorter than its header or runs past the end.
pub fn objects(bytes: &[u8]) -> Result<Vec<Object>> {
    let mut cursor = Cursor::new(bytes);
    let mut read = Vec::new();
    while !cursor.is_empty() {
        let length = cursor.u16_be()?;
        let codepoint = cursor.u16_be()?;
        let data = if length & EXTENDED == 0 {
            let carried = usize::from(length)
                .checked_sub(HEADER)
                .ok_or_else(|| protocol_error(format!("a DDM length of {length}")))?;
            cursor.take(carried)?
        } else {
            match usize::from(length & !EXTENDED).checked_sub(HEADER) {
                Some(0) => cursor.take_rest(),
                Some(width @ 1..=8) => {
                    let mut carried = 0u64;
                    for byte in cursor.take(width)? {
                        carried = carried << 8 | u64::from(*byte);
                    }
                    let carried = usize::try_from(carried)
                        .map_err(|_| protocol_error("a DDM length past this machine"))?;
                    cursor.take(carried)?
                }
                _ => {
                    return Err(protocol_error(format!(
                        "an extended DDM length {length:#x}"
                    )));
                }
            }
        };
        read.push(Object::new(codepoint, data.to_vec()));
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_and_its_parameters_round_trip_short_and_extended() {
        let command = Object::of(0x106D, &[(0x11A2, &[0, 3]), (0x2110, b"SAMPLE")]);
        let written = command.encode();
        assert_eq!(&written[..4], &[0, 20, 0x10, 0x6D]);
        let read = objects(&written).expect("one object");
        assert_eq!(read, std::slice::from_ref(&command));
        assert_eq!(read[0].parameter(0x11A2), Some(vec![0, 3]));
        assert_eq!(read[0].parameter(0x9999), None);
        let long = Object::new(0x2414, vec![7; 40_000]);
        let written = long.encode();
        assert_eq!(&written[..8], &[0x80, 0x08, 0x24, 0x14, 0, 0, 0x9C, 0x40]);
        assert_eq!(objects(&written).expect("extended"), [long]);
        let streamed = [&[0x80, 0x04, 0x24, 0x1B][..], &[1, 2, 3]].concat();
        assert_eq!(objects(&streamed).expect("to the end")[0].data, [1, 2, 3]);
        assert!(objects(&[0, 2, 0, 0]).is_err(), "shorter than its header");
        assert!(objects(&[0, 9, 0, 0, 1]).is_err(), "past the end");
    }

    #[test]
    fn a_reply_message_says_its_severity() {
        let reply = Object::of(0x1219, &[(0x1149, &[0, 8]), (0x11A4, &[0x0F])]);
        assert_eq!(reply.severity(), 8);
        assert_eq!(Object::new(0x2201, Vec::new()).severity(), 0);
    }
}
