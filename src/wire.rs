//! The DSS, DRDA's frame, and a connection that carries chains of them
//! (DRDA Version 5, Volume 3, *Data Stream Structures*).
//!
//! A DSS is a six-byte header — its length, `0xD0`, a format byte and a
//! correlator — and one object. The format byte's low nibble is the kind
//! (a request, a reply, an object); `0x40` says another DSS follows in the
//! chain, `0x10` that the next one shares this one's correlator, as a
//! statement shares its command's. A DSS longer than 32 767 bytes is cut
//! into segments: a length with its high bit set says a two-byte segment
//! header follows the full segment, and so on until one without it.
//!
//! A chain is what one side writes before it waits: a request and its
//! objects, several commands at once, or every reply to them. Its last DSS
//! is the one without the chain bit, which is how a reader knows the other
//! side now waits.

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;

use transport::error::{Result, classify, protocol_error};

use crate::ddm::{Object, objects};

/// A request: a command.
pub const REQUEST: u8 = 1;
/// A reply message.
pub const REPLY: u8 = 2;
/// An object: a statement, a row descriptor, rows, a SQL communications
/// area.
pub const OBJECT: u8 = 3;

/// The second header byte of every DSS.
const MAGIC: u8 = 0xD0;
/// Another DSS follows in this chain.
const CHAINED: u8 = 0x40;
/// The next DSS shares this one's correlator.
const SAME_CORRELATOR: u8 = 0x10;
/// The most one segment holds, its header counted.
const SEGMENT: usize = 0x7FFF;
/// A segment length's bit that says another segment follows.
const CONTINUED: u16 = 0x8000;
/// The header of a DSS and of a continuing segment.
const HEADER: usize = 6;
const SEGMENT_HEADER: usize = 2;

/// One DSS as read: its kind, its correlator, and the objects it carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dss {
    pub kind: u8,
    pub correlation: u16,
    pub objects: Vec<Object>,
}

/// A chain to write, one object a DSS, the correlators assigned in order.
#[derive(Clone, Debug, Default)]
pub struct Chain {
    written: Vec<(u8, u16, Vec<u8>)>,
}

impl Chain {
    /// Nothing in it yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A command, on the next correlator.
    #[must_use]
    pub fn request(mut self, object: &Object) -> Self {
        let next = self.written.last().map_or(1, |(_, last, _)| last + 1);
        self.written.push((REQUEST, next, object.encode()));
        self
    }

    /// An object the last command carries, on its correlator.
    #[must_use]
    pub fn object(mut self, object: &Object) -> Self {
        let same = self.written.last().map_or(1, |(_, last, _)| *last);
        self.written.push((OBJECT, same, object.encode()));
        self
    }

    /// A reply of `kind` to the command on `correlation`.
    #[must_use]
    pub fn reply(mut self, kind: u8, correlation: u16, object: &Object) -> Self {
        self.written.push((kind, correlation, object.encode()));
        self
    }

    /// Whether nothing was put in.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.written.is_empty()
    }

    /// The chain as it travels.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (at, (kind, correlation, payload)) in self.written.iter().enumerate() {
            let next = self.written.get(at + 1);
            let mut format = *kind;
            if next.is_some() {
                format |= CHAINED;
            }
            if next.is_some_and(|(_, following, _)| following == correlation) {
                format |= SAME_CORRELATOR;
            }
            frame(&mut out, format, *correlation, payload);
        }
        out
    }
}

/// One DSS appended to `out`, cut into segments where it is long.
fn frame(out: &mut Vec<u8>, format: u8, correlation: u16, payload: &[u8]) {
    let first = payload.len().min(SEGMENT - HEADER);
    let mut rest = &payload[first..];
    out.extend_from_slice(&length(HEADER + first, !rest.is_empty()).to_be_bytes());
    out.extend_from_slice(&[MAGIC, format]);
    out.extend_from_slice(&correlation.to_be_bytes());
    out.extend_from_slice(&payload[..first]);
    while !rest.is_empty() {
        let piece = rest.len().min(SEGMENT - SEGMENT_HEADER);
        let more = rest.len() > piece;
        out.extend_from_slice(&length(SEGMENT_HEADER + piece, more).to_be_bytes());
        out.extend_from_slice(&rest[..piece]);
        rest = &rest[piece..];
    }
}

/// A segment's length field: its length, or the continued mark.
fn length(carried: usize, continued: bool) -> u16 {
    if continued {
        return 0xFFFF;
    }
    u16::try_from(carried).unwrap_or(u16::MAX)
}

/// One connection's two directions and the socket under them.
pub struct Wire {
    reader: BufReader<Box<dyn Read + Send>>,
    writer: Box<dyn Write + Send>,
    socket: TcpStream,
}

impl Wire {
    /// A connection over `reader` and `writer`, `socket` under them.
    #[must_use]
    pub fn new(
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        socket: TcpStream,
    ) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            socket,
        }
    }

    /// A connection in the clear over `stream`.
    ///
    /// # Errors
    /// Where the socket could not be cloned.
    pub fn plain(stream: TcpStream) -> Result<Self> {
        let clone = |what| stream.try_clone().map_err(|e| classify(what, &e));
        let reader = clone("cloning the connection to read")?;
        let writer = clone("cloning the connection to write")?;
        Ok(Self::new(Box::new(reader), Box::new(writer), stream))
    }

    /// The socket under the connection.
    #[must_use]
    pub const fn socket(&self) -> &TcpStream {
        &self.socket
    }

    /// Write `chain` whole.
    ///
    /// # Errors
    /// Where the connection broke.
    pub fn send(&mut self, chain: &Chain) -> Result<()> {
        self.writer
            .write_all(&chain.encode())
            .map_err(|e| classify("writing a DSS chain", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a DSS chain", &e))
    }

    /// The next whole chain, or `None` where the other side closed before
    /// it began one.
    ///
    /// # Errors
    /// Where the connection broke mid-chain, or what came is not DSSs.
    pub fn receive(&mut self) -> Result<Option<Vec<Dss>>> {
        let mut chain = Vec::new();
        let mut total = 0;
        loop {
            let mut header = [0u8; HEADER];
            if chain.is_empty() {
                if !self.opening(&mut header)? {
                    return Ok(None);
                }
            } else {
                self.exact(&mut header, "a DSS header")?;
            }
            if header[2] != MAGIC {
                return Err(protocol_error(
                    "what came is not a DRDA data stream structure",
                ));
            }
            let first = u16::from_be_bytes([header[0], header[1]]);
            let mut payload = self.segment(first, HEADER, &mut total)?;
            let mut continued = first & CONTINUED != 0;
            while continued {
                let mut mark = [0u8; SEGMENT_HEADER];
                self.exact(&mut mark, "a DSS segment header")?;
                let next = u16::from_be_bytes(mark);
                payload.extend(self.segment(next, SEGMENT_HEADER, &mut total)?);
                continued = next & CONTINUED != 0;
            }
            chain.push(Dss {
                kind: header[3] & 0x0F,
                correlation: u16::from_be_bytes([header[4], header[5]]),
                objects: objects(&payload)?,
            });
            if header[3] & CHAINED == 0 {
                return Ok(Some(chain));
            }
        }
    }

    /// The header a chain opens with, into `header`; false where the other
    /// side closed instead of beginning one.
    fn opening(&mut self, header: &mut [u8; HEADER]) -> Result<bool> {
        let read = self
            .reader
            .read(&mut header[..1])
            .map_err(|e| classify("reading a DSS", &e))?;
        if read == 0 {
            return Ok(false);
        }
        self.exact(&mut header[1..], "a DSS header")?;
        Ok(true)
    }

    /// One segment's bytes past its header of `width`.
    fn segment(&mut self, length: u16, width: usize, total: &mut usize) -> Result<Vec<u8>> {
        let whole = if length & CONTINUED == 0 {
            usize::from(length)
        } else {
            SEGMENT
        };
        let carried = whole
            .checked_sub(width)
            .ok_or_else(|| protocol_error(format!("a DSS segment of {whole} bytes")))?;
        *total += carried;
        if *total > net::MAX_BODY {
            return Err(protocol_error(
                "a DSS chain past the ceiling a connection is read for",
            ));
        }
        let mut bytes = vec![0u8; carried];
        self.exact(&mut bytes, "a DSS")?;
        Ok(bytes)
    }

    fn exact(&mut self, into: &mut [u8], what: &str) -> Result<()> {
        self.reader
            .read_exact(into)
            .map_err(|e| classify(&format!("reading {what}"), &e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_shares_a_correlator_with_its_objects_and_marks_its_end() {
        let command = Object::new(0x200A, vec![1]);
        let statement = Object::new(0x2414, vec![2]);
        let commit = Object::new(0x200E, Vec::new());
        let written = Chain::new()
            .request(&command)
            .object(&statement)
            .request(&commit)
            .encode();
        assert_eq!(&written[..6], &[0, 11, 0xD0, 0x51, 0, 1], "chained, same");
        assert_eq!(&written[11..17], &[0, 11, 0xD0, 0x43, 0, 1], "chained");
        assert_eq!(&written[22..28], &[0, 10, 0xD0, 0x01, 0, 2], "the end");
    }
}
