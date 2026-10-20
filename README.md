# xmip-core-transport-db2

IBM DB2 transport: one row of a query is one Stream, a send is one INSERT;
DRDA over TCP with the user ID and password security mechanism, TLS through
the estate's own behind the `tls` feature. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).
A transport only: DB2 is never a Xmip Storage server.

## The wire

DRDA, The Open Group's Distributed Relational Database Architecture,
Version 5: DSS framing, DDM commands and replies, FD:OCA rows. Pure Rust; no
IBM client library and no ODBC. A server listens on port 50000 unless the
address names another.

- **Login**: `EXCSAT` (SQLAM level 11, Unicode manager 1208), `ACCSEC`,
  `SECCHK` and `ACCRDB`, the client's numbers in Intel order (`QTDSQLX86`)
  and its strings in UTF-8. DDM names travel in EBCDIC code page 500, as DB2's
  own clients send them.
- **Security mechanism 3** (`USRIDPWD`): a user ID and a password. It sends
  the password as it is, so a Location that crosses a network says
  `tls = true`: TLS from the first byte to the server's TLS port
  (`SSL_SVCENAME`), the certificate checked against the operating system's
  trust store, for `tls_name` where given (ADR-0033). The mechanisms that
  encrypt the password inside DRDA (`EUSRIDPWD`, 9) key DES or AES with an
  anonymous Diffie-Hellman exchange that authenticates neither side, and IBM
  marks the server's `SERVER_ENCRYPT` deprecated in favor of TLS; they are not
  spoken. A server that refuses mechanism 3 is told so: its authentication
  must be `SERVER`, the default.
- **Statements**: dynamic SQL in the package every DB2 database binds,
  `NULLID.SYSSH200`. A query is `PRPSQLSTT`, `SQLSTT` and `OPNQRY` in one
  chain, continued with `CNTQRY` under the limited block protocol, then
  committed; a statement is `EXCSQLIMM` with `RDBCMM` chained behind it. DRDA
  has no autocommit, so every call ends its own unit of work.

## Acknowledgement

The Location's query only reads; what consumes a row is the `accept`
statement, run after the row's receive cycle. `accept` (text, receive side,
optional) is a statement — `DELETE FROM inbox WHERE id = ?`, an `UPDATE` of a
status column — with the row's name, the query's first column as the origin
carries it, in place of `?`, written as DB2's string literal
(`transport::sql::accept`), so whatever the column holds stays one value. It
runs on the connection kept for the server and database, and is committed:

- **Accepted**: `accept` runs; the row is consumed once its Stream is Xmip's.
- **Refused**: nothing runs. A refusal is not a consumption: the row is the
  only copy, so it is left where it lies, and this Location does not receive
  it again while its body is unchanged; a row whose body changed is a new
  arrival. The memory is the node process's (`transport::refused`).
- **Failed**: nothing runs, and the next receive reads the row again.

A row whose first column is NULL has no name to bind, and nothing runs for
it. Where `accept` is left out a row's verdict tells the database nothing.

## The column

The SQL it writes and its far end reads is DB2's as `xmip-core-library-sql`
writes it (`sql::DB2`): `"…"` identifiers, `'…'` literals with the quote
doubled, bytes as the binary string constant `BX'…'`. A constant holds at
most 32 672 bytes, so a longer value goes as its pieces concatenated —
`CLOB('…') || CLOB('…')`, `BLOB(BX'…') || …` — up to the 2 097 152 bytes a DB2
statement holds: about 1 MB of binary payload, 2 MB of text.

The table and column of a send target are always quoted, so they name what
the catalog holds: DB2 folds a bare name to upper case, and a table created
as `inbox` is `INBOX/PAYLOAD` in a target. A target is
`db2://host:port/<database>/<table>/<column>`,
`host:port/<database>/<table>/<column>` or `<table>/<column>`.

The payload column holds bytes unless the Location declares otherwise
(ADR-0038). `column = "binary"`, the default, writes every Stream as a binary
constant and reads a value back only as hex digits — what a `VARBINARY`,
`BINARY` or `FOR BIT DATA` column comes back as here, and what `HEX(…)`
answers; `column = "text"` decodes the Stream strictly in its `encoding` and
writes it as a string literal. A value read back is text: characters as
UTF-8, numbers in their decimal form, dates and times as the server spells
them. A large object (`BLOB`, `CLOB`), a graphic string or a decimal float is
refused with what to do: name it in the query as
`CAST(payload AS VARBINARY(32672))` or `VARCHAR(…)`.

A Send Location inserts on a connection logged in once per server and
database and kept (`transport::Pool`); a Receive Location queries on one kept
the same way. Rows are artifacts and this transport claims none of them
(ADR-0024).

## Verification

The tests run against the far end this crate carries (`session.rs`), which
speaks the same DRDA subset — two rows a query block, so a client must
continue a query to read it whole — and, with `--features tls`, over TLS with
a certificate from the estate's self-signed provisioning. No test here runs
against an IBM DB2 server.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
