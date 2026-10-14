//! The DDM code points this transport speaks: each command, reply message,
//! object and parameter is named by one two-byte number (The Open Group,
//! DRDA Version 5, Volume 3: Distributed Data Management Architecture).

// Commands.
pub const EXCSAT: u16 = 0x1041;
pub const ACCSEC: u16 = 0x106D;
pub const SECCHK: u16 = 0x106E;
pub const ACCRDB: u16 = 0x2001;
pub const CNTQRY: u16 = 0x2006;
pub const EXCSQLIMM: u16 = 0x200A;
pub const OPNQRY: u16 = 0x200C;
pub const PRPSQLSTT: u16 = 0x200D;
pub const RDBCMM: u16 = 0x200E;
pub const RDBRLLBCK: u16 = 0x200F;

// Reply data and reply messages.
pub const EXCSATRD: u16 = 0x1443;
pub const ACCSECRD: u16 = 0x14AC;
pub const SECCHKRM: u16 = 0x1219;
pub const ACCRDBRM: u16 = 0x2201;
pub const OPNQRYRM: u16 = 0x2205;
pub const ENDQRYRM: u16 = 0x220B;
pub const ENDUOWRM: u16 = 0x220C;
pub const QRYNOPRM: u16 = 0x2202;
pub const RDBNACRM: u16 = 0x2204;
pub const RDBNFNRM: u16 = 0x2211;
pub const OPNQFLRM: u16 = 0x2212;
pub const SQLERRRM: u16 = 0x2213;
pub const RDBAFLRM: u16 = 0x221A;
pub const CMDNSPRM: u16 = 0x1250;
pub const PRCCNVRM: u16 = 0x1245;
pub const SYNTAXRM: u16 = 0x124C;
pub const MGRLVLRM: u16 = 0x1210;

// Objects.
pub const SQLSTT: u16 = 0x2414;
pub const SQLCARD: u16 = 0x2408;
pub const SQLDARD: u16 = 0x2411;
pub const QRYDSC: u16 = 0x241A;
pub const QRYDTA: u16 = 0x241B;

// Parameters.
pub const EXTNAM: u16 = 0x115E;
pub const SRVNAM: u16 = 0x116D;
pub const SRVRLSLV: u16 = 0x115A;
pub const SRVCLSNM: u16 = 0x1147;
pub const MGRLVLLS: u16 = 0x1404;
pub const SECMEC: u16 = 0x11A2;
pub const SECCHKCD: u16 = 0x11A4;
pub const USRID: u16 = 0x11A0;
pub const PASSWORD: u16 = 0x11A1;
pub const SVRCOD: u16 = 0x1149;
pub const SRVDGN: u16 = 0x1153;
pub const RDBNAM: u16 = 0x2110;
pub const RDBACCCL: u16 = 0x210F;
pub const PRDID: u16 = 0x112E;
pub const TYPDEFNAM: u16 = 0x002F;
pub const TYPDEFOVR: u16 = 0x0035;
pub const CCSIDSBC: u16 = 0x119C;
pub const CCSIDDBC: u16 = 0x119D;
pub const CCSIDMBC: u16 = 0x119E;
pub const CRRTKN: u16 = 0x2135;
pub const PKGNAMCSN: u16 = 0x2113;
pub const RDBCMTOK: u16 = 0x2105;
pub const RTNSQLDA: u16 = 0x2116;
pub const QRYBLKSZ: u16 = 0x2114;
pub const MAXBLKEXT: u16 = 0x2141;
pub const QRYCLSIMP: u16 = 0x215D;
pub const QRYINSID: u16 = 0x215B;
pub const QRYPRCTYP: u16 = 0x2102;
pub const RTNEXTDTA: u16 = 0x2148;
pub const UOWDSP: u16 = 0x2115;
pub const CODPNT: u16 = 0x000C;

// Managers, named in MGRLVLLS with the level each is spoken at.
pub const AGENT: u16 = 0x1403;
pub const SQLAM: u16 = 0x2407;
pub const RDB: u16 = 0x240F;
pub const SECMGR: u16 = 0x1440;
pub const CMNTCPIP: u16 = 0x1474;
pub const UNICODEMGR: u16 = 0x1C08;
pub const CCSIDMGR: u16 = 0x14CC;

/// The limited block query protocol, as `QRYPRCTYP` names it.
pub const LMTBLKPRC: u16 = 0x2417;
