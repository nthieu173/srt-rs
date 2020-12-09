use std::{
    convert::TryFrom,
    error::Error,
    fmt::{self, Display, Formatter},
    io::{self, ErrorKind},
};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum SrtError {
    Unknown = -1,
    Success = 0,
    ConnSetup = 1000,
    NoServer = 1001,
    ConnRej = 1002,
    SockFail = 1003,
    SecFail = 1004,
    ConnFail = 2000,
    ConnLost = 2001,
    NoConn = 2002,
    Resource = 3000,
    Thread = 3001,
    NoBuf = 3002,
    File = 4000,
    InvRdOff = 4001,
    RdPerm = 4002,
    InvWrOff = 4003,
    WrPerm = 4004,
    InvOp = 5000,
    BoundSock = 5001,
    ConnSock = 5002,
    InvParam = 5003,
    InvSock = 5004,
    UnboundSock = 5005,
    NoListen = 5006,
    RdvNoServ = 5007,
    RdvUnbound = 5008,
    InvalMsgApi = 5009,
    InvalBufferApi = 5010,
    DupListen = 5011,
    LargeMsg = 5012,
    InvPollId = 5013,
    PollEmpty = 5014,
    AsyncFail = 6000,
    AsyncSnd = 6001,
    AsyncRcv = 6002,
    Timeout = 6003,
    Congest = 6004,
    PeerErr = 7000,
}

impl Display for SrtError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} (SRT error {})", *self as i32, error_msg(self))
    }
}

impl Error for SrtError {}

pub fn wrap_result<T>(ok: T, err_no: i32) -> Result<T, SrtError> {
    if let Ok(e) = SrtError::try_from(err_no) {
        return match e {
            SrtError::Success => Ok(ok),
            e => Err(e),
        };
    }
    unreachable!(format!("SRT error code not found: {}", err_no));
}

impl From<SrtError> for io::Error {
    fn from(e: SrtError) -> Self {
        io::Error::new(
            match e {
                SrtError::Unknown => ErrorKind::Other,
                SrtError::Success => ErrorKind::Other,
                SrtError::ConnSetup => ErrorKind::ConnectionRefused,
                SrtError::NoServer => ErrorKind::ConnectionRefused,
                SrtError::ConnRej => ErrorKind::ConnectionRefused,
                SrtError::SockFail => ErrorKind::AddrNotAvailable,
                SrtError::SecFail => ErrorKind::ConnectionRefused,
                SrtError::ConnFail => ErrorKind::ConnectionRefused,
                SrtError::ConnLost => ErrorKind::ConnectionAborted,
                SrtError::NoConn => ErrorKind::NotConnected,
                SrtError::Resource => ErrorKind::Other,
                SrtError::Thread => ErrorKind::Other,
                SrtError::NoBuf => ErrorKind::Other,
                SrtError::File => ErrorKind::NotFound,
                SrtError::InvRdOff => ErrorKind::InvalidInput,
                SrtError::RdPerm => ErrorKind::PermissionDenied,
                SrtError::InvWrOff => ErrorKind::InvalidInput,
                SrtError::WrPerm => ErrorKind::PermissionDenied,
                SrtError::InvOp => ErrorKind::InvalidInput,
                SrtError::BoundSock => ErrorKind::AddrInUse,
                SrtError::ConnSock => ErrorKind::AddrInUse,
                SrtError::InvParam => ErrorKind::InvalidInput,
                SrtError::InvSock => ErrorKind::AddrNotAvailable,
                SrtError::UnboundSock => ErrorKind::NotConnected,
                SrtError::NoListen => ErrorKind::InvalidInput,
                SrtError::RdvNoServ => ErrorKind::ConnectionRefused,
                SrtError::RdvUnbound => ErrorKind::ConnectionRefused,
                SrtError::InvalMsgApi => ErrorKind::InvalidInput,
                SrtError::InvalBufferApi => ErrorKind::InvalidInput,
                SrtError::DupListen => ErrorKind::AddrInUse,
                SrtError::LargeMsg => ErrorKind::Other,
                SrtError::InvPollId => ErrorKind::AddrNotAvailable,
                SrtError::PollEmpty => ErrorKind::Other,
                SrtError::AsyncFail => ErrorKind::WouldBlock,
                SrtError::AsyncSnd => ErrorKind::WouldBlock,
                SrtError::AsyncRcv => ErrorKind::WouldBlock,
                SrtError::Timeout => ErrorKind::TimedOut,
                SrtError::Congest => ErrorKind::Other,
                SrtError::PeerErr => ErrorKind::Other,
            },
            e,
        )
    }
}

impl TryFrom<i32> for SrtError {
    type Error = ();

    fn try_from(err_no: i32) -> Result<Self, Self::Error> {
        match err_no {
            -1 => Ok(SrtError::Unknown),
            0 => Ok(SrtError::Success),
            1000 => Ok(SrtError::ConnSetup),
            1001 => Ok(SrtError::NoServer),
            1002 => Ok(SrtError::ConnRej),
            1003 => Ok(SrtError::SockFail),
            1004 => Ok(SrtError::SecFail),
            2000 => Ok(SrtError::ConnFail),
            2001 => Ok(SrtError::ConnLost),
            2002 => Ok(SrtError::NoConn),
            3000 => Ok(SrtError::Resource),
            3001 => Ok(SrtError::Thread),
            3002 => Ok(SrtError::NoBuf),
            4000 => Ok(SrtError::File),
            4001 => Ok(SrtError::InvRdOff),
            4002 => Ok(SrtError::RdPerm),
            4003 => Ok(SrtError::InvWrOff),
            4004 => Ok(SrtError::WrPerm),
            5000 => Ok(SrtError::InvOp),
            5001 => Ok(SrtError::BoundSock),
            5002 => Ok(SrtError::ConnSock),
            5003 => Ok(SrtError::InvParam),
            5004 => Ok(SrtError::InvSock),
            5005 => Ok(SrtError::UnboundSock),
            5006 => Ok(SrtError::NoListen),
            5007 => Ok(SrtError::RdvNoServ),
            5008 => Ok(SrtError::RdvUnbound),
            5009 => Ok(SrtError::InvalMsgApi),
            5010 => Ok(SrtError::InvalBufferApi),
            5011 => Ok(SrtError::DupListen),
            5012 => Ok(SrtError::LargeMsg),
            5013 => Ok(SrtError::InvPollId),
            5014 => Ok(SrtError::PollEmpty),
            6000 => Ok(SrtError::AsyncFail),
            6001 => Ok(SrtError::AsyncSnd),
            6002 => Ok(SrtError::AsyncRcv),
            6003 => Ok(SrtError::Timeout),
            6004 => Ok(SrtError::Congest),
            7000 => Ok(SrtError::PeerErr),
            _ => Err(()),
        }
    }
}

fn error_msg(err: &SrtError) -> &str {
    match err {
        SrtError::Unknown => "Unknown",
        SrtError::Success => "Success",
        SrtError::ConnSetup => "Connection Setup",
        SrtError::NoServer => "No Server",
        SrtError::ConnRej => "Connection Rejected",
        SrtError::SockFail => "Socket Fail",
        SrtError::SecFail => "Security Fail",
        SrtError::ConnFail => "Connection Fail",
        SrtError::ConnLost => "Connnection Lost",
        SrtError::NoConn => "No Connection",
        SrtError::Resource => "System Resource",
        SrtError::Thread => "System Thread",
        SrtError::NoBuf => "No Buffer",
        SrtError::File => "File",
        SrtError::InvRdOff => "Invalid Read Offset",
        SrtError::RdPerm => "Read Fail",
        SrtError::InvWrOff => "Invalid Write Offset",
        SrtError::WrPerm => "Write Fail",
        SrtError::InvOp => "Invalid Operation",
        SrtError::BoundSock => "Bound Socket",
        SrtError::ConnSock => "Connected Socket",
        SrtError::InvParam => "Invalid Parameter",
        SrtError::InvSock => "Invalid Socket",
        SrtError::UnboundSock => "Unbounded Socket",
        SrtError::NoListen => "Not Listening",
        SrtError::RdvNoServ => "Rendezvous No Server",
        SrtError::RdvUnbound => "Rendezvous Unbound",
        SrtError::InvalMsgApi => "Invalid Message API",
        SrtError::InvalBufferApi => "Invalid Buffer API",
        SrtError::DupListen => "Duplicate Listen",
        SrtError::LargeMsg => "Large Message",
        SrtError::InvPollId => "Invalid Poll ID",
        SrtError::PollEmpty => "Poll Empty",
        SrtError::AsyncFail => "Async Fail",
        SrtError::AsyncSnd => "Async Send",
        SrtError::AsyncRcv => "Async Receive",
        SrtError::Timeout => "Timeout",
        SrtError::Congest => "Congestion",
        SrtError::PeerErr => "Peer Error",
    }
}
