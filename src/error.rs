use libsrt_sys as srt;

use std::{
    convert::From,
    error::Error,
    fmt::{self, Display, Formatter},
    io::{self, ErrorKind},
    os::raw::c_int,
};

#[derive(Clone, Copy, Debug)]
pub enum SrtError {
    Unknown,
    Success,
    ConnSetup,
    NoServer,
    ConnRej(SrtRejectReason),
    SockFail,
    SecFail,
    Closed,
    ConnFail,
    ConnLost,
    NoConn,
    Resource,
    Thread,
    NoBuf,
    SysObj,
    File,
    InvRdOff,
    RdPerm,
    InvWrOff,
    WrPerm,
    InvOp,
    BoundSock,
    ConnSock,
    InvParam,
    InvSock,
    UnboundSock,
    NoListen,
    RdvNoServ,
    RdvUnbound,
    InvalMsgApi,
    InvalBufferApi,
    DupListen,
    LargeMsg,
    InvPollId,
    PollEmpty,
    AsyncFail,
    AsyncSnd,
    AsyncRcv,
    Timeout,
    Congest,
    PeerErr,
}

impl Display for SrtError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", error_msg(self))
    }
}

impl Error for SrtError {}

pub fn handle_result<T>(ok: T, return_code: i32) -> Result<T, SrtError> {
    match return_code {
        0 => Ok(ok),
        -1 => {
            let mut _errno_loc = 0;
            let err_no = unsafe { srt::srt_getlasterror(&mut _errno_loc as *mut c_int) };
            let err = srt::SRT_ERRNO(err_no);
            match SrtError::from(err) {
                SrtError::Success => Ok(ok),
                e => Err(e),
            }
        }
        e => unreachable!("unrecognized return code {}", e),
    }
}

impl From<SrtError> for io::Error {
    fn from(e: SrtError) -> Self {
        io::Error::new(
            match e {
                SrtError::Unknown => ErrorKind::Other,
                SrtError::Success => ErrorKind::Other,
                SrtError::ConnSetup => ErrorKind::ConnectionRefused,
                SrtError::NoServer => ErrorKind::ConnectionRefused,
                SrtError::ConnRej(_) => ErrorKind::ConnectionRefused,
                SrtError::SockFail => ErrorKind::AddrNotAvailable,
                SrtError::SecFail => ErrorKind::ConnectionRefused,
                SrtError::ConnFail => ErrorKind::ConnectionRefused,
                SrtError::Closed => ErrorKind::AddrNotAvailable,
                SrtError::ConnLost => ErrorKind::ConnectionAborted,
                SrtError::NoConn => ErrorKind::NotConnected,
                SrtError::Resource => ErrorKind::Other,
                SrtError::Thread => ErrorKind::Other,
                SrtError::NoBuf => ErrorKind::Other,
                SrtError::SysObj => ErrorKind::Other,
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

impl From<srt::SRT_ERRNO> for SrtError {
    fn from(err_no: srt::SRT_ERRNO) -> Self {
        match err_no {
            srt::SRT_ERRNO::SRT_EUNKNOWN => SrtError::Unknown,
            srt::SRT_ERRNO::SRT_SUCCESS => SrtError::Success,
            srt::SRT_ERRNO::SRT_ECONNSETUP => SrtError::ConnSetup,
            srt::SRT_ERRNO::SRT_ENOSERVER => SrtError::NoServer,
            srt::SRT_ERRNO::SRT_ECONNREJ => SrtError::ConnRej(SrtRejectReason::Unknown),
            srt::SRT_ERRNO::SRT_ESOCKFAIL => SrtError::SockFail,
            srt::SRT_ERRNO::SRT_ESECFAIL => SrtError::SecFail,
            srt::SRT_ERRNO::SRT_ESCLOSED => SrtError::Closed,
            srt::SRT_ERRNO::SRT_ECONNFAIL => SrtError::ConnFail,
            srt::SRT_ERRNO::SRT_ECONNLOST => SrtError::ConnLost,
            srt::SRT_ERRNO::SRT_ENOCONN => SrtError::NoConn,
            srt::SRT_ERRNO::SRT_ERESOURCE => SrtError::Resource,
            srt::SRT_ERRNO::SRT_ETHREAD => SrtError::Thread,
            srt::SRT_ERRNO::SRT_ENOBUF => SrtError::NoBuf,
            srt::SRT_ERRNO::SRT_ESYSOBJ => SrtError::SysObj,
            srt::SRT_ERRNO::SRT_EFILE => SrtError::File,
            srt::SRT_ERRNO::SRT_EINVRDOFF => SrtError::InvRdOff,
            srt::SRT_ERRNO::SRT_ERDPERM => SrtError::RdPerm,
            srt::SRT_ERRNO::SRT_EINVWROFF => SrtError::InvWrOff,
            srt::SRT_ERRNO::SRT_EWRPERM => SrtError::WrPerm,
            srt::SRT_ERRNO::SRT_EINVOP => SrtError::InvOp,
            srt::SRT_ERRNO::SRT_EBOUNDSOCK => SrtError::BoundSock,
            srt::SRT_ERRNO::SRT_ECONNSOCK => SrtError::ConnSock,
            srt::SRT_ERRNO::SRT_EINVPARAM => SrtError::InvParam,
            srt::SRT_ERRNO::SRT_EINVSOCK => SrtError::InvSock,
            srt::SRT_ERRNO::SRT_EUNBOUNDSOCK => SrtError::UnboundSock,
            srt::SRT_ERRNO::SRT_ENOLISTEN => SrtError::NoListen,
            srt::SRT_ERRNO::SRT_ERDVNOSERV => SrtError::RdvNoServ,
            srt::SRT_ERRNO::SRT_ERDVUNBOUND => SrtError::RdvUnbound,
            srt::SRT_ERRNO::SRT_EINVALMSGAPI => SrtError::InvalMsgApi,
            srt::SRT_ERRNO::SRT_EINVALBUFFERAPI => SrtError::InvalBufferApi,
            srt::SRT_ERRNO::SRT_EDUPLISTEN => SrtError::DupListen,
            srt::SRT_ERRNO::SRT_ELARGEMSG => SrtError::LargeMsg,
            srt::SRT_ERRNO::SRT_EINVPOLLID => SrtError::InvPollId,
            srt::SRT_ERRNO::SRT_EPOLLEMPTY => SrtError::PollEmpty,
            srt::SRT_ERRNO::SRT_EASYNCFAIL => SrtError::AsyncFail,
            srt::SRT_ERRNO::SRT_EASYNCSND => SrtError::AsyncSnd,
            srt::SRT_ERRNO::SRT_EASYNCRCV => SrtError::AsyncRcv,
            srt::SRT_ERRNO::SRT_ETIMEOUT => SrtError::Timeout,
            srt::SRT_ERRNO::SRT_ECONGEST => SrtError::Congest,
            srt::SRT_ERRNO::SRT_EPEERERR => SrtError::PeerErr,
            _ => unreachable!("unrecognized error no"),
        }
    }
}

fn error_msg(err: &SrtError) -> String {
    match err {
        SrtError::Unknown => "Internal error when setting the right error code".to_string(),
        SrtError::Success => "The value set when the last error was cleared and no error has occurred since then".to_string(),
        SrtError::ConnSetup => "General setup error resulting from internal system state".to_string(),
        SrtError::NoServer => "Connection timed out while attempting to connect to the remote address".to_string(),
        SrtError::ConnRej(reason) => format!("Connection has been rejected: {:?}", reason),
        SrtError::SockFail => "An error occurred when trying to call a system function on an internally used UDP socket".to_string(),
        SrtError::SecFail => "A possible tampering with the handshake packets was detected, or encryption request wasn't properly fulfilled.".to_string(),
        SrtError::Closed => "A socket that was vital for an operation called in blocking mode has been closed during the operation".to_string(),
        SrtError::ConnFail => "General connection failure of unknown details".to_string(),
        SrtError::ConnLost => "The socket was properly connected, but the connection has been broken".to_string(),
        SrtError::NoConn => "The socket is not connected".to_string(),
        SrtError::Resource => "System or standard library error reported unexpectedly for unknown purpose".to_string(),
        SrtError::Thread => "System was unable to spawn a new thread when requried".to_string(),
        SrtError::NoBuf => "System was unable to allocate memory for buffers".to_string(),
        SrtError::SysObj => "System was unable to allocate system specific objects".to_string(),
        SrtError::File => "General filesystem error (for functions operating with file transmission)".to_string(),
        SrtError::InvRdOff => "Failure when trying to read from a given position in the file".to_string(),
        SrtError::RdPerm => "Read permission was denied when trying to read from file".to_string(),
        SrtError::InvWrOff => "Failed to set position in the written file".to_string(),
        SrtError::WrPerm => "Write permission was denied when trying to write to a file".to_string(),
        SrtError::InvOp => "Invalid operation performed for the current state of a socket".to_string(),
        SrtError::BoundSock => "The socket is currently bound and the required operation cannot be performed in this state".to_string(),
        SrtError::ConnSock => "The socket is currently connected and therefore performing the required operation is not possible".to_string(),
        SrtError::InvParam => "Call parameters for API functions have some requirements that were not satisfied".to_string(),
        SrtError::InvSock => "The API function required an ID of an entity (socket or group) and it was invalid".to_string(),
        SrtError::UnboundSock => "The operation to be performed on a socket requires that it first be explicitly bound".to_string(),
        SrtError::NoListen => "The socket passed for the operation is required to be in the listen state".to_string(),
        SrtError::RdvNoServ => "The required operation cannot be performed when the socket is set to rendezvous mode".to_string(),
        SrtError::RdvUnbound => "An attempt was made to connect to a socket set to rendezvous mode that was not first bound".to_string(),
        SrtError::InvalMsgApi => "The function was used incorrectly in the message API".to_string(),
        SrtError::InvalBufferApi => "The function was used incorrectly in the stream (buffer) API".to_string(),
        SrtError::DupListen => "The port tried to be bound for listening is already busy".to_string(),
        SrtError::LargeMsg => "Size exceeded".to_string(),
        SrtError::InvPollId => "The epoll ID passed to an epoll function is invalid".to_string(),
        SrtError::PollEmpty => "The epoll container currently has no subscribed sockets".to_string(),
        SrtError::AsyncFail => "General asynchronous failure (not in use currently)".to_string(),
        SrtError::AsyncSnd => "Sending operation is not ready to perform".to_string(),
        SrtError::AsyncRcv => "Receiving operation is not ready to perform".to_string(),
        SrtError::Timeout => "The operation timed out".to_string(),
        SrtError::Congest => "With SRTO_TSBPDMODE and SRTO_TLPKTDROP set to true, some packets were dropped by sender".to_string(),
        SrtError::PeerErr => "Receiver peer is writing to a file that the agent is sending".to_string(),
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SrtRejectReason {
    Unknown,    // initial set when in progress
    System,     // broken due to system function error
    Peer,       // connection was rejected by peer
    Resource,   // internal problem with resource allocation
    Rogue,      // incorrect data in handshake messages
    Backlog,    // listener's backlog exceeded
    IPE,        // internal program error
    Close,      // socket is closing
    Version,    // peer is older version than agent's minimum set
    RdvCookie,  // rendezvous cookie collision
    BadSecret,  // wrong password
    Unsecure,   // password required or unexpected
    MessageAPI, // streamapi/messageapi collision
    Congestion, // incompatible congestion-controller type
    Filter,     // incompatible packet filter
    Group,      // incompatible group
    Timeout,    // connection timeout
}

impl From<srt::SRT_REJECT_REASON> for SrtRejectReason {
    fn from(reject_reason: srt::SRT_REJECT_REASON) -> Self {
        match reject_reason {
            srt::SRT_REJECT_REASON::SRT_REJ_UNKNOWN => SrtRejectReason::Unknown, // initial set when in progress
            srt::SRT_REJECT_REASON::SRT_REJ_SYSTEM => SrtRejectReason::System,
            srt::SRT_REJECT_REASON::SRT_REJ_PEER => SrtRejectReason::Peer,
            srt::SRT_REJECT_REASON::SRT_REJ_RESOURCE => SrtRejectReason::Resource,
            srt::SRT_REJECT_REASON::SRT_REJ_ROGUE => SrtRejectReason::Rogue,
            srt::SRT_REJECT_REASON::SRT_REJ_BACKLOG => SrtRejectReason::Backlog,
            srt::SRT_REJECT_REASON::SRT_REJ_IPE => SrtRejectReason::IPE,
            srt::SRT_REJECT_REASON::SRT_REJ_CLOSE => SrtRejectReason::Close,
            srt::SRT_REJECT_REASON::SRT_REJ_VERSION => SrtRejectReason::Version,
            srt::SRT_REJECT_REASON::SRT_REJ_RDVCOOKIE => SrtRejectReason::RdvCookie,
            srt::SRT_REJECT_REASON::SRT_REJ_BADSECRET => SrtRejectReason::BadSecret,
            srt::SRT_REJECT_REASON::SRT_REJ_UNSECURE => SrtRejectReason::Unsecure,
            srt::SRT_REJECT_REASON::SRT_REJ_MESSAGEAPI => SrtRejectReason::MessageAPI,
            srt::SRT_REJECT_REASON::SRT_REJ_CONGESTION => SrtRejectReason::Congestion,
            srt::SRT_REJECT_REASON::SRT_REJ_FILTER => SrtRejectReason::Filter,
            srt::SRT_REJECT_REASON::SRT_REJ_GROUP => SrtRejectReason::Group,
            srt::SRT_REJECT_REASON::SRT_REJ_TIMEOUT => SrtRejectReason::Timeout,
            _ => unreachable!("unrecognized SRT_REJECT_REASON"),
        }
    }
}
