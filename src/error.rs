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
    ConnRej,
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
                SrtError::ConnRej => ErrorKind::ConnectionRefused,
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
            srt::SRT_ERRNO::SRT_ECONNREJ => SrtError::ConnRej,
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

fn error_msg(err: &SrtError) -> &str {
    match err {
       SrtError::Unknown => "Internal error when setting the right error code",
       SrtError::Success => "The value set when the last error was cleared and no error has occurred since then",
       SrtError::ConnSetup => "General setup error resulting from internal system state",
       SrtError::NoServer => "Connection timed out while attempting to connect to the remote address",
       SrtError::ConnRej => "Connection has been rejected",
       SrtError::SockFail => "An error occurred when trying to call a system function on an internally used UDP socket",
       SrtError::SecFail => "A possible tampering with the handshake packets was detected, or encryption request wasn't properly fulfilled.",
       SrtError::Closed => "A socket that was vital for an operation called in blocking mode has been closed during the operation",
       SrtError::ConnFail => "General connection failure of unknown details",
       SrtError::ConnLost => "The socket was properly connected, but the connection has been broken",
       SrtError::NoConn => "The socket is not connected",
       SrtError::Resource => "System or standard library error reported unexpectedly for unknown purpose",
       SrtError::Thread => "System was unable to spawn a new thread when requried",
       SrtError::NoBuf => "System was unable to allocate memory for buffers",
       SrtError::SysObj => "System was unable to allocate system specific objects",
       SrtError::File => "General filesystem error (for functions operating with file transmission)",
       SrtError::InvRdOff => "Failure when trying to read from a given position in the file",
       SrtError::RdPerm => "Read permission was denied when trying to read from file",
       SrtError::InvWrOff => "Failed to set position in the written file",
       SrtError::WrPerm => "Write permission was denied when trying to write to a file",
       SrtError::InvOp => "Invalid operation performed for the current state of a socket",
       SrtError::BoundSock => "The socket is currently bound and the required operation cannot be performed in this state",
       SrtError::ConnSock => "The socket is currently connected and therefore performing the required operation is not possible",
       SrtError::InvParam => "Call parameters for API functions have some requirements that were not satisfied",
       SrtError::InvSock => "The API function required an ID of an entity (socket or group) and it was invalid",
       SrtError::UnboundSock => "The operation to be performed on a socket requires that it first be explicitly bound",
       SrtError::NoListen => "The socket passed for the operation is required to be in the listen state",
       SrtError::RdvNoServ => "The required operation cannot be performed when the socket is set to rendezvous mode",
       SrtError::RdvUnbound => "An attempt was made to connect to a socket set to rendezvous mode that was not first bound",
       SrtError::InvalMsgApi => "The function was used incorrectly in the message API",
       SrtError::InvalBufferApi => "The function was used incorrectly in the stream (buffer) API",
       SrtError::DupListen => "The port tried to be bound for listening is already busy",
       SrtError::LargeMsg => "Size exceeded",
       SrtError::InvPollId => "The epoll ID passed to an epoll function is invalid",
       SrtError::PollEmpty => "The epoll container currently has no subscribed sockets",
       SrtError::AsyncFail => "General asynchronous failure (not in use currently)",
       SrtError::AsyncSnd => "Sending operation is not ready to perform",
       SrtError::AsyncRcv => "Receiving operation is not ready to perform",
       SrtError::Timeout => "The operation timed out",
       SrtError::Congest => "With SRTO_TSBPDMODE and SRTO_TLPKTDROP set to true, some packets were dropped by sender",
        SrtError::PeerErr => "Receiver peer is writing to a file that the agent is sending",
    }
}
