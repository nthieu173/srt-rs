use libc::{c_char, c_int, c_void, sockaddr};

type SRTSOCKET = c_int;

#[link(name = "srt")]
extern "C" {
    pub fn srt_startup() -> c_int;
    pub fn srt_cleanup() -> c_int;
    pub fn srt_create_socket() -> SRTSOCKET;
    pub fn srt_bind(u: SRTSOCKET, name: *const sockaddr, namelen: c_int) -> c_int;
    pub fn srt_listen(u: SRTSOCKET, backlog: c_int) -> c_int;
    pub fn srt_connect(u: SRTSOCKET, name: *const sockaddr, len: c_int) -> c_int;
    pub fn srt_rendezvous(
        u: SRTSOCKET,
        local_name: *const sockaddr,
        local_len: c_int,
        remote_name: *const sockaddr,
        remote_len: c_int,
    ) -> c_int;
    pub fn srt_close(u: SRTSOCKET) -> c_int;
    pub fn srt_accept(u: SRTSOCKET, addr: *mut sockaddr, addrlen: *mut c_int) -> SRTSOCKET;
    pub fn srt_getpeername(u: SRTSOCKET, name: *mut sockaddr, namelen: *mut c_int) -> c_int;
    pub fn srt_getsockname(u: SRTSOCKET, name: *mut sockaddr, namelen: *mut c_int) -> c_int;
    pub fn srt_getsockflag(
        u: SRTSOCKET,
        opt: SrtSockOpt,
        optval: *mut c_void,
        optlen: *mut c_int,
    ) -> c_int;
    pub fn srt_setsockflag(
        u: SRTSOCKET,
        opt: SrtSockOpt,
        optval: *const c_void,
        optlen: c_int,
    ) -> c_int;
    pub fn srt_send(u: SRTSOCKET, buf: *const c_char, len: c_int) -> c_int;
    pub fn srt_recv(u: SRTSOCKET, buf: *mut c_char, len: c_int) -> c_int;
}

#[repr(C)]
pub enum SrtSockOpt {
    Mss = 0,            // the Maximum Transfer Unit
    SndSyn = 1,         // if sending is blocking
    RcvSyn = 2,         // if receiving is blocking
    ISN = 3, // Initial Sequence Number (valid only after srt_connect or srt_accept-ed sockets)
    FC = 4,  // Flight flag size (window size)
    SndBuf = 5, // maximum buffer in sending queue
    RcvBuf = 6, // UDT receiving buffer size
    Linger = 7, // waiting for unsent data when closing
    UdpSndBuf = 8, // UDP sending buffer size
    UdpRcvBuf = 9, // UDP receiving buffer size
    Rendezvous = 12, // rendezvous connection mode
    SndTimeO = 13, // send() timeout
    RcvTimeO = 14, // recv() timeout
    ReuseAddr = 15, // reuse an existing port or create a new one
    MaxBW = 16, // maximum bandwidth (bytes per second) that the connection can use
    State = 17, // current socket state, see UDTSTATUS, read only
    Event = 18, // current available events associated with the socket
    SndData = 19, // size of data in the sending buffer
    RcvData = 20, // size of data available for recv
    TsbPdMode = 22, // Enable/Disable TsbPd. Enable -> Tx set origin timestamp, Rx deliver packet at origin time + delay
    InputBW = 24,   // Estimated input stream rate.
    OHeadBW, // MaxBW ceiling based on % over input stream rate. Applies when UDT_MAXBW=0 (auto).
    Passphrase = 26, // Crypto PBKDF2 Passphrase size[0,10..64] 0:disable crypto
    PBKeyLen, // Crypto key len in bytes {16,24,32} Default: 16 (128-bit)
    IpTtl = 29, // IP Time To Live (passthru for system sockopt IPPROTO_IP/IP_TTL)
    IpTos,   // IP Type of Service (passthru for system sockopt IPPROTO_IP/IP_TOS)
    TlPktDrop = 31, // Enable receiver pkt drop
    SndDropDelay = 32, // Extra delay towards latency for sender TLPKTDROP decision (-1 to off)
    NakReport = 33, // Enable receiver to send periodic NAK reports
    Version = 34, // Local SRT Version
    PeerVersion, // Peer SRT Version (from SRT Handshake)
    ConnTimeO = 36, // Connect timeout in msec. Ccaller default: 3000, rendezvous (x 10)
    SndKmState = 40, // (GET) the current state of the encryption at the peer side
    RcvKmState, // (GET) the current state of the encryption at the agent side
    LossMaxTtl, // Maximum possible packet reorder tolerance (number of packets to receive after loss to send lossreport)
    RcvLatency, // TsbPd receiver delay (mSec) to absorb burst of missed packet retransmission
    PeerLatency, // Minimum value of the TsbPd receiver delay (mSec) for the opposite side (peer)
    MinVersion, // Minimum SRT version needed for the peer (peers with less version will get connection reject)
    StreamId,   // A string set to a socket and passed to the listener's accepted socket
    Congestion, // Congestion controller type selection
    MessageApi, // In File mode, use message API (portions of data with boundaries)
    PayloadSize, // Maximum payload size sent in one UDP packet (0 if unlimited)
    TransType = 50, // Transmission type (set of options required for given transmission type)
    KmRrefreshRate, // After sending how many packets the encryption key should be flipped to the new key
    KmPreAnnounce, // How many packets before key flip the new key is annnounced and after key flip the old one decommissioned
    EnforcedEncryption, // Connection to be rejected or quickly broken when one side encryption set or bad password
    Ipv6Only,           // IPV6_V6ONLY mode
    PeerIdleTimeO,      // Peer-idle timeout (max time of silence heard from peer) in [ms]
    // (some space left)
    PacketFilter = 60, // Add and configure a packet filter
}
