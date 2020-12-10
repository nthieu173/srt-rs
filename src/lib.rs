pub mod error;
use error::SrtError;
use libsrt_sys as srt;
use srt::sockaddr;

#[cfg(target_os = "linux")]
use libc::{in6_addr, in_addr, linger, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6};

#[cfg(target_os = "windows")]
use winapi::{
    shared::{
        in6addr::in6_addr,
        inaddr::in_addr,
        ws2def::{AF_INET, AF_INET6, SOCKADDR_IN as sockaddr_in},
        ws2ipdef::{SOCKADDR_IN6_LH_u, SOCKADDR_IN6_LH as sockaddr_in6},
    },
    um::winsock2::linger,
};

use std::{
    ffi::c_void,
    io::{self, Read, Write},
    iter::FromIterator,
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    os::raw::{c_char, c_int},
};

type Result<T> = std::result::Result<T, SrtError>;

pub fn startup() -> Result<()> {
    let result = unsafe { srt::srt_startup() };
    error::handle_result((), result)
}

pub fn cleanup() -> Result<()> {
    let result = unsafe { srt::srt_cleanup() };
    error::handle_result((), result)
}

pub struct SrtBuilder {
    opt_vec: Vec<SrtPreConnectOpt>,
}

impl SrtBuilder {
    pub fn new() -> Self {
        Self {
            opt_vec: Vec::new(),
        }
    }
    pub fn connect<A: ToSocketAddrs, B: ToSocketAddrs>(
        self,
        local: A,
        remote: B,
    ) -> Result<SrtSocket> {
        let socket = SrtSocket::new();
        self.config_socket(&socket)?;
        let socket = socket.bind(local)?;
        socket.connect(remote)?;
        Ok(socket)
    }
    pub fn listen<A: ToSocketAddrs>(self, addr: A, backlog: i32) -> Result<SrtSocket> {
        let socket = SrtSocket::new();
        self.config_socket(&socket)?;
        let socket = socket.bind(addr)?;
        socket.listen(backlog)?;
        Ok(socket)
    }
    pub fn rendezvous<A: ToSocketAddrs, B: ToSocketAddrs>(
        self,
        local: A,
        remote: B,
    ) -> Result<SrtSocket> {
        let socket = SrtSocket::new();
        self.config_socket(&socket)?;
        socket.rendezvous(local, remote)?;
        Ok(socket)
    }
}

impl SrtBuilder {
    pub fn set_connection_timeout(mut self, msecs: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::ConnTimeO(msecs));
        self
    }
    pub fn set_flight_flag_size(mut self, packets: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::FC(packets));
        self
    }
    pub fn set_ip_type_of_service(mut self, tos: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::IpTos(tos));
        self
    }
    pub fn set_ipv4_time_to_live(mut self, hops: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::IpTtl(hops));
        self
    }
    pub fn set_ipv6_only(mut self, value: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::Ipv6Only(value));
        self
    }
    pub fn set_km_refresh_rate(mut self, packets: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::KmRefreshRate(packets));
        self
    }
    pub fn set_km_preannounce(mut self, packets: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::KmPreAnnounce(packets));
        self
    }
    pub fn set_linger(mut self, secs: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::Linger(secs));
        self
    }
    pub fn set_max_reorder_tolerance(mut self, packets: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::LossMaxTtl(packets));
        self
    }
    pub fn set_max_bandwith(mut self, bytes_per_sec: i64) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::MaxBW(bytes_per_sec));
        self
    }
    pub fn set_message_api(mut self, enable: bool) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::MessageApi(enable));
        self
    }
    pub fn set_min_version(mut self, version: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::MinVersion(version));
        self
    }
    pub fn set_mss(mut self, bytes: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::Mss(bytes));
        self
    }
    pub fn set_nak_report(mut self, enable: bool) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::NakReport(enable));
        self
    }
    pub fn set_packet_filter(mut self, filter: String) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::PacketFilter(filter));
        self
    }
    pub fn set_passphrase(mut self, passphrase: String) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::Passphrase(passphrase));
        self
    }
    pub fn set_payload_size(mut self, bytes: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::PayloadSize(bytes));
        self
    }
    pub fn set_encryption_key_length(mut self, bytes: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::PBKeyLen(bytes));
        self
    }
    pub fn set_peer_idle_timeout(mut self, msecs: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::PeerIdleTimeO(msecs));
        self
    }
    pub fn set_peer_latency(mut self, msecs: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::PeerLatency(msecs));
        self
    }
    pub fn set_receive_buffer(mut self, bytes: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::RcvBuf(bytes));
        self
    }
    pub fn set_receive_latency(mut self, msecs: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::RcvLatency(msecs));
        self
    }
    pub fn set_receive_blocking(mut self, blocking: bool) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::RcvSyn(blocking));
        self
    }
    pub fn set_rendezvous(mut self, rendezvous: bool) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::Rendezvous(rendezvous));
        self
    }
    pub fn set_reuse_address(mut self, reuse_address: bool) -> Self {
        self.opt_vec
            .push(SrtPreConnectOpt::ReuseAddr(reuse_address));
        self
    }
    pub fn set_live_congestion_controller(mut self) -> Self {
        self.opt_vec
            .push(SrtPreConnectOpt::Congestion(SrtCongestionController::Live));
        self
    }
    pub fn set_file_congestion_controller(mut self) -> Self {
        self.opt_vec
            .push(SrtPreConnectOpt::Congestion(SrtCongestionController::File));
        self
    }
    pub fn set_send_buffer(mut self, bytes: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::SndBuf(bytes));
        self
    }
    pub fn set_send_drop_delay(mut self, msecs: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::SndDropDelay(msecs));
        self
    }
    pub fn set_stream_id(mut self, id: String) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::StreamId(id));
        self
    }
    pub fn set_enforced_encryption(mut self, enforced: bool) -> Self {
        self.opt_vec
            .push(SrtPreConnectOpt::EnforcedEncryption(enforced));
        self
    }
    pub fn set_too_late_packet_drop(mut self, enable: bool) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::TlPktDrop(enable));
        self
    }
    pub fn set_live_transmission_type(mut self) -> Self {
        self.opt_vec
            .push(SrtPreConnectOpt::TransType(SrtTransmissionType::Live));
        self
    }
    pub fn set_file_transmission_type(mut self) -> Self {
        self.opt_vec
            .push(SrtPreConnectOpt::TransType(SrtTransmissionType::File));
        self
    }
    pub fn set_timestamp_based_packet_delivery_mode(mut self, enable: bool) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::TsbPdMode(enable));
        self
    }
    pub fn set_udp_send_buffer(mut self, bytes: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::UdpSndBuf(bytes));
        self
    }
    pub fn set_udp_receive_buffer(mut self, bytes: i32) -> Self {
        self.opt_vec.push(SrtPreConnectOpt::UdpRcvBuf(bytes));
        self
    }
    fn config_socket(self, socket: &SrtSocket) -> Result<()> {
        for opt in self.opt_vec {
            match opt {
                SrtPreConnectOpt::ConnTimeO(value) => socket.set_connection_timeout(value)?,
                SrtPreConnectOpt::FC(value) => socket.set_flight_flag_size(value)?,
                SrtPreConnectOpt::IpTos(value) => socket.set_ip_type_of_service(value)?,
                SrtPreConnectOpt::IpTtl(value) => socket.set_ipv4_time_to_live(value)?,
                SrtPreConnectOpt::Ipv6Only(value) => socket.set_ipv6_only(value)?,
                SrtPreConnectOpt::KmRefreshRate(value) => socket.set_km_refresh_rate(value)?,
                SrtPreConnectOpt::KmPreAnnounce(value) => socket.set_km_preannounce(value)?,
                SrtPreConnectOpt::Linger(value) => socket.set_linger(value)?,
                SrtPreConnectOpt::LossMaxTtl(value) => socket.set_max_reorder_tolerance(value)?,
                SrtPreConnectOpt::MaxBW(value) => socket.set_max_bandwith(value)?,
                SrtPreConnectOpt::MessageApi(value) => socket.set_message_api(value)?,
                SrtPreConnectOpt::MinVersion(value) => socket.set_min_version(value)?,
                SrtPreConnectOpt::Mss(value) => socket.set_mss(value)?,
                SrtPreConnectOpt::NakReport(value) => socket.set_nak_report(value)?,
                SrtPreConnectOpt::PacketFilter(value) => socket.set_packet_filter(&value)?,
                SrtPreConnectOpt::Passphrase(value) => socket.set_passphrase(&value)?,
                SrtPreConnectOpt::PayloadSize(value) => socket.set_payload_size(value)?,
                SrtPreConnectOpt::PBKeyLen(value) => socket.set_encryption_key_length(value)?,
                SrtPreConnectOpt::PeerIdleTimeO(value) => socket.set_peer_idle_timeout(value)?,
                SrtPreConnectOpt::PeerLatency(value) => socket.set_peer_latency(value)?,
                SrtPreConnectOpt::RcvBuf(value) => socket.set_receive_buffer(value)?,
                SrtPreConnectOpt::RcvLatency(value) => socket.set_receive_latency(value)?,
                SrtPreConnectOpt::RcvSyn(value) => socket.set_receive_blocking(value)?,
                SrtPreConnectOpt::Rendezvous(value) => socket.set_rendezvous(value)?,
                SrtPreConnectOpt::ReuseAddr(value) => socket.set_reuse_address(value)?,
                SrtPreConnectOpt::Congestion(value) => socket.set_congestion_controller(value)?,
                SrtPreConnectOpt::SndBuf(value) => socket.set_send_buffer(value)?,
                SrtPreConnectOpt::SndDropDelay(value) => socket.set_send_drop_delay(value)?,
                SrtPreConnectOpt::StreamId(value) => socket.set_stream_id(&value)?,
                SrtPreConnectOpt::EnforcedEncryption(value) => {
                    socket.set_enforced_encryption(value)?
                }
                SrtPreConnectOpt::TlPktDrop(value) => socket.set_too_late_packet_drop(value)?,
                SrtPreConnectOpt::TransType(value) => socket.set_transmission_type(value)?,
                SrtPreConnectOpt::TsbPdMode(value) => {
                    socket.set_timestamp_based_packet_delivery_mode(value)?
                }
                SrtPreConnectOpt::UdpSndBuf(value) => socket.set_udp_receive_buffer(value)?,
                SrtPreConnectOpt::UdpRcvBuf(value) => socket.set_udp_send_buffer(value)?,
            }
        }
        Ok(())
    }
}

pub enum SrtSocketStatus {
    Init,
    Opened,
    Listening,
    Connecting,
    Connected,
    Broken,
    Closing,
    Closed,
    NonExist,
}

#[derive(Debug)]
pub struct SrtSocket {
    id: i32,
}

#[cfg(target_os = "linux")]
fn create_socket_addr_v4(addr: sockaddr_in) -> SocketAddrV4 {
    let ip = addr.sin_addr.s_addr.to_le_bytes();
    SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), addr.sin_port)
}

#[cfg(target_os = "windows")]
fn create_socket_addr_v4(addr: sockaddr_in) -> SocketAddrV4 {
    let ip = unsafe { addr.sin_addr.S_un.S_un_b() };
    SocketAddrV4::new(
        Ipv4Addr::new(ip.s_b1, ip.s_b2, ip.s_b3, ip.s_b4),
        addr.sin_port,
    )
}

#[cfg(target_os = "linux")]
fn create_socket_addr_v6(addr: sockaddr_in6) -> SocketAddrV6 {
    let ip = addr.sin6_addr.s6_addr;
    SocketAddrV6::new(
        Ipv6Addr::new(
            u16::from_be_bytes([ip[0], ip[1]]),
            u16::from_be_bytes([ip[2], ip[3]]),
            u16::from_be_bytes([ip[4], ip[5]]),
            u16::from_be_bytes([ip[6], ip[7]]),
            u16::from_be_bytes([ip[8], ip[9]]),
            u16::from_be_bytes([ip[10], ip[11]]),
            u16::from_be_bytes([ip[12], ip[13]]),
            u16::from_be_bytes([ip[14], ip[15]]),
        ),
        addr.sin6_port,
        addr.sin6_flowinfo,
        addr.sin6_scope_id,
    )
}

#[cfg(target_os = "windows")]
fn create_socket_addr_v6(addr: sockaddr_in6) -> SocketAddrV6 {
    let ip = unsafe { addr.sin6_addr.u.Word() };
    SocketAddrV6::new(
        Ipv6Addr::new(ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]),
        addr.sin6_port,
        addr.sin6_flowinfo,
        unsafe { *addr.u.sin6_scope_id() },
    )
}

//Public operational methods
impl SrtSocket {
    pub fn local_addr(&self) -> Result<SocketAddr> {
        let local_addr: SocketAddr;
        let mut addr = unsafe {
            mem::transmute::<[u8; mem::size_of::<sockaddr_in6>()], sockaddr_in6>(
                [0; mem::size_of::<sockaddr_in6>()],
            )
        };
        let mut addrlen: c_int = mem::size_of::<sockaddr_in6>() as i32;
        unsafe {
            srt::srt_getsockname(
                self.id,
                &mut addr as *mut sockaddr_in6 as *mut sockaddr,
                &mut addrlen as *mut c_int,
            )
        };
        local_addr = match addr.sin6_family as i32 {
            AF_INET => SocketAddr::V4(create_socket_addr_v4(unsafe { mem::transmute_copy(&addr) })),
            AF_INET6 => SocketAddr::V6(create_socket_addr_v6(addr)),
            _ => unreachable!("libsrt returned a socket with an unrecognized family"),
        };
        error::handle_result(local_addr, 0)
    }
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        let peer_addr: SocketAddr;
        let mut addr = unsafe {
            mem::transmute::<[u8; mem::size_of::<sockaddr_in6>()], sockaddr_in6>(
                [0; mem::size_of::<sockaddr_in6>()],
            )
        };
        let mut addrlen: c_int = mem::size_of::<sockaddr_in6>() as i32;
        let result = unsafe {
            srt::srt_getpeername(
                self.id,
                &mut addr as *mut sockaddr_in6 as *mut sockaddr,
                &mut addrlen as *mut c_int,
            )
        };
        peer_addr = match addr.sin6_family as i32 {
            AF_INET => SocketAddr::V4(create_socket_addr_v4(unsafe { mem::transmute_copy(&addr) })),
            AF_INET6 => SocketAddr::V6(create_socket_addr_v6(addr)),
            _ => unreachable!("libsrt returned a socket with an unrecognized family"),
        };
        error::handle_result(peer_addr, result)
    }
    pub fn accept(&self) -> Result<(Self, SocketAddr)> {
        let mut addr = unsafe {
            mem::transmute::<[u8; mem::size_of::<sockaddr_in6>()], sockaddr_in6>(
                [0; mem::size_of::<sockaddr_in6>()],
            )
        };
        let mut _addrlen: c_int = mem::size_of::<sockaddr_in6>() as i32;
        let peer_id = unsafe {
            srt::srt_accept(
                self.id,
                &mut addr as *mut sockaddr_in6 as *mut libsrt_sys::sockaddr,
                &mut _addrlen as *mut c_int,
            )
        };
        let peer_addr = match addr.sin6_family as i32 {
            AF_INET => SocketAddr::V4(create_socket_addr_v4(unsafe { mem::transmute_copy(&addr) })),
            AF_INET6 => SocketAddr::V6(create_socket_addr_v6(addr)),
            f => unreachable!("libsrt returned a socket with an unrecognized family {}", f),
        };
        Ok((Self { id: peer_id }, peer_addr))
    }
    pub fn close(self) -> Result<()> {
        let result = unsafe { srt::srt_close(self.id) };
        error::handle_result((), result)
    }
}
//Public get flag methods
impl SrtSocket {
    pub fn get_connection_timeout(&self) -> Result<i32> {
        let mut msecs = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_CONNTIMEO,
                &mut msecs as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(msecs, result)
    }
    pub fn get_flight_flag_size(&self) -> Result<i32> {
        let mut packets = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_FC,
                &mut packets as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(packets, result)
    }
    pub fn get_input_bandwith(&self) -> Result<i64> {
        let mut bytes_per_sec = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_INPUTBW,
                &mut bytes_per_sec as *mut i64 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(bytes_per_sec, result)
    }
    pub fn get_ip_type_of_service(&self) -> Result<i32> {
        let mut tos = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_IPTOS,
                &mut tos as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(tos, result)
    }
    pub fn get_initial_sequence_number(&self) -> Result<i32> {
        let mut sequences = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_ISN,
                &mut sequences as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(sequences, result)
    }
    pub fn get_ip_time_to_live(&self) -> Result<i32> {
        let mut hops = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_IPTTL,
                &mut hops as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(hops, result)
    }
    pub fn get_ipv6_only(&self) -> Result<i32> {
        let mut value = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_IPV6ONLY,
                &mut value as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(value, result)
    }
    pub fn get_km_refresh_rate(&self) -> Result<i32> {
        let mut packets = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_KMREFRESHRATE,
                &mut packets as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(packets, result)
    }
    pub fn get_km_preannounce(&self) -> Result<i32> {
        let mut packets = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_KMPREANNOUNCE,
                &mut packets as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(packets, result)
    }
    pub fn get_linger(&self) -> Result<i32> {
        let mut linger = linger {
            l_onoff: 0,
            l_linger: 0,
        };
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_LINGER,
                &mut linger as *mut linger as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(linger.l_linger as i32, result)
    }
    pub fn get_max_reorder_tolerance(&self) -> Result<i32> {
        let mut packets = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_LOSSMAXTTL,
                &mut packets as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(packets, result)
    }
    pub fn get_max_bandwith(&self) -> Result<i64> {
        let mut bytes_per_sec = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_MAXBW,
                &mut bytes_per_sec as *mut i64 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(bytes_per_sec, result)
    }
    pub fn get_mss(&self) -> Result<i32> {
        let mut bytes = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_MSS,
                &mut bytes as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(bytes, result)
    }
    pub fn get_nak_report(&self) -> Result<bool> {
        let mut enabled = true;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_NAKREPORT,
                &mut enabled as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(enabled, result)
    }
    pub fn get_encryption_key_length(&self) -> Result<i32> {
        let mut len = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_PBKEYLEN,
                &mut len as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(len, result)
    }
    pub fn get_peer_latency(&self) -> Result<i32> {
        let mut msecs = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_PEERLATENCY,
                &mut msecs as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(msecs, result)
    }
    pub fn get_peer_version(&self) -> Result<i32> {
        let mut version = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_PEERVERSION,
                &mut version as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(version, result)
    }
    pub fn get_receive_buffer(&self) -> Result<i32> {
        let mut bytes = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RCVBUF,
                &mut bytes as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(bytes, result)
    }
    pub fn get_receive_data(&self) -> Result<i32> {
        let mut packets = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RCVDATA,
                &mut packets as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(packets, result)
    }
    pub fn get_receive_km_state(&self) -> Result<SrtKmState> {
        let mut state = SrtKmState::Unsecured;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RCVKMSTATE,
                &mut state as *mut SrtKmState as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(state, result)
    }
    pub fn get_receive_latency(&self) -> Result<i32> {
        let mut msecs = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RCVLATENCY,
                &mut msecs as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(msecs, result)
    }
    pub fn get_receive_blocking(&self) -> Result<bool> {
        let mut blocking = true;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RCVSYN,
                &mut blocking as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(blocking, result)
    }
    pub fn get_receive_timeout(&self) -> Result<i32> {
        let mut msecs = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RCVTIMEO,
                &mut msecs as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(msecs, result)
    }
    pub fn get_rendezvous(&self) -> Result<bool> {
        let mut rendezvous = false;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RENDEZVOUS,
                &mut rendezvous as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(rendezvous, result)
    }
    pub fn get_reuse_address(&self) -> Result<bool> {
        let mut rendezvous = false;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_REUSEADDR,
                &mut rendezvous as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(rendezvous, result)
    }
    pub fn get_send_buffer(&self) -> Result<i32> {
        let mut bytes = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_SNDBUF,
                &mut bytes as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(bytes, result)
    }
    pub fn get_send_data(&self) -> Result<i32> {
        let mut packets = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_SNDDATA,
                &mut packets as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(packets, result)
    }
    pub fn get_send_km_state(&self) -> Result<SrtKmState> {
        let mut state = SrtKmState::Unsecured;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_SNDKMSTATE,
                &mut state as *mut SrtKmState as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(state, result)
    }
    pub fn get_send_blocking(&self) -> Result<bool> {
        let mut blocking = true;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_SNDSYN,
                &mut blocking as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(blocking, result)
    }
    pub fn get_send_timeout(&self) -> Result<i32> {
        let mut secs = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_SNDTIMEO,
                &mut secs as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(secs, result)
    }
    pub fn get_connection_state(&self) -> Result<SrtSocketStatus> {
        let mut state = srt::SRT_SOCKSTATUS::SRTS_INIT;
        let mut _optlen = mem::size_of_val(&state) as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_STATE,
                &mut state as *mut srt::SRT_SOCKSTATUS as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        let state = match state {
            srt::SRT_SOCKSTATUS::SRTS_INIT => SrtSocketStatus::Init,
            srt::SRT_SOCKSTATUS::SRTS_OPENED => SrtSocketStatus::Opened,
            srt::SRT_SOCKSTATUS::SRTS_LISTENING => SrtSocketStatus::Listening,
            srt::SRT_SOCKSTATUS::SRTS_CONNECTING => SrtSocketStatus::Connecting,
            srt::SRT_SOCKSTATUS::SRTS_CONNECTED => SrtSocketStatus::Connected,
            srt::SRT_SOCKSTATUS::SRTS_BROKEN => SrtSocketStatus::Broken,
            srt::SRT_SOCKSTATUS::SRTS_CLOSING => SrtSocketStatus::Closing,
            srt::SRT_SOCKSTATUS::SRTS_CLOSED => SrtSocketStatus::Closed,
            srt::SRT_SOCKSTATUS::SRTS_NONEXIST => SrtSocketStatus::NonExist,
            _ => unreachable!("unrecognized SOCKSTATUS"),
        };
        error::handle_result(state, result)
    }
    pub fn get_stream_id(&self) -> Result<String> {
        let mut id = String::from_iter([' '; 512].iter());
        let mut id_len = mem::size_of_val(&id) as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_STATE,
                id.as_mut_ptr() as *mut c_void,
                &mut id_len as *mut c_int,
            )
        };
        id.truncate(id_len as usize);
        error::handle_result(id, result)
    }
    pub fn get_too_late_packet_drop(&self) -> Result<bool> {
        let mut enable = true;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_TLPKTDROP,
                &mut enable as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(enable, result)
    }
    pub fn get_timestamp_based_packet_delivery_mode(&self) -> Result<bool> {
        let mut enable = true;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_TSBPDMODE,
                &mut enable as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(enable, result)
    }
    pub fn get_udp_receive_buffer(&self) -> Result<i32> {
        let mut bytes = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_UDP_RCVBUF,
                &mut bytes as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(bytes, result)
    }
    pub fn get_udp_send_buffer(&self) -> Result<i32> {
        let mut bytes = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_UDP_SNDBUF,
                &mut bytes as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(bytes, result)
    }
    pub fn get_srt_version(&self) -> Result<i32> {
        let mut version = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_VERSION,
                &mut version as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(version, result)
    }
}
//Public set flag methods
impl SrtSocket {
    pub fn set_input_bandwith(&self, bytes_per_sec: i64) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_INPUTBW,
                &bytes_per_sec as *const i64 as *const c_void,
                mem::size_of::<i64>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    pub fn set_recovery_bandwidth_overhead(&self, per_cent: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_OHEADBW,
                &per_cent as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    pub fn set_receive_timeout(&self, msecs: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RCVTIMEO,
                &msecs as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    pub fn set_send_blocking(&self, blocking: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_SNDSYN,
                &blocking as *const bool as *const c_void,
                mem::size_of::<bool>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    pub fn set_send_timeout(&self, msecs: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_SNDTIMEO,
                &msecs as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
}

impl Write for SrtSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let size = unsafe {
            srt::srt_send(
                self.id,
                buf as *const [u8] as *const c_char,
                buf.len() as i32,
            )
        };
        Ok(size as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Read for SrtSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size;
        unsafe { size = srt::srt_recv(self.id, buf as *mut [u8] as *mut c_char, buf.len() as i32) };
        Ok(size as usize)
    }
}

//Private methods
impl SrtSocket {
    fn new() -> Self {
        Self {
            id: unsafe { srt::srt_create_socket() },
        }
    }
    fn bind<A: ToSocketAddrs>(self, addrs: A) -> Result<Self> {
        if let Ok(addrs) = addrs.to_socket_addrs() {
            for addr in addrs {
                match addr {
                    SocketAddr::V4(addr) => {
                        let addr = create_sockaddr_in(addr);
                        let result;
                        unsafe {
                            result = srt::srt_bind(
                                self.id,
                                &addr as *const sockaddr_in as *const sockaddr,
                                mem::size_of::<sockaddr_in>() as c_int,
                            );
                        }
                        return error::handle_result(self, result);
                    }
                    SocketAddr::V6(addr) => {
                        let addr = create_sockaddr_in6(addr);
                        let result;
                        unsafe {
                            result = srt::srt_bind(
                                self.id,
                                &addr as *const sockaddr_in6 as *const sockaddr,
                                mem::size_of::<sockaddr_in6>() as c_int,
                            );
                        }
                        return error::handle_result(self, result);
                    }
                }
            }
        }
        Err(SrtError::SockFail)
    }
    fn rendezvous<A: ToSocketAddrs, B: ToSocketAddrs>(&self, local: A, remote: B) -> Result<()> {
        let local_addr;
        if let Ok(mut addr) = local.to_socket_addrs() {
            local_addr = addr.next()
        } else {
            return Err(SrtError::SockFail);
        };
        let remote_addr;
        if let Ok(mut addr) = remote.to_socket_addrs() {
            remote_addr = addr.next()
        } else {
            return Err(SrtError::SockFail);
        };
        match (local_addr, remote_addr) {
            (Some(SocketAddr::V4(local)), Some(SocketAddr::V4(remote))) => {
                let local_addr = create_sockaddr_in(local);
                let remote_addr = create_sockaddr_in(remote);
                let result = unsafe {
                    srt::srt_rendezvous(
                        self.id,
                        &local_addr as *const sockaddr_in as *const sockaddr,
                        mem::size_of::<sockaddr_in>() as c_int,
                        &remote_addr as *const sockaddr_in as *const sockaddr,
                        mem::size_of::<sockaddr_in>() as c_int,
                    )
                };
                error::handle_result((), result)
            }
            (Some(SocketAddr::V6(local)), Some(SocketAddr::V6(remote))) => {
                let local_addr = create_sockaddr_in6(local);
                let remote_addr = create_sockaddr_in6(remote);
                let result;
                unsafe {
                    result = srt::srt_rendezvous(
                        self.id,
                        &local_addr as *const sockaddr_in6 as *const sockaddr,
                        mem::size_of::<sockaddr_in6>() as c_int,
                        &remote_addr as *const sockaddr_in6 as *const sockaddr,
                        mem::size_of::<sockaddr_in6>() as c_int,
                    );
                }
                error::handle_result((), result)
            }
            _ => Err(SrtError::SockFail),
        }
    }
    fn connect<A: ToSocketAddrs>(&self, addrs: A) -> Result<()> {
        let target_addr: SocketAddr;
        if let Ok(mut target) = addrs.to_socket_addrs() {
            if let Some(addr) = target.next() {
                target_addr = addr;
            } else {
                return Err(SrtError::SockFail);
            }
        } else {
            return Err(SrtError::SockFail);
        };
        match target_addr {
            SocketAddr::V4(target) => {
                let target_addr = create_sockaddr_in(target);
                let result;
                unsafe {
                    result = srt::srt_connect(
                        self.id,
                        &target_addr as *const sockaddr_in as *const sockaddr,
                        mem::size_of::<sockaddr_in>() as c_int,
                    );
                }
                return error::handle_result((), result);
            }
            SocketAddr::V6(target) => {
                let id = unsafe { srt::srt_create_socket() };
                let target_addr = create_sockaddr_in6(target);
                let result;
                unsafe {
                    result = srt::srt_connect(
                        id,
                        &target_addr as *const sockaddr_in6 as *const sockaddr,
                        mem::size_of::<sockaddr_in6>() as c_int,
                    );
                }
                return error::handle_result((), result);
            }
        }
    }
    fn listen(&self, backlog: i32) -> Result<()> {
        let result = unsafe { srt::srt_listen(self.id, backlog) };
        error::handle_result((), result)
    }
}

impl SrtSocket {
    fn set_connection_timeout(&self, msecs: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_CONNTIMEO,
                &msecs as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_flight_flag_size(&self, packets: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_FC,
                &packets as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_ip_type_of_service(&self, type_of_service: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_IPTOS,
                &type_of_service as *const i32 as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_ipv4_time_to_live(&self, hops: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_IPTTL,
                &hops as *const i32 as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_ipv6_only(&self, value: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_IPV6ONLY,
                &value as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_km_refresh_rate(&self, packets: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_KMREFRESHRATE,
                &packets as *const i32 as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_km_preannounce(&self, packets: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_KMPREANNOUNCE,
                &packets as *const i32 as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    #[cfg(target_os = "linux")]
    fn set_linger(&self, secs: i32) -> Result<()> {
        let lin = linger {
            l_onoff: (secs > 0) as i32,
            l_linger: secs,
        };
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_LINGER,
                &lin as *const linger as *const c_void,
                mem::size_of::<linger>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    #[cfg(target_os = "windows")]
    fn set_linger(&self, secs: i32) -> Result<()> {
        let lin = linger {
            l_onoff: (secs > 0) as u16,
            l_linger: secs as u16,
        };
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_LINGER,
                &lin as *const linger as *const c_void,
                mem::size_of::<linger>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_max_reorder_tolerance(&self, packets: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_LOSSMAXTTL,
                &packets as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_max_bandwith(&self, bytes_per_sec: i64) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_MAXBW,
                &bytes_per_sec as *const i64 as *const c_void,
                mem::size_of::<i64>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_message_api(&self, enable: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_MESSAGEAPI,
                &enable as *const bool as *const c_void,
                mem::size_of::<bool>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_min_version(&self, version: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_MINVERSION,
                &version as *const i32 as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_mss(&self, bytes: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_MSS,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_nak_report(&self, enable: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_NAKREPORT,
                &enable as *const bool as *const c_void,
                mem::size_of::<bool>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_packet_filter(&self, filter: &str) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_PACKETFILTER,
                filter[..512].as_ptr() as *const c_void,
                filter[..512].len() as i32,
            )
        };
        error::handle_result((), result)
    }
    fn set_passphrase(&self, passphrase: &str) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_PASSPHRASE,
                passphrase as *const str as *const c_void,
                passphrase.len() as i32,
            )
        };
        error::handle_result((), result)
    }
    fn set_payload_size(&self, bytes: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_PAYLOADSIZE,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_encryption_key_length(&self, bytes: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_PBKEYLEN,
                &bytes as *const i32 as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_peer_idle_timeout(&self, msecs: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_PEERIDLETIMEO,
                &msecs as *const i32 as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_peer_latency(&self, msecs: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_PEERLATENCY,
                &msecs as *const i32 as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_receive_buffer(&self, bytes: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RCVBUF,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_receive_latency(&self, msecs: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RCVLATENCY,
                &msecs as *const i32 as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_receive_blocking(&self, blocking: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RCVSYN,
                &blocking as *const bool as *const c_void,
                mem::size_of::<bool>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_rendezvous(&self, rendezvous: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RENDEZVOUS,
                &rendezvous as *const bool as *const c_void,
                mem::size_of::<bool>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_reuse_address(&self, reuse: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_REUSEADDR,
                &reuse as *const bool as *const c_void,
                mem::size_of::<bool>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_congestion_controller(&self, controller: SrtCongestionController) -> Result<()> {
        let value = match controller {
            SrtCongestionController::Live => "live",
            SrtCongestionController::File => "file",
        };
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_CONGESTION,
                value.as_ptr() as *const c_void,
                value.len() as i32,
            )
        };
        error::handle_result((), result)
    }
    fn set_send_buffer(&self, bytes: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_SNDBUF,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_send_drop_delay(&self, msecs: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_SNDDROPDELAY,
                &msecs as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_stream_id(&self, id: &str) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_STREAMID,
                id[..512].as_ptr() as *const c_void,
                id[..512].len() as i32,
            )
        };
        error::handle_result((), result)
    }
    fn set_enforced_encryption(&self, enforced: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_ENFORCEDENCRYPTION,
                &enforced as *const bool as *const c_void,
                mem::size_of::<bool>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_too_late_packet_drop(&self, enable: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_TLPKTDROP,
                &enable as *const bool as *const c_void,
                mem::size_of::<bool>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_transmission_type(&self, transmission_type: SrtTransmissionType) -> Result<()> {
        let trans_type = match transmission_type {
            SrtTransmissionType::File => srt::SRT_TRANSTYPE::SRTT_FILE,
            SrtTransmissionType::Live => srt::SRT_TRANSTYPE::SRTT_LIVE,
            SrtTransmissionType::Invalid => srt::SRT_TRANSTYPE::SRTT_INVALID,
        };
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_TRANSTYPE,
                &trans_type as *const srt::SRT_TRANSTYPE as *const c_void,
                mem::size_of_val(&trans_type) as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_timestamp_based_packet_delivery_mode(&self, enable: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_TSBPDMODE,
                &enable as *const bool as *const c_void,
                mem::size_of::<bool>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_udp_send_buffer(&self, bytes: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_UDP_SNDBUF,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    fn set_udp_receive_buffer(&self, bytes: i32) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_UDP_RCVBUF,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as c_int,
            )
        };
        error::handle_result((), result)
    }
}

pub enum SrtKmState {
    Unsecured,
    Securing,
    Secured,
    NoSecret,
    BadSecret,
}

#[allow(dead_code)]
enum SrtTransmissionType {
    Live,
    File,
    Invalid,
}
enum SrtCongestionController {
    Live,
    File,
}
enum SrtPreConnectOpt {
    ConnTimeO(i32),
    FC(i32),
    IpTos(i32),
    IpTtl(i32),
    Ipv6Only(i32),
    KmRefreshRate(i32),
    KmPreAnnounce(i32),
    Linger(i32),
    LossMaxTtl(i32),
    MaxBW(i64),
    MessageApi(bool),
    MinVersion(i32),
    Mss(i32),
    NakReport(bool),
    PacketFilter(String),
    Passphrase(String),
    PayloadSize(i32),
    PBKeyLen(i32),
    PeerIdleTimeO(i32),
    PeerLatency(i32),
    RcvBuf(i32),
    RcvLatency(i32),
    RcvSyn(bool),
    Rendezvous(bool),
    ReuseAddr(bool),
    Congestion(SrtCongestionController),
    SndBuf(i32),
    SndDropDelay(i32),
    StreamId(String),
    EnforcedEncryption(bool),
    TlPktDrop(bool),
    TransType(SrtTransmissionType),
    TsbPdMode(bool),
    UdpSndBuf(i32),
    UdpRcvBuf(i32),
}

#[cfg(target_os = "linux")]
fn create_sockaddr_in(addr: SocketAddrV4) -> sockaddr_in {
    sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: addr.port(),
        sin_addr: in_addr {
            s_addr: u32::from_le_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

#[cfg(target_os = "windows")]
fn create_sockaddr_in(addr: SocketAddrV4) -> sockaddr_in {
    let mut sin_addr = unsafe { mem::zeroed::<in_addr>() };
    let mut sin_ip = unsafe { sin_addr.S_un.S_un_b_mut() };
    let ip = addr.ip().octets();
    sin_ip.s_b1 = ip[0];
    sin_ip.s_b2 = ip[1];
    sin_ip.s_b3 = ip[2];
    sin_ip.s_b4 = ip[3];
    sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: addr.port(),
        sin_addr,
        sin_zero: [0; 8],
    }
}

#[cfg(target_os = "linux")]
fn create_sockaddr_in6(addr: SocketAddrV6) -> sockaddr_in6 {
    sockaddr_in6 {
        sin6_family: AF_INET6 as u16,
        sin6_port: addr.port(),
        sin6_flowinfo: addr.flowinfo(),
        sin6_addr: in6_addr {
            s6_addr: addr.ip().octets(),
        },
        sin6_scope_id: addr.scope_id(),
    }
}

#[cfg(target_os = "windows")]
fn create_sockaddr_in6(addr: SocketAddrV6) -> sockaddr_in6 {
    let mut sin6_addr = unsafe { mem::zeroed::<in6_addr>() };
    let sin_ip = unsafe { sin6_addr.u.Byte_mut() };
    *sin_ip = addr.ip().octets();
    let mut u = unsafe { mem::zeroed::<SOCKADDR_IN6_LH_u>() };
    let scope_id = unsafe { u.sin6_scope_id_mut() };
    *scope_id = addr.scope_id();
    sockaddr_in6 {
        sin6_family: AF_INET6 as u16,
        sin6_port: addr.port(),
        sin6_flowinfo: addr.flowinfo(),
        sin6_addr,
        u,
    }
}

#[cfg(test)]
mod tests {
    use crate as srt;
    use srt::SrtBuilder;
    use std::{
        io::{Read, Write},
        net::SocketAddr,
        sync::mpsc,
        thread,
    };

    #[test]
    fn test_connect_accept() {
        srt::startup().expect("failed startup");
        let (tx, rx) = mpsc::channel::<SocketAddr>();
        thread::spawn(move || {
            let listen = SrtBuilder::new()
                .set_file_transmission_type()
                .listen("127.0.0.2:0", 1)
                .expect("fail listen()");
            let local = listen.local_addr().expect("fail local_addr()");
            tx.send(local).expect("fail send through mpsc channel");
            let (mut peer, _peer_addr) = listen.accept().expect("fail accep()");
            peer.write_all(b"testing").expect("fail write()");
            assert!(peer.close().is_ok());
            assert!(listen.close().is_ok());
        });
        let addr = rx.recv().expect("fail recv through mpsc channel");
        let mut connect = SrtBuilder::new()
            .set_file_transmission_type()
            .connect("127.0.0.1:0", addr)
            .expect("fail connect()");
        let mut buf = Vec::new();
        connect.read_to_end(&mut buf).expect("fail read()");
        assert_eq!(
            std::str::from_utf8(&buf).expect("malformed message"),
            "testing"
        );
        assert!(connect.close().is_ok());
        srt::cleanup().expect("failed cleanup()");
    }
    #[test]
    fn test_rendezvous() {
        srt::startup().expect("failed startup");
        thread::spawn(move || {
            let mut one = SrtBuilder::new()
                .set_file_transmission_type()
                .rendezvous("127.0.0.2:123", "127.0.0.1:234")
                .expect("fail rendezvous()");
            one.write_all(b"testing").expect("fail write()");
            assert!(one.close().is_ok());
        });
        let mut two = SrtBuilder::new()
            .set_file_transmission_type()
            .rendezvous("127.0.0.1:234", "127.0.0.2:123")
            .expect("fail rendezvous()");
        let mut buf = Vec::new();
        two.read_to_end(&mut buf).expect("fail read()");
        assert_eq!(
            std::str::from_utf8(&buf).expect("malformed message"),
            "testing"
        );
        srt::cleanup().expect("failed cleanup");
    }
}
