use libc::{c_char, c_int, c_void, in_addr, linger, sockaddr, sockaddr_in, AF_INET};

use std::{
    io::{self, Read, Write},
    iter::FromIterator,
    mem,
    net::{Ipv4Addr, SocketAddrV4},
    result,
};

use crate::error::{self, SrtError};

type SRTSOCKET = c_int;

type Result<T> = result::Result<T, SrtError>;

pub struct SrtBuilder {
    opt_vec: Vec<SrtPreConnectOpt>,
}
impl SrtBuilder {
    pub fn new() -> Self {
        Self {
            opt_vec: Vec::new(),
        }
    }
    pub fn connect(self, source: SocketAddrV4, target: SocketAddrV4) -> Result<SrtSocket> {
        let socket = SrtSocket::connect_bind(source, target)?;
        self.config_socket(&socket)?;
        Ok(socket)
    }
    pub fn listen(self, addr: SocketAddrV4, backlog: i32) -> Result<SrtSocket> {
        let socket = SrtSocket::bind(addr)?;
        socket.listen(backlog)?;
        Ok(socket)
    }
    pub fn set_connection_timeout(mut self, msecs: i32) {
        self.opt_vec.push(SrtPreConnectOpt::ConnTimeO(msecs));
    }
    pub fn set_flight_flag_size(mut self, packets: i32) {
        self.opt_vec.push(SrtPreConnectOpt::FC(packets));
    }
    pub fn set_ip_type_of_service(mut self, tos: i32) {
        self.opt_vec.push(SrtPreConnectOpt::IpTos(tos));
    }
    pub fn set_ipv4_time_to_live(mut self, hops: i32) {
        self.opt_vec.push(SrtPreConnectOpt::IpTtl(hops));
    }
    pub fn set_ipv6_only(mut self, value: i32) {
        self.opt_vec.push(SrtPreConnectOpt::Ipv6Only(value));
    }
    pub fn set_km_refresh_rate(mut self, packets: i32) {
        self.opt_vec.push(SrtPreConnectOpt::KmRefreshRate(packets));
    }
    pub fn set_km_preannounce(mut self, packets: i32) {
        self.opt_vec.push(SrtPreConnectOpt::KmPreAnnounce(packets));
    }
    pub fn set_linger(mut self, secs: i32) {
        self.opt_vec.push(SrtPreConnectOpt::Linger(secs));
    }
    pub fn set_max_reorder_tolerance(mut self, packets: i32) {
        self.opt_vec.push(SrtPreConnectOpt::LossMaxTtl(packets));
    }
    pub fn set_max_bandwith(mut self, bytes_per_sec: i64) {
        self.opt_vec.push(SrtPreConnectOpt::MaxBW(bytes_per_sec));
    }
    pub fn set_message_api(mut self, enable: bool) {
        self.opt_vec.push(SrtPreConnectOpt::MessageApi(enable));
    }
    pub fn set_min_version(mut self, version: i32) {
        self.opt_vec.push(SrtPreConnectOpt::MinVersion(version));
    }
    pub fn set_mss(mut self, bytes: i32) {
        self.opt_vec.push(SrtPreConnectOpt::Mss(bytes));
    }
    pub fn set_nak_report(mut self, enable: bool) {
        self.opt_vec.push(SrtPreConnectOpt::NakReport(enable));
    }
    pub fn set_packet_filter(mut self, filter: String) {
        self.opt_vec.push(SrtPreConnectOpt::PacketFilter(filter));
    }
    pub fn set_passphrase(mut self, passphrase: String) {
        self.opt_vec.push(SrtPreConnectOpt::Passphrase(passphrase));
    }
    pub fn set_payload_size(mut self, bytes: i32) {
        self.opt_vec.push(SrtPreConnectOpt::PayloadSize(bytes));
    }
    pub fn set_encryption_key_length(mut self, bytes: i32) {
        self.opt_vec.push(SrtPreConnectOpt::PBKeyLen(bytes));
    }
    pub fn set_peer_idle_timeout(mut self, msecs: i32) {
        self.opt_vec.push(SrtPreConnectOpt::PeerIdleTimeO(msecs));
    }
    pub fn set_peer_latency(mut self, msecs: i32) {
        self.opt_vec.push(SrtPreConnectOpt::PeerLatency(msecs));
    }
    pub fn set_receive_buffer(mut self, bytes: i32) {
        self.opt_vec.push(SrtPreConnectOpt::RcvBuf(bytes));
    }
    pub fn set_receive_latency(mut self, msecs: i32) {
        self.opt_vec.push(SrtPreConnectOpt::RcvLatency(msecs));
    }
    pub fn set_receive_blocking(mut self, blocking: bool) {
        self.opt_vec.push(SrtPreConnectOpt::RcvSyn(blocking));
    }
    pub fn set_rendezvous(mut self, rendezvous: bool) {
        self.opt_vec.push(SrtPreConnectOpt::Rendezvous(rendezvous));
    }
    pub fn set_reuse_address(mut self, reuse_address: bool) {
        self.opt_vec
            .push(SrtPreConnectOpt::ReuseAddr(reuse_address));
    }
    pub fn set_live_congestion_controller(mut self) {
        self.opt_vec
            .push(SrtPreConnectOpt::Congestion(SrtCongestionController::Live));
    }
    pub fn set_file_congestion_controller(mut self) {
        self.opt_vec
            .push(SrtPreConnectOpt::Congestion(SrtCongestionController::File));
    }
    pub fn set_send_buffer(mut self, bytes: i32) {
        self.opt_vec.push(SrtPreConnectOpt::SndBuf(bytes));
    }
    pub fn set_send_drop_delay(mut self, msecs: i32) {
        self.opt_vec.push(SrtPreConnectOpt::SndDropDelay(msecs));
    }
    pub fn set_stream_id(mut self, id: String) {
        self.opt_vec.push(SrtPreConnectOpt::StreamId(id));
    }
    pub fn set_enforced_encryption(mut self, enforced: bool) {
        self.opt_vec
            .push(SrtPreConnectOpt::EnforcedEncryption(enforced));
    }
    pub fn set_too_late_packet_drop(mut self, enable: bool) {
        self.opt_vec.push(SrtPreConnectOpt::TlPktDrop(enable));
    }
    pub fn set_live_transmission_type(mut self) {
        self.opt_vec
            .push(SrtPreConnectOpt::TransType(SrtTransmissionType::Live));
    }
    pub fn set_file_transmission_type(mut self) {
        self.opt_vec
            .push(SrtPreConnectOpt::TransType(SrtTransmissionType::File));
    }
    pub fn set_timestamp_based_packet_delivery_mode(mut self, enable: bool) {
        self.opt_vec.push(SrtPreConnectOpt::TsbPdMode(enable));
    }
    pub fn set_udp_send_buffer(mut self, bytes: i32) {
        self.opt_vec.push(SrtPreConnectOpt::UdpSndBuf(bytes));
    }
    pub fn set_udp_receive_buffer(mut self, bytes: i32) {
        self.opt_vec.push(SrtPreConnectOpt::UdpRcvBuf(bytes));
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

#[repr(C)]
pub enum SrtSocketStatus {
    Init = 1,
    Opened,
    Listening,
    Connecting,
    Connected,
    Broken,
    Closing,
    Closed,
    NonExist,
}

pub struct SrtSocket {
    id: SRTSOCKET,
}

//Public operational methods
impl SrtSocket {
    pub fn local_addr(&self) -> Result<SocketAddrV4> {
        let local_addr: SocketAddrV4;
        let result;
        unsafe {
            let mut addr = sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            let mut _addrlen: c_int = 0;
            result = srt_getsockname(
                self.id,
                &mut addr as *mut sockaddr_in as *mut sockaddr,
                &mut _addrlen as *mut c_int,
            );
            let ip = addr.sin_addr.s_addr.to_be_bytes();
            local_addr =
                SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), addr.sin_port);
        };
        error::wrap_result(local_addr, result)
    }
    pub fn peer_addr(&self) -> Result<SocketAddrV4> {
        let peer_addr: SocketAddrV4;
        let result;
        unsafe {
            let mut addr = sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            let mut _addrlen: c_int = 0;
            result = srt_getpeername(
                self.id,
                &mut addr as *mut sockaddr_in as *mut sockaddr,
                &mut _addrlen as *mut c_int,
            );
            let ip = addr.sin_addr.s_addr.to_be_bytes();
            peer_addr = SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), addr.sin_port);
        };
        error::wrap_result(peer_addr, result)
    }
    pub fn accept(&self) -> Result<(SrtSocket, SocketAddrV4)> {
        let peer_id;
        let peer_addr: SocketAddrV4;
        unsafe {
            let mut addr = sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            let mut _addrlen: c_int = 0;
            peer_id = srt_accept(
                self.id,
                &mut addr as *mut sockaddr_in as *mut sockaddr,
                &mut _addrlen as *mut c_int,
            );
            let ip = addr.sin_addr.s_addr.to_be_bytes();
            peer_addr = SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), addr.sin_port);
        };
        Ok((SrtSocket { id: peer_id }, peer_addr))
    }
    pub fn close(self) -> Result<()> {
        let result;
        unsafe {
            result = srt_close(self.id);
        }
        error::wrap_result((), result)
    }
}
//Public get flag methods
impl SrtSocket {
    pub fn get_connection_timeout(&self) -> Result<i32> {
        let mut msecs = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::ConnTimeO,
                &mut msecs as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(msecs, result)
    }
    pub fn get_flight_flag_size(&self) -> Result<i32> {
        let mut packets = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::FC,
                &mut packets as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(packets, result)
    }
    pub fn get_input_bandwith(&self) -> Result<i64> {
        let mut bytes_per_sec = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::InputBW,
                &mut bytes_per_sec as *mut i64 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(bytes_per_sec, result)
    }
    pub fn get_ip_type_of_service(&self) -> Result<i32> {
        let mut tos = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::IpTos,
                &mut tos as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(tos, result)
    }
    pub fn get_initial_sequence_number(&self) -> Result<i32> {
        let mut sequences = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::ISN,
                &mut sequences as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(sequences, result)
    }
    pub fn get_ip_time_to_live(&self) -> Result<i32> {
        let mut hops = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::IpTtl,
                &mut hops as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(hops, result)
    }
    pub fn get_ipv6_only(&self) -> Result<i32> {
        let mut value = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::Ipv6Only,
                &mut value as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(value, result)
    }
    pub fn get_km_refresh_rate(&self) -> Result<i32> {
        let mut packets = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::KmRrefreshRate,
                &mut packets as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(packets, result)
    }
    pub fn get_km_preannounce(&self) -> Result<i32> {
        let mut packets = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::KmPreAnnounce,
                &mut packets as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(packets, result)
    }
    pub fn get_linger(&self) -> Result<i32> {
        let mut linger = linger {
            l_onoff: 0,
            l_linger: 0,
        };
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::Linger,
                &mut linger as *mut linger as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(linger.l_linger, result)
    }
    pub fn get_max_reorder_tolerance(&self) -> Result<i32> {
        let mut packets = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::LossMaxTtl,
                &mut packets as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(packets, result)
    }
    pub fn get_max_bandwith(&self) -> Result<i64> {
        let mut bytes_per_sec = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::MaxBW,
                &mut bytes_per_sec as *mut i64 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(bytes_per_sec, result)
    }
    pub fn get_mss(&self) -> Result<i32> {
        let mut bytes = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::Mss,
                &mut bytes as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(bytes, result)
    }
    pub fn get_nak_report(&self) -> Result<bool> {
        let mut enabled = true;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::NakReport,
                &mut enabled as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(enabled, result)
    }
    pub fn get_encryption_key_length(&self) -> Result<i32> {
        let mut len = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::PBKeyLen,
                &mut len as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(len, result)
    }
    pub fn get_peer_latency(&self) -> Result<i32> {
        let mut msecs = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::PeerLatency,
                &mut msecs as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(msecs, result)
    }
    pub fn get_peer_version(&self) -> Result<i32> {
        let mut version = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::PeerVersion,
                &mut version as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(version, result)
    }
    pub fn get_receive_buffer(&self) -> Result<i32> {
        let mut bytes = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::RcvBuf,
                &mut bytes as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(bytes, result)
    }
    pub fn get_receive_data(&self) -> Result<i32> {
        let mut packets = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::RcvData,
                &mut packets as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(packets, result)
    }
    pub fn get_receive_km_state(&self) -> Result<SrtKmState> {
        let mut state = SrtKmState::Unsecured;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::RcvKmState,
                &mut state as *mut SrtKmState as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(state, result)
    }
    pub fn get_receive_latency(&self) -> Result<i32> {
        let mut msecs = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::RcvLatency,
                &mut msecs as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(msecs, result)
    }
    pub fn get_receive_blocking(&self) -> Result<bool> {
        let mut blocking = true;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::RcvSyn,
                &mut blocking as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(blocking, result)
    }
    pub fn get_receive_timeout(&self) -> Result<i32> {
        let mut msecs = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::RcvTimeO,
                &mut msecs as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(msecs, result)
    }
    pub fn get_rendezvous(&self) -> Result<bool> {
        let mut rendezvous = false;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::Rendezvous,
                &mut rendezvous as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(rendezvous, result)
    }
    pub fn get_reuse_address(&self) -> Result<bool> {
        let mut rendezvous = false;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::ReuseAddr,
                &mut rendezvous as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(rendezvous, result)
    }
    pub fn get_send_buffer(&self) -> Result<i32> {
        let mut bytes = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::SndBuf,
                &mut bytes as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(bytes, result)
    }
    pub fn get_send_data(&self) -> Result<i32> {
        let mut packets = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::SndData,
                &mut packets as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(packets, result)
    }
    pub fn get_send_km_state(&self) -> Result<SrtKmState> {
        let mut state = SrtKmState::Unsecured;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::SndKmState,
                &mut state as *mut SrtKmState as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(state, result)
    }
    pub fn get_send_blocking(&self) -> Result<bool> {
        let mut blocking = true;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::SndSyn,
                &mut blocking as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(blocking, result)
    }
    pub fn get_send_timeout(&self) -> Result<i32> {
        let mut secs = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::SndTimeO,
                &mut secs as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(secs, result)
    }
    pub fn get_connection_state(&self) -> Result<SrtSocketStatus> {
        let mut state = SrtSocketStatus::Init;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::State,
                &mut state as *mut SrtSocketStatus as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(state, result)
    }
    pub fn get_stream_id(&self) -> Result<String> {
        let mut id = String::from_iter([' '; 512].iter());
        let mut id_len: i32 = 0;
        let result;
        unsafe {
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::State,
                id.as_mut_ptr() as *mut c_void,
                &mut id_len as *mut c_int,
            );
        }
        id.truncate(id_len as usize);
        error::wrap_result(id, result)
    }
    pub fn get_too_late_packet_drop(&self) -> Result<bool> {
        let mut enable = true;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::TlPktDrop,
                &mut enable as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(enable, result)
    }
    pub fn get_timestamp_based_packet_delivery_mode(&self) -> Result<bool> {
        let mut enable = true;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::TsbPdMode,
                &mut enable as *mut bool as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(enable, result)
    }
    pub fn get_udp_receive_buffer(&self) -> Result<i32> {
        let mut bytes = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::UdpRcvBuf,
                &mut bytes as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(bytes, result)
    }
    pub fn get_udp_send_buffer(&self) -> Result<i32> {
        let mut bytes = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::UdpSndBuf,
                &mut bytes as *mut c_int as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(bytes, result)
    }
    pub fn get_srt_version(&self) -> Result<i32> {
        let mut version = 0;
        let result;
        unsafe {
            let mut _optlen = 0;
            result = srt_getsockflag(
                self.id,
                SrtSockOpt::Version,
                &mut version as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            );
        }
        error::wrap_result(version, result)
    }
}
//Public set flag methods
impl SrtSocket {
    pub fn set_input_bandwith(&self, bytes_per_sec: i64) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::InputBW,
                &bytes_per_sec as *const i64 as *const c_void,
                mem::size_of::<i64>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    pub fn set_recovery_bandwidth_overhead(&self, per_cent: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::OHeadBW,
                &per_cent as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    pub fn set_receive_timeout(&self, msecs: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::RcvTimeO,
                &msecs as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    pub fn set_send_blocking(&self, blocking: bool) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::SndSyn,
                &blocking as *const bool as *const c_void,
                mem::size_of::<bool>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    pub fn set_send_timeout(&self, msecs: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::SndTimeO,
                &msecs as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
}
impl Write for SrtSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let size;
        unsafe {
            size = srt_send(
                self.id,
                buf as *const [u8] as *const c_char,
                buf.len() as i32,
            );
        }
        Ok(size as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Read for SrtSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size;
        unsafe {
            size = srt_recv(self.id, buf as *mut [u8] as *mut c_char, buf.len() as i32);
        }
        Ok(size as usize)
    }
}

impl SrtSocket {
    fn bind(addr: SocketAddrV4) -> Result<Self> {
        let id = unsafe { srt_create_socket() };
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: addr.port(),
            sin_addr: in_addr {
                s_addr: u32::from_be_bytes(addr.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        let result;
        unsafe {
            result = srt_bind(
                id,
                &addr as *const sockaddr_in as *const sockaddr,
                mem::size_of::<sockaddr_in>() as i32,
            );
        }
        error::wrap_result(Self { id }, result)
    }
    fn connect_bind(source: SocketAddrV4, target: SocketAddrV4) -> Result<Self> {
        let id = unsafe { srt_create_socket() };
        let source_addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: source.port(),
            sin_addr: in_addr {
                s_addr: u32::from_be_bytes(source.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        let target_addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: target.port(),
            sin_addr: in_addr {
                s_addr: u32::from_be_bytes(target.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        let result;
        unsafe {
            result = srt_connect_bind(
                id,
                &source_addr as *const sockaddr_in as *const sockaddr,
                &target_addr as *const sockaddr_in as *const sockaddr,
                mem::size_of::<sockaddr_in>() as i32,
            );
        }
        error::wrap_result(Self { id }, result)
    }
    fn listen(&self, backlog: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_listen(self.id, backlog);
        }
        error::wrap_result((), result)
    }
    fn set_connection_timeout(&self, msecs: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::ConnTimeO,
                &msecs as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_flight_flag_size(&self, packets: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::FC,
                &packets as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_ip_type_of_service(&self, type_of_service: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::IpTos,
                &type_of_service as *const i32 as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_ipv4_time_to_live(&self, hops: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::IpTtl,
                &hops as *const i32 as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_ipv6_only(&self, value: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::Ipv6Only,
                &value as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_km_refresh_rate(&self, packets: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::KmRrefreshRate,
                &packets as *const i32 as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_km_preannounce(&self, packets: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::KmPreAnnounce,
                &packets as *const i32 as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_linger(&self, secs: i32) -> Result<()> {
        let lin = linger {
            l_onoff: (secs > 0) as i32,
            l_linger: secs,
        };
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::Linger,
                &lin as *const linger as *const c_void,
                mem::size_of::<linger>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_max_reorder_tolerance(&self, packets: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::LossMaxTtl,
                &packets as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_max_bandwith(&self, bytes_per_sec: i64) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::MaxBW,
                &bytes_per_sec as *const i64 as *const c_void,
                mem::size_of::<i64>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_message_api(&self, enable: bool) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::MessageApi,
                &enable as *const bool as *const c_void,
                mem::size_of::<bool>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_min_version(&self, version: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::MinVersion,
                &version as *const i32 as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_mss(&self, bytes: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::Mss,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_nak_report(&self, enable: bool) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::NakReport,
                &enable as *const bool as *const c_void,
                mem::size_of::<bool>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_packet_filter(&self, filter: &str) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::PacketFilter,
                filter[..512].as_ptr() as *const c_void,
                filter[..512].len() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_passphrase(&self, passphrase: &str) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::Passphrase,
                passphrase as *const str as *const c_void,
                passphrase.len() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_payload_size(&self, bytes: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::PayloadSize,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_encryption_key_length(&self, bytes: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::PBKeyLen,
                &bytes as *const i32 as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_peer_idle_timeout(&self, msecs: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::PeerIdleTimeO,
                &msecs as *const i32 as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_peer_latency(&self, msecs: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::PeerLatency,
                &msecs as *const i32 as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_receive_buffer(&self, bytes: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::RcvBuf,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_receive_latency(&self, msecs: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::RcvLatency,
                &msecs as *const i32 as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_receive_blocking(&self, blocking: bool) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::RcvSyn,
                &blocking as *const bool as *const c_void,
                mem::size_of::<bool>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_rendezvous(&self, rendezvous: bool) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::Rendezvous,
                &rendezvous as *const bool as *const c_void,
                mem::size_of::<bool>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_reuse_address(&self, reuse: bool) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::ReuseAddr,
                &reuse as *const bool as *const c_void,
                mem::size_of::<bool>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_congestion_controller(&self, controller: SrtCongestionController) -> Result<()> {
        let value = match controller {
            SrtCongestionController::Live => "live",
            SrtCongestionController::File => "file",
        };
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::Congestion,
                value.as_ptr() as *const c_void,
                value.len() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_send_buffer(&self, bytes: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::SndBuf,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_send_drop_delay(&self, msecs: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::SndDropDelay,
                &msecs as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_stream_id(&self, id: &str) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::StreamId,
                id[..512].as_ptr() as *const c_void,
                id[..512].len() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_enforced_encryption(&self, enforced: bool) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::EnforcedEncryption,
                &enforced as *const bool as *const c_void,
                mem::size_of::<bool>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_too_late_packet_drop(&self, enable: bool) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::TlPktDrop,
                &enable as *const bool as *const c_void,
                mem::size_of::<bool>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_transmission_type(&self, transmission_type: SrtTransmissionType) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::TransType,
                &transmission_type as *const SrtTransmissionType as *const c_void,
                mem::size_of::<SrtTransmissionType>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_timestamp_based_packet_delivery_mode(&self, enable: bool) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::TsbPdMode,
                &enable as *const bool as *const c_void,
                mem::size_of::<bool>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_udp_send_buffer(&self, bytes: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::UdpSndBuf,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
    fn set_udp_receive_buffer(&self, bytes: i32) -> Result<()> {
        let result;
        unsafe {
            result = srt_setsockflag(
                self.id,
                SrtSockOpt::UdpRcvBuf,
                &bytes as *const c_int as *const c_void,
                mem::size_of::<i32>() as i32,
            );
        }
        error::wrap_result((), result)
    }
}

#[repr(C)]
pub enum SrtKmState {
    Unsecured = 0,
    Securing = 1,
    Secured = 2,
    NoSecret = 3,
    BadSecret = 4,
}
#[repr(C)]
enum SrtTransmissionType {
    Live,
    File,
    _Invalid,
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

#[repr(C)]
enum SrtSockOpt {
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

#[link(name = "srt")]
extern "C" {
    fn srt_create_socket() -> SRTSOCKET;
    fn srt_bind(u: SRTSOCKET, name: *const sockaddr, namelen: c_int) -> c_int;
    fn srt_listen(u: SRTSOCKET, backlog: c_int) -> c_int;
    fn srt_connect_bind(
        u: SRTSOCKET,
        source: *const sockaddr,
        target: *const sockaddr,
        len: c_int,
    ) -> c_int;
    fn srt_close(u: SRTSOCKET) -> c_int;
    fn srt_accept(u: SRTSOCKET, addr: *mut sockaddr, addrlen: *mut c_int) -> SRTSOCKET;
    fn srt_getpeername(u: SRTSOCKET, name: *mut sockaddr, namelen: *mut c_int) -> c_int;
    fn srt_getsockname(u: SRTSOCKET, name: *mut sockaddr, namelen: *mut c_int) -> c_int;
    fn srt_getsockflag(
        u: SRTSOCKET,
        opt: SrtSockOpt,
        optval: *mut c_void,
        optlen: *mut c_int,
    ) -> c_int;
    fn srt_setsockflag(
        u: SRTSOCKET,
        opt: SrtSockOpt,
        optval: *const c_void,
        optlen: c_int,
    ) -> c_int;
    fn srt_send(u: SRTSOCKET, buf: *const c_char, len: c_int) -> c_int;
    fn srt_recv(u: SRTSOCKET, buf: *mut c_char, len: c_int) -> c_int;
}
