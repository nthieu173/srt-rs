use crate::error;

use error::SrtError;
use libsrt_sys as srt;
use srt::sockaddr;

use std::{
    convert::TryInto,
    ffi::{c_void, CStr},
    iter::FromIterator,
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    os::raw::{c_char, c_int},
};

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

type Result<T> = std::result::Result<T, SrtError>;

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

#[derive(Copy, Clone, Debug)]
pub struct SrtSocket {
    pub id: i32,
}

//General methods
impl SrtSocket {
    pub fn new() -> Result<Self> {
        let result = unsafe { srt::srt_create_socket() };
        if result == -1 {
            error::handle_result(Self { id: 0 }, result)
        } else {
            Ok(Self { id: result })
        }
    }
    pub fn bind<A: ToSocketAddrs>(self, addrs: A) -> Result<Self> {
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
    pub fn rendezvous<A: ToSocketAddrs, B: ToSocketAddrs>(
        &self,
        local: A,
        remote: B,
    ) -> Result<()> {
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
    pub fn connect<A: ToSocketAddrs>(&self, addrs: A) -> Result<()> {
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
    pub fn listen(&self, backlog: i32) -> Result<()> {
        let result = unsafe { srt::srt_listen(self.id, backlog) };
        error::handle_result((), result)
    }
}

//Public operational methods
impl SrtSocket {
    pub fn local_addr(&self) -> Result<SocketAddr> {
        let mut addr = unsafe {
            mem::transmute::<[u8; mem::size_of::<sockaddr_in6>()], sockaddr_in6>(
                [0; mem::size_of::<sockaddr_in6>()],
            )
        };
        let mut addrlen: c_int = mem::size_of::<sockaddr_in6>() as i32;
        let result = unsafe {
            srt::srt_getsockname(
                self.id,
                &mut addr as *mut sockaddr_in6 as *mut sockaddr,
                &mut addrlen as *mut c_int,
            )
        };
        if result == -1 {
            error::handle_result("0.0.0.0:0".parse().unwrap(), result)
        } else {
            let local_addr = match addr.sin6_family as i32 {
                AF_INET => {
                    SocketAddr::V4(create_socket_addr_v4(unsafe { mem::transmute_copy(&addr) }))
                }
                AF_INET6 => SocketAddr::V6(create_socket_addr_v6(addr)),
                _ => unreachable!("libsrt returned a socket with an unrecognized family"),
            };
            error::handle_result(local_addr, 0)
        }
    }
    pub fn peer_addr(&self) -> Result<SocketAddr> {
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
        if result == -1 {
            error::handle_result("0.0.0.0:0".parse().unwrap(), result)
        } else {
            let peer_addr = match addr.sin6_family as i32 {
                AF_INET => {
                    SocketAddr::V4(create_socket_addr_v4(unsafe { mem::transmute_copy(&addr) }))
                }
                AF_INET6 => SocketAddr::V6(create_socket_addr_v6(addr)),
                _ => unreachable!("libsrt returned a socket with an unrecognized family"),
            };
            error::handle_result(peer_addr, result)
        }
    }
    pub fn accept(&self) -> Result<(Self, SocketAddr)> {
        let mut addr = unsafe {
            mem::transmute::<[u8; mem::size_of::<sockaddr_in6>()], sockaddr_in6>(
                [0; mem::size_of::<sockaddr_in6>()],
            )
        };
        let mut _addrlen: c_int = mem::size_of::<sockaddr_in6>() as i32;
        let result = unsafe {
            srt::srt_accept(
                self.id,
                &mut addr as *mut sockaddr_in6 as *mut libsrt_sys::sockaddr,
                &mut _addrlen as *mut c_int,
            )
        };
        if result == -1 {
            error::handle_result((Self { id: 0 }, "0.0.0.0:0".parse().unwrap()), result)
        } else {
            let peer_addr = match addr.sin6_family as i32 {
                AF_INET => {
                    SocketAddr::V4(create_socket_addr_v4(unsafe { mem::transmute_copy(&addr) }))
                }
                AF_INET6 => SocketAddr::V6(create_socket_addr_v6(addr)),
                f => unreachable!("libsrt returned a socket with an unrecognized family {}", f),
            };
            Ok((Self { id: result }, peer_addr))
        }
    }
    pub fn close(self) -> Result<()> {
        let result = unsafe { srt::srt_close(self.id) };
        error::handle_result((), result)
    }
    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        let result = unsafe {
            srt::srt_send(
                self.id,
                buf as *const [u8] as *const c_char,
                buf.len() as i32,
            )
        };
        if result == -1 {
            error::handle_result(result as usize, result)
        } else {
            Ok(result as usize)
        }
    }
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let result =
            unsafe { srt::srt_recv(self.id, buf as *mut [u8] as *mut c_char, buf.len() as i32) };
        if result == -1 {
            error::handle_result(result as usize, result)
        } else {
            Ok(result as usize)
        }
    }
    pub fn get_sender_buffer(&self) -> Result<(usize, usize)> {
        let mut blocks = 0;
        let mut bytes = 0;
        let result = unsafe {
            srt::srt_getsndbuffer(self.id, &mut blocks as *mut usize, &mut bytes as *mut usize)
        };
        if result == -1 {
            error::handle_result((blocks, bytes), result)
        } else {
            Ok((blocks, bytes))
        }
    }
    pub fn get_events(&self) -> Result<srt::SRT_EPOLL_OPT> {
        let mut events: i32 = 0;
        let mut _optlen = mem::size_of::<i32>() as i32;
        let result = unsafe {
            srt::srt_getsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_EVENT,
                &mut events as *mut i32 as *mut c_void,
                &mut _optlen as *mut c_int,
            )
        };
        error::handle_result(
            srt::SRT_EPOLL_OPT(events.try_into().expect("invalid events")),
            result,
        )
    }
}
//Public get flag methods
impl SrtSocket {
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
    pub fn get_reject_reason(&self) -> Option<&str> {
        let result = unsafe { srt::srt_getrejectreason(self.id) };
        let reason = srt::SRT_REJECT_REASON(result.try_into().expect("invalid reject code"));
        if reason == srt::SRT_REJECT_REASON::SRT_REJ_UNKNOWN {
            None
        } else {
            let result = unsafe { CStr::from_ptr(srt::srt_rejectreason_str(result)) };
            Some(result.to_str().expect("malformed reject reason"))
        }
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
    pub fn get_socket_state(&self) -> Result<SrtSocketStatus> {
        let mut _optlen = mem::size_of::<srt::SRT_SOCKSTATUS>() as i32;
        let state = unsafe { srt::srt_getsockstate(self.id) };
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
            _ => return error::handle_result(SrtSocketStatus::Broken, -1),
        };
        error::handle_result(state, 0)
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
//Post set flag methods
impl SrtSocket {
    pub fn set_time_drift_tracer(&self, enable: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_DRIFTTRACER,
                &enable as *const bool as *const c_void,
                mem::size_of::<i64>() as c_int,
            )
        };
        error::handle_result((), result)
    }
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

//Pre set flag methods
impl SrtSocket {
    pub fn set_bind_to_device(&self, device: String) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_BINDTODEVICE,
                device.as_ptr() as *const c_void,
                device.len() as c_int,
            )
        };
        error::handle_result((), result)
    }
    pub fn set_connection_timeout(&self, msecs: i32) -> Result<()> {
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
    pub fn set_flight_flag_size(&self, packets: i32) -> Result<()> {
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
    pub fn set_ip_type_of_service(&self, type_of_service: i32) -> Result<()> {
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
    pub fn set_ipv4_time_to_live(&self, hops: i32) -> Result<()> {
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
    pub fn set_ipv6_only(&self, value: i32) -> Result<()> {
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
    pub fn set_km_refresh_rate(&self, packets: i32) -> Result<()> {
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
    pub fn set_km_preannounce(&self, packets: i32) -> Result<()> {
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
    pub fn set_linger(&self, secs: i32) -> Result<()> {
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
    pub fn set_linger(&self, secs: i32) -> Result<()> {
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
    pub fn set_max_reorder_tolerance(&self, packets: i32) -> Result<()> {
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
    pub fn set_max_bandwith(&self, bytes_per_sec: i64) -> Result<()> {
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
    pub fn set_message_api(&self, enable: bool) -> Result<()> {
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
    pub fn set_min_version(&self, version: i32) -> Result<()> {
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
    pub fn set_mss(&self, bytes: i32) -> Result<()> {
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
    pub fn set_nak_report(&self, enable: bool) -> Result<()> {
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
    pub fn set_packet_filter(&self, filter: &str) -> Result<()> {
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
    pub fn set_passphrase(&self, passphrase: &str) -> Result<()> {
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
    pub fn set_payload_size(&self, bytes: i32) -> Result<()> {
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
    pub fn set_encryption_key_length(&self, bytes: i32) -> Result<()> {
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
    pub fn set_peer_idle_timeout(&self, msecs: i32) -> Result<()> {
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
    pub fn set_peer_latency(&self, msecs: i32) -> Result<()> {
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
    pub fn set_receive_buffer(&self, bytes: i32) -> Result<()> {
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
    pub fn set_receive_latency(&self, msecs: i32) -> Result<()> {
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
    pub fn set_receive_blocking(&self, blocking: bool) -> Result<()> {
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
    pub fn set_rendezvous(&self, rendezvous: bool) -> Result<()> {
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
    pub fn set_retransmission_algorithm(&self, reduced: bool) -> Result<()> {
        let result = unsafe {
            srt::srt_setsockflag(
                self.id,
                srt::SRT_SOCKOPT::SRTO_RETRANSMITALGO,
                &reduced as *const bool as *const c_void,
                mem::size_of::<bool>() as c_int,
            )
        };
        error::handle_result((), result)
    }
    pub fn set_reuse_address(&self, reuse: bool) -> Result<()> {
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
    pub fn set_congestion_controller(&self, controller: SrtCongestionController) -> Result<()> {
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
    pub fn set_send_buffer(&self, bytes: i32) -> Result<()> {
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
    pub fn set_send_drop_delay(&self, msecs: i32) -> Result<()> {
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
    pub fn set_stream_id(&self, id: &str) -> Result<()> {
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
    pub fn set_enforced_encryption(&self, enforced: bool) -> Result<()> {
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
    pub fn set_too_late_packet_drop(&self, enable: bool) -> Result<()> {
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
    pub fn set_transmission_type(&self, transmission_type: SrtTransmissionType) -> Result<()> {
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
    pub fn set_timestamp_based_packet_delivery_mode(&self, enable: bool) -> Result<()> {
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
    pub fn set_udp_send_buffer(&self, bytes: i32) -> Result<()> {
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
    pub fn set_udp_receive_buffer(&self, bytes: i32) -> Result<()> {
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

#[derive(Copy, Clone)]
pub enum SrtKmState {
    Unsecured,
    Securing,
    Secured,
    NoSecret,
    BadSecret,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum SrtTransmissionType {
    Live,
    File,
    Invalid,
}

#[derive(Copy, Clone)]
pub enum SrtCongestionController {
    Live,
    File,
}

#[cfg(target_os = "linux")]
fn create_socket_addr_v4(addr: sockaddr_in) -> SocketAddrV4 {
    let ip = addr.sin_addr.s_addr.to_le_bytes();
    SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), addr.sin_port)
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
fn create_socket_addr_v4(addr: sockaddr_in) -> SocketAddrV4 {
    let ip = unsafe { addr.sin_addr.S_un.S_un_b() };
    SocketAddrV4::new(
        Ipv4Addr::new(ip.s_b1, ip.s_b2, ip.s_b3, ip.s_b4),
        addr.sin_port,
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
