use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::identity::Identity;
use crate::interfaces::interface::InterfaceMode;
use crate::transport::Transport;

// HDLC constants
const HDLC_FLAG: u8 = 0x7E;
const HDLC_ESC: u8 = 0x7D;
const HDLC_ESC_MASK: u8 = 0x20;

// KISS constants
const KISS_FEND: u8 = 0xC0;
const KISS_FESC: u8 = 0xDB;
const KISS_TFEND: u8 = 0xDC;
const KISS_TFESC: u8 = 0xDD;
const KISS_CMD_DATA: u8 = 0x00;

// I2P interface constants
#[allow(dead_code)]
const I2P_USER_TIMEOUT: u64 = 45;
#[allow(dead_code)]
const I2P_PROBE_AFTER: u64 = 10;
#[allow(dead_code)]
const I2P_PROBE_INTERVAL: u64 = 9;
#[allow(dead_code)]
const I2P_PROBES: u32 = 5;
#[allow(dead_code)]
const I2P_READ_TIMEOUT: u64 = 6;
#[allow(dead_code)]
const RECONNECT_WAIT: u64 = 15;
#[allow(dead_code)]
const RECONNECT_MAX_TRIES: usize = 10;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum TunnelState {
    Init,
    Active,
    Stale,
}

#[allow(dead_code)]
struct I2PInterfacePeerInner {
    socket: Option<TcpStream>,
    online: bool,
    writing: bool,
    kiss_framing: bool,
    last_read: Instant,
    last_write: Instant,
    tunnel_state: TunnelState,
    detached: bool,
    reconnecting: bool,
}

#[allow(dead_code)]
pub struct I2PInterfacePeer {
    pub name: String,
    pub hw_mtu: usize,
    pub mode: InterfaceMode,
    pub bitrate: u64,
    /// Experimental: force bitrate throttle on outgoing data
    pub _force_bitrate: bool,
    pub ifac_size: Option<usize>,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    pub ifac_identity: Option<Identity>,
    pub ifac_signature: Option<Vec<u8>>,
    
    pub rxb: Arc<Mutex<u64>>,
    pub txb: Arc<Mutex<u64>>,
    
    inner: Arc<Mutex<I2PInterfacePeerInner>>,
    initiator: bool,
    parent_interface_name: Option<String>,
}

impl I2PInterfacePeer {
    pub fn new_outbound(
        parent_name: &str,
        _owner: &Transport,
        peer_name: &str,
        _target_i2p_dest: &str,
        _sam_address: Option<&str>,
        ifac_size: Option<usize>,
        ifac_netname: Option<String>,
        ifac_netkey: Option<String>,
    ) -> io::Result<Self> {
        let name = format!("{} to {}", parent_name, peer_name);
        
        let inner = I2PInterfacePeerInner {
            socket: None,
            online: false,
            writing: false,
            kiss_framing: false,
            last_read: Instant::now(),
            last_write: Instant::now(),
            tunnel_state: TunnelState::Init,
            detached: false,
            reconnecting: false,
        };

        let mut peer = I2PInterfacePeer {
            name,
            hw_mtu: 1064,
            mode: InterfaceMode::Full,
            bitrate: 256 * 1000,
            _force_bitrate: false,
            ifac_size,
            ifac_netname: ifac_netname.clone(),
            ifac_netkey: ifac_netkey.clone(),
            ifac_identity: None,
            ifac_signature: None,
            rxb: Arc::new(Mutex::new(0)),
            txb: Arc::new(Mutex::new(0)),
            inner: Arc::new(Mutex::new(inner)),
            initiator: true,
            parent_interface_name: Some(parent_name.to_string()),
        };

        // Set up IFAC if needed
        peer.setup_ifac()?;

        // TODO: Set up I2P tunnel connection in a background thread
        // This would involve:
        // 1. Creating a SAM connection
        // 2. Setting up a client tunnel
        // 3. Connecting through the tunnel
        // 4. Starting the read loop

        Ok(peer)
    }

    pub fn new_inbound(
        parent_name: &str,
        _owner: &Transport,
        socket: TcpStream,
        ifac_size: Option<usize>,
        ifac_netname: Option<String>,
        ifac_netkey: Option<String>,
    ) -> io::Result<Self> {
        let name = format!("Connected peer on {}", parent_name);
        
        #[cfg(target_os = "linux")]
        Self::set_timeouts_linux(&socket)?;
        
        #[cfg(target_os = "macos")]
        Self::set_timeouts_macos(&socket)?;

        let inner = I2PInterfacePeerInner {
            socket: Some(socket),
            online: true,
            writing: false,
            kiss_framing: false,
            last_read: Instant::now(),
            last_write: Instant::now(),
            tunnel_state: TunnelState::Active,
            detached: false,
            reconnecting: false,
        };

        let mut peer = I2PInterfacePeer {
            name,
            hw_mtu: 1064,
            mode: InterfaceMode::Full,
            bitrate: 256 * 1000,
            _force_bitrate: false,
            ifac_size,
            ifac_netname: ifac_netname.clone(),
            ifac_netkey: ifac_netkey.clone(),
            ifac_identity: None,
            ifac_signature: None,
            rxb: Arc::new(Mutex::new(0)),
            txb: Arc::new(Mutex::new(0)),
            inner: Arc::new(Mutex::new(inner)),
            initiator: false,
            parent_interface_name: Some(parent_name.to_string()),
        };

        // Set up IFAC if needed
        peer.setup_ifac()?;

        Ok(peer)
    }

    fn setup_ifac(&mut self) -> io::Result<()> {
        if self.ifac_netname.is_some() || self.ifac_netkey.is_some() {
            use sha2::{Sha256, Digest};
            use hkdf::Hkdf;

            let mut ifac_origin = Vec::new();
            
            if let Some(ref netname) = self.ifac_netname {
                let hash = Sha256::digest(netname.as_bytes());
                ifac_origin.extend_from_slice(&hash);
            }
            
            if let Some(ref netkey) = self.ifac_netkey {
                let hash = Sha256::digest(netkey.as_bytes());
                ifac_origin.extend_from_slice(&hash);
            }

            let ifac_origin_hash = Sha256::digest(&ifac_origin);
            
            // HKDF derivation
            let hk = Hkdf::<Sha256>::new(
                Some(&crate::reticulum::IFAC_SALT),
                &ifac_origin_hash
            );
            let mut ifac_key = [0u8; 64];
            hk.expand(&[], &mut ifac_key)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("HKDF error: {}", e)))?;

            let ifac_identity = Identity::from_bytes(&ifac_key)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Identity error: {}", e)))?;
            
            let ifac_signature = ifac_identity.sign(&Sha256::digest(&ifac_key).to_vec());
            
            self.ifac_identity = Some(ifac_identity);
            self.ifac_signature = Some(ifac_signature);
        }
        
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn set_timeouts_linux(socket: &TcpStream) -> io::Result<()> {
        use std::os::unix::io::AsRawFd;
        use libc::{setsockopt, SOL_SOCKET, SO_KEEPALIVE, IPPROTO_TCP};
        use libc::{TCP_USER_TIMEOUT, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT};

        let fd = socket.as_raw_fd();
        
        unsafe {
            let optval: libc::c_int = 1;
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_KEEPALIVE,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );

            let timeout_ms: libc::c_int = (I2P_USER_TIMEOUT * 1000) as libc::c_int;
            setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_USER_TIMEOUT,
                &timeout_ms as *const _ as *const libc::c_void,
                std::mem::size_of_val(&timeout_ms) as libc::socklen_t,
            );

            let keepidle: libc::c_int = I2P_PROBE_AFTER as libc::c_int;
            setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_KEEPIDLE,
                &keepidle as *const _ as *const libc::c_void,
                std::mem::size_of_val(&keepidle) as libc::socklen_t,
            );

            let keepintvl: libc::c_int = I2P_PROBE_INTERVAL as libc::c_int;
            setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_KEEPINTVL,
                &keepintvl as *const _ as *const libc::c_void,
                std::mem::size_of_val(&keepintvl) as libc::socklen_t,
            );

            let keepcnt: libc::c_int = I2P_PROBES as libc::c_int;
            setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_KEEPCNT,
                &keepcnt as *const _ as *const libc::c_void,
                std::mem::size_of_val(&keepcnt) as libc::socklen_t,
            );
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn set_timeouts_macos(socket: &TcpStream) -> io::Result<()> {
        use std::os::unix::io::AsRawFd;
        use libc::{setsockopt, SOL_SOCKET, SO_KEEPALIVE, IPPROTO_TCP};
        
        const TCP_KEEPALIVE: libc::c_int = 0x10;

        let fd = socket.as_raw_fd();
        
        unsafe {
            let optval: libc::c_int = 1;
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_KEEPALIVE,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );

            let keepidle: libc::c_int = I2P_PROBE_AFTER as libc::c_int;
            setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_KEEPALIVE,
                &keepidle as *const _ as *const libc::c_void,
                std::mem::size_of_val(&keepidle) as libc::socklen_t,
            );
        }

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[allow(dead_code)]
    fn set_timeouts_linux(_socket: &TcpStream) -> io::Result<()> {
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[allow(dead_code)]
    fn set_timeouts_macos(_socket: &TcpStream) -> io::Result<()> {
        Ok(())
    }

    fn hdlc_escape(data: &[u8]) -> Vec<u8> {
        let mut escaped = Vec::with_capacity(data.len() * 2);
        for &byte in data {
            if byte == HDLC_FLAG || byte == HDLC_ESC {
                escaped.push(HDLC_ESC);
                escaped.push(byte ^ HDLC_ESC_MASK);
            } else {
                escaped.push(byte);
            }
        }
        escaped
    }

    fn kiss_escape(data: &[u8]) -> Vec<u8> {
        let mut escaped = Vec::with_capacity(data.len() * 2);
        for &byte in data {
            if byte == KISS_FEND {
                escaped.push(KISS_FESC);
                escaped.push(KISS_TFEND);
            } else if byte == KISS_FESC {
                escaped.push(KISS_FESC);
                escaped.push(KISS_TFESC);
            } else {
                escaped.push(byte);
            }
        }
        escaped
    }

    pub fn process_outgoing(&self, data: &[u8], _transport: &Transport) -> io::Result<()> {
        // Apply forced bitrate delay if set
        if self._force_bitrate && self.bitrate > 0 {
            let delay_secs = (data.len() as f64 / self.bitrate as f64) * 8.0;
            thread::sleep(Duration::from_secs_f64(delay_secs));
        }

        let mut inner = self.inner.lock().unwrap();
        
        if !inner.online {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "Interface not online"));
        }

        // Wait for any ongoing write to complete
        while inner.writing {
            drop(inner);
            thread::sleep(Duration::from_millis(1));
            inner = self.inner.lock().unwrap();
        }

        inner.writing = true;
        
        // Get framing mode before mutable borrow
        let kiss_framing = inner.kiss_framing;
        
        let result = if let Some(ref mut socket) = inner.socket {
            let framed_data = if kiss_framing {
                let mut output = vec![KISS_FEND, KISS_CMD_DATA];
                output.extend(Self::kiss_escape(data));
                output.push(KISS_FEND);
                output
            } else {
                let mut output = vec![HDLC_FLAG];
                output.extend(Self::hdlc_escape(data));
                output.push(HDLC_FLAG);
                output
            };

            match socket.write_all(&framed_data) {
                Ok(_) => {
                    *self.txb.lock().unwrap() += framed_data.len() as u64;
                    inner.last_write = Instant::now();
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "No socket"))
        };

        inner.writing = false;
        result
    }

    pub fn start_read_loop(&self, transport: Arc<Mutex<Transport>>) {
        let inner_clone = self.inner.clone();
        let rxb_clone = self.rxb.clone();
        let hw_mtu = self.hw_mtu;
        let name = self.name.clone();
        let _initiator = self.initiator;

        thread::spawn(move || {
            let mut in_frame = false;
            let mut escape = false;
            let mut data_buffer = Vec::new();
            let mut kiss_command = 0xFF;

            loop {
                let (socket_clone, kiss_framing) = {
                    let inner = inner_clone.lock().unwrap();
                    if let Some(ref socket) = inner.socket {
                        (socket.try_clone().ok(), inner.kiss_framing)
                    } else {
                        break;
                    }
                };

                if let Some(mut socket) = socket_clone {
                    let mut buffer = [0u8; 4096];
                    match socket.read(&mut buffer) {
                        Ok(0) => {
                            // Connection closed
                            let mut inner = inner_clone.lock().unwrap();
                            inner.online = false;
                            println!("I2PInterfacePeer[{}]: Connection closed", name);
                            break;
                        }
                        Ok(n) => {
                            let mut inner = inner_clone.lock().unwrap();
                            inner.last_read = Instant::now();
                            drop(inner);

                            *rxb_clone.lock().unwrap() += n as u64;

                            for &byte in &buffer[..n] {
                                if kiss_framing {
                                    // KISS framing
                                    if in_frame && byte == KISS_FEND && kiss_command == KISS_CMD_DATA {
                                        in_frame = false;
                                        if !data_buffer.is_empty() {
                                            // Process incoming data
                                            let _transport_guard = transport.lock().unwrap();
                                            // transport_guard.inbound(&data_buffer, self);
                                            // TODO: Need interface reference
                                        }
                                    } else if byte == KISS_FEND {
                                        in_frame = true;
                                        kiss_command = 0xFF;
                                        data_buffer.clear();
                                    } else if in_frame && data_buffer.len() < hw_mtu {
                                        if data_buffer.is_empty() && kiss_command == 0xFF {
                                            kiss_command = byte & 0x0F;
                                        } else if kiss_command == KISS_CMD_DATA {
                                            if byte == KISS_FESC {
                                                escape = true;
                                            } else if escape {
                                                escape = false;
                                                let actual_byte = if byte == KISS_TFEND {
                                                    KISS_FEND
                                                } else if byte == KISS_TFESC {
                                                    KISS_FESC
                                                } else {
                                                    byte
                                                };
                                                data_buffer.push(actual_byte);
                                            } else {
                                                data_buffer.push(byte);
                                            }
                                        }
                                    }
                                } else {
                                    // HDLC framing
                                    if in_frame && byte == HDLC_FLAG {
                                        in_frame = false;
                                        if !data_buffer.is_empty() {
                                            // Process incoming data
                                            let _transport_guard = transport.lock().unwrap();
                                            // transport_guard.inbound(&data_buffer, self);
                                            // TODO: Need interface reference
                                        }
                                    } else if byte == HDLC_FLAG {
                                        in_frame = true;
                                        data_buffer.clear();
                                    } else if in_frame && data_buffer.len() < hw_mtu {
                                        if byte == HDLC_ESC {
                                            escape = true;
                                        } else if escape {
                                            escape = false;
                                            let actual_byte = if byte == (HDLC_FLAG ^ HDLC_ESC_MASK) {
                                                HDLC_FLAG
                                            } else if byte == (HDLC_ESC ^ HDLC_ESC_MASK) {
                                                HDLC_ESC
                                            } else {
                                                byte
                                            };
                                            data_buffer.push(actual_byte);
                                        } else {
                                            data_buffer.push(byte);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("I2PInterfacePeer[{}]: Read error: {}", name, e);
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
        });
    }

    pub fn is_online(&self) -> bool {
        self.inner.lock().unwrap().online
    }
}
