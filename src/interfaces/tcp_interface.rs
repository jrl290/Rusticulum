use super::interface::{Interface, InterfaceMode};
use crate::transport::Transport;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

// ── Global reconnect nudge ──────────────────────────────────────────────
// A Condvar shared by all TCP client reconnect loops.  When the platform
// layer detects that network connectivity has been restored it calls
// `nudge_reconnect()`, which wakes every sleeping reconnect loop so they
// can attempt an immediate connect instead of waiting out the full
// RECONNECT_WAIT interval.
static RECONNECT_NUDGE: once_cell::sync::Lazy<(Mutex<()>, Condvar)> =
    once_cell::sync::Lazy::new(|| (Mutex::new(()), Condvar::new()));

/// Wake all TCP client reconnect loops immediately.
/// Safe to call from any thread, including C FFI.
pub fn nudge_reconnect() {
    let (lock, cvar) = &*RECONNECT_NUDGE;
    let _guard = lock.lock().unwrap();
    cvar.notify_all();
}

/// Sleep for up to `secs` but return early if `nudge_reconnect()` is called.
fn wait_or_nudge(secs: u64) {
    let (lock, cvar) = &*RECONNECT_NUDGE;
    let nudged = lock.lock().unwrap();
    // Use wait_timeout (not wait_timeout_while) so that ANY notify_all
    // wakes us, regardless of whether another thread consumed the flag first.
    // We don't care about the flag value — the nudge is purely a "try now" hint.
    let _ = cvar.wait_timeout(nudged, Duration::from_secs(secs));
}

/// HDLC framing for TCP Interface
pub struct Hdlc;

impl Hdlc {
    pub const FLAG: u8 = 0x7E;
    pub const ESC: u8 = 0x7D;
    pub const ESC_MASK: u8 = 0x20;

    pub fn escape(data: &[u8]) -> Vec<u8> {
        let mut escaped = Vec::with_capacity(data.len() + 10);
        for &byte in data {
            if byte == Self::ESC {
                escaped.push(Self::ESC);
                escaped.push(Self::ESC ^ Self::ESC_MASK);
            } else if byte == Self::FLAG {
                escaped.push(Self::ESC);
                escaped.push(Self::FLAG ^ Self::ESC_MASK);
            } else {
                escaped.push(byte);
            }
        }
        escaped
    }
}

/// KISS framing for TCP Interface
pub struct Kiss;

impl Kiss {
    pub const FEND: u8 = 0xC0;
    pub const FESC: u8 = 0xDB;
    pub const TFEND: u8 = 0xDC;
    pub const TFESC: u8 = 0xDD;
    pub const CMD_DATA: u8 = 0x00;
    pub const CMD_UNKNOWN: u8 = 0xFE;

    pub fn escape(data: &[u8]) -> Vec<u8> {
        let mut escaped = Vec::with_capacity(data.len() + 10);
        for &byte in data {
            if byte == Self::FESC {
                escaped.push(Self::FESC);
                escaped.push(Self::TFESC);
            } else if byte == Self::FEND {
                escaped.push(Self::FESC);
                escaped.push(Self::TFEND);
            } else {
                escaped.push(byte);
            }
        }
        escaped
    }
}

/// TCP Client Interface
/// 
/// Connects to a remote TCP server for Reticulum communication.
/// Supports both HDLC and KISS framing, automatic reconnection,
/// and I2P tunneling configuration.
pub struct TcpClientInterface {
    pub base: Interface,
    pub target_ip: String,
    pub target_port: u16,
    pub initiator: bool,
    pub reconnecting: bool,
    pub never_connected: bool,
    pub detached: bool,
    pub kiss_framing: bool,
    pub i2p_tunneled: bool,
    pub mode: u8,
    pub max_reconnect_tries: Option<usize>,
    pub connect_timeout: u64,
    socket: Option<TcpStream>,
    writing: bool,
}

impl TcpClientInterface {
    pub const HW_MTU: usize = 262144;
    pub const BITRATE_GUESS: u64 = 10_000_000; // 10 Mbps
    pub const DEFAULT_IFAC_SIZE: usize = 16;
    pub const RECONNECT_WAIT: u64 = 5; // seconds
    pub const INITIAL_CONNECT_TIMEOUT: u64 = 5; // seconds
    
    // TCP socket timeouts (Linux)
    pub const TCP_USER_TIMEOUT: u64 = 24;
    pub const TCP_PROBE_AFTER: u64 = 5;
    pub const TCP_PROBE_INTERVAL: u64 = 2;
    pub const TCP_PROBES: u64 = 12;
    
    // I2P tunnel timeouts
    pub const I2P_USER_TIMEOUT: u64 = 45;
    pub const I2P_PROBE_AFTER: u64 = 10;
    pub const I2P_PROBE_INTERVAL: u64 = 9;
    pub const I2P_PROBES: u64 = 5;

    /// Create new TCP client from configuration
    pub fn new(config: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let name = config.get("name")
            .ok_or("TCPClientInterface requires 'name' in config")?
            .clone();
        
        let target_ip = config.get("target_host")
            .ok_or("TCPClientInterface requires 'target_host' in config")?
            .clone();
        
        let target_port = config.get("target_port")
            .ok_or("TCPClientInterface requires 'target_port' in config")?
            .parse::<u16>()
            .map_err(|_| "Invalid target_port")?;
        
        let kiss_framing = config.get("kiss_framing")
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);
        
        let i2p_tunneled = config.get("i2p_tunneled")
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);
        
        let connect_timeout = config.get("connect_timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(Self::INITIAL_CONNECT_TIMEOUT);
        
        let max_reconnect_tries = config.get("max_reconnect_tries")
            .and_then(|s| s.parse::<usize>().ok());
        
        let fixed_mtu = config.get("fixed_mtu")
            .and_then(|s| s.parse::<usize>().ok());

        let mut base = Interface::new();
        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = false;
        base.bitrate = Self::BITRATE_GUESS;
        base.online = false;
        base.supports_discovery = true;
        
        if let Some(mtu) = fixed_mtu {
            base.hw_mtu = Some(mtu);
            base.fixed_mtu = true;
            base.autoconfigure_mtu = false;
        } else {
            base.hw_mtu = Some(Self::HW_MTU);
            base.autoconfigure_mtu = true;
        }

        let mut interface = TcpClientInterface {
            base,
            target_ip,
            target_port,
            initiator: true,
            reconnecting: false,
            never_connected: true,
            detached: false,
            kiss_framing,
            i2p_tunneled,
            mode: 0x01, // MODE_FULL
            max_reconnect_tries,
            connect_timeout,
            socket: None,
            writing: false,
        };

        // Attempt initial connection.  If it fails, the interface is still
        // created in a "pending" state — start_read_loop will handle the
        // reconnect using the same condvar-based wait as a mid-session drop.
        let _ = interface.initial_connect();

        Ok(interface)
    }

    /// Create from existing socket (spawned from server)
    pub fn from_socket(name: String, socket: TcpStream) -> Self {
        let peer_addr = socket.peer_addr().ok();
        
        let mut base = Interface::new();
        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = true;
        base.hw_mtu = Some(Self::HW_MTU);
        base.bitrate = Self::BITRATE_GUESS;
        base.online = true;
        base.autoconfigure_mtu = true;
        base.supports_discovery = true;

        // Set TCP_NODELAY
        let _ = socket.set_nodelay(true);

        TcpClientInterface {
            base,
            target_ip: peer_addr.as_ref().map(|a| a.ip().to_string()).unwrap_or_default(),
            target_port: peer_addr.as_ref().map(|a| a.port()).unwrap_or(0),
            initiator: false,
            reconnecting: false,
            never_connected: false,
            detached: false,
            kiss_framing: false,
            i2p_tunneled: false,
            mode: 0x01,
            max_reconnect_tries: None,
            connect_timeout: Self::INITIAL_CONNECT_TIMEOUT,
            socket: Some(socket),
            writing: false,
        }
    }

    /// Initial connection attempt
    fn initial_connect(&mut self) -> Result<(), String> {
        crate::log(&format!("TCP connecting to {}:{}...", self.target_ip, self.target_port), crate::LOG_NOTICE, false, false);
        println!("Establishing TCP connection for {}...", self.to_string());
        
        match self.connect(true) {
            Ok(_) => {
                crate::log(&format!("TCP connection established to {}:{}", self.target_ip, self.target_port), crate::LOG_NOTICE, false, false);
                println!("TCP connection for {} established", self.to_string());
                // TODO: Start read_loop in thread
                Ok(())
            }
            Err(e) => {
                crate::log(&format!("TCP connection failed to {}:{}: {}", self.target_ip, self.target_port, e), crate::LOG_ERROR, false, false);
                // TODO: Start reconnect thread
                Err(e)
            }
        }
    }

    /// Connect to target
    fn connect(&mut self, _initial: bool) -> Result<(), String> {
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", self.target_ip, self.target_port);
        
        // Use ToSocketAddrs to support both hostnames and IP addresses
        let sock_addr = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve {}: {}", addr_str, e))?
            .next()
            .ok_or_else(|| format!("No addresses found for {}", addr_str))?;

        let stream = TcpStream::connect_timeout(
            &sock_addr,
            Duration::from_secs(self.connect_timeout)
        ).map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_nodelay(true)
            .map_err(|e| format!("Failed to set TCP_NODELAY: {}", e))?;

        // Set keepalive and timeouts
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.set_socket_options_linux(&stream)?;
        
        #[cfg(target_os = "macos")]
        self.set_socket_options_macos(&stream)?;

        self.socket = Some(stream);
        self.base.online = true;
        self.writing = false;
        self.never_connected = false;

        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn set_socket_options_linux(&self, stream: &TcpStream) -> Result<(), String> {
        use std::os::unix::io::AsRawFd;
        use libc::{setsockopt, SOL_SOCKET, SO_KEEPALIVE, IPPROTO_TCP, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT, TCP_USER_TIMEOUT};
        
        let optlen = std::mem::size_of::<i32>();
        unsafe {
            let fd = stream.as_raw_fd();
            let keepalive: i32 = 1;
            
            if !self.i2p_tunneled {
                let user_timeout = (Self::TCP_USER_TIMEOUT * 1000) as i32;
                let keepidle = Self::TCP_PROBE_AFTER as i32;
                let keepintvl = Self::TCP_PROBE_INTERVAL as i32;
                let keepcnt = Self::TCP_PROBES as i32;
                
                setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout as *const _ as *const _, optlen as _);
                setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive as *const _ as *const _, optlen as _);
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle as *const _ as *const _, optlen as _);
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl as *const _ as *const _, optlen as _);
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt as *const _ as *const _, optlen as _);
            } else {
                let user_timeout = (Self::I2P_USER_TIMEOUT * 1000) as i32;
                let keepidle = Self::I2P_PROBE_AFTER as i32;
                let keepintvl = Self::I2P_PROBE_INTERVAL as i32;
                let keepcnt = Self::I2P_PROBES as i32;
                
                setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout as *const _ as *const _, optlen as _);
                setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive as *const _ as *const _, optlen as _);
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle as *const _ as *const _, optlen as _);
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl as *const _ as *const _, optlen as _);
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt as *const _ as *const _, optlen as _);
            }
        }
        
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn set_socket_options_macos(&self, stream: &TcpStream) -> Result<(), String> {
        use std::os::unix::io::AsRawFd;
        use libc::{setsockopt, SOL_SOCKET, SO_KEEPALIVE, IPPROTO_TCP};
        
        const TCP_KEEPALIVE: i32 = 0x10;
        
        unsafe {
            let fd = stream.as_raw_fd();
            let keepalive: i32 = 1;
            
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive as *const _ as *const _, std::mem::size_of::<i32>() as u32);
            
            let keepidle = if !self.i2p_tunneled {
                Self::TCP_PROBE_AFTER as i32
            } else {
                Self::I2P_PROBE_AFTER as i32
            };
            
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &keepidle as *const _ as *const _, std::mem::size_of::<i32>() as u32);
        }
        
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    #[allow(dead_code)]
    fn set_socket_options_linux(&self, _stream: &TcpStream) -> Result<(), String> {
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    #[allow(dead_code)]
    fn set_socket_options_macos(&self, _stream: &TcpStream) -> Result<(), String> {
        Ok(())
    }

    /// Reconnect after disconnection
    pub fn reconnect(&mut self) {
        if !self.initiator {
            return;
        }

        if self.reconnecting {
            return;
        }

        self.reconnecting = true;
        let mut attempts = 0;

        while !self.base.online {
            thread::sleep(Duration::from_secs(Self::RECONNECT_WAIT));
            attempts += 1;

            if let Some(max_tries) = self.max_reconnect_tries {
                if attempts > max_tries {
                    // TODO: self.teardown()
                    break;
                }
            }

            match self.connect(false) {
                Ok(_) => {
                    if !self.never_connected {
                        println!("Reconnected socket for {}", self.to_string());
                    }
                    break;
                }
                Err(_e) => {
                }
            }
        }

        self.reconnecting = false;
        // TODO: Start read_loop thread
        // TODO: RNS.Transport.synthesize_tunnel(self) if not kiss_framing
    }

    /// Process incoming data
    fn process_incoming(&mut self, data: Vec<u8>) {
        if self.base.online && !self.detached {
            self.base.rxb += data.len() as u64;
            let interface_name = self.base.name.clone();
            let inbound_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Transport::inbound(data, interface_name)
            }));
            if let Err(panic) = inbound_result {
                let _detail = if let Some(msg) = panic.downcast_ref::<&str>() {
                    (*msg).to_string()
                } else if let Some(msg) = panic.downcast_ref::<String>() {
                    msg.clone()
                } else {
                    "unknown panic".to_string()
                };
            }
        }
    }

    /// Process outgoing data
    pub fn process_outgoing(&mut self, data: Vec<u8>) -> Result<(), String> {
        crate::log(&format!("TCP outgoing {} bytes, online={}, detached={}", data.len(), self.base.online, self.detached), crate::LOG_VERBOSE, false, false);
        if !self.base.online || self.detached {
            return Err("Interface offline or detached".to_string());
        }

        self.writing = true;

        // Apply forced bitrate delay if set
        self.base.enforce_bitrate(data.len());

        let framed = if self.kiss_framing {
            let mut frame = vec![Kiss::FEND, Kiss::CMD_DATA];
            frame.extend_from_slice(&Kiss::escape(&data));
            frame.push(Kiss::FEND);
            frame
        } else {
            let mut frame = vec![Hdlc::FLAG];
            frame.extend_from_slice(&Hdlc::escape(&data));
            frame.push(Hdlc::FLAG);
            frame
        };

        if let Some(ref mut socket) = self.socket {
            #[cfg(unix)]
            let write_fd = {
                use std::os::unix::io::AsRawFd;
                socket.as_raw_fd()
            };
            match socket.write_all(&framed) {
                Ok(_) => {
                    self.base.txb += framed.len() as u64;
                }
                Err(e) => {
                    #[cfg(unix)]
                    crate::log(&format!("TCP write failed on fd={}, marking offline: {}", write_fd, e), crate::LOG_ERROR, false, false);
                    #[cfg(not(unix))]
                    crate::log(&format!("TCP write failed, marking offline: {}", e), crate::LOG_ERROR, false, false);
                    self.base.online = false;
                    self.socket = None;
                    self.writing = false;
                    return Err(format!("Failed to send data: {}", e));
                }
            }
        } else {
            return Err("No socket connection".to_string());
        }

        self.writing = false;
        Ok(())
    }

    /// Read loop (to be run in thread)
    pub fn read_loop(&mut self) -> Result<(), String> {
        let mut in_frame = false;
        let mut escape = false;
        let mut frame_buffer = Vec::new();
        let mut data_buffer = Vec::new();
        let mut command = Kiss::CMD_UNKNOWN;
        let mut buf = [0u8; 4096];

        loop {
            if let Some(ref mut socket) = self.socket {
                match socket.read(&mut buf) {
                    Ok(0) => {
                        // Connection closed
                        self.base.online = false;
                        if self.initiator && !self.detached {
                            println!("Socket for {} was closed, attempting to reconnect...", self.to_string());
                            self.reconnect();
                        } else {
                            println!("Socket for remote client {} was closed", self.to_string());
                            // TODO: self.teardown()
                        }
                        break;
                    }
                    Ok(n) => {
                        let data_in = &buf[..n];
                        
                        if self.kiss_framing {
                            // KISS framing
                            for &byte in data_in {
                                if in_frame && byte == Kiss::FEND && command == Kiss::CMD_DATA {
                                    in_frame = false;
                                    if !data_buffer.is_empty() {
                                        self.process_incoming(data_buffer.clone());
                                        data_buffer.clear();
                                    }
                                } else if byte == Kiss::FEND {
                                    in_frame = true;
                                    command = Kiss::CMD_UNKNOWN;
                                    data_buffer.clear();
                                } else if in_frame && data_buffer.len() < self.base.hw_mtu.unwrap_or(Self::HW_MTU) {
                                    if data_buffer.is_empty() && command == Kiss::CMD_UNKNOWN {
                                        command = byte & 0x0F;
                                    } else if command == Kiss::CMD_DATA {
                                        if byte == Kiss::FESC {
                                            escape = true;
                                        } else {
                                            if escape {
                                                let unescaped = match byte {
                                                    b if b == Kiss::TFEND => Kiss::FEND,
                                                    b if b == Kiss::TFESC => Kiss::FESC,
                                                    b => b,
                                                };
                                                data_buffer.push(unescaped);
                                                escape = false;
                                            } else {
                                                data_buffer.push(byte);
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            // HDLC framing
                            frame_buffer.extend_from_slice(data_in);
                            
                            loop {
                                if let Some(frame_start) = frame_buffer.iter().position(|&b| b == Hdlc::FLAG) {
                                    if let Some(frame_end_offset) = frame_buffer[frame_start + 1..].iter().position(|&b| b == Hdlc::FLAG) {
                                        let frame_end = frame_start + 1 + frame_end_offset;
                                        let frame = &frame_buffer[frame_start + 1..frame_end];
                                        
                                        // Unescape frame
                                        let mut unescaped = Vec::new();
                                        let mut esc = false;
                                        for &byte in frame {
                                            if esc {
                                                if byte == (Hdlc::FLAG ^ Hdlc::ESC_MASK) {
                                                    unescaped.push(Hdlc::FLAG);
                                                } else if byte == (Hdlc::ESC ^ Hdlc::ESC_MASK) {
                                                    unescaped.push(Hdlc::ESC);
                                                }
                                                esc = false;
                                            } else if byte == Hdlc::ESC {
                                                esc = true;
                                            } else {
                                                unescaped.push(byte);
                                            }
                                        }

                                        const HEADER_MINSIZE: usize = 2; // Placeholder
                                        if unescaped.len() > HEADER_MINSIZE {
                                            self.process_incoming(unescaped);
                                        }
                                        
                                        frame_buffer.drain(..=frame_end);
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        self.base.online = false;
                        
                        if self.initiator {
                            println!("Attempting to reconnect...");
                            self.reconnect();
                        } else {
                            // TODO: self.teardown()
                        }
                        return Err(format!("Read error: {}", e));
                    }
                }
            } else {
                return Err("No socket".to_string());
            }
        }

        Ok(())
    }

    /// How long (seconds) to wait with no inbound data before declaring
    /// the TCP connection dead and forcing a reconnect.  On backbone
    /// servers traffic arrives every few seconds, so 180 s without a
    /// single byte is a reliable indicator of a zombie connection.
    /// (Lower values can cause false reconnects on quiet networks.)
    const READ_WATCHDOG_TIMEOUT: u64 = 180;

    pub fn start_read_loop(interface: Arc<Mutex<TcpClientInterface>>) {
        // Guard: use `reconnecting` as a "loop is live" sentinel.
        // If another loop is already running for this exact Arc (e.g. a duplicate
        // call from a stale code path), silently return so we never accumulate
        // parallel read loops on a single interface.
        {
            let mut iface = interface.lock().unwrap();
            if iface.reconnecting {
                crate::log(
                    "TCP start_read_loop: loop already active for this interface, ignoring duplicate call",
                    crate::LOG_WARNING, false, false,
                );
                return;
            }
            iface.reconnecting = true;
        }

        thread::spawn(move || {
            // ── Outer loop: read → reconnect → read → … ─────────────────────
            // We never spawn a second thread.  After a successful reconnect we
            // simply `continue 'running` to re-clone the new socket and start
            // reading again in the same thread.
            'running: loop {
                // ── Clone current socket and read static config ───────────────
                let socket_result: Option<(TcpStream, Option<String>, bool, usize, bool)> = {
                    let iface = interface.lock().unwrap();
                    if let Some(socket_ref) = iface.socket.as_ref() {
                        if let Ok(cloned_socket) = socket_ref.try_clone() {
                            #[cfg(unix)] {
                                use std::os::unix::io::AsRawFd;
                                crate::log(&format!("TCP socket clone: original_fd={} clone_fd={}", socket_ref.as_raw_fd(), cloned_socket.as_raw_fd()), crate::LOG_NOTICE, false, false);
                            }
                            Some((
                                cloned_socket,
                                iface.base.name.clone(),
                                iface.kiss_framing,
                                iface.base.hw_mtu.unwrap_or(Self::HW_MTU),
                                iface.initiator,
                            ))
                        } else {
                            crate::log("TCP read loop: socket clone failed", crate::LOG_WARNING, false, false);
                            None
                        }
                    } else {
                        // No socket yet (initial connect failed) — fall through
                        // to the reconnect section below.
                        None
                    }
                };

                // If we have no socket, skip straight to the reconnect logic
                // instead of breaking out entirely.
                if socket_result.is_none() {
                    let iface_name = interface.lock().unwrap().base.name.clone();
                    crate::log(
                        &format!("TCP read loop: no socket for {:?}, entering reconnect", iface_name),
                        crate::LOG_NOTICE, false, false,
                    );
                } else {

                let (raw_socket, interface_name, kiss_framing, hw_mtu, is_initiator) = socket_result.unwrap();
                // Wrap in ManuallyDrop so we control when close() is called.
                // If the OS reclaims our fd (e.g., iOS background), Rust's
                // automatic Drop would call close() on a potentially-reused fd
                // number, corrupting an unrelated socket.
                let mut socket = std::mem::ManuallyDrop::new(raw_socket);
                let mut ebadf = false;

                crate::log(&format!("TCP read loop started for {:?}", interface_name), crate::LOG_NOTICE, false, false);

                // Set a read timeout so we can detect zombie / half-open
                // connections that Android's TCP keepalive fails to catch.
                let watchdog_duration = Duration::from_secs(Self::READ_WATCHDOG_TIMEOUT);
                if let Err(e) = socket.set_read_timeout(Some(watchdog_duration)) {
                    crate::log(&format!("TCP read loop: set_read_timeout failed: {}", e), crate::LOG_WARNING, false, false);
                }

                // Framing state resets on each new connection.
                let mut in_frame = false;
                let mut escape = false;
                let mut frame_buffer = Vec::new();
                let mut data_buffer = Vec::new();
                let mut command = Kiss::CMD_UNKNOWN;
                let mut buf = [0u8; 4096];
                let mut read_count: u64 = 0;
                let mut last_data_time = std::time::Instant::now();

                crate::log("TCP read loop: entering blocking read", crate::LOG_NOTICE, false, false);

                // ── Inner read loop ───────────────────────────────────────────
                'reading: loop {
                    match socket.read(&mut buf) {
                        Ok(0) => {
                            crate::log("TCP read loop: connection closed (read 0)", crate::LOG_NOTICE, false, false);
                            break 'reading;
                        }
                        Ok(n) => {
                            read_count += 1;
                            last_data_time = std::time::Instant::now();
                            crate::log(&format!("TCP inbound: {} bytes (read #{})", n, read_count), crate::LOG_VERBOSE, false, false);
                            let data_in = &buf[..n];

                            if kiss_framing {
                                for &byte in data_in {
                                    if in_frame && byte == Kiss::FEND && command == Kiss::CMD_DATA {
                                        in_frame = false;
                                        if !data_buffer.is_empty() {
                                            let _ = Transport::inbound(data_buffer.clone(), interface_name.clone());
                                            data_buffer.clear();
                                        }
                                    } else if byte == Kiss::FEND {
                                        in_frame = true;
                                        command = Kiss::CMD_UNKNOWN;
                                        data_buffer.clear();
                                    } else if in_frame && data_buffer.len() < hw_mtu {
                                        if data_buffer.is_empty() && command == Kiss::CMD_UNKNOWN {
                                            command = byte & 0x0F;
                                        } else if command == Kiss::CMD_DATA {
                                            if byte == Kiss::FESC {
                                                escape = true;
                                            } else if escape {
                                                let unescaped = match byte {
                                                    b if b == Kiss::TFEND => Kiss::FEND,
                                                    b if b == Kiss::TFESC => Kiss::FESC,
                                                    b => b,
                                                };
                                                data_buffer.push(unescaped);
                                                escape = false;
                                            } else {
                                                data_buffer.push(byte);
                                            }
                                        }
                                    }
                                }
                            } else {
                                frame_buffer.extend_from_slice(data_in);

                                loop {
                                    if let Some(frame_start) = frame_buffer.iter().position(|&b| b == Hdlc::FLAG) {
                                        if let Some(frame_end_offset) = frame_buffer[frame_start + 1..].iter().position(|&b| b == Hdlc::FLAG) {
                                            let frame_end = frame_start + 1 + frame_end_offset;
                                            let frame = &frame_buffer[frame_start + 1..frame_end];

                                            let mut unescaped = Vec::new();
                                            let mut esc = false;
                                            for &byte in frame {
                                                if esc {
                                                    if byte == (Hdlc::FLAG ^ Hdlc::ESC_MASK) {
                                                        unescaped.push(Hdlc::FLAG);
                                                    } else if byte == (Hdlc::ESC ^ Hdlc::ESC_MASK) {
                                                        unescaped.push(Hdlc::ESC);
                                                    }
                                                    esc = false;
                                                } else if byte == Hdlc::ESC {
                                                    esc = true;
                                                } else {
                                                    unescaped.push(byte);
                                                }
                                            }

                                            const HEADER_MINSIZE: usize = 2;
                                            if unescaped.len() > HEADER_MINSIZE {
                                                crate::log(&format!("TCP frame: {} bytes, passing to Transport::inbound", unescaped.len()), crate::LOG_VERBOSE, false, false);
                                                let _ = std::io::Write::flush(&mut std::io::stderr());
                                                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                                    Transport::inbound(unescaped.clone(), interface_name.clone())
                                                }));
                                                match &result {
                                                    Ok(_v) => {
                                                        let _ = std::io::Write::flush(&mut std::io::stderr());
                                                    }
                                                    Err(panic) => {
                                                        let _detail = if let Some(s) = panic.downcast_ref::<&str>() {
                                                            s.to_string()
                                                        } else if let Some(s) = panic.downcast_ref::<String>() {
                                                            s.clone()
                                                        } else {
                                                            "unknown panic".to_string()
                                                        };
                                                    }
                                                }
                                            }

                                            frame_buffer.drain(..=frame_end);
                                        } else {
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                            let idle_secs = last_data_time.elapsed().as_secs();
                            if idle_secs >= Self::READ_WATCHDOG_TIMEOUT {
                                crate::log(
                                    &format!(
                                        "TCP watchdog: no data received for {}s (threshold {}s), connection appears dead — triggering reconnect",
                                        idle_secs, Self::READ_WATCHDOG_TIMEOUT
                                    ),
                                    crate::LOG_WARNING,
                                    false, false,
                                );
                                break 'reading;
                            }
                            // Timeout fired but we haven't exceeded the watchdog threshold yet.
                            continue 'reading;
                        }
                        Err(e) => {
                            #[cfg(unix)] {
                                use std::os::unix::io::AsRawFd;
                                let fd = socket.as_raw_fd();
                                if e.raw_os_error() == Some(9) { // EBADF
                                    ebadf = true;
                                    crate::log(&format!("TCP read loop: EBADF on fd={} — fd was reclaimed by OS", fd), crate::LOG_ERROR, false, false);
                                } else {
                                    crate::log(&format!("TCP read loop: socket error on fd={}: {}", fd, e), crate::LOG_ERROR, false, false);
                                }
                            }
                            #[cfg(not(unix))]
                            crate::log(&format!("TCP read loop: socket error: {}", e), crate::LOG_ERROR, false, false);
                            break 'reading;
                        }
                    }
                } // 'reading

                // ── Read loop exited ──────────────────────────────────────────
                // Handle the cloned socket carefully.  If EBADF occurred the fd
                // was already closed/reclaimed by the OS (common on iOS during
                // background transitions).  Calling close() on that fd number
                // would corrupt whatever new socket inherited it.
                if ebadf {
                    // Intentionally leak — the fd is already gone.
                    crate::log("TCP: leaking dead socket fd (EBADF — already reclaimed by OS)", crate::LOG_WARNING, false, false);
                    // ManuallyDrop prevents close(); nothing else needed.
                } else {
                    // Normal exit (EOF, timeout, connection reset) — close the clone.
                    unsafe { std::mem::ManuallyDrop::drop(&mut socket); }
                }

                crate::log("TCP read loop exited, marking interface offline", crate::LOG_WARNING, false, false);
                {
                    let mut iface = interface.lock().unwrap();
                    iface.base.online = false;
                    iface.socket = None;
                }

                // For server-side (accepted) connections, deregister and stop.
                if !is_initiator {
                    let iface_name = interface.lock().unwrap().base.name.clone();
                    if let Some(ref name) = iface_name {
                        crate::transport::Transport::deregister_interface_stub(name);
                        crate::transport::Transport::unregister_outbound_handler(name);
                        crate::log(
                            &format!("TCP server client disconnected, deregistered interface {}", name),
                            crate::LOG_NOTICE, false, false,
                        );
                    }
                    break 'running;
                }

                } // end of `if socket_result.is_some()` block

                // ── Reconnect (initiator only) ────────────────────────────────
                crate::log("TCP read loop: initiator, attempting reconnect...", crate::LOG_NOTICE, false, false);
                let mut attempts = 0u32;
                let reconnected = 'reconnect: loop {
                    // Wait up to RECONNECT_WAIT seconds, but wake immediately
                    // if the platform signals that network connectivity is back.
                    wait_or_nudge(Self::RECONNECT_WAIT);
                    attempts += 1;

                    let (detached, max_tries) = {
                        let iface = interface.lock().unwrap();
                        (iface.detached, iface.max_reconnect_tries)
                    };

                    if detached {
                        crate::log("TCP reconnect: interface detached, giving up", crate::LOG_NOTICE, false, false);
                        break 'reconnect false;
                    }

                    if let Some(max) = max_tries {
                        if attempts as usize > max {
                            crate::log(&format!("TCP reconnect: max attempts ({}) reached, giving up", max), crate::LOG_ERROR, false, false);
                            break 'reconnect false;
                        }
                    }

                    crate::log(&format!("TCP reconnect attempt {}...", attempts), crate::LOG_NOTICE, false, false);
                    let ok = {
                        let mut iface = interface.lock().unwrap();
                        iface.connect(false).is_ok()
                    };

                    if ok {
                        crate::log("TCP reconnected successfully, restarting read loop", crate::LOG_NOTICE, false, false);
                        break 'reconnect true;
                    } else {
                        crate::log(&format!("TCP reconnect attempt {} failed", attempts), crate::LOG_WARNING, false, false);
                    }
                }; // 'reconnect

                if !reconnected {
                    break 'running;
                }

                // Synthesize tunnel on the new connection then loop back to read.
                let (kiss_framing2, iname, irepr) = {
                    let iface = interface.lock().unwrap();
                    (iface.kiss_framing, iface.base.name.clone().unwrap_or_default(), iface.to_string())
                };
                if !kiss_framing2 {
                    crate::transport::Transport::synthesize_tunnel(&iname, &irepr);
                }
                // continue 'running → re-clone the new socket and read again
            } // 'running

            // Clear the "loop is live" sentinel so the interface can be restarted.
            interface.lock().unwrap().reconnecting = false;
        });
    }

    /// Detach interface
    pub fn detach(&mut self) {
        self.base.online = false;
        self.detached = true;
        
        if let Some(ref mut socket) = self.socket {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        self.socket = None;
    }

    /// Get string representation
    pub fn to_string(&self) -> String {
        let ip_str = if self.target_ip.contains(':') {
            format!("[{}]", self.target_ip)
        } else {
            self.target_ip.clone()
        };
        
        format!(
            "TCPInterface[{}/{}:{}]",
            self.base.name.as_ref().unwrap_or(&"unnamed".to_string()),
            ip_str,
            self.target_port
        )
    }
}

/// TCP Server Interface
/// 
/// Listens for incoming TCP connections and spawns TcpClientInterface
/// for each connection.
pub struct TcpServerInterface {
    pub base: Interface,
    pub bind_ip: String,
    pub bind_port: u16,
    pub i2p_tunneled: bool,
    pub mode: u8,
    spawn_config: SpawnConfig,
    pub spawned_interfaces: Arc<Mutex<Vec<Arc<Mutex<TcpClientInterface>>>>>,
    #[allow(dead_code)]
    listener: Option<Arc<TcpListener>>,
}

#[derive(Clone)]
struct SpawnConfig {
    mode: InterfaceMode,
    out_enabled: bool,
    bitrate: u64,
    announce_cap: f64,
    announce_rate_target: Option<f64>,
    announce_rate_grace: Option<f64>,
    announce_rate_penalty: Option<f64>,
    ingress_control: bool,
    ic_max_held_announces: usize,
    ic_burst_hold: f64,
    ic_burst_freq_new: f64,
    ic_burst_freq: f64,
    ic_new_time: f64,
    ic_burst_penalty: f64,
    ic_held_release_interval: f64,
    bootstrap_only: bool,
    discoverable: bool,
    discovery_announce_interval: Option<f64>,
    discovery_publish_ifac: bool,
    reachable_on: Option<String>,
    discovery_name: Option<String>,
    discovery_encrypt: bool,
    discovery_stamp_value: Option<u32>,
    discovery_latitude: Option<f64>,
    discovery_longitude: Option<f64>,
    discovery_height: Option<f64>,
    discovery_frequency: Option<u64>,
    discovery_bandwidth: Option<u32>,
    discovery_modulation: Option<String>,
    ifac_size: usize,
    ifac_netname: Option<String>,
    ifac_netkey: Option<String>,
    ifac_key: Option<Vec<u8>>,
    ifac_signature: Option<Vec<u8>>,
}

impl SpawnConfig {
    fn from_base(base: &Interface) -> Self {
        SpawnConfig {
            mode: base.mode,
            out_enabled: base.out_enabled,
            bitrate: base.bitrate,
            announce_cap: base.announce_cap,
            announce_rate_target: base.announce_rate_target,
            announce_rate_grace: base.announce_rate_grace,
            announce_rate_penalty: base.announce_rate_penalty,
            ingress_control: base.ingress_control,
            ic_max_held_announces: base.ic_max_held_announces,
            ic_burst_hold: base.ic_burst_hold,
            ic_burst_freq_new: base.ic_burst_freq_new,
            ic_burst_freq: base.ic_burst_freq,
            ic_new_time: base.ic_new_time,
            ic_burst_penalty: base.ic_burst_penalty,
            ic_held_release_interval: base.ic_held_release_interval,
            bootstrap_only: base.bootstrap_only,
            discoverable: base.discoverable,
            discovery_announce_interval: base.discovery_announce_interval,
            discovery_publish_ifac: base.discovery_publish_ifac,
            reachable_on: base.reachable_on.clone(),
            discovery_name: base.discovery_name.clone(),
            discovery_encrypt: base.discovery_encrypt,
            discovery_stamp_value: base.discovery_stamp_value,
            discovery_latitude: base.discovery_latitude,
            discovery_longitude: base.discovery_longitude,
            discovery_height: base.discovery_height,
            discovery_frequency: base.discovery_frequency,
            discovery_bandwidth: base.discovery_bandwidth,
            discovery_modulation: base.discovery_modulation.clone(),
            ifac_size: base.ifac_size,
            ifac_netname: base.ifac_netname.clone(),
            ifac_netkey: base.ifac_netkey.clone(),
            ifac_key: base.ifac_key.clone(),
            ifac_signature: base.ifac_signature.clone(),
        }
    }

    fn apply_to_base(&self, base: &mut Interface) {
        base.mode = self.mode;
        base.out_enabled = self.out_enabled;
        base.bitrate = self.bitrate;
        base.announce_cap = self.announce_cap;
        base.announce_rate_target = self.announce_rate_target;
        base.announce_rate_grace = self.announce_rate_grace;
        base.announce_rate_penalty = self.announce_rate_penalty;
        base.ingress_control = self.ingress_control;
        base.ic_max_held_announces = self.ic_max_held_announces;
        base.ic_burst_hold = self.ic_burst_hold;
        base.ic_burst_freq_new = self.ic_burst_freq_new;
        base.ic_burst_freq = self.ic_burst_freq;
        base.ic_new_time = self.ic_new_time;
        base.ic_burst_penalty = self.ic_burst_penalty;
        base.ic_held_release_interval = self.ic_held_release_interval;
        base.bootstrap_only = self.bootstrap_only;
        base.discoverable = self.discoverable;
        base.discovery_announce_interval = self.discovery_announce_interval;
        base.discovery_publish_ifac = self.discovery_publish_ifac;
        base.reachable_on = self.reachable_on.clone();
        base.discovery_name = self.discovery_name.clone();
        base.discovery_encrypt = self.discovery_encrypt;
        base.discovery_stamp_value = self.discovery_stamp_value;
        base.discovery_latitude = self.discovery_latitude;
        base.discovery_longitude = self.discovery_longitude;
        base.discovery_height = self.discovery_height;
        base.discovery_frequency = self.discovery_frequency;
        base.discovery_bandwidth = self.discovery_bandwidth;
        base.discovery_modulation = self.discovery_modulation.clone();
        base.ifac_size = self.ifac_size;
        base.ifac_netname = self.ifac_netname.clone();
        base.ifac_netkey = self.ifac_netkey.clone();
        base.ifac_key = self.ifac_key.clone();
        base.ifac_signature = self.ifac_signature.clone();
    }
}

fn mode_to_u8(mode: InterfaceMode) -> u8 {
    match mode {
        InterfaceMode::Full => 0x01,
        InterfaceMode::PointToPoint => 0x02,
        InterfaceMode::AccessPoint => 0x03,
        InterfaceMode::Roaming => 0x04,
        InterfaceMode::Boundary => 0x05,
        InterfaceMode::Gateway => 0x06,
    }
}

impl TcpServerInterface {
    pub const HW_MTU: usize = 262144;
    pub const BITRATE_GUESS: u64 = 10_000_000;
    pub const DEFAULT_IFAC_SIZE: usize = 16;

    /// Create new TCP server from configuration
    pub fn new(config: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let name = config.get("name")
            .ok_or("TCPServerInterface requires 'name' in config")?
            .clone();
        
        let bind_ip = config.get("listen_ip")
            .ok_or("TCPServerInterface requires 'listen_ip' in config")?
            .clone();
        
        let bind_port = config.get("listen_port")
            .or_else(|| config.get("port"))
            .ok_or("TCPServerInterface requires 'listen_port' or 'port' in config")?
            .parse::<u16>()
            .map_err(|_| "Invalid bind port")?;
        
        let i2p_tunneled = config.get("i2p_tunneled")
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);

        let mut base = Interface::new();
        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = false;
        base.hw_mtu = Some(Self::HW_MTU);
        base.bitrate = Self::BITRATE_GUESS;
        base.online = false;
        base.supports_discovery = true;

        let bind_addr = format!("{}:{}", bind_ip, bind_port);
        let listener = TcpListener::bind(&bind_addr)
            .map_err(|e| format!("Failed to bind to {}: {}", bind_addr, e))?;

        let listener_arc = Arc::new(listener);
        let spawned = Arc::new(Mutex::new(Vec::new()));

        // Spawn accept loop
        let listener_clone = listener_arc.clone();
        let spawned_clone = spawned.clone();
        let name_clone = base.name.clone();
        let spawn_config = SpawnConfig::from_base(&base);
        let spawn_config_clone = spawn_config.clone();
        
        thread::spawn(move || {
            Self::accept_loop(listener_clone, spawned_clone, name_clone, spawn_config_clone);
        });

        base.online = true;

        Ok(TcpServerInterface {
            base,
            bind_ip,
            bind_port,
            i2p_tunneled,
            mode: 0x01, // MODE_FULL
            spawn_config,
            spawned_interfaces: spawned,
            listener: Some(listener_arc),
        })
    }

    pub fn update_spawn_config(&mut self) {
        self.spawn_config = SpawnConfig::from_base(&self.base);
        self.mode = mode_to_u8(self.base.mode);
    }

    /// Accept loop for incoming connections
    fn accept_loop(
        listener: Arc<TcpListener>,
        spawned: Arc<Mutex<Vec<Arc<Mutex<TcpClientInterface>>>>>,
        server_name: Option<String>,
        spawn_config: SpawnConfig,
    ) {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    println!("Accepting incoming TCP connection");
                    
                    let peer_addr = stream.peer_addr().ok();
                    let client_name = match &peer_addr {
                        Some(addr) => format!("Client on {} [{}]", server_name.as_ref().unwrap_or(&"Server".to_string()), addr),
                        None => format!("Client on {}", server_name.as_ref().unwrap_or(&"Server".to_string())),
                    };
                    
                    let spawned_interface = Arc::new(Mutex::new(TcpClientInterface::from_socket(client_name, stream)));
                    let iface_name;
                    {
                        let mut iface = spawned_interface.lock().unwrap();
                        spawn_config.apply_to_base(&mut iface.base);
                        iface.mode = mode_to_u8(spawn_config.mode);

                        if let Some(addr) = peer_addr {
                            iface.target_ip = addr.ip().to_string();
                            iface.target_port = addr.port();
                        }

                        iface_name = iface.base.name.clone().unwrap_or_default();
                        println!("Spawned new TCPClient Interface: {}", iface.to_string());
                    }

                    // Register the spawned interface with Transport so it can send outbound data
                    // (path responses, announces, etc.) back to the connected client.
                    let handler_iface = Arc::clone(&spawned_interface);
                    crate::transport::Transport::register_outbound_handler(
                        &iface_name,
                        Arc::new(move |raw| {
                            let mut iface = handler_iface.lock().unwrap();
                            iface.process_outgoing(raw.to_vec()).is_ok()
                        }),
                    );
                    crate::transport::Transport::register_interface_stub(&iface_name, "TCPClientInterface");

                    TcpClientInterface::start_read_loop(Arc::clone(&spawned_interface));
                    spawned.lock().unwrap().push(spawned_interface);
                }
                Err(_e) => {
                }
            }
        }
    }

    /// Get number of connected clients
    pub fn clients(&self) -> usize {
        self.spawned_interfaces.lock().unwrap().len()
    }

    /// Track received announce from spawned interface
    pub fn received_announce(&mut self, from_spawned: bool) {
        if from_spawned {
            self.base.received_announce(false);
        }
    }

    /// Track sent announce from spawned interface
    pub fn sent_announce(&mut self, from_spawned: bool) {
        if from_spawned {
            self.base.sent_announce(false);
        }
    }

    /// Process outgoing (no-op for server)
    pub fn process_outgoing(&self, _data: Vec<u8>) {
        // Server doesn't send directly
    }

    /// Detach server
    pub fn detach(&mut self) {
        self.base.online = false;
        // Listener will be dropped when Arc count reaches 0
    }

    /// Get string representation
    pub fn to_string(&self) -> String {
        let ip_str = if self.bind_ip.contains(':') {
            format!("[{}]", self.bind_ip)
        } else {
            self.bind_ip.clone()
        };
        
        format!(
            "TCPServerInterface[{}/{}:{}]",
            self.base.name.as_ref().unwrap_or(&"unnamed".to_string()),
            ip_str,
            self.bind_port
        )
    }
}

impl std::fmt::Display for TcpClientInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::fmt::Display for TcpServerInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hdlc_escape() {
        let data = vec![0x12, Hdlc::FLAG, 0x34, Hdlc::ESC, 0x56];
        let escaped = Hdlc::escape(&data);
        assert!(escaped.len() > data.len());
        assert!(!escaped.contains(&Hdlc::FLAG));
    }

    #[test]
    fn test_kiss_escape() {
        let data = vec![0x12, Kiss::FEND, 0x34, Kiss::FESC, 0x56];
        let escaped = Kiss::escape(&data);
        assert!(escaped.len() > data.len());
        assert!(!escaped.contains(&Kiss::FEND));
        assert_eq!(escaped.iter().filter(|&&b| b == Kiss::FESC).count(), 2);
    }
}
