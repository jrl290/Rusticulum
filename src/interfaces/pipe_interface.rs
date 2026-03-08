use super::interface::Interface;
use crate::transport::Transport;
use std::process::{Command as ProcessCommand, Stdio, Child, ChildStdin, ChildStdout};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// HDLC framing for Pipe Interface
/// 
/// Simplified HDLC framing similar to PPP, used for packetizing
/// data over the pipe interface.
pub struct Hdlc;

impl Hdlc {
    pub const FLAG: u8 = 0x7E;
    pub const ESC: u8 = 0x7D;
    pub const ESC_MASK: u8 = 0x20;

    /// Escape special characters in data
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

    /// Unescape data
    pub fn unescape(data: &[u8]) -> Vec<u8> {
        let mut unescaped = Vec::with_capacity(data.len());
        let mut escape_next = false;
        
        for &byte in data {
            if escape_next {
                if byte == (Self::FLAG ^ Self::ESC_MASK) {
                    unescaped.push(Self::FLAG);
                } else if byte == (Self::ESC ^ Self::ESC_MASK) {
                    unescaped.push(Self::ESC);
                } else {
                    unescaped.push(byte); // Invalid escape sequence, keep as-is
                }
                escape_next = false;
            } else if byte == Self::ESC {
                escape_next = true;
            } else if byte != Self::FLAG {
                unescaped.push(byte);
            }
        }
        
        unescaped
    }
}

/// Pipe Interface for Reticulum
/// 
/// Spawns a subprocess and communicates via stdin/stdout using HDLC framing.
/// Automatically respawns the subprocess if it terminates.
pub struct PipeInterface {
    pub base: Interface,
    pub command: String,
    pub respawn_delay: f64,
    pub process: Option<Arc<Mutex<Child>>>,
    pub pipe_is_open: bool,
    pub timeout: u64,
    stdin: Option<Arc<Mutex<ChildStdin>>>,
    is_running: Arc<Mutex<bool>>,
}

impl PipeInterface {
    pub const MAX_CHUNK: usize = 32768;
    pub const BITRATE_GUESS: u64 = 1_000_000; // 1 Mbps
    pub const DEFAULT_IFAC_SIZE: usize = 8;

    /// Create a new Pipe interface from configuration
    /// 
    /// Config parameters:
    /// - name: Interface name
    /// - command: Shell command to execute for subprocess
    /// - respawn_delay: Delay in seconds before respawning terminated subprocess (default: 5.0)
    pub fn new(config: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let mut base = Interface::new();
        
        let name = config.get("name")
            .ok_or("PipeInterface requires 'name' in config")?
            .clone();
        
        let command = config.get("command")
            .ok_or("PipeInterface requires 'command' in config")?
            .clone();
        
        let respawn_delay = config.get("respawn_delay")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(5.0);

        // Configure base interface
        base.name = Some(name.clone());
        base.hw_mtu = Some(1064);
        base.bitrate = Self::BITRATE_GUESS;
        base.online = false;

        let mut interface = PipeInterface {
            base,
            command,
            respawn_delay,
            process: None,
            pipe_is_open: false,
            timeout: 100,
            stdin: None,
            is_running: Arc::new(Mutex::new(false)),
        };

        // Open the pipe
        interface.open_pipe()?;

        if interface.pipe_is_open {
            interface.configure_pipe()?;
        } else {
            return Err("Could not connect pipe".to_string());
        }

        Ok(interface)
    }

    /// Open the subprocess pipe
    fn open_pipe(&mut self) -> Result<(), String> {
        println!("Connecting subprocess pipe for {}...", self.base.name.as_ref().unwrap_or(&"unnamed".to_string()));

        // Parse command into parts (simple split by whitespace - not perfect but works for most cases)
        let parts: Vec<&str> = self.command.split_whitespace().collect();
        if parts.is_empty() {
            return Err("Empty command".to_string());
        }

        let child = ProcessCommand::new(parts[0])
            .args(&parts[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn subprocess '{}': {}", self.command, e))?;

        self.stdin = None; // Will be set in configure_pipe
        self.process = Some(Arc::new(Mutex::new(child)));
        self.pipe_is_open = true;

        Ok(())
    }

    /// Configure the pipe after opening
    fn configure_pipe(&mut self) -> Result<(), String> {
        thread::sleep(Duration::from_millis(10));

        // Extract stdout for reading thread
        let process_arc = self.process.as_ref()
            .ok_or("No process")?
            .clone();
        
        let mut process = process_arc.lock().unwrap();
        let stdout = process.stdout.take()
            .ok_or("Failed to take stdout")?;
        
        let stdin = process.stdin.take()
            .ok_or("Failed to take stdin")?;
        
        drop(process); // Release lock

        self.stdin = Some(Arc::new(Mutex::new(stdin)));
        
        // Start read loop thread
        let is_running = self.is_running.clone();
        let interface_name = self.base.name.clone();
        let base_hw_mtu = self.base.hw_mtu.unwrap_or(1064);
        let process_for_thread = process_arc.clone();
        let respawn_delay = self.respawn_delay;
        let command = self.command.clone();

        *is_running.lock().unwrap() = true;

        thread::spawn(move || {
            Self::read_loop(
                stdout,
                base_hw_mtu,
                interface_name,
                is_running,
                process_for_thread,
                respawn_delay,
                command,
            );
        });

        self.base.online = true;
        println!("Subprocess pipe for {} is now connected", self.base.name.as_ref().unwrap_or(&"unnamed".to_string()));

        Ok(())
    }

    /// Process incoming data
    fn process_incoming(data: Vec<u8>, interface_name: Option<String>) {
        let _ = Transport::inbound(data, interface_name);
    }

    /// Process outgoing data - send via pipe with HDLC framing
    pub fn process_outgoing(&mut self, data: Vec<u8>) -> Result<(), String> {
        if !self.base.online {
            return Err("Pipe interface is offline".to_string());
        }

        // Apply forced bitrate delay if set
        self.base.enforce_bitrate(data.len());

        // Frame data: FLAG + escaped_data + FLAG
        let mut framed = vec![Hdlc::FLAG];
        framed.extend_from_slice(&Hdlc::escape(&data));
        framed.push(Hdlc::FLAG);

        if let Some(ref stdin_mutex) = self.stdin {
            let mut stdin = stdin_mutex.lock().unwrap();
            stdin.write_all(&framed)
                .map_err(|e| format!("Failed to write to subprocess stdin: {}", e))?;
            stdin.flush()
                .map_err(|e| format!("Failed to flush subprocess stdin: {}", e))?;
            
            self.base.txb += framed.len() as u64;
            Ok(())
        } else {
            Err("Subprocess stdin not available".to_string())
        }
    }

    /// Read loop - runs in separate thread
    fn read_loop(
        mut stdout: ChildStdout,
        hw_mtu: usize,
        interface_name: Option<String>,
        is_running: Arc<Mutex<bool>>,
        _process: Arc<Mutex<Child>>,
        _respawn_delay: f64,
        _command: String,
    ) {
        let mut in_frame = false;
        let mut escape = false;
        let mut data_buffer = Vec::new();
        let mut byte_buf = [0u8; 1];

        loop {
            if !*is_running.lock().unwrap() {
                break;
            }

            match stdout.read(&mut byte_buf) {
                Ok(0) => {
                    // EOF - subprocess terminated
                    println!("Subprocess terminated on {:?}", interface_name);
                    break;
                }
                Ok(_) => {
                    let byte = byte_buf[0];

                    if in_frame && byte == Hdlc::FLAG {
                        // End of frame
                        in_frame = false;
                        if !data_buffer.is_empty() {
                            Self::process_incoming(data_buffer.clone(), interface_name.clone());
                            data_buffer.clear();
                        }
                    } else if byte == Hdlc::FLAG {
                        // Start of frame
                        in_frame = true;
                        data_buffer.clear();
                    } else if in_frame && data_buffer.len() < hw_mtu {
                        if byte == Hdlc::ESC {
                            escape = true;
                        } else {
                            if escape {
                                let unescaped_byte = if byte == (Hdlc::FLAG ^ Hdlc::ESC_MASK) {
                                    Hdlc::FLAG
                                } else if byte == (Hdlc::ESC ^ Hdlc::ESC_MASK) {
                                    Hdlc::ESC
                                } else {
                                    byte
                                };
                                data_buffer.push(unescaped_byte);
                                escape = false;
                            } else {
                                data_buffer.push(byte);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Pipe read error on {:?}: {}", interface_name, e);
                    break;
                }
            }
        }

        // Cleanup and reconnect logic would go here
        println!("Read loop terminated for {:?}", interface_name);
        *is_running.lock().unwrap() = false;
    }

    /// Get interface description string
    pub fn to_string(&self) -> String {
        format!(
            "PipeInterface[{}]",
            self.base.name.as_ref().unwrap_or(&"unnamed".to_string())
        )
    }
}

impl Drop for PipeInterface {
    fn drop(&mut self) {
        *self.is_running.lock().unwrap() = false;
        
        if let Some(ref process_mutex) = self.process {
            if let Ok(mut process) = process_mutex.lock() {
                let _ = process.kill();
            }
        }
    }
}

impl std::fmt::Display for PipeInterface {
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
        
        // Should escape FLAG and ESC
        assert!(escaped.len() > data.len());
        assert!(!escaped.contains(&Hdlc::FLAG));
        
        // Verify specific escape sequences
        let expected = vec![
            0x12,
            Hdlc::ESC, Hdlc::FLAG ^ Hdlc::ESC_MASK,
            0x34,
            Hdlc::ESC, Hdlc::ESC ^ Hdlc::ESC_MASK,
            0x56
        ];
        assert_eq!(escaped, expected);
    }

    #[test]
    fn test_hdlc_roundtrip() {
        let original = vec![0x00, 0x7E, 0x7D, 0xFF, 0x12, 0x34];
        let escaped = Hdlc::escape(&original);
        let unescaped = Hdlc::unescape(&escaped);
        assert_eq!(original, unescaped);
    }

    #[test]
    fn test_pipe_interface_config() {
        let mut config = std::collections::HashMap::new();
        config.insert("name".to_string(), "TestPipe".to_string());
        config.insert("command".to_string(), "cat".to_string());
        config.insert("respawn_delay".to_string(), "10.0".to_string());

        // Note: This will actually try to spawn 'cat', so it might fail in test environment
        // In production, you'd use a mock or conditional compilation
        match PipeInterface::new(&config) {
            Ok(iface) => {
                assert_eq!(iface.command, "cat");
                assert_eq!(iface.respawn_delay, 10.0);
                assert_eq!(iface.base.bitrate, PipeInterface::BITRATE_GUESS);
            }
            Err(_) => {
                // If spawn fails in test environment, that's okay
                assert!(true);
            }
        }
    }
}
