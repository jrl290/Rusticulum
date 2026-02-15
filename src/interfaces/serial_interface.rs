use super::interface::Interface;
use crate::log;
use crate::transport::Transport as RnsTransport;
use serialport::{DataBits, Parity, SerialPort, StopBits};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct Hdlc;

impl Hdlc {
    pub const FLAG: u8 = 0x7E;
    pub const ESC: u8 = 0x7D;
    pub const ESC_MASK: u8 = 0x20;

    pub fn escape(data: &[u8]) -> Vec<u8> {
        let mut escaped = Vec::with_capacity(data.len() + 8);
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

pub struct SerialInterface {
    pub base: Interface,
    pub port: String,
    pub speed: u32,
    pub databits: u8,
    pub parity: Parity,
    pub stopbits: u8,
    pub timeout_ms: u64,
    pub online: bool,
    pub serial: Option<Arc<Mutex<Box<dyn SerialPort>>>>,
}

impl SerialInterface {
    pub const MAX_CHUNK: usize = 32768;
    pub const DEFAULT_IFAC_SIZE: usize = 8;
    pub const HW_MTU: usize = 564;

    pub fn new(config: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let mut base = Interface::new();

        let name = config
            .get("name")
            .ok_or("SerialInterface requires 'name' in config")?
            .clone();

        let port = config
            .get("port")
            .ok_or("No port specified for serial interface")?
            .clone();

        let speed = config
            .get("speed")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(9600);

        let databits = config
            .get("databits")
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(8);

        let parity_str = config.get("parity").cloned().unwrap_or_else(|| "N".to_string());
        let stopbits = config
            .get("stopbits")
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(1);

        let parity = match parity_str.to_lowercase().as_str() {
            "e" | "even" => Parity::Even,
            "o" | "odd" => Parity::Odd,
            _ => Parity::None,
        };

        base.name = Some(name.clone());
        base.hw_mtu = Some(Self::HW_MTU);
        base.fixed_mtu = true;
        base.in_enabled = true;
        base.out_enabled = false;
        base.bitrate = speed as u64;
        base.online = false;

        let mut interface = SerialInterface {
            base,
            port,
            speed,
            databits,
            parity,
            stopbits,
            timeout_ms: 100,
            online: false,
            serial: None,
        };

        interface.open_port()?;
        interface.online = true;
        interface.base.online = true;

        Ok(interface)
    }

    pub fn start_read_loop(iface: Arc<Mutex<SerialInterface>>) {
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(500));
            {
                let iface_guard = iface.lock().unwrap();
                log(
                    &format!("Serial port {} is now open", iface_guard.port),
                    crate::LOG_VERBOSE,
                    false,
                    false,
                );
            }

            let mut in_frame = false;
            let mut escape = false;
            let mut data_buffer = Vec::new();
            let mut last_read_ms = now_ms();

            loop {
                let (serial, timeout_ms, name, hw_mtu) = {
                    let iface_guard = iface.lock().unwrap();
                    (
                        iface_guard.serial.clone(),
                        iface_guard.timeout_ms,
                        iface_guard.base.name.clone(),
                        iface_guard.base.hw_mtu.unwrap_or(Self::HW_MTU),
                    )
                };

                let serial = match serial {
                    Some(port) => port,
                    None => {
                        thread::sleep(Duration::from_millis(80));
                        continue;
                    }
                };

                let bytes_available = {
                    let guard = serial.lock().unwrap();
                    guard.bytes_to_read().unwrap_or(0)
                };

                if bytes_available > 0 {
                    let mut byte = [0u8; 1];
                    let read_ok = {
                        let mut guard = serial.lock().unwrap();
                        guard.read_exact(&mut byte).is_ok()
                    };

                    if !read_ok {
                        break;
                    }

                    last_read_ms = now_ms();
                    let byte = byte[0];

                    if in_frame && byte == Hdlc::FLAG {
                        in_frame = false;
                        let _ = RnsTransport::inbound(data_buffer.clone(), name.clone());
                        data_buffer.clear();
                    } else if byte == Hdlc::FLAG {
                        in_frame = true;
                        data_buffer.clear();
                    } else if in_frame && data_buffer.len() < hw_mtu {
                        if byte == Hdlc::ESC {
                            escape = true;
                        } else {
                            let mut out_byte = byte;
                            if escape {
                                if byte == (Hdlc::FLAG ^ Hdlc::ESC_MASK) {
                                    out_byte = Hdlc::FLAG;
                                }
                                if byte == (Hdlc::ESC ^ Hdlc::ESC_MASK) {
                                    out_byte = Hdlc::ESC;
                                }
                                escape = false;
                            }
                            data_buffer.push(out_byte);
                        }
                    }
                } else {
                    let time_since_last = now_ms().saturating_sub(last_read_ms);
                    if !data_buffer.is_empty() && time_since_last > timeout_ms {
                        data_buffer.clear();
                        in_frame = false;
                        escape = false;
                    }
                    thread::sleep(Duration::from_millis(80));
                }
            }

            {
                let mut iface_guard = iface.lock().unwrap();
                iface_guard.online = false;
                iface_guard.base.online = false;
                iface_guard.serial = None;
                log(
                    &format!("A serial port error occurred, the interface {} is now offline.", iface_guard),
                    crate::LOG_ERROR,
                    false,
                    false,
                );
                log(
                    &format!("The interface {} experienced an unrecoverable error and is now offline.", iface_guard),
                    crate::LOG_ERROR,
                    false,
                    false,
                );
            }

            if crate::reticulum::panic_on_interface_error_enabled() {
                panic!("Serial interface error");
            }

            log(
                "Reticulum will attempt to reconnect the interface periodically.",
                crate::LOG_ERROR,
                false,
                false,
            );

            SerialInterface::reconnect_port(iface);
        });
    }

    fn open_port(&mut self) -> Result<(), String> {
        log(
            &format!("Opening serial port {}...", self.port),
            crate::LOG_VERBOSE,
            false,
            false,
        );

        let data_bits = match self.databits {
            5 => DataBits::Five,
            6 => DataBits::Six,
            7 => DataBits::Seven,
            _ => DataBits::Eight,
        };

        let stop_bits = match self.stopbits {
            2 => StopBits::Two,
            _ => StopBits::One,
        };

        let port = serialport::new(&self.port, self.speed)
            .data_bits(data_bits)
            .parity(self.parity)
            .stop_bits(stop_bits)
            .timeout(Duration::from_millis(0))
            .open()
            .map_err(|e| format!("Could not open serial port: {}", e))?;

        self.serial = Some(Arc::new(Mutex::new(port)));
        Ok(())
    }

    fn reconnect_port(iface: Arc<Mutex<SerialInterface>>) {
        loop {
            {
                let iface_guard = iface.lock().unwrap();
                if iface_guard.online {
                    break;
                }
            }

            thread::sleep(Duration::from_secs(5));
            let port_name = {
                let iface_guard = iface.lock().unwrap();
                iface_guard.port.clone()
            };

            log(
                &format!("Attempting to reconnect serial port {} for {}...", port_name, iface.lock().unwrap()),
                crate::LOG_VERBOSE,
                false,
                false,
            );

            let result = {
                let mut iface_guard = iface.lock().unwrap();
                iface_guard.open_port()
            };

            if result.is_ok() {
                {
                    let mut iface_guard = iface.lock().unwrap();
                    iface_guard.online = true;
                    iface_guard.base.online = true;
                }
                SerialInterface::start_read_loop(Arc::clone(&iface));
                log(
                    &format!("Reconnected serial port for {}", iface.lock().unwrap()),
                    crate::LOG_VERBOSE,
                    false,
                    false,
                );
                break;
            }
        }
    }

    pub fn process_outgoing(&mut self, data: Vec<u8>) -> Result<(), String> {
        if !self.online {
            return Ok(());
        }

        let mut framed = Vec::with_capacity(data.len() + 2);
        framed.push(Hdlc::FLAG);
        framed.extend_from_slice(&Hdlc::escape(&data));
        framed.push(Hdlc::FLAG);

        let mut written = 0usize;
        if let Some(port) = &self.serial {
            let mut guard = port.lock().unwrap();
            written = guard.write(&framed).unwrap_or(0);
        }

        self.base.txb += framed.len() as u64;
        if written != framed.len() {
            return Err(format!("Serial interface only wrote {} bytes of {}", written, framed.len()));
        }

        Ok(())
    }

    pub fn to_string(&self) -> String {
        format!("SerialInterface[{}]", self.base.name.as_ref().unwrap_or(&"unnamed".to_string()))
    }
}

impl std::fmt::Display for SerialInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
