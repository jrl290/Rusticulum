use super::interface::Interface;
use crate::transport::Transport as RnsTransport;
use std::net::{UdpSocket, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;

/// UDP Interface for Reticulum
/// 
/// Provides UDP broadcast/multicast communication for local area networks.
/// Can receive on one address/port and forward to another, enabling
/// flexible network topologies.

pub struct UdpInterface {
    pub base: Interface,
    pub bind_ip: String,
    pub bind_port: u16,
    pub forward_ip: String,
    pub forward_port: u16,
    pub receives: bool,
    pub forwards: bool,
    pub owner: Option<Arc<Mutex<dyn Transport>>>,
    socket: Option<Arc<UdpSocket>>,
}

// Transport trait to be implemented by RNS.Transport
pub trait Transport: Send {
    fn inbound(&mut self, data: Vec<u8>, interface: &UdpInterface);
}

impl UdpInterface {
    pub const BITRATE_GUESS: u64 = 10_000_000; // 10 Mbps
    pub const DEFAULT_IFAC_SIZE: usize = 16;

    /// Create a new UDP interface from configuration
    /// 
    /// Config parameters:
    /// - name: Interface name
    /// - device: Network device name (optional, for auto IP detection)
    /// - port: Port number (sets both bind_port and forward_port if not specified)
    /// - listen_ip: IP to bind for receiving
    /// - listen_port: Port to bind for receiving
    /// - forward_ip: IP to send to
    /// - forward_port: Port to send to
    pub fn new(owner: Option<Arc<Mutex<dyn Transport>>>, config: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let mut base = Interface::new();
        
        let name = config.get("name")
            .ok_or("UDPInterface requires 'name' in config")?
            .clone();
        
        let device = config.get("device").cloned();
        let port = config.get("port").and_then(|p| p.parse::<u16>().ok());
        let listen_ip = config.get("listen_ip").cloned();
        let listen_port = config.get("listen_port").and_then(|p| p.parse::<u16>().ok());
        let forward_ip = config.get("forward_ip").cloned();
        let forward_port = config.get("forward_port").and_then(|p| p.parse::<u16>().ok());

        // Determine bind and forward ports
        let bind_port = listen_port.or(port).ok_or("UDPInterface requires 'listen_port' or 'port'")?;
        let forward_port = forward_port.or(port).ok_or("UDPInterface requires 'forward_port' or 'port'")?;

        // Determine bind and forward IPs
        let bind_ip = if let Some(ref dev) = device {
            listen_ip.unwrap_or_else(|| Self::get_broadcast_for_if(dev))
        } else {
            listen_ip.ok_or("UDPInterface requires 'listen_ip' or 'device'")?
        };

        let forward_ip = if let Some(ref dev) = device {
            forward_ip.unwrap_or_else(|| Self::get_broadcast_for_if(dev))
        } else {
            forward_ip.ok_or("UDPInterface requires 'forward_ip' or 'device'")?
        };

        // Configure base interface
        base.name = Some(name.clone());
        base.in_enabled = true;
        base.out_enabled = false;
        base.hw_mtu = Some(1064);
        base.bitrate = Self::BITRATE_GUESS;
        base.online = false;

        let mut interface = UdpInterface {
            base,
            bind_ip: bind_ip.clone(),
            bind_port,
            forward_ip: forward_ip.clone(),
            forward_port,
            receives: true,
            forwards: true,
            owner,
            socket: None,
        };

        // Start UDP server for receiving
        if interface.receives {
            interface.start_server()?;
        }

        Ok(interface)
    }

    /// Get the IP address for a network interface
    pub fn get_address_for_if(_name: &str) -> String {
        // TODO: Implement proper network interface enumeration
        // For now, return a placeholder
        #[cfg(target_os = "linux")]
        {
            // Use pnet or similar crate to get interface info
            "0.0.0.0".to_string()
        }
        #[cfg(not(target_os = "linux"))]
        {
            "0.0.0.0".to_string()
        }
    }

    /// Get the broadcast address for a network interface
    pub fn get_broadcast_for_if(_name: &str) -> String {
        // TODO: Implement proper network interface enumeration
        // For now, return standard broadcast
        #[cfg(target_os = "linux")]
        {
            // Use pnet or similar to get interface broadcast address
            "255.255.255.255".to_string()
        }
        #[cfg(not(target_os = "linux"))]
        {
            "255.255.255.255".to_string()
        }
    }

    /// Start the UDP server to receive packets
    fn start_server(&mut self) -> Result<(), String> {
        let bind_addr = format!("{}:{}", self.bind_ip, self.bind_port);
        let socket = UdpSocket::bind(&bind_addr)
            .map_err(|e| format!("Failed to bind UDP socket to {}: {}", bind_addr, e))?;

        socket.set_broadcast(true)
            .map_err(|e| format!("Failed to enable broadcast: {}", e))?;

        let socket_arc = Arc::new(socket);
        self.socket = Some(socket_arc.clone());
        self.base.online = true;

        // Spawn receiver thread
        let owner = self.owner.clone();
        let interface_name = self.base.name.clone();
        
        thread::spawn(move || {
            let mut buf = [0u8; 65536];
            loop {
                match socket_arc.recv_from(&mut buf) {
                    Ok((size, _addr)) => {
                        let data = buf[..size].to_vec();
                        let _ = RnsTransport::inbound(data, interface_name.clone());
                        if let Some(ref _owner_mutex) = owner {
                            // Owner callbacks are not wired yet.
                        }
                    }
                    Err(e) => {
                        eprintln!("UDP receive error on {:?}: {}", interface_name, e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Process incoming data (called by receiver thread)
    pub fn process_incoming(&mut self, data: Vec<u8>) {
        self.base.rxb += data.len() as u64;
        let interface_name = self.base.name.clone();
        let _ = RnsTransport::inbound(data, interface_name);
    }

    /// Process outgoing data - send via UDP
    pub fn process_outgoing(&mut self, data: Vec<u8>) -> Result<(), String> {
        // Apply forced bitrate delay if set
        self.base.enforce_bitrate(data.len());

        let forward_addr = format!("{}:{}", self.forward_ip, self.forward_port);
        let addr: SocketAddr = forward_addr.parse()
            .map_err(|e| format!("Invalid forward address {}: {}", forward_addr, e))?;

        // Create a new socket for sending (allows broadcast)
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to create send socket: {}", e))?;
        
        socket.set_broadcast(true)
            .map_err(|e| format!("Failed to enable broadcast on send socket: {}", e))?;

        socket.send_to(&data, addr)
            .map_err(|e| format!("Failed to send UDP packet to {}: {}", forward_addr, e))?;

        self.base.txb += data.len() as u64;
        Ok(())
    }

    /// Get interface description string
    pub fn to_string(&self) -> String {
        format!(
            "UDPInterface[{}/{}:{}]",
            self.base.name.as_ref().unwrap_or(&"unnamed".to_string()),
            self.bind_ip,
            self.bind_port
        )
    }
}

impl std::fmt::Display for UdpInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_udp_interface_config_parsing() {
        let mut config = HashMap::new();
        config.insert("name".to_string(), "TestUDP".to_string());
        config.insert("listen_ip".to_string(), "127.0.0.1".to_string());
        config.insert("listen_port".to_string(), "4242".to_string());
        config.insert("forward_ip".to_string(), "127.0.0.1".to_string());
        config.insert("forward_port".to_string(), "4243".to_string());

        let interface = UdpInterface::new(None, &config).unwrap();
        assert_eq!(interface.bind_ip, "127.0.0.1");
        assert_eq!(interface.bind_port, 4242);
        assert_eq!(interface.forward_ip, "127.0.0.1");
        assert_eq!(interface.forward_port, 4243);
        assert_eq!(interface.base.bitrate, UdpInterface::BITRATE_GUESS);
    }

    #[test]
    fn test_udp_interface_port_defaulting() {
        let mut config = HashMap::new();
        config.insert("name".to_string(), "TestUDP".to_string());
        config.insert("listen_ip".to_string(), "0.0.0.0".to_string());
        config.insert("forward_ip".to_string(), "255.255.255.255".to_string());
        config.insert("port".to_string(), "5000".to_string());

        let interface = UdpInterface::new(None, &config).unwrap();
        assert_eq!(interface.bind_port, 5000);
        assert_eq!(interface.forward_port, 5000);
    }

    #[test]
    fn test_udp_interface_display() {
        let mut config = HashMap::new();
        config.insert("name".to_string(), "MyUDP".to_string());
        config.insert("listen_ip".to_string(), "192.168.1.1".to_string());
        config.insert("port".to_string(), "8080".to_string());
        config.insert("forward_ip".to_string(), "192.168.1.255".to_string());

        let interface = UdpInterface::new(None, &config).unwrap();
        let display = format!("{}", interface);
        assert!(display.contains("UDPInterface"));
        assert!(display.contains("MyUDP"));
        assert!(display.contains("192.168.1.1"));
        assert!(display.contains("8080"));
    }
}
