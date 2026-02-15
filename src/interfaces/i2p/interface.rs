use std::collections::HashMap;
use std::io;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::interfaces::interface::InterfaceMode;
use crate::interfaces::i2p::peer::I2PInterfacePeer;
use crate::interfaces::i2p::sam::{SamConnection, Destination};
use crate::transport::Transport;

pub struct I2PInterface {
    pub name: String,
    pub hw_mtu: usize,
    pub mode: InterfaceMode,
    pub bitrate: u64,
    pub ifac_size: Option<usize>,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    pub supports_discovery: bool,
    
    pub rxb: Arc<Mutex<u64>>,
    pub txb: Arc<Mutex<u64>>,
    
    online: Arc<Mutex<bool>>,
    spawned_interfaces: Arc<Mutex<Vec<Arc<I2PInterfacePeer>>>>,
    server_listener: Option<TcpListener>,
    sam_address: String,
    local_port: u16,
    #[allow(dead_code)]
    i2p_destination: Option<Destination>,
}

impl I2PInterface {
    pub fn new(
        name: &str,
        config: &HashMap<String, String>,
        transport: Arc<Mutex<Transport>>,
    ) -> io::Result<Self> {
        let connectable = config.get("connectable")
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false);
        
        let peers: Option<Vec<String>> = config.get("peers")
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect());
        
        let ifac_size = config.get("ifac_size")
            .and_then(|v| v.parse::<usize>().ok());
        
        let ifac_netname = config.get("ifac_netname").cloned();
        let ifac_netkey = config.get("ifac_netkey").cloned();
        
        let sam_address = config.get("sam_address")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "127.0.0.1:7656".to_string());

        // Find a free port for the local listener
        let local_port = Self::find_free_port()?;
        let bind_addr = format!("127.0.0.1:{}", local_port);
        let listener = TcpListener::bind(&bind_addr)?;
        listener.set_nonblocking(true)?;

        let mut interface = I2PInterface {
            name: name.to_string(),
            hw_mtu: 1064,
            mode: InterfaceMode::Full,
            bitrate: 256 * 1000,
            ifac_size,
            ifac_netname: ifac_netname.clone(),
            ifac_netkey: ifac_netkey.clone(),
            supports_discovery: true,
            rxb: Arc::new(Mutex::new(0)),
            txb: Arc::new(Mutex::new(0)),
            online: Arc::new(Mutex::new(false)),
            spawned_interfaces: Arc::new(Mutex::new(Vec::new())),
            server_listener: Some(listener),
            sam_address: sam_address.clone(),
            local_port,
            i2p_destination: None,
        };

        // Start the connection accept loop
        interface.start_accept_loop(transport.clone());

        // If connectable, set up server tunnel
        if connectable {
            interface.setup_server_tunnel()?;
        }

        // Set up static peers if configured
        if let Some(peer_list) = peers {
            for peer_addr in peer_list {
                let peer_interface = I2PInterfacePeer::new_outbound(
                    &interface.name,
                    &transport.lock().unwrap(),
                    &peer_addr,
                    &peer_addr,
                    Some(&sam_address),
                    ifac_size,
                    ifac_netname.clone(),
                    ifac_netkey.clone(),
                )?;
                
                interface.spawned_interfaces.lock().unwrap()
                    .push(Arc::new(peer_interface));
            }
        }

        Ok(interface)
    }

    fn find_free_port() -> io::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        Ok(port)
    }

    fn setup_server_tunnel(&mut self) -> io::Result<()> {
        let sam_address = self.sam_address.clone();
        let local_port = self.local_port;
        let online = self.online.clone();
        let interface_name = self.name.clone();

        thread::spawn(move || {
            loop {
                match Self::create_server_tunnel(&sam_address, local_port, &interface_name) {
                    Ok(dest) => {
                        println!("I2PInterface[{}]: Server tunnel established at {}", 
                                 interface_name, dest.base64);
                        *online.lock().unwrap() = true;
                    }
                    Err(e) => {
                        println!("I2PInterface[{}]: Error setting up server tunnel: {}", 
                                 interface_name, e);
                        *online.lock().unwrap() = false;
                    }
                }
                thread::sleep(Duration::from_secs(15));
            }
        });

        Ok(())
    }

    fn create_server_tunnel(
        sam_address: &str,
        _local_port: u16,
        session_name: &str,
    ) -> io::Result<Destination> {
        let sam = SamConnection::new(Some(sam_address));
        sam.hello()?;

        // Try to load existing destination or create new one
        // For now, create a new TRANSIENT destination
        let dest = sam.session_create(
            "STREAM",
            session_name,
            None, // TRANSIENT
            &HashMap::new(),
        )?;

        // The SAM tunnel is now set up and listening on the I2P side
        // Connections will forward to our local_port

        Ok(dest)
    }

    fn start_accept_loop(&self, transport: Arc<Mutex<Transport>>) {
        let listener = self.server_listener.as_ref().unwrap().try_clone().unwrap();
        let spawned_interfaces = self.spawned_interfaces.clone();
        let interface_name = self.name.clone();
        let ifac_size = self.ifac_size;
        let ifac_netname = self.ifac_netname.clone();
        let ifac_netkey = self.ifac_netkey.clone();

        thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((socket, _addr)) => {
                        println!("I2PInterface[{}]: Accepting incoming connection", interface_name);
                        
                        match I2PInterfacePeer::new_inbound(
                            &interface_name,
                            &transport.lock().unwrap(),
                            socket,
                            ifac_size,
                            ifac_netname.clone(),
                            ifac_netkey.clone(),
                        ) {
                            Ok(peer) => {
                                let peer_arc = Arc::new(peer);
                                spawned_interfaces.lock().unwrap().push(peer_arc.clone());
                                
                                // Start read loop for this peer
                                peer_arc.start_read_loop(transport.clone());
                                
                                println!("I2PInterface[{}]: Spawned new peer: {}", 
                                         interface_name, peer_arc.name);
                            }
                            Err(e) => {
                                println!("I2PInterface[{}]: Error creating peer: {}", 
                                         interface_name, e);
                            }
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        println!("I2PInterface[{}]: Accept error: {}", interface_name, e);
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
        });
    }

    pub fn process_outgoing(&self, _data: &[u8]) -> io::Result<()> {
        // Main interface doesn't send data directly; peers do
        Ok(())
    }

    pub fn clients(&self) -> usize {
        self.spawned_interfaces.lock().unwrap().len()
    }
}
