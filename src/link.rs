use crate::{identity, reticulum, destination::Destination, resource::Resource};
use crate::packet::{self, Packet, DATA, PROOF, LINKIDENTIFY};
use crate::identity::{Identity, Token};
use rmp_serde::{decode::from_slice, encode::to_vec_named};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread;
use x25519_dalek::{StaticSecret as X25519PrivateKey, PublicKey as X25519PublicKey};
use ed25519_dalek::{PublicKey as Ed25519PublicKey, Signature, Signer, Verifier};
use hkdf::Hkdf;
use sha2::Sha256;

// Link state constants
pub const STATE_PENDING: u8 = 0x00;
pub const STATE_HANDSHAKE: u8 = 0x01;
pub const STATE_ACTIVE: u8 = 0x02;
pub const STATE_STALE: u8 = 0x03;
pub const STATE_CLOSED: u8 = 0x04;

// Link close reasons
pub const REASON_TIMEOUT: u8 = 0x01;
pub const REASON_INITIATOR_CLOSED: u8 = 0x02;
pub const REASON_DESTINATION_CLOSED: u8 = 0x03;

// Resource acceptance strategies
pub const ACCEPT_NONE: u8 = 0x00;
pub const ACCEPT_APP: u8 = 0x01;
pub const ACCEPT_ALL: u8 = 0x02;

// Link modes and constants
pub const CURVE: &str = identity::CURVE;
pub const ECPUBSIZE: usize = 32 + 32;
pub const KEYSIZE: usize = 32;

pub const MDU: usize = ((reticulum::MTU
    - reticulum::IFAC_MIN_SIZE
    - reticulum::HEADER_MINSIZE
    - identity::TOKEN_OVERHEAD)
    / identity::AES128_BLOCKSIZE)
    * identity::AES128_BLOCKSIZE
    - 1;

pub const ESTABLISHMENT_TIMEOUT_PER_HOP: f64 = reticulum::DEFAULT_PER_HOP_TIMEOUT;
pub const LINK_MTU_SIZE: usize = 3;
pub const TRAFFIC_TIMEOUT_MIN_MS: f64 = 5.0;
pub const TRAFFIC_TIMEOUT_FACTOR: f64 = 6.0;
pub const KEEPALIVE_MAX_RTT: f64 = 1.75;
pub const KEEPALIVE_TIMEOUT_FACTOR: f64 = 4.0;
pub const STALE_GRACE: f64 = 5.0;
pub const KEEPALIVE_MAX: f64 = 360.0;
pub const KEEPALIVE_MIN: f64 = 5.0;
pub const KEEPALIVE: f64 = KEEPALIVE_MAX;
pub const STALE_FACTOR: f64 = 2.0;
pub const STALE_TIME: f64 = STALE_FACTOR * KEEPALIVE;
pub const WATCHDOG_MAX_SLEEP: f64 = 5.0;
pub const REQUEST_TIMEOUT_CHECK_INTERVAL: f64 = 0.5;

// Encryption modes
pub const MODE_AES128_CBC: u8 = 0x00;
pub const MODE_AES256_CBC: u8 = 0x01;
pub const MODE_AES256_GCM: u8 = 0x02;
pub const MODE_OTP_RESERVED: u8 = 0x03;
pub const MODE_PQ_RESERVED_1: u8 = 0x04;
pub const MODE_PQ_RESERVED_2: u8 = 0x05;
pub const MODE_PQ_RESERVED_3: u8 = 0x06;
pub const MODE_PQ_RESERVED_4: u8 = 0x07;
pub const MODE_DEFAULT: u8 = MODE_AES256_CBC;

pub const MTU_BYTEMASK: u32 = 0x1FFFFF;
pub const MODE_BYTEMASK: u32 = 0xE0;

/// Signalling byte helper
pub fn signalling_bytes(mtu: usize, mode: u8) -> Result<[u8; 3], String> {
    if mode != MODE_AES256_CBC && mode != MODE_AES128_CBC {
        return Err(format!("Requested link mode {} not enabled", mode));
    }
    let signalling_value = (mtu as u32 & MTU_BYTEMASK) + (((mode as u32) << 5) & MODE_BYTEMASK) << 16;
    let bytes = signalling_value.to_be_bytes();
    Ok([bytes[1], bytes[2], bytes[3]])
}

/// Extract MTU from link request packet
pub fn mtu_from_lr_packet(data: &[u8]) -> Option<usize> {
    if data.len() == ECPUBSIZE + LINK_MTU_SIZE {
        let mtu = ((data[ECPUBSIZE] as u32) << 16)
            + ((data[ECPUBSIZE + 1] as u32) << 8)
            + (data[ECPUBSIZE + 2] as u32);
        Some((mtu & MTU_BYTEMASK) as usize)
    } else {
        None
    }
}

/// Extract MTU from link proof packet
pub fn mtu_from_lp_packet(data: &[u8]) -> Option<usize> {
    let offset = identity::SIGLENGTH / 8 + ECPUBSIZE / 2;
    if data.len() == offset + LINK_MTU_SIZE {
        let mtu = ((data[offset] as u32) << 16) + ((data[offset + 1] as u32) << 8) + (data[offset + 2] as u32);
        Some((mtu & MTU_BYTEMASK) as usize)
    } else {
        None
    }
}

/// Extract mode from link request packet
pub fn mode_from_lr_packet(data: &[u8]) -> u8 {
    if data.len() > ECPUBSIZE {
        ((data[ECPUBSIZE] as u32 & MODE_BYTEMASK) >> 5) as u8
    } else {
        MODE_DEFAULT
    }
}

/// Extract mode from link proof packet
pub fn mode_from_lp_packet(data: &[u8]) -> u8 {
    let offset = identity::SIGLENGTH / 8 + ECPUBSIZE / 2;
    if data.len() > offset {
        (data[offset] >> 5) as u8
    } else {
        MODE_DEFAULT
    }
}

/// Derive link ID from a link request packet
pub fn link_id_from_lr_packet(packet: &Packet) -> Vec<u8> {
    let mut hashable_part = packet.get_hashable_part();
    if packet.data.len() > ECPUBSIZE {
        let diff = packet.data.len() - ECPUBSIZE;
        if hashable_part.len() >= diff {
            hashable_part.truncate(hashable_part.len() - diff);
        }
    }
    identity::truncated_hash(&hashable_part)
}

/// Callbacks for link lifecycle events
#[derive(Clone, Default)]
pub struct LinkCallbacks {
    pub link_established: Option<Arc<dyn Fn(Arc<Mutex<Link>>) + Send + Sync>>,
    pub link_closed: Option<Arc<dyn Fn(Arc<Mutex<Link>>) + Send + Sync>>,
    pub packet: Option<Arc<dyn Fn(&[u8], &Packet) + Send + Sync>>,
    pub resource: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    pub resource_started: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    pub resource_concluded: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    pub remote_identified: Option<Arc<dyn Fn(Arc<Mutex<Link>>, Identity) + Send + Sync>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequestPayload {
    path: String,
    data: Vec<u8>,
    request_id: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResponsePayload {
    request_id: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Clone)]
pub struct RequestReceipt {
    pub request_id: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub link: Arc<Mutex<Link>>,
    pub sent_at: f64,
    pub received_at: Option<f64>,
    pub progress: f64,
}

impl RequestReceipt {
    pub fn get_progress(&self) -> f64 {
        self.progress
    }
}

/// Background thread that monitors pending requests for timeouts
fn request_timeout_watchdog(
    pending_requests: Arc<Mutex<Vec<PendingRequest>>>,
    link: Arc<Mutex<Link>>,
) {
    loop {
        thread::sleep(Duration::from_millis((REQUEST_TIMEOUT_CHECK_INTERVAL * 1000.0) as u64));
        
        let mut timed_out_requests = Vec::new();
        
        // Check for timed out requests
        {
            let pending = match pending_requests.lock() {
                Ok(p) => p,
                Err(_) => break, // Exit if lock is poisoned
            };
            
            // If no pending requests, exit the watchdog thread
            if pending.is_empty() {
                break;
            }
            
            let now = now_seconds();
            for request in pending.iter() {
                if now > request.sent_at + request.timeout {
                    timed_out_requests.push(request.clone());
                }
            }
        }
        
        // Process timed out requests
        if !timed_out_requests.is_empty() {
            let mut pending = match pending_requests.lock() {
                Ok(p) => p,
                Err(_) => break,
            };
            
            for timed_out in timed_out_requests {
                // Remove from pending list
                pending.retain(|r| r.request_id != timed_out.request_id);
                
                // Call failed callback
                if let Some(callback) = timed_out.failed_callback {
                    // Create receipt for callback
                    let receipt = RequestReceipt {
                        request_id: timed_out.request_id.clone(),
                        response: None,
                        link: Arc::clone(&link),
                        sent_at: timed_out.sent_at,
                        received_at: None,
                        progress: 0.0,
                    };
                    
                    // Spawn thread to avoid blocking the watchdog
                    thread::spawn(move || {
                        callback(receipt);
                    });
                }
            }
        }
    }
}

#[derive(Clone)]
struct PendingRequest {
    request_id: Vec<u8>,
    sent_at: f64,
    timeout: f64,
    response_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
    failed_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
    #[allow(dead_code)]
    progress_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
}

/// A link to a remote destination for encrypted communication
pub struct Link {
    // Core identifiers
    pub link_id: Vec<u8>,
    pub destination: Arc<Mutex<Destination>>,
    
    // State management
    pub state: u8,
    pub status: u8,
    pub teardown_reason: u8,
    
    // Configuration
    pub mode: u8,
    pub initiator: bool,
    pub mtu: usize,
    pub mdu: usize,
    
    // Timing
    pub rtt: Option<f64>,
    pub established_at: Option<u64>,
    pub activated_at: Option<u64>,
    pub request_time: Option<u64>,
    pub last_inbound: u64,
    pub last_outbound: u64,
    pub last_keepalive: u64,
    pub last_proof: u64,
    pub last_data: u64,
    
    // Statistics
    pub tx: u64,
    pub rx: u64,
    pub txbytes: u64,
    pub rxbytes: u64,
    pub rssi: Option<i32>,
    pub snr: Option<f64>,
    pub q: Option<f64>,
    pub establishment_cost: usize,
    pub establishment_rate: Option<f64>,
    pub expected_rate: Option<f64>,
    pub expected_hops: Option<usize>,
    
    // Cryptography
    pub prv_bytes: Option<Vec<u8>>,  // X25519 private key bytes
    pub pub_bytes: Option<Vec<u8>>,  // X25519 public key bytes
    pub sig_prv_bytes: Option<Vec<u8>>,  // Ed25519 private key bytes
    pub sig_pub_bytes: Option<Vec<u8>>,  // Ed25519 public key bytes
    
    pub peer_pub_bytes: Option<Vec<u8>>,  // Peer's X25519 public key
    pub peer_sig_pub_bytes: Option<Vec<u8>>,  // Peer's Ed25519 public key
    
    pub shared_key: Option<Vec<u8>>,
    pub derived_key: Option<Vec<u8>>,
    pub token: Arc<Mutex<Option<Token>>>,
    
    // Remote identity
    pub remote_identity: Arc<Mutex<Option<Identity>>>,
    
    // Callbacks and resources
    pub callbacks: LinkCallbacks,
    pub resource_strategy: u8,
    
    // Resource tracking
    pub outgoing_resources: Arc<Mutex<Vec<Arc<Mutex<Resource>>>>>,
    pub incoming_resources: Arc<Mutex<Vec<Arc<Mutex<Resource>>>>>,
    pending_requests: Arc<Mutex<Vec<PendingRequest>>>,
    pub last_resource_window: Option<usize>,
    pub last_resource_eifr: Option<f64>,
    
    // Connection management
    pub attached_interface: Option<String>,
    pub traffic_timeout_factor: f64,
    pub keepalive_timeout_factor: f64,
    pub keepalive: f64,
    pub stale_time: f64,
    pub establishment_timeout: f64,
    pub watchdog_lock: bool,
    pub track_phy_stats: bool,
    
    // Channel support
    pub channel: Option<()>, // Placeholder for Channel integration
}

impl Clone for Link {
    fn clone(&self) -> Self {
        Link {
            link_id: self.link_id.clone(),
            destination: Arc::clone(&self.destination),
            state: self.state,
            status: self.status,
            teardown_reason: self.teardown_reason,
            mode: self.mode,
            initiator: self.initiator,
            mtu: self.mtu,
            mdu: self.mdu,
            rtt: self.rtt,
            established_at: self.established_at,
            activated_at: self.activated_at,
            request_time: self.request_time,
            last_inbound: self.last_inbound,
            last_outbound: self.last_outbound,
            last_keepalive: self.last_keepalive,
            last_proof: self.last_proof,
            last_data: self.last_data,
            tx: self.tx,
            rx: self.rx,
            txbytes: self.txbytes,
            rxbytes: self.rxbytes,
            rssi: self.rssi,
            snr: self.snr,
            q: self.q,
            establishment_cost: self.establishment_cost,
            establishment_rate: self.establishment_rate,
            expected_rate: self.expected_rate,
            expected_hops: self.expected_hops,
            prv_bytes: self.prv_bytes.clone(),
            pub_bytes: self.pub_bytes.clone(),
            sig_prv_bytes: self.sig_prv_bytes.clone(),
            sig_pub_bytes: self.sig_pub_bytes.clone(),
            peer_pub_bytes: self.peer_pub_bytes.clone(),
            peer_sig_pub_bytes: self.peer_sig_pub_bytes.clone(),
            shared_key: self.shared_key.clone(),
            derived_key: self.derived_key.clone(),
            token: Arc::clone(&self.token),
            remote_identity: Arc::clone(&self.remote_identity),
            callbacks: self.callbacks.clone(),
            resource_strategy: self.resource_strategy,
            outgoing_resources: Arc::clone(&self.outgoing_resources),
            incoming_resources: Arc::clone(&self.incoming_resources),
            pending_requests: Arc::clone(&self.pending_requests),
            last_resource_window: self.last_resource_window,
            last_resource_eifr: self.last_resource_eifr,
            attached_interface: self.attached_interface.clone(),
            traffic_timeout_factor: self.traffic_timeout_factor,
            keepalive_timeout_factor: self.keepalive_timeout_factor,
            keepalive: self.keepalive,
            stale_time: self.stale_time,
            establishment_timeout: self.establishment_timeout,
            watchdog_lock: self.watchdog_lock,
            track_phy_stats: self.track_phy_stats,
            channel: self.channel.clone(),
        }
    }
}

impl Link {
    /// Create a new outbound link to a destination
    pub fn new_outbound(destination: Destination, mode: u8) -> Result<Self, String> {
        let link_id = (0..16).map(|i| ((i * 7) % 256) as u8).collect::<Vec<_>>();
        let established_at = current_time();
        
        Ok(Link {
            link_id,
            destination: Arc::new(Mutex::new(destination)),
            state: STATE_PENDING,
            status: 0,
            teardown_reason: 0,
            mode,
            initiator: true,
            mtu: reticulum::MTU,
            mdu: MDU,
            rtt: None,
            established_at,
            activated_at: None,
            request_time: established_at,
            last_inbound: current_time().unwrap_or(0),
            last_outbound: current_time().unwrap_or(0),
            last_keepalive: 0,
            last_proof: 0,
            last_data: 0,
            tx: 0,
            rx: 0,
            txbytes: 0,
            rxbytes: 0,
            rssi: None,
            snr: None,
            q: None,
            establishment_cost: 0,
            establishment_rate: None,
            expected_rate: None,
            expected_hops: None,
            prv_bytes: None,
            pub_bytes: None,
            sig_prv_bytes: None,
            sig_pub_bytes: None,
            peer_pub_bytes: None,
            peer_sig_pub_bytes: None,
            shared_key: None,
            derived_key: None,
            token: Arc::new(Mutex::new(None)),
            remote_identity: Arc::new(Mutex::new(None)),
            callbacks: LinkCallbacks::default(),
            resource_strategy: ACCEPT_NONE,
            outgoing_resources: Arc::new(Mutex::new(Vec::new())),
            incoming_resources: Arc::new(Mutex::new(Vec::new())),
            pending_requests: Arc::new(Mutex::new(Vec::new())),
            last_resource_window: None,
            last_resource_eifr: None,
            attached_interface: None,
            traffic_timeout_factor: TRAFFIC_TIMEOUT_FACTOR,
            keepalive_timeout_factor: KEEPALIVE_TIMEOUT_FACTOR,
            keepalive: KEEPALIVE,
            stale_time: STALE_TIME,
            establishment_timeout: ESTABLISHMENT_TIMEOUT_PER_HOP,
            watchdog_lock: false,
            track_phy_stats: false,
            channel: None,
        })
    }
    
    /// Create a new inbound link for an incoming request
    pub fn new_inbound(owner_destination: Destination) -> Result<Self, String> {
        let link_id = (0..16).map(|i| ((i * 7) % 256) as u8).collect::<Vec<_>>();
        let established_at = current_time();
        
        Ok(Link {
            link_id,
            destination: Arc::new(Mutex::new(owner_destination)),
            state: STATE_PENDING,
            status: 0,
            teardown_reason: 0,
            mode: MODE_DEFAULT,
            initiator: false,
            mtu: reticulum::MTU,
            mdu: MDU,
            rtt: None,
            established_at,
            activated_at: None,
            request_time: established_at,
            last_inbound: current_time().unwrap_or(0),
            last_outbound: current_time().unwrap_or(0),
            last_keepalive: 0,
            last_proof: 0,
            last_data: 0,
            tx: 0,
            rx: 0,
            txbytes: 0,
            rxbytes: 0,
            rssi: None,
            snr: None,
            q: None,
            establishment_cost: 0,
            establishment_rate: None,
            expected_rate: None,
            expected_hops: None,
            prv_bytes: None,
            pub_bytes: None,
            sig_prv_bytes: None,
            sig_pub_bytes: None,
            peer_pub_bytes: None,
            peer_sig_pub_bytes: None,
            shared_key: None,
            derived_key: None,
            token: Arc::new(Mutex::new(None)),
            remote_identity: Arc::new(Mutex::new(None)),
            callbacks: LinkCallbacks::default(),
            resource_strategy: ACCEPT_NONE,
            outgoing_resources: Arc::new(Mutex::new(Vec::new())),
            incoming_resources: Arc::new(Mutex::new(Vec::new())),
            pending_requests: Arc::new(Mutex::new(Vec::new())),
            last_resource_window: None,
            last_resource_eifr: None,
            attached_interface: None,
            traffic_timeout_factor: TRAFFIC_TIMEOUT_FACTOR,
            keepalive_timeout_factor: KEEPALIVE_TIMEOUT_FACTOR,
            keepalive: KEEPALIVE,
            stale_time: STALE_TIME,
            establishment_timeout: ESTABLISHMENT_TIMEOUT_PER_HOP,
            watchdog_lock: false,
            track_phy_stats: false,
            channel: None,
        })
    }
    
    /// Perform key exchange handshake
    pub fn handshake(&mut self) -> Result<(), String> {
        if self.state != STATE_PENDING {
            return Err("Invalid link state for handshake".to_string());
        }
        
        if self.prv_bytes.is_none() || self.peer_pub_bytes.is_none() {
            return Err("Missing keys for handshake".to_string());
        }
        
        self.state = STATE_HANDSHAKE;
        
        // Perform ECDH key exchange
        let prv_bytes_vec = self.prv_bytes.as_ref().unwrap();
        if prv_bytes_vec.len() != 32 {
            return Err("Invalid private key length".to_string());
        }
        let prv_array: [u8; 32] = prv_bytes_vec.as_slice().try_into()
            .map_err(|_| "Invalid private key".to_string())?;
        let prv = X25519PrivateKey::from(prv_array);
        
        let peer_pub_bytes = self.peer_pub_bytes.as_ref().unwrap();
        if peer_pub_bytes.len() != 32 {
            return Err("Invalid peer public key length".to_string());
        }
        
        let peer_pub_array: [u8; 32] = peer_pub_bytes.as_slice().try_into()
            .map_err(|_| "Invalid peer public key".to_string())?;
        let peer_pub = X25519PublicKey::from(peer_pub_array);
        
        let shared_secret = prv.diffie_hellman(&peer_pub);
        self.shared_key = Some(shared_secret.as_bytes().to_vec());
        
        // Derive encryption key using HKDF
        let derived_key_length = match self.mode {
            MODE_AES128_CBC => 32,
            MODE_AES256_CBC => 64,
            _ => return Err(format!("Invalid link mode {}", self.mode)),
        };
        
        self.derived_key = Some(self.derive_key_hkdf(derived_key_length)?);
        
        // Create token for encryption/decryption
        if let Some(derived_key) = &self.derived_key {
            let token = Token::new(derived_key)?;
            *self.token.lock().unwrap() = Some(token);
        }
        
        Ok(())
    }
    
    /// Derive encryption key using HKDF with salt=link_id, context=None
    fn derive_key_hkdf(&self, length: usize) -> Result<Vec<u8>, String> {
        if let Some(shared_key) = &self.shared_key {
            let hkdf = Hkdf::<Sha256>::new(Some(self.link_id.as_slice()), shared_key.as_slice());
            let mut derived_key = vec![0u8; length];
            hkdf.expand(&[], &mut derived_key)
                .map_err(|_| "HKDF expansion failed".to_string())?;
            Ok(derived_key)
        } else {
            Err("Missing shared key for derivation".to_string())
        }
    }
    
    /// Derive encryption key using HKDF (legacy simplified version)
    #[allow(dead_code)]
    fn derive_key(&self, length: usize) -> Result<Vec<u8>, String> {
        if let Some(shared_key) = &self.shared_key {
            // Simplified key derivation - in real implementation use HKDF
            let mut derived = Vec::with_capacity(length);
            let mut hash_input = self.link_id.clone();
            hash_input.extend_from_slice(shared_key);
            
            for _ in 0..((length + 31) / 32) {
                let chunk = identity::full_hash(&hash_input);
                derived.extend_from_slice(&chunk);
                hash_input = chunk.to_vec();
            }
            
            Ok(derived[..length].to_vec())
        } else {
            Err("Missing keys for derivation".to_string())
        }
    }
    
    /// Encrypt data for transmission
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(derived_key) = &self.derived_key {
            let token = Token::new(derived_key)?;
            token.encrypt(plaintext)
        } else {
            Err("Link not properly established for encryption".to_string())
        }
    }
    
    /// Decrypt received data
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(derived_key) = &self.derived_key {
            let token = Token::new(derived_key)?;
            token.decrypt(ciphertext)
        } else {
            Err("Link not properly established for decryption".to_string())
        }
    }
    
    /// Sign data with link's signing key
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(sig_prv_bytes) = &self.sig_prv_bytes {
            if sig_prv_bytes.len() != 32 {
                return Err("Invalid signing key length".to_string());
            }
            
            let sig_prv_array: [u8; 32] = sig_prv_bytes.as_slice().try_into()
                .map_err(|_| "Invalid signing key".to_string())?;
            let keypair = ed25519_dalek::Keypair::from_bytes(&sig_prv_array)
                .map_err(|e| format!("Failed to construct keypair: {}", e))?;
            let signature = keypair.sign(data);
            Ok(signature.to_bytes().to_vec())
        } else {
            Err("Signing key not available".to_string())
        }
    }
    
    /// Validate a signature with peer's public key
    pub fn validate(&self, signature: &[u8], data: &[u8]) -> Result<bool, String> {
        if signature.len() != 64 {
            return Ok(false);
        }
        
        if let Some(peer_sig_pub_bytes) = &self.peer_sig_pub_bytes {
            if peer_sig_pub_bytes.len() != 32 {
                return Ok(false);
            }
            
            let sig_array: [u8; 64] = signature.try_into()
                .map_err(|_| "Invalid signature length".to_string())?;
            let sig = Signature::from_bytes(&sig_array)
                .map_err(|e| format!("Invalid signature: {}", e))?;
            
            let pub_array: [u8; 32] = peer_sig_pub_bytes.as_slice().try_into()
                .map_err(|_| "Invalid public key".to_string())?;
            let public_key = Ed25519PublicKey::from_bytes(&pub_array)
                .map_err(|e| format!("Invalid public key: {}", e))?;
            
            match public_key.verify(data, &sig) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Err("Peer signing key not available".to_string())
        }
    }
    
    /// Load peer public keys from bytes
    pub fn load_peer(&mut self, peer_pub_bytes: Vec<u8>, peer_sig_pub_bytes: Vec<u8>) -> Result<(), String> {
        if peer_pub_bytes.len() != 32 {
            return Err("Invalid peer public key length".to_string());
        }
        if peer_sig_pub_bytes.len() != 32 {
            return Err("Invalid peer signing public key length".to_string());
        }
        
        self.peer_pub_bytes = Some(peer_pub_bytes);
        self.peer_sig_pub_bytes = Some(peer_sig_pub_bytes);
        Ok(())
    }
    
    /// Send link proof after handshake
    pub fn prove(&mut self, owner_sig_prv_bytes: Option<&[u8]>) -> Result<(), String> {
        let signalling_bytes = signalling_bytes(self.mtu, self.mode)?;
        
        let mut signed_data = self.link_id.clone();
        if let Some(pub_bytes) = &self.pub_bytes {
            signed_data.extend_from_slice(pub_bytes);
        } else {
            return Err("Own public key not available".to_string());
        }
        if let Some(sig_pub_bytes) = &self.sig_pub_bytes {
            signed_data.extend_from_slice(sig_pub_bytes);
        } else {
            return Err("Own signing public key not available".to_string());
        }
        signed_data.extend_from_slice(&signalling_bytes);
        
        // Sign with owner's identity (or our own if this is inbound link)
        let signature = if let Some(owner_sig_prv) = owner_sig_prv_bytes {
            // Sign with owner's key
            if owner_sig_prv.len() != 32 {
                return Err("Invalid owner signing key".to_string());
            }
            let owner_keypair = ed25519_dalek::Keypair::from_bytes(owner_sig_prv)
                .map_err(|e| format!("Failed to construct owner keypair: {}", e))?;
            owner_keypair.sign(&signed_data).to_bytes().to_vec()
        } else if let Some(_sig_prv_bytes) = &self.sig_prv_bytes {
            self.sign(&signed_data)?
        } else {
            return Err("Signing key not available for proof".to_string())
        };
        
        let mut proof_data = signature;
        if let Some(pub_bytes) = &self.pub_bytes {
            proof_data.extend_from_slice(pub_bytes);
        }
        proof_data.extend_from_slice(&signalling_bytes);
        
        // Note: Actual packet sending would happen here
        // For now, we've assembled the proof data that would be sent
        self.last_proof = current_time().unwrap_or(0);
        self.establishment_cost += proof_data.len();
        
        Ok(())
    }
    
    /// Get salt for HKDF (link_id)
    pub fn get_salt(&self) -> Vec<u8> {
        self.link_id.clone()
    }
    
    /// Get context for HKDF (None in RNS)
    pub fn get_context(&self) -> Option<Vec<u8>> {
        None
    }
    
    /// Check if link is active
    pub fn is_active(&self) -> bool {
        self.state == STATE_ACTIVE
    }
    
    /// Check if link is stale
    pub fn is_stale(&self) -> bool {
        self.state == STATE_STALE
    }
    
    /// Check if link is closed
    pub fn is_closed(&self) -> bool {
        self.state == STATE_CLOSED
    }
    
    /// Get human-readable state name
    pub fn state_name(&self) -> &'static str {
        match self.state {
            STATE_PENDING => "PENDING",
            STATE_HANDSHAKE => "HANDSHAKE",
            STATE_ACTIVE => "ACTIVE",
            STATE_STALE => "STALE",
            STATE_CLOSED => "CLOSED",
            _ => "UNKNOWN",
        }
    }
    
    /// Record outbound activity
    pub fn had_outbound(&mut self, is_keepalive: bool) {
        self.last_outbound = current_time().unwrap_or(0);
        if !is_keepalive {
            self.last_data = self.last_outbound;
        } else {
            self.last_keepalive = self.last_outbound;
        }
    }
    
    /// Record inbound activity
    pub fn had_inbound(&mut self, is_data: bool) {
        self.last_inbound = current_time().unwrap_or(0);
        if is_data {
            self.last_data = self.last_inbound;
        }
    }
    
    /// Get time since last inbound
    pub fn no_inbound_for(&self) -> u64 {
        let activated = self.activated_at.unwrap_or(0);
        let last_inbound = std::cmp::max(self.last_inbound, activated);
        current_time().unwrap_or(0).saturating_sub(last_inbound)
    }
    
    /// Get time since last outbound
    pub fn no_outbound_for(&self) -> u64 {
        current_time().unwrap_or(0).saturating_sub(self.last_outbound)
    }
    
    /// Get time since last data
    pub fn no_data_for(&self) -> u64 {
        current_time().unwrap_or(0).saturating_sub(self.last_data)
    }
    
    /// Get time since activity (min of inbound/outbound)
    pub fn inactive_for(&self) -> u64 {
        std::cmp::min(self.no_inbound_for(), self.no_outbound_for())
    }
    
    /// Get age of link (time since activation)
    pub fn get_age(&self) -> Option<u64> {
        self.activated_at.and_then(|activated| {
            current_time().map(|now| now.saturating_sub(activated))
        })
    }
    
    /// Get remote identity
    pub fn get_remote_identity(&self) -> Option<String> {
        // Returns a string placeholder since Identity doesn't implement Clone
        if let Ok(id) = self.remote_identity.lock() {
            if id.is_some() {
                Some("remote_identity".to_string())
            } else {
                None
            }
        } else {
            None
        }
    }
    
    /// Set link established callback
    pub fn set_link_established_callback(
        &mut self,
        callback: Option<Arc<dyn Fn(Arc<Mutex<Link>>) + Send + Sync>>,
    ) {
        self.callbacks.link_established = callback;
    }
    
    /// Set link closed callback
    pub fn set_link_closed_callback(
        &mut self,
        callback: Option<Arc<dyn Fn(Arc<Mutex<Link>>) + Send + Sync>>,
    ) {
        self.callbacks.link_closed = callback;
    }
    
    /// Set packet received callback
    pub fn set_packet_callback(&mut self, callback: Option<Arc<dyn Fn(&[u8], &Packet) + Send + Sync>>) {
        self.callbacks.packet = callback;
    }
    
    /// Set resource callback
    pub fn set_resource_callback(&mut self, callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>) {
        self.callbacks.resource = callback;
    }
    
    /// Set resource started callback
    pub fn set_resource_started_callback(
        &mut self,
        callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    ) {
        self.callbacks.resource_started = callback;
    }
    
    /// Set resource concluded callback
    pub fn set_resource_concluded_callback(
        &mut self,
        callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    ) {
        self.callbacks.resource_concluded = callback;
    }
    
    /// Set remote identified callback
    pub fn set_remote_identified_callback(
        &mut self,
        callback: Option<Arc<dyn Fn(Arc<Mutex<Link>>, Identity) + Send + Sync>>,
    ) {
        self.callbacks.remote_identified = callback;
    }
    
    /// Set resource acceptance strategy
    pub fn set_resource_strategy(&mut self, strategy: u8) -> Result<(), String> {
        match strategy {
            ACCEPT_NONE | ACCEPT_APP | ACCEPT_ALL => {
                self.resource_strategy = strategy;
                Ok(())
            }
            _ => Err(format!("Invalid resource strategy: {}", strategy)),
        }
    }
    
    /// Update MDU based on MTU
    pub fn update_mdu(&mut self) {
        self.mdu = ((self.mtu - reticulum::IFAC_MIN_SIZE - reticulum::HEADER_MINSIZE - identity::TOKEN_OVERHEAD) / identity::AES128_BLOCKSIZE) * identity::AES128_BLOCKSIZE - 1;
    }
    
    /// Get MTU if link is active
    pub fn get_mtu(&self) -> Option<usize> {
        if self.is_active() {
            Some(self.mtu)
        } else {
            None
        }
    }

    pub fn mtu(&self) -> Option<usize> {
        self.get_mtu()
    }
    
    /// Get MDU if link is active
    pub fn get_mdu(&self) -> Option<usize> {
        if self.is_active() {
            Some(self.mdu)
        } else {
            None
        }
    }
    
    /// Get RTT if available
    pub fn get_rtt(&self) -> Option<f64> {
        self.rtt
    }

    pub fn rtt(&self) -> Option<f64> {
        self.get_rtt()
    }

    pub fn traffic_timeout_factor(&self) -> Option<f64> {
        Some(self.traffic_timeout_factor)
    }

    pub fn establishment_cost(&self) -> Option<f64> {
        Some(self.establishment_cost as f64)
    }

    pub fn set_expected_rate(&mut self, rate: f64) {
        self.expected_rate = Some(rate);
        self.last_resource_eifr = Some(rate);
    }

    pub fn get_last_resource_window(&self) -> Option<usize> {
        self.last_resource_window
    }

    pub fn get_last_resource_eifr(&self) -> Option<f64> {
        self.last_resource_eifr
    }
    
    /// Get establishment rate
    pub fn get_establishment_rate(&self) -> Option<f64> {
        self.establishment_rate.map(|rate| rate * 8.0)
    }
    
    /// Get expected data rate
    pub fn get_expected_rate(&self) -> Option<f64> {
        if self.is_active() {
            self.expected_rate
        } else {
            None
        }
    }
    
    /// Get mode
    pub fn get_mode(&self) -> u8 {
        self.mode
    }
    
    /// Get physical stats if tracking enabled
    pub fn get_rssi(&self) -> Option<i32> {
        if self.track_phy_stats {
            self.rssi
        } else {
            None
        }
    }
    
    /// Get SNR if tracking enabled
    pub fn get_snr(&self) -> Option<f64> {
        if self.track_phy_stats {
            self.snr
        } else {
            None
        }
    }
    
    /// Get link quality if tracking enabled
    pub fn get_q(&self) -> Option<f64> {
        if self.track_phy_stats {
            self.q
        } else {
            None
        }
    }
    
    /// Enable/disable physical layer statistics tracking
    pub fn track_phy_stats(&mut self, track: bool) {
        self.track_phy_stats = track;
    }
    
    /// Tear down the link
    pub fn teardown(&mut self) {
        if self.state != STATE_CLOSED && self.state != STATE_PENDING {
            // Send teardown packet
        }
        self.state = STATE_CLOSED;
        self.link_closed();
    }
    
    /// Handle link closure cleanup
    fn link_closed(&mut self) {
        // Cancel resources
        self.prv_bytes = None;
        self.pub_bytes = None;
        self.sig_prv_bytes = None;
        self.sig_pub_bytes = None;
        self.shared_key = None;
        self.derived_key = None;
        
        if let Ok(mut token) = self.token.lock() {
            *token = None;
        }
        
        if let Some(callback) = &self.callbacks.link_closed {
            callback(Arc::new(Mutex::new(self.clone())));
        }
    }
    
    /// Process received packet
    pub fn receive(&mut self, packet: &Packet) -> Result<(), String> {
        self.watchdog_lock = true;
        
        if !self.is_closed() {
            self.last_inbound = current_time().unwrap_or(0);
            self.rx += 1;
            self.rxbytes += packet.data.len() as u64;
            
            // Mark active if stale
            if self.state == STATE_STALE {
                self.state = STATE_ACTIVE;
            }
            
            // Route based on packet context
            match packet.packet_type {
                DATA => {
                    self.handle_data_packet(packet)?;
                }
                PROOF => {
                    self.handle_proof_packet(packet)?;
                }
                _ => {}
            }
        }
        
        self.watchdog_lock = false;
        Ok(())
    }
    
    /// Handle DATA packets
    fn handle_data_packet(&mut self, packet: &Packet) -> Result<(), String> {
        let plaintext = self.decrypt(&packet.data)?;

        if packet.context == crate::packet::REQUEST {
            self.handle_request_packet(&plaintext)?;
            return Ok(());
        }

        if packet.context == crate::packet::RESPONSE {
            self.handle_response_packet(&plaintext)?;
            return Ok(());
        }

        if packet.context == LINKIDENTIFY {
            self.handle_linkidentify_packet(&plaintext)?;
            return Ok(());
        }

        if let Some(callback) = &self.callbacks.packet {
            callback(&plaintext, packet);
        }
        
        Ok(())
    }

    fn handle_request_packet(&mut self, plaintext: &[u8]) -> Result<(), String> {
        let payload: RequestPayload = match from_slice(plaintext) {
            Ok(parsed) => parsed,
            Err(_) => return Ok(()),
        };

        let handler = {
            let dest = self.destination.lock().map_err(|_| "Destination lock poisoned")?;
            let path_hash = identity::truncated_hash(payload.path.as_bytes());
            dest.request_handlers.get(&path_hash).cloned()
        };

        let response = if let Some(handler) = handler {
            let remote_identity_guard = self.remote_identity.lock().ok();
            let remote_identity_ref = remote_identity_guard.as_ref().and_then(|guard| guard.as_ref());
            let allowed = match handler.allow_policy {
                crate::destination::ALLOW_NONE => false,
                crate::destination::ALLOW_ALL => true,
                crate::destination::ALLOW_LIST => {
                    if let (Some(identity), Some(allowed_list)) = (remote_identity_ref, handler.allowed_list.as_ref()) {
                        identity
                            .hash
                            .as_ref()
                            .map(|hash| allowed_list.iter().any(|allowed| allowed == hash))
                            .unwrap_or(false)
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if !allowed {
                Vec::new()
            } else if let Some(callback) = handler.callback {
                callback(
                    &payload.path,
                    &payload.data,
                    &payload.request_id,
                    remote_identity_ref,
                    0.0,
                )
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let response_payload = ResponsePayload {
            request_id: payload.request_id,
            response,
        };
        let response_data = to_vec_named(&response_payload).map_err(|e| e.to_string())?;

        let dest = self.destination.lock().map_err(|_| "Destination lock poisoned")?.clone();
        let mut response_packet = Packet::new(
            Some(dest),
            response_data,
            DATA,
            crate::packet::RESPONSE,
            crate::transport::BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            0,
        );
        let _ = response_packet.send();
        Ok(())
    }

    fn handle_response_packet(&mut self, plaintext: &[u8]) -> Result<(), String> {
        let payload: ResponsePayload = match from_slice(plaintext) {
            Ok(parsed) => parsed,
            Err(_) => return Ok(()),
        };

        let mut pending = self.pending_requests.lock().map_err(|_| "Pending request lock poisoned")?;
        if let Some(index) = pending.iter().position(|p| p.request_id == payload.request_id) {
            let request = pending.remove(index);
            let receipt = RequestReceipt {
                request_id: payload.request_id,
                response: Some(payload.response),
                link: Arc::new(Mutex::new(self.clone())),
                sent_at: request.sent_at,
                received_at: Some(current_time().unwrap_or(0) as f64),
                progress: 1.0,
            };

            if let Some(callback) = request.response_callback {
                callback(receipt);
            }
        }

        Ok(())
    }

    pub fn request(
        &self,
        path: String,
        data: Vec<u8>,
        response_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
        failed_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
        progress_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
    ) -> Result<Vec<u8>, String> {
        let request_id = identity::get_random_hash();
        let payload = RequestPayload {
            path,
            data,
            request_id: request_id.clone(),
        };

        let payload_data = to_vec_named(&payload).map_err(|e| e.to_string())?;
        let dest = self.destination.lock().map_err(|_| "Destination lock poisoned")?.clone();
        let mut packet = Packet::new(
            Some(dest),
            payload_data,
            DATA,
            crate::packet::REQUEST,
            crate::transport::BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            0,
        );

        let sent_at = current_time().unwrap_or(0) as f64;
        let receipt = RequestReceipt {
            request_id: request_id.clone(),
            response: None,
            link: Arc::new(Mutex::new(self.clone())),
            sent_at,
            received_at: None,
            progress: 0.0,
        };

        if let Err(err) = packet.send() {
            if let Some(callback) = failed_callback {
                callback(receipt);
            }
            return Err(err);
        }

        if let Some(callback) = progress_callback.as_ref() {
            let mut initial = receipt.clone();
            initial.progress = 0.1;
            callback(initial);
        }

        // Calculate timeout based on RTT or default
        let timeout = if let Some(rtt) = self.rtt {
            rtt * self.traffic_timeout_factor + crate::resource::Resource::RESPONSE_MAX_GRACE_TIME * 1.125
        } else {
            // Default timeout when RTT not available
            self.traffic_timeout_factor * 3.0 + crate::resource::Resource::RESPONSE_MAX_GRACE_TIME * 1.125
        };

        let mut pending = self.pending_requests.lock().map_err(|_| "Pending request lock poisoned")?;
        
        // Spawn timeout watchdog thread if this is the first request
        if pending.is_empty() {
            let pending_requests = Arc::clone(&self.pending_requests);
            let link = Arc::new(Mutex::new(self.clone()));
            
            thread::spawn(move || {
                request_timeout_watchdog(pending_requests, link);
            });
        }
        
        pending.push(PendingRequest {
            request_id: request_id.clone(),
            sent_at,
            timeout,
            response_callback,
            failed_callback,
            progress_callback,
        });

        Ok(request_id)
    }
    
    /// Handle LINKIDENTIFY packets - validate identity signature and establish remote identity
    fn handle_linkidentify_packet(&mut self, plaintext: &[u8]) -> Result<(), String> {
        // LINKIDENTIFY packet format: public_key (64 bytes) + signature (64 bytes)
        if plaintext.len() != 128 {
            return Err("Invalid LINKIDENTIFY packet length".to_string());
        }

        let public_key = &plaintext[0..64];
        let signature = &plaintext[64..128];

        // Create signed data: link_id + public_key
        let mut signed_data = self.link_id.clone();
        signed_data.extend_from_slice(public_key);

        // Create Identity from public key bytes for signature validation
        match Identity::from_public_key(public_key) {
            Ok(identity) => {
                // Validate the signature
                if identity.validate(signature, &signed_data) {
                    // Store the remote identity
                    if let Ok(mut remote_id) = self.remote_identity.lock() {
                        *remote_id = Some(identity.clone());
                    }

                    // Call remote_identified callback
                    if let Some(callback) = &self.callbacks.remote_identified {
                        callback(Arc::new(Mutex::new(self.clone())), identity);
                    }

                    Ok(())
                } else {
                    Err("LINKIDENTIFY signature validation failed".to_string())
                }
            }
            Err(e) => Err(format!("Failed to create identity from public key: {}", e)),
        }
    }
    
    /// Handle PROOF packets
    fn handle_proof_packet(&mut self, _packet: &Packet) -> Result<(), String> {
        // Validate proof based on context
        Ok(())
    }
    
    /// Send keep-alive packet
    pub fn send_keepalive(&mut self) -> Result<(), String> {
        self.had_outbound(true);
        Ok(())
    }

    /// Identify the initiator of the link to the remote peer over the encrypted link.
    /// This can only happen once the link has been established, and is carried out
    /// over the encrypted link. The identity is only revealed to the remote peer,
    /// and initiator anonymity is thus preserved. This method can be used for authentication.
    pub fn identify(&mut self, identity: &Identity) -> Result<(), String> {
        if !self.initiator || self.state != STATE_ACTIVE {
            return Err("Can only identify on outbound link after activation".to_string());
        }

        let public_key = identity.get_public_key()?;
        // Create signed data: link_id + public_key
        let mut signed_data = self.link_id.clone();
        signed_data.extend_from_slice(&public_key);

        // Sign the data with the identity
        let signature = identity.sign(&signed_data);

        // Create proof data: public_key + signature
        let mut proof_data = public_key.clone();
        proof_data.extend_from_slice(&signature);

        // Get destination (clone the Arc reference)
        let dest = self.destination.lock()
            .map_err(|_| "Failed to lock destination".to_string())?
            .clone();

        // Create packet with LINKIDENTIFY context
        let packet = Packet::new(
            Some(dest),
            proof_data,
            DATA,
            LINKIDENTIFY,
            crate::transport::BROADCAST,
            packet::HEADER_1,
            None,
            None,
            false,
            0,
        );

        // Send the packet
        let mut packet = packet;
        packet.send()?;

        // Record outbound activity
        self.had_outbound(false);

        Ok(())
    }
    
    /// Register resource management
    pub fn register_outgoing_resource(&self, resource: Arc<Mutex<Resource>>) {
        if let Ok(mut resources) = self.outgoing_resources.lock() {
            resources.push(resource);
        }
    }
    
    /// Register incoming resource
    pub fn register_incoming_resource(&self, resource: Arc<Mutex<Resource>>) {
        if let Ok(mut resources) = self.incoming_resources.lock() {
            resources.push(resource);
        }
    }

    /// Check if incoming resource is already registered
    pub fn has_incoming_resource(&self, resource: &Arc<Mutex<Resource>>) -> bool {
        if let Ok(resources) = self.incoming_resources.lock() {
            resources.iter().any(|r| Arc::ptr_eq(r, resource))
        } else {
            false
        }
    }

    /// Cancel outgoing resource and remove from tracking
    pub fn cancel_outgoing_resource(&self, resource: Arc<Mutex<Resource>>) {
        if let Ok(mut resources) = self.outgoing_resources.lock() {
            resources.retain(|r| !Arc::ptr_eq(r, &resource));
        }
    }

    /// Cancel incoming resource and remove from tracking
    pub fn cancel_incoming_resource(&self, resource: Arc<Mutex<Resource>>) {
        if let Ok(mut resources) = self.incoming_resources.lock() {
            resources.retain(|r| !Arc::ptr_eq(r, &resource));
        }
    }

    /// Mark resource concluded and update tracking stats
    pub fn resource_concluded(&mut self, resource: Arc<Mutex<Resource>>) {
        if let Ok(resource_guard) = resource.lock() {
            self.last_resource_window = Some(resource_guard.window);
            self.last_resource_eifr = resource_guard.eifr;
        }
        if let Some(callback) = &self.callbacks.resource_concluded {
            callback(resource.clone());
        }
        self.cancel_outgoing_resource(resource.clone());
        self.cancel_incoming_resource(resource);
    }
    
    /// Check if ready for new resource
    pub fn ready_for_new_resource(&self) -> bool {
        self.outgoing_resources.lock().map(|r| r.is_empty()).unwrap_or(true)
    }
}

/// Helper to get current Unix timestamp
fn current_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Helper to get current Unix timestamp as f64 with subsecond precision
fn now_seconds() -> f64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0));
    now.as_secs() as f64 + (now.subsec_nanos() as f64 / 1_000_000_000.0)
}
