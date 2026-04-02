use crate::{identity, reticulum, destination::{Destination, DestinationType}, resource::Resource};
use crate::packet::{self, Packet, DATA, PROOF, LINKIDENTIFY};
use crate::identity::{Identity, Token};
use once_cell::sync::Lazy;
use rand::RngCore;
use rmp_serde::{decode::from_slice, encode::to_vec};
use rmpv::decode::read_value as rmpv_read_value;
use rmpv::encode::write_value as rmpv_write_value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::Weak;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread;
use x25519_dalek::{StaticSecret as X25519PrivateKey, PublicKey as X25519PublicKey};
use ed25519_dalek::{PublicKey as Ed25519PublicKey, Signature, Signer, Verifier};
use hkdf::Hkdf;
use sha2::Sha256;

static RUNTIME_LINKS: Lazy<Mutex<HashMap<Vec<u8>, Weak<Mutex<Link>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Strong references for incoming (non-initiator) links to keep Arc alive
/// so that RUNTIME_LINKS Weak references remain valid.
static INCOMING_LINK_ARCS: Lazy<Mutex<Vec<Arc<Mutex<Link>>>>> =
    Lazy::new(|| Mutex::new(Vec::new()));

pub fn register_runtime_link(link: Arc<Mutex<Link>>) {
    if let Ok(link_guard) = link.lock() {
        let is_incoming = !link_guard.initiator;
        let link_id_hex = crate::hexrep(&link_guard.link_id, false);
        let strong = Arc::strong_count(&link);
        if let Ok(mut links) = RUNTIME_LINKS.lock() {
            crate::log(&format!("RUNTIME register link={} strong_count={} incoming={} total={}", link_id_hex, strong, is_incoming, links.len() + 1), crate::LOG_NOTICE, false, false);
            links.insert(link_guard.link_id.clone(), Arc::downgrade(&link));
        }
        drop(link_guard);
        // For incoming links, store a strong reference so the Weak doesn't expire
        if is_incoming {
            if let Ok(mut arcs) = INCOMING_LINK_ARCS.lock() {
                arcs.push(Arc::clone(&link));
            }
        }
        // Start link watchdog (establishment timeout, keepalive, stale detection)
        start_link_watchdog(Arc::clone(&link));
    }
}

pub fn unregister_runtime_link(link_id: &[u8]) {
    if let Ok(mut links) = RUNTIME_LINKS.lock() {
        let removed = links.remove(link_id).is_some();
        crate::log(&format!("RUNTIME unregister link={} removed={} remaining={}", crate::hexrep(link_id, false), removed, links.len()), crate::LOG_NOTICE, false, false);
    }
}

/// Returns (attached_interface, is_closed) for a link by its link_id.
/// Used by Transport::outbound to filter link packets to only the correct interface,
/// matching Python's `packet.destination.attached_interface` check.
pub fn get_link_outbound_info(link_id: &[u8]) -> Option<(Option<String>, bool)> {
    let links = RUNTIME_LINKS.lock().ok()?;
    let link = links.get(link_id)?.upgrade()?;
    let link_guard = link.lock().ok()?;
    Some((link_guard.attached_interface.clone(), link_guard.state == STATE_CLOSED))
}

pub fn dispatch_runtime_packet(packet: &Packet) -> bool {
    let destination_hash = match packet.destination_hash.as_ref() {
        Some(hash) => hash.clone(),
        None => return false,
    };
    crate::log(&format!("[LINK-DISPATCH] packet type={} ctx={} dst={}", packet.packet_type, packet.context, crate::hexrep(&destination_hash, false)), crate::LOG_DEBUG, false, false);

    let link = {
        let mut links = match RUNTIME_LINKS.lock() {
            Ok(links) => links,
            Err(_) => return false,
        };

        match links.get(&destination_hash).and_then(|w| w.upgrade()) {
            Some(link) => link,
            None => {
                links.remove(&destination_hash);
                return false;
            }
        }
    };

    let (handled, should_fire_link_established, should_fire_remote_identified) = if let Ok(mut link_guard) = link.lock() {
        let was_pending = link_guard.state != STATE_ACTIVE;
        let ok = link_guard.receive(packet).is_ok();
        let now_active = link_guard.state == STATE_ACTIVE;
        let fire = was_pending && now_active && !link_guard.initiator && link_guard.callbacks.link_established.is_some();
        let fire_remote = link_guard.pending_remote_identified;
        if fire_remote { link_guard.pending_remote_identified = false; }
        (ok, fire, fire_remote)
    } else {
        (false, false, false)
    };

    // Fire link_established callback OUTSIDE the lock so the callback
    // can re-lock the Arc and modify the link (set resource_strategy, etc.)
    if should_fire_link_established {
        if let Ok(mut link_guard) = link.lock() {
            if let Some(callback) = link_guard.callbacks.link_established.take() {
                drop(link_guard);
                callback(Arc::clone(&link));
            }
        }
    }

    // Fire remote_identified callback OUTSIDE the lock, passing the ORIGINAL
    // Arc so backchannel_links stores the same Arc as RUNTIME_LINKS (not a clone).
    if should_fire_remote_identified {
        if let Ok(link_guard) = link.lock() {
            let identity = link_guard.remote_identity.lock().ok().and_then(|r| r.clone());
            let callback = link_guard.callbacks.remote_identified.clone();
            drop(link_guard);
            if let (Some(identity), Some(callback)) = (identity, callback) {
                callback(Arc::clone(&link), identity);
            }
        }
    }

    handled
}

pub fn runtime_encrypt_for_destination(destination_hash: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let link = {
        let mut links = RUNTIME_LINKS
            .lock()
            .map_err(|_| "Runtime link registry lock poisoned".to_string())?;

        match links.get(destination_hash).and_then(|w| w.upgrade()) {
            Some(link) => link,
            None => {
                let known: Vec<String> = links.keys().map(|k| crate::hexrep(k, false)).collect();
                crate::log(&format!("RUNTIME encrypt FAILED: no link for {} known=[{}]", crate::hexrep(destination_hash, false), known.join(", ")), crate::LOG_ERROR, false, false);
                links.remove(destination_hash);
                return Err("No runtime link found for destination".to_string());
            }
        }
    };

    let link_guard = link
        .lock()
        .map_err(|_| "Runtime link lock poisoned".to_string())?;
    link_guard.encrypt(plaintext)
}

pub fn validate_runtime_proof_for_receipt(
    destination_hash: &[u8],
    proof: &[u8],
    receipt: &mut crate::packet::PacketReceipt,
) -> bool {
    let link = {
        let mut links = match RUNTIME_LINKS.lock() {
            Ok(links) => links,
            Err(_) => {
                crate::log("validate_runtime_proof: RUNTIME_LINKS lock poisoned", crate::LOG_ERROR, false, false);
                return false;
            }
        };

        match links.get(destination_hash).and_then(|w| w.upgrade()) {
            Some(link) => link,
            None => {
                crate::log(&format!("validate_runtime_proof: no link for {}",
                    crate::hexrep(destination_hash, false)), crate::LOG_DEBUG, false, false);
                links.remove(destination_hash);
                return false;
            }
        }
    };

    let proof_hash_hex = if proof.len() >= 32 {
        crate::hexrep(&proof[..32], false)
    } else {
        format!("<short:{}>" , proof.len())
    };

    let validated = if let Ok(link_guard) = link.lock() {
        let result = receipt.validate_link_proof(proof, &link_guard);
        if result {
            crate::log(&format!("validate_runtime_proof: MATCH proof_hash={} receipt_hash={} link={}",
                proof_hash_hex, crate::hexrep(&receipt.hash, false),
                crate::hexrep(&link_guard.link_id, false)), crate::LOG_NOTICE, false, false);
        }
        result
    } else {
        crate::log("validate_runtime_proof: link lock failed", crate::LOG_ERROR, false, false);
        false
    };

    validated
}

pub fn runtime_decrypt_for_destination(destination_hash: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let link = {
        let mut links = RUNTIME_LINKS
            .lock()
            .map_err(|_| "Runtime link registry lock poisoned".to_string())?;

        match links.get(destination_hash).and_then(|w| w.upgrade()) {
            Some(link) => link,
            None => {
                links.remove(destination_hash);
                return Err("No runtime link found for destination".to_string());
            }
        }
    };

    let link_guard = link
        .lock()
        .map_err(|_| "Runtime link lock poisoned".to_string())?;
    link_guard.decrypt(ciphertext)
}

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
    let signalling_value = (mtu as u32 & MTU_BYTEMASK) + ((((mode as u32) << 5) & MODE_BYTEMASK) << 16);
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
    let result = identity::truncated_hash(&hashable_part);
    result
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

/// Python RNS wire format for a REQUEST packet payload:
/// msgpack array [timestamp_f64, path_hash_16bytes, data_bytes]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequestPayload(f64, serde_bytes::ByteBuf, serde_bytes::ByteBuf);

/// Python RNS wire format for a RESPONSE packet payload:
/// msgpack array [request_id_16bytes, response_bytes]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResponsePayload(serde_bytes::ByteBuf, serde_bytes::ByteBuf);

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

/// Link watchdog thread — monitors link state and sends keepalives.
/// Matches Python's __watchdog_job.
pub fn start_link_watchdog(link: Arc<Mutex<Link>>) {
    let link_weak = Arc::downgrade(&link);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));

            let link_arc = match link_weak.upgrade() {
                Some(l) => l,
                None => break, // Link dropped
            };

            // Determine what action to take while holding the lock briefly
            enum WatchdogAction {
                Continue,
                Exit,
                SendKeepalive(Destination, Vec<u8>),
                Teardown,
            }

            let action = {
                let mut link_guard = match link_arc.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };

                if link_guard.state == STATE_CLOSED {
                    break;
                }

                if link_guard.watchdog_lock {
                    WatchdogAction::Continue
                } else {
                    match link_guard.state {
                        STATE_PENDING | STATE_HANDSHAKE => {
                            if let Some(request_time) = link_guard.request_time {
                                if now_seconds() >= request_time + link_guard.establishment_timeout {
                                    let state_name = if link_guard.state == STATE_PENDING { "PENDING" } else { "HANDSHAKE" };
                                    crate::log(&format!("Link establishment timed out ({}): {}", state_name, crate::hexrep(&link_guard.link_id, false)), crate::LOG_DEBUG, false, false);
                                    link_guard.state = STATE_CLOSED;
                                    link_guard.status = STATE_CLOSED;
                                    link_guard.teardown_reason = REASON_TIMEOUT;
                                    link_guard.link_closed();
                                    WatchdogAction::Exit
                                } else {
                                    WatchdogAction::Continue
                                }
                            } else {
                                WatchdogAction::Continue
                            }
                        }
                        STATE_ACTIVE => {
                            let activated_at = link_guard.activated_at.unwrap_or(0);
                            let last_inbound = link_guard.last_inbound
                                .max(link_guard.last_proof)
                                .max(activated_at);
                            let now = current_time().unwrap_or(0);
                            let keepalive_secs = link_guard.keepalive as u64;

                            if now >= last_inbound + keepalive_secs {
                                // Check stale first
                                let stale_secs = link_guard.stale_time as u64;
                                if now >= last_inbound + stale_secs {
                                    link_guard.state = STATE_STALE;
                                    link_guard.status = STATE_STALE;
                                    WatchdogAction::Teardown
                                } else if link_guard.initiator && now >= link_guard.last_keepalive + keepalive_secs {
                                    // Send keepalive (initiator only)
                                    if let Some(info) = link_guard.prepare_keepalive() {
                                        WatchdogAction::SendKeepalive(info.0, info.1)
                                    } else {
                                        WatchdogAction::Continue
                                    }
                                } else {
                                    WatchdogAction::Continue
                                }
                            } else {
                                WatchdogAction::Continue
                            }
                        }
                        STATE_STALE => {
                            WatchdogAction::Teardown
                        }
                        _ => WatchdogAction::Continue,
                    }
                }
            };

            match action {
                WatchdogAction::Exit => break,
                WatchdogAction::SendKeepalive(dest, _link_id) => {
                    let mut keepalive_packet = Packet::new(
                        Some(dest),
                        vec![0xFF],
                        DATA,
                        crate::packet::KEEPALIVE,
                        crate::transport::BROADCAST,
                        packet::HEADER_1,
                        None,
                        None,
                        false,
                        0,
                    );
                    let _ = keepalive_packet.send();
                }
                WatchdogAction::Teardown => {
                    if let Ok(mut link_guard) = link_arc.lock() {
                        crate::log(&format!("Link timeout, tearing down {}", crate::hexrep(&link_guard.link_id, false)), crate::LOG_DEBUG, false, false);
                        link_guard.teardown();
                    }
                    break;
                }
                WatchdogAction::Continue => {}
            }
        }
    });
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
    pub request_time: Option<f64>,
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
    
    /// Flag set by handle_linkidentify_packet so dispatch_runtime_packet
    /// can fire the remote_identified callback OUTSIDE the link lock,
    /// passing the original Arc (not a clone).
    pub pending_remote_identified: bool,
    
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
            pending_remote_identified: false,
            channel: self.channel.clone(),
        }
    }
}

impl Link {
    fn set_link_id_from_packet(&mut self, packet: &Packet) {
        self.link_id = link_id_from_lr_packet(packet);
    }

    /// Validate an incoming link request and create a Link if valid.
    /// This is the receiver-side counterpart to `initiate()`.
    pub fn validate_request(owner: &Destination, data: &[u8], packet: &Packet) -> Result<Link, String> {
        if data.len() != ECPUBSIZE && data.len() != ECPUBSIZE + LINK_MTU_SIZE {
            return Err(format!("Invalid link request data length: {} (expected {} or {})", data.len(), ECPUBSIZE, ECPUBSIZE + LINK_MTU_SIZE));
        }


        // Extract peer's public keys
        let peer_pub_bytes = data[..ECPUBSIZE / 2].to_vec();         // X25519 (32 bytes)
        let peer_sig_pub_bytes = data[ECPUBSIZE / 2..ECPUBSIZE].to_vec(); // Ed25519 (32 bytes)

        // Create inbound link
        let mut link = Link::new_inbound(owner.clone())?;
        link.load_peer(peer_pub_bytes, peer_sig_pub_bytes)?;

        // Copy the destination's link_established callback to the link so it fires
        // when LRRTT arrives and the link activates
        if let Some(cb) = &owner.callbacks.link_established {
            link.callbacks.link_established = Some(Arc::clone(cb));
        }

        // Set link_id from packet
        link.set_link_id_from_packet(packet);

        // Parse MTU and mode from signalling bytes
        if data.len() == ECPUBSIZE + LINK_MTU_SIZE {
            if let Some(mtu) = mtu_from_lr_packet(data) {
                link.mtu = mtu;
            }
        }
        link.mode = mode_from_lr_packet(data);
        link.update_mdu();

        link.establishment_timeout = ESTABLISHMENT_TIMEOUT_PER_HOP * (packet.hops.max(1) as f64) + KEEPALIVE;
        link.establishment_cost += packet.raw.len();

        // Generate our ephemeral X25519 keypair
        let mut x25519_private = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut x25519_private);
        let x25519_public = X25519PublicKey::from(&X25519PrivateKey::from(x25519_private));

        link.prv_bytes = Some(x25519_private.to_vec());
        link.pub_bytes = Some(x25519_public.as_bytes().to_vec());

        // For incoming links, use the destination's Ed25519 signing key (not ephemeral)
        let identity = owner.identity.as_ref().ok_or("Destination has no identity for link proof")?;
        let public_key = identity.get_public_key()?;
        if public_key.len() != 64 {
            return Err("Invalid destination public key length".to_string());
        }
        // sig_pub_bytes = Ed25519 public key (second 32 bytes of the 64-byte public key)
        link.sig_pub_bytes = Some(public_key[32..64].to_vec());

        // Store the Ed25519 signing private key so we can prove received packets later
        let private_key = identity.get_private_key()?;
        if private_key.len() >= 64 {
            link.sig_prv_bytes = Some(private_key[32..64].to_vec());
        }

        // Perform ECDH handshake
        link.handshake()?;

        link.attached_interface = packet.receiving_interface.clone();

        // Generate and send the link proof
        link.prove_with_identity(identity)?;

        link.request_time = Some(now_seconds());
        link.had_inbound(true); // Initialize last_data/last_inbound before cloning

        // Register in Transport's active_links (incoming links go directly to active)
        crate::transport::Transport::register_link(link.clone());

        // Also register as runtime link so dispatch_runtime_packet can find it
        let link_arc = Arc::new(Mutex::new(link.clone()));
        register_runtime_link(Arc::clone(&link_arc));


        Ok(link)
    }

    pub fn initiate(&mut self) -> Result<(), String> {
        if !self.initiator {
            return Err("Cannot initiate inbound link".to_string());
        }

        let mut x25519_private = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut x25519_private);
        let x25519_public = X25519PublicKey::from(&X25519PrivateKey::from(x25519_private));

        let signing_identity = Identity::new(true);
        let signing_private = signing_identity.get_private_key()?;
        let signing_public = signing_identity.get_public_key()?;
        if signing_private.len() != 64 || signing_public.len() != 64 {
            return Err("Invalid generated key sizes for link initiation".to_string());
        }

        self.prv_bytes = Some(x25519_private.to_vec());
        self.pub_bytes = Some(x25519_public.as_bytes().to_vec());
        self.sig_prv_bytes = Some(signing_private[32..64].to_vec());
        self.sig_pub_bytes = Some(signing_public[32..64].to_vec());

        let mut request_data = self.pub_bytes.clone().ok_or("Missing link public key")?;
        request_data.extend_from_slice(&self.sig_pub_bytes.clone().ok_or("Missing link signing public key")?);
        request_data.extend_from_slice(&signalling_bytes(reticulum::MTU, self.mode)?);

        let destination = self.destination.lock().map_err(|_| "Destination lock poisoned")?.clone();

        // Calculate establishment timeout based on hops and first hop latency (matches Python Link.__init__)
        let dest_hash = destination.hash.clone();
        let hops = crate::transport::Transport::hops_to(&dest_hash);
        let first_hop_timeout = if let Some(ret) = reticulum::Reticulum::get_instance() {
            if let Ok(ret_guard) = ret.lock() {
                ret_guard.get_first_hop_timeout(&dest_hash)
            } else {
                crate::transport::Transport::first_hop_timeout(&dest_hash)
            }
        } else {
            crate::transport::Transport::first_hop_timeout(&dest_hash)
        };
        self.establishment_timeout = first_hop_timeout + ESTABLISHMENT_TIMEOUT_PER_HOP * (hops.max(1) as f64);
        self.expected_hops = Some(hops as usize);
        crate::log(
            &format!(
                "Link establishment timeout {:.1}s (first_hop={:.1}s, hops={}, per_hop={:.1}s)",
                self.establishment_timeout, first_hop_timeout, hops, ESTABLISHMENT_TIMEOUT_PER_HOP
            ),
            crate::LOG_NOTICE,
            false,
            false,
        );

        let mut packet = Packet::new(
            Some(destination),
            request_data,
            packet::LINKREQUEST,
            packet::NONE,
            crate::transport::BROADCAST,
            packet::HEADER_1,
            None,
            None,
            false,
            0,
        );

        packet.pack()?;
        self.establishment_cost += packet.raw.len();
        self.set_link_id_from_packet(&packet);
        self.request_time = Some(now_seconds());

        crate::transport::Transport::register_link(self.clone());
        packet.send()?;
        self.had_outbound(false);

        Ok(())
    }

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
            request_time: Some(now_seconds()),
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
            pending_remote_identified: false,
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
            request_time: Some(now_seconds()),
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
            pending_remote_identified: false,
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
    
    /// Sign data with link's signing key (Ed25519)
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let sig_prv = self.sig_prv_bytes.as_ref().ok_or("Signing private key not available")?;
        let sig_pub = self.sig_pub_bytes.as_ref().ok_or("Signing public key not available")?;
        if sig_prv.len() != 32 || sig_pub.len() != 32 {
            return Err(format!("Invalid signing key lengths: prv={} pub={}", sig_prv.len(), sig_pub.len()));
        }

        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[..32].copy_from_slice(sig_prv);
        keypair_bytes[32..].copy_from_slice(sig_pub);
        let keypair = ed25519_dalek::Keypair::from_bytes(&keypair_bytes)
            .map_err(|e| format!("Failed to construct keypair: {}", e))?;
        let signature = keypair.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Prove a received packet by signing its hash and sending a PROOF packet
    /// back to the sender via this link.
    pub fn prove_packet(&self, packet: &Packet) -> Result<(), String> {
        let packet_hash = packet.get_hash();
        let signature = self.sign(&packet_hash)?;

        let mut proof_data = packet_hash.clone();
        proof_data.extend_from_slice(&signature);

        crate::log(&format!("prove_packet hash={} link={} proof_len={} iface={:?}",
            crate::hexrep(&packet_hash, false),
            crate::hexrep(&self.link_id, false),
            proof_data.len(),
            self.attached_interface), crate::LOG_NOTICE, false, false);

        let link_destination = {
            let dest = self.destination.lock()
                .map_err(|_| "Destination lock poisoned")?;
            let mut ld = dest.clone();
            ld.dest_type = crate::destination::DestinationType::Link;
            ld.hash = self.link_id.clone();
            ld.hexhash = crate::hexrep(&ld.hash, false);
            // ── FIX: PROOF INTERFACE ROUTING ───────────────────────────────────────
            // DO NOT REMOVE THE ld.link = Some(...) ASSIGNMENT BELOW.
            //
            // Bug (pre-fix): prove_packet() left ld.link as None, so
            // Transport::outbound() broadcast the 96-byte PROOF packet on ALL
            // interfaces instead of routing it only through the link's own
            // attached interface.  The receiving peer never saw the proof on the
            // correct interface, so delivery receipts never fired.
            //
            // Fix: populate ld.link with a LinkInfo that carries attached_interface.
            // Transport::outbound() checks link.attached_interface and sends only
            // via that interface, matching Python's Packet.prove() behaviour.
            // ────────────────────────────────────────────────────────────────────────
            ld.link = Some(crate::destination::LinkInfo {
                rtt: self.rtt,
                traffic_timeout_factor: crate::link::TRAFFIC_TIMEOUT_FACTOR,
                status_closed: self.state == crate::link::STATE_CLOSED,
                mtu: Some(self.mtu),
                attached_interface: self.attached_interface.clone(),
            });
            ld
        };

        let mut proof_packet = Packet::new(
            Some(link_destination),
            proof_data,
            PROOF,
            packet::NONE,
            crate::transport::BROADCAST,
            packet::HEADER_1,
            None,
            None,
            false,
            0,
        );
        proof_packet.send()?;
        Ok(())
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

    /// Send link proof using the destination's identity for signing, and actually dispatch the packet
    pub fn prove_with_identity(&mut self, identity: &Identity) -> Result<(), String> {
        let sig_bytes = signalling_bytes(self.mtu, self.mode)?;

        let mut signed_data = self.link_id.clone();
        if let Some(pub_bytes) = &self.pub_bytes {
            signed_data.extend_from_slice(pub_bytes);
        } else {
            return Err("Own public key not available for proof".to_string());
        }
        if let Some(sig_pub_bytes) = &self.sig_pub_bytes {
            signed_data.extend_from_slice(sig_pub_bytes);
        } else {
            return Err("Own signing public key not available for proof".to_string());
        }
        signed_data.extend_from_slice(&sig_bytes);

        // Sign with the destination's identity Ed25519 key
        let signature = identity.sign(&signed_data);

        let mut proof_data = signature;
        if let Some(pub_bytes) = &self.pub_bytes {
            proof_data.extend_from_slice(pub_bytes);
        }
        proof_data.extend_from_slice(&sig_bytes);


        // Create a Link destination with dest_type=Link and hash=link_id for the proof packet
        let mut link_destination = self.destination.lock()
            .map_err(|_| "Destination lock poisoned")?
            .clone();
        link_destination.dest_type = DestinationType::Link;
        link_destination.hash = self.link_id.clone();
        link_destination.hexhash = crate::hexrep(&link_destination.hash, false);

        // Create and send the proof packet
        let mut proof_packet = Packet::new(
            Some(link_destination),
            proof_data,
            PROOF,
            packet::LRPROOF,
            crate::transport::BROADCAST,
            packet::HEADER_1,
            None,
            None,
            false,
            0,
        );
        proof_packet.send()?;

        self.last_proof = current_time().unwrap_or(0);
        self.establishment_cost += proof_packet.raw.len();

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
        crate::log(&format!("LINK teardown link={} state={}", crate::hexrep(&self.link_id, false), self.state), crate::LOG_NOTICE, false, false);
        if self.state != STATE_CLOSED && self.state != STATE_PENDING {
            // Send teardown packet
        }
        self.state = STATE_CLOSED;
        self.status = STATE_CLOSED;
        unregister_runtime_link(&self.link_id);
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
            self.had_inbound(packet.packet_type == DATA);
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
                    if let Err(err) = self.handle_proof_packet(packet) {
						return Err(err);
					}
                }
                _ => {}
            }
        }
        
        self.watchdog_lock = false;
        Ok(())
    }
    
    /// Handle DATA packets
    fn handle_data_packet(&mut self, packet: &Packet) -> Result<(), String> {
        crate::log(&format!("[HDR] context=0x{:02x} data_len={} link={}",
            packet.context, packet.data.len(),
            crate::hexrep(&self.link_id, false)), crate::LOG_NOTICE, false, false);

        if packet.context == crate::packet::RESOURCE {
            let mut deferred_actions: Vec<(Arc<Mutex<Resource>>, bool, bool)> = Vec::new();
            if let Ok(resources) = self.incoming_resources.lock() {
                for resource in resources.iter() {
                    if let Ok(mut resource_guard) = resource.lock() {
                        let (needs_request_next, needs_start_watchdog) = resource_guard.receive_part(packet);
                        if needs_request_next || needs_start_watchdog {
                            deferred_actions.push((resource.clone(), needs_request_next, needs_start_watchdog));
                        }
                    }
                }
            }
            // Defer request_next and start_watchdog to background threads.
            // These need the link for encryption, and the link lock is currently
            // held by dispatch_runtime_packet — calling them inline would deadlock.
            for (resource_arc, needs_request_next, needs_start_watchdog) in deferred_actions {
                if needs_start_watchdog {
                    Resource::start_watchdog(resource_arc.clone());
                }
                if needs_request_next {
                    let r = resource_arc.clone();
                    std::thread::spawn(move || {
                        // Brief delay so the caller can release the link lock.
                        // Without this, the deferred thread would immediately
                        // contend on the link lock that the TCP reader still holds.
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        // Phase 1: Lock resource, prepare packet, then RELEASE lock
                        let maybe_packet = match r.lock() {
                            Ok(mut guard) => {
                                guard.prepare_request_next()
                            }
                            Err(e) => {
                                crate::log(&format!("Resource lock poisoned in deferred REQ: {}", e), crate::LOG_ERROR, false, false);
                                None
                            }
                        };
                        // Phase 2: Send packet WITHOUT holding resource lock (avoids deadlock with dispatch_runtime_packet)
                        if let Some(mut packet) = maybe_packet {
                            match packet.send() {
                                Ok(_) => {
                                    // Phase 3: Re-lock resource to record success
                                    if let Ok(mut guard) = r.lock() {
                                        guard.record_request_sent(packet.raw.len());
                                    }
                                }
                                Err(e) => {
                                    crate::log(&format!("Deferred REQ send failed: {}", e), crate::LOG_ERROR, false, false);
                                    if let Ok(mut guard) = r.lock() {
                                        guard.cancel();
                                    }
                                }
                            }
                        }
                    });
                }
            }
            return Ok(());
        }

        if packet.context == crate::packet::RESOURCE_ADV {
            let plaintext = match self.decrypt(&packet.data) {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    crate::log(&format!("[RESP-RES] RESOURCE_ADV decrypt failed: {}", e), crate::LOG_NOTICE, false, false);
                    return Ok(());
                }
            };

            let mut advertisement_packet = packet.clone();
            advertisement_packet.plaintext = Some(plaintext);

            let is_req = crate::resource::ResourceAdvertisement::is_request(&advertisement_packet);
            let is_resp = crate::resource::ResourceAdvertisement::is_response(&advertisement_packet);
            crate::log(&format!("[RESP-RES] RESOURCE_ADV is_request={} is_response={}",
                is_req, is_resp), crate::LOG_NOTICE, false, false);

            if is_req {
                if let Some(resource) = Resource::accept(
                    &advertisement_packet,
                    Arc::new(Mutex::new(self.clone())),
                    self.callbacks.resource_concluded.clone(),
                    None,
                    crate::resource::ResourceAdvertisement::read_request_id(&advertisement_packet),
                ) {
                    // Register on real link so RESOURCE data packets find it
                    self.register_incoming_resource(resource);
                }
                return Ok(());
            }

            if is_resp {
                let request_id_opt = crate::resource::ResourceAdvertisement::read_request_id(&advertisement_packet);
                crate::log(&format!(
                    "[RESP-RES] incoming response resource, request_id={}",
                    request_id_opt.as_ref().map(|id| crate::hexrep(id, false)).unwrap_or_else(|| "None".to_string())
                ), crate::LOG_NOTICE, false, false);

                // Build a per-request concluded callback so that when the resource is fully
                // assembled we can route the data to the correct pending request callback.
                // Python RNS encodes response resources as msgpack([request_id_bytes, response_value])
                // — identical to the direct RESPONSE packet plaintext format.
                let pending_requests = Arc::clone(&self.pending_requests);
                let link_arc = Arc::new(Mutex::new(self.clone()));
                let concluded_callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>> =
                    Some(Arc::new(move |resource: Arc<Mutex<Resource>>| {
                        let (data_opt, res_request_id_opt) = {
                            let res = resource.lock().unwrap();
                            (res.data.clone(), res.request_id.clone())
                        };
                        crate::log(&format!(
                            "[RESP-RES] concluded, data_len={:?}, res_request_id={}",
                            data_opt.as_ref().map(|d| d.len()),
                            res_request_id_opt.as_ref().map(|id| crate::hexrep(id, false)).unwrap_or_else(|| "None".to_string())
                        ), crate::LOG_NOTICE, false, false);

                        let data = match data_opt {
                            Some(d) => d,
                            None => {
                                crate::log("[RESP-RES] concluded but data is None", crate::LOG_NOTICE, false, false);
                                return;
                            }
                        };

                        // Parse msgpack([request_id_bytes, response_value]) — same as direct RESPONSE format.
                        let parsed = rmpv_read_value(&mut std::io::Cursor::new(&data));
                        let (request_id, response_bytes) = match parsed {
                            Ok(rmpv::Value::Array(elements)) if elements.len() >= 2 => {
                                match &elements[0] {
                                    rmpv::Value::Binary(b) => {
                                        let rid = b.clone();
                                        let mut rb = Vec::new();
                                        if rmpv_write_value(&mut rb, &elements[1]).is_ok() {
                                            (rid, rb)
                                        } else {
                                            crate::log("[RESP-RES] failed to re-encode response value", crate::LOG_NOTICE, false, false);
                                            return;
                                        }
                                    }
                                    _ => match res_request_id_opt {
                                        Some(rid) => (rid, data),
                                        None => { crate::log("[RESP-RES] no request_id (non-binary elements[0])", crate::LOG_NOTICE, false, false); return; }
                                    }
                                }
                            }
                            _ => match res_request_id_opt {
                                Some(rid) => (rid, data),
                                None => { crate::log("[RESP-RES] no request_id (non-array data)", crate::LOG_NOTICE, false, false); return; }
                            }
                        };

                        let mut pending = match pending_requests.lock() {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        crate::log(&format!(
                            "[RESP-RES] pending_requests count={}, looking for id={}",
                            pending.len(), crate::hexrep(&request_id, false)
                        ), crate::LOG_NOTICE, false, false);

                        if let Some(index) = pending.iter().position(|p| p.request_id == request_id) {
                            crate::log("[RESP-RES] found pending request, spawning callback thread", crate::LOG_NOTICE, false, false);
                            let request = pending.remove(index);
                            let receipt = RequestReceipt {
                                request_id: request_id.clone(),
                                response: Some(response_bytes),
                                link: Arc::clone(&link_arc),
                                sent_at: request.sent_at,
                                received_at: Some(current_time().unwrap_or(0) as f64),
                                progress: 1.0,
                            };
                            if let Some(callback) = request.response_callback {
                                thread::spawn(move || { callback(receipt); });
                            }
                        } else {
                            crate::log(&format!(
                                "[RESP-RES] NO matching pending request for id={}",
                                crate::hexrep(&request_id, false)
                            ), crate::LOG_NOTICE, false, false);
                        }
                    }));

                if let Some(resource) = Resource::accept(
                    &advertisement_packet,
                    Arc::new(Mutex::new(self.clone())),
                    concluded_callback,
                    None,
                    request_id_opt,
                ) {
                    self.register_incoming_resource(resource);
                }
                return Ok(());
            }

            match self.resource_strategy {
                ACCEPT_NONE => {
                }
                ACCEPT_APP => {
                    if let Some(resource) = Resource::accept(
                        &advertisement_packet,
                        Arc::new(Mutex::new(self.clone())),
                        self.callbacks.resource_concluded.clone(),
                        None,
                        None,
                    ) {
                        // Register on real link so RESOURCE data packets find it
                        self.register_incoming_resource(resource.clone());
                        if let Some(callback) = &self.callbacks.resource {
                            callback(resource);
                        }
                    } else {
                        Resource::reject(&advertisement_packet);
                    }
                }
                ACCEPT_ALL => {
                    if let Some(resource) = Resource::accept(
                        &advertisement_packet,
                        Arc::new(Mutex::new(self.clone())),
                        self.callbacks.resource_concluded.clone(),
                        None,
                        None,
                    ) {
                        self.register_incoming_resource(resource);
                    }
                }
                _ => {}
            }

            return Ok(());
        }

        if packet.context == crate::packet::LRRTT {
            // LRRTT packets are encrypted over the link, decrypt first
            let plaintext = match self.decrypt(&packet.data) {
                Ok(pt) => pt,
                Err(_) => {
                    return Ok(());
                }
            };
            self.handle_lrrtt_packet(&plaintext)?;
            return Ok(());
        }

        let plaintext = match self.decrypt(&packet.data) {
            Ok(plaintext) => {
                plaintext
            },
            Err(_) => {
                return Ok(());
            },
        };

        if packet.context == crate::packet::REQUEST {
            let request_id = packet.get_truncated_hash();
            self.handle_request_packet(request_id, &plaintext)?;
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

        if packet.context == crate::packet::LINKCLOSE {
            crate::log(&format!("[LINK] LINKCLOSE received on link={}", crate::hexrep(&self.link_id, false)), crate::LOG_NOTICE, false, false);
            self.teardown();
            return Ok(());
        }

        if packet.context == crate::packet::RESOURCE_REQ {
            let hash_len = identity::HASHLENGTH / 8;
            if plaintext.len() >= 1 + hash_len {
                let offset = if plaintext[0] == crate::resource::Resource::HASHMAP_IS_EXHAUSTED {
                    1 + crate::resource::Resource::MAPHASH_LEN
                } else {
                    1
                };
                if plaintext.len() >= offset + hash_len {
                    let resource_hash = plaintext[offset..offset + hash_len].to_vec();
                    let packet_hash = packet.packet_hash.clone();
                    // Clone the list of outgoing resource Arcs WITHOUT locking
                    // individual resources.  We must NOT lock any resource while
                    // the link lock is held — request() sends RESOURCE_HMU
                    // packets whose encrypt path needs the link lock, creating
                    // an AB-BA deadlock (link→resource vs resource→link).
                    let resources: Vec<Arc<Mutex<Resource>>> = if let Ok(resources) = self.outgoing_resources.lock() {
                        resources.clone()
                    } else {
                        Vec::new()
                    };
                    let pt = plaintext.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        // Find matching resource OUTSIDE the link lock
                        let mut target_resource: Option<Arc<Mutex<Resource>>> = None;
                        for resource in resources.iter() {
                            if let Ok(guard) = resource.lock() {
                                if guard.hash == resource_hash.as_slice() {
                                    target_resource = Some(resource.clone());
                                    break;
                                }
                            }
                        }
                        if let Some(resource_arc) = target_resource {
                            if let Ok(mut guard) = resource_arc.lock() {
                                if let Some(req_hash) = packet_hash.as_ref() {
                                    if !guard.req_hashlist.iter().any(|h| h == req_hash) {
                                        guard.req_hashlist.push(req_hash.clone());
                                        if guard.req_hashlist.len() > 64 {
                                            let drop_count = guard.req_hashlist.len().saturating_sub(64);
                                            guard.req_hashlist.drain(0..drop_count);
                                        }
                                    }
                                }
                                guard.request(&pt);
                            }
                        }
                    });
                }
            }
            return Ok(());
        }

        if packet.context == crate::packet::RESOURCE_HMU {
            let hash_len = identity::HASHLENGTH / 8;
            if plaintext.len() >= hash_len {
                let resource_hash = &plaintext[..hash_len];
                let mut needs_request_next: Option<Arc<Mutex<Resource>>> = None;
                if let Ok(mut resources) = self.incoming_resources.lock() {
                    for resource in resources.iter_mut() {
                        if let Ok(mut resource_guard) = resource.lock() {
                            if resource_guard.hash == resource_hash {
                                if resource_guard.hashmap_update_packet(&plaintext) {
                                    needs_request_next = Some(resource.clone());
                                }
                            }
                        }
                    }
                }
                // Defer request_next to a background thread — we're inside
                // the link mutex and request_next needs to encrypt via
                // the same link, which would deadlock.
                if let Some(r) = needs_request_next {
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        // Phase 1: Lock resource, prepare packet, then RELEASE lock
                        let maybe_packet = match r.lock() {
                            Ok(mut guard) => {
                                guard.prepare_request_next()
                            }
                            Err(e) => {
                                crate::log(&format!("Resource lock poisoned in deferred HMU REQ: {}", e), crate::LOG_ERROR, false, false);
                                None
                            }
                        };
                        // Phase 2: Send packet WITHOUT holding resource lock
                        if let Some(mut packet) = maybe_packet {
                            match packet.send() {
                                Ok(_) => {
                                    if let Ok(mut guard) = r.lock() {
                                        guard.record_request_sent(packet.raw.len());
                                    }
                                }
                                Err(e) => {
                                    crate::log(&format!("Deferred HMU REQ send failed: {}", e), crate::LOG_ERROR, false, false);
                                    if let Ok(mut guard) = r.lock() {
                                        guard.cancel();
                                    }
                                }
                            }
                        }
                    });
                }
            }
            return Ok(());
        }

        if packet.context == crate::packet::RESOURCE_ICL {
            let hash_len = identity::HASHLENGTH / 8;
            if plaintext.len() >= hash_len {
                let resource_hash = plaintext[..hash_len].to_vec();
                // Clone the incoming resource list without locking individual
                // resources — avoids deadlock with deferred request_next threads
                // that hold the resource lock and need the link lock to send.
                let resources: Vec<Arc<Mutex<Resource>>> = if let Ok(resources) = self.incoming_resources.lock() {
                    resources.clone()
                } else {
                    Vec::new()
                };
                std::thread::spawn(move || {
                    for resource in resources.iter() {
                        if let Ok(mut resource_guard) = resource.lock() {
                            if resource_guard.hash == resource_hash.as_slice() {
                                resource_guard.cancel();
                            }
                        }
                    }
                });
            }
            return Ok(());
        }

        if packet.context == crate::packet::RESOURCE_RCL {
            let hash_len = identity::HASHLENGTH / 8;
            if plaintext.len() >= hash_len {
                let resource_hash = plaintext[..hash_len].to_vec();
                // Clone without locking individual resources — same deadlock
                // avoidance as RESOURCE_REQ handler.
                let resources: Vec<Arc<Mutex<Resource>>> = if let Ok(resources) = self.outgoing_resources.lock() {
                    resources.clone()
                } else {
                    Vec::new()
                };
                std::thread::spawn(move || {
                    for resource in resources.iter() {
                        if let Ok(mut resource_guard) = resource.lock() {
                            if resource_guard.hash == resource_hash.as_slice() {
                                resource_guard.rejected();
                            }
                        }
                    }
                });
            }
            return Ok(());
        }

        if let Some(callback) = &self.callbacks.packet {
            // Prove the packet (sign hash and send PROOF back to sender)
            let _ = self.prove_packet(packet);
            callback(&plaintext, packet);
        }
        
        Ok(())
    }

    fn handle_lrrtt_packet(&mut self, plaintext: &[u8]) -> Result<(), String> {
        if self.initiator {
            return Ok(());
        }

        let measured_rtt = self
            .request_time
            .map(|requested| (now_seconds() - requested).max(0.001))
            .unwrap_or(0.0);

        let peer_rtt: f64 = from_slice(plaintext).map_err(|e| format!("Invalid LRRTT payload: {}", e))?;
        self.rtt = Some(measured_rtt.max(peer_rtt));
        self.status = STATE_ACTIVE;
        self.state = STATE_ACTIVE;
        self.activated_at = current_time();
        self.update_keepalive();


        // NOTE: We do NOT fire the link_established callback here because we
        // are inside a Mutex lock. The callback would receive a clone Arc
        // and modifications wouldn't affect the real link. Instead,
        // dispatch_runtime_packet handles this after the lock is released.

        Ok(())
    }

    fn handle_request_packet(&mut self, request_id: Vec<u8>, plaintext: &[u8]) -> Result<(), String> {
        crate::log(&format!("[REQ] handle_request_packet: request_id={} plaintext_len={}", crate::hexrep(&request_id, false), plaintext.len()), crate::LOG_NOTICE, false, false);
        // Python RNS wire format: msgpack array [timestamp_f64, path_hash_bytes, data_any]
        // The third element (data) can be ANY msgpack type (bytes, array, nil, etc.)
        // so we must use rmpv to parse the outer array generically.
        let outer = match rmpv_read_value(&mut std::io::Cursor::new(plaintext)) {
            Ok(rmpv::Value::Array(arr)) if arr.len() >= 3 => arr,
            Ok(_) => {
                crate::log("[REQ] msgpack not a 3-element array", crate::LOG_ERROR, false, false);
                return Ok(());
            }
            Err(e) => {
                crate::log(&format!("[REQ] msgpack parse FAILED: {}", e), crate::LOG_ERROR, false, false);
                return Ok(());
            }
        };

        let timestamp = match &outer[0] {
            rmpv::Value::F64(f) => *f,
            rmpv::Value::F32(f) => *f as f64,
            rmpv::Value::Integer(i) => i.as_f64().unwrap_or(0.0),
            _ => 0.0,
        };

        let path_hash: Vec<u8> = match &outer[1] {
            rmpv::Value::Binary(b) => b.clone(),
            _ => {
                crate::log("[REQ] path_hash is not binary", crate::LOG_ERROR, false, false);
                return Ok(());
            }
        };

        // Re-serialize the data element back to msgpack bytes for the handler
        let request_data = {
            let mut buf = Vec::new();
            rmpv_write_value(&mut buf, &outer[2]).map_err(|e| e.to_string())?;
            buf
        };
        crate::log(&format!("[REQ] path_hash={} request_data_len={} timestamp={}", crate::hexrep(&path_hash, false), request_data.len(), timestamp), crate::LOG_NOTICE, false, false);

        let handler = {
            let dest = self.destination.lock().map_err(|_| "Destination lock poisoned")?;
            let h = dest.request_handlers.get(&path_hash).cloned();
            if h.is_none() {
                let registered: Vec<String> = dest.request_handlers.keys().map(|k| crate::hexrep(k, false)).collect();
                crate::log(&format!("[REQ] NO handler for path_hash={}, registered={:?}", crate::hexrep(&path_hash, false), registered), crate::LOG_ERROR, false, false);
            }
            h
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
                crate::log(&format!("[REQ] request denied for path '{}' (not allowed)", handler.path), crate::LOG_NOTICE, false, false);
                Vec::new()
            } else if let Some(callback) = handler.callback {
                let path_hex = crate::hexrep(&path_hash, false);
                callback(
                    &path_hex,
                    &request_data,
                    &request_id,
                    remote_identity_ref,
                    timestamp,
                )
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Python RNS response wire format: msgpack array [request_id_bytes, response_value]
        // CRITICAL: The response must be encoded as [Binary(request_id), <native_msgpack_value>]
        // where the response value is embedded as its native msgpack type (array, int, nil, etc.)
        // NOT wrapped in a Binary container. Our handler returns pre-encoded msgpack bytes,
        // so we build the outer array manually: write array header, write request_id as Binary,
        // then append the raw response bytes directly (they are already valid msgpack).
        crate::log(&format!("[REQ] handler returned {} bytes, building response", response.len()), crate::LOG_NOTICE, false, false);
        let mut response_data = Vec::new();
        // 2-element array header
        rmp::encode::write_array_len(&mut response_data, 2).map_err(|e| e.to_string())?;
        // First element: request_id as Binary
        rmp::encode::write_bin(&mut response_data, &request_id).map_err(|e| e.to_string())?;
        // Second element: raw msgpack response value (already encoded by handler)
        response_data.extend_from_slice(&response);
        crate::log(&format!("[REQ] response_data (msgpack) {} bytes: {:02x?}", response_data.len(), &response_data[..response_data.len().min(64)]), crate::LOG_NOTICE, false, false);

        // Encrypt directly via self (we already hold the link lock, so we MUST NOT
        // go through runtime_encrypt_for_destination which would try to re-acquire
        // the same mutex → deadlock).
        let ciphertext = match self.encrypt(&response_data) {
            Ok(ct) => ct,
            Err(e) => {
                crate::log(&format!("[REQ] encrypt FAILED: {}", e), crate::LOG_ERROR, false, false);
                return Ok(());
            }
        };

        // Build wire bytes manually: [flags(1), hops(1), link_id(16), context(1), ciphertext]
        // flags = HEADER_1(0)<<6 | BROADCAST(0)<<4 | Link(3)<<2 | DATA(0) = 0x0C
        let flags: u8 = (DestinationType::Link as u8) << 2;
        let mut raw = vec![flags, 0u8]; // flags, hops=0
        raw.extend_from_slice(&self.link_id);
        raw.push(crate::packet::RESPONSE);
        raw.extend_from_slice(&ciphertext);

        // Send directly on the link's attached interface (no need to acquire link lock again).
        // Using dispatch_outbound bypasses Packet::pack()'s encryption which would deadlock.
        let sent = if let Some(ref iface) = self.attached_interface {
            crate::transport::Transport::dispatch_outbound(iface, &raw)
        } else {
            crate::log("[REQ] NO attached_interface!", crate::LOG_ERROR, false, false);
            false
        };

        if !sent {
            crate::log("[REQ] dispatch_outbound FAILED - response not sent!", crate::LOG_ERROR, false, false);
        } else {
            crate::log(&format!("[REQ] response SENT: {} bytes on wire (ciphertext={} bytes)", raw.len(), ciphertext.len()), crate::LOG_NOTICE, false, false);
        }

        self.had_outbound(false);
        Ok(())
    }

    fn handle_response_packet(&mut self, plaintext: &[u8]) -> Result<(), String> {
        // Python RNS wire format: msgpack array [request_id_bytes, response_value]
        // The response_value can be any msgpack type (integer error code, list, bytes)
        // so we must NOT decode it as ByteBuf — use rmpv to read the outer array.
        crate::log(&format!("[RESP] handle_response_packet: {} bytes plaintext", plaintext.len()), crate::LOG_NOTICE, false, false);
        let outer = match rmpv_read_value(&mut std::io::Cursor::new(plaintext)) {
            Ok(v) => v,
            Err(e) => {
                crate::log(&format!("[RESP] rmpv_read_value failed: {}", e), crate::LOG_NOTICE, false, false);
                return Ok(());
            }
        };
        let elements = match outer {
            rmpv::Value::Array(v) if v.len() >= 2 => v,
            ref other => {
                crate::log(&format!("[RESP] outer value is not Array(>=2): {:?}", other), crate::LOG_NOTICE, false, false);
                return Ok(());
            }
        };
        let request_id: Vec<u8> = match &elements[0] {
            rmpv::Value::Binary(b) => b.clone(),
            other => {
                crate::log(&format!("[RESP] elements[0] is not Binary: {:?}", other), crate::LOG_NOTICE, false, false);
                return Ok(());
            }
        };
        crate::log(&format!("[RESP] response request_id={}", crate::hexrep(&request_id, false)), crate::LOG_NOTICE, false, false);
        // Re-encode the response value as raw msgpack bytes so callers can decode it.
        let mut response_bytes: Vec<u8> = Vec::new();
        if rmpv_write_value(&mut response_bytes, &elements[1]).is_err() {
            return Ok(());
        }

        let mut pending = self.pending_requests.lock().map_err(|_| "Pending request lock poisoned")?;
        crate::log(&format!("[RESP] pending_requests count={}, looking for id={}", pending.len(), crate::hexrep(&request_id, false)), crate::LOG_NOTICE, false, false);
        if let Some(index) = pending.iter().position(|p| p.request_id == request_id) {
            crate::log(&format!("[RESP] found pending request, spawning callback thread"), crate::LOG_NOTICE, false, false);
            let request = pending.remove(index);
            let receipt = RequestReceipt {
                request_id: request_id.clone(),
                response: Some(response_bytes),
                link: Arc::new(Mutex::new(self.clone())),
                sent_at: request.sent_at,
                received_at: Some(current_time().unwrap_or(0) as f64),
                progress: 1.0,
            };

            if let Some(callback) = request.response_callback {
                // Spawn a thread so the callback can re-lock the link
                // (e.g. for teardown) without deadlocking the TCP reader thread
                // that currently holds the link mutex.
                thread::spawn(move || { callback(receipt); });
            }
        } else {
            crate::log(&format!("[RESP] NO matching pending request found for id={}", crate::hexrep(&request_id, false)), crate::LOG_NOTICE, false, false);
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
        // Python RNS wire format: [timestamp_f64, path_hash_16bytes, data_bytes]
        let path_hash = identity::truncated_hash(path.as_bytes());
        let timestamp = current_time().unwrap_or(0) as f64;
        let payload = RequestPayload(
            timestamp,
            serde_bytes::ByteBuf::from(path_hash),
            serde_bytes::ByteBuf::from(data),
        );

        // Python wire format: msgpack.packb([timestamp_f64, path_hash_bytes, data])
        // where `data` is the VALUE itself — not double-encoded as bin.
        // We decode our pre-encoded `data` bytes back to an rmpv Value so we can
        // embed it inline in the outer array (matching Python's msgpack.packb behaviour).
        let data_value = rmpv_read_value(&mut std::io::Cursor::new(&payload.2.as_ref()))
            .unwrap_or(rmpv::Value::Nil);
        let outer_value = rmpv::Value::Array(vec![
            rmpv::Value::F64(payload.0),
            rmpv::Value::Binary(payload.1.into_vec()),
            data_value,
        ]);
        let mut payload_data = Vec::new();
        rmpv_write_value(&mut payload_data, &outer_value).map_err(|e| format!("Failed to encode request payload: {}", e))?;
        // Encrypt the payload using the link session key directly (via self.encrypt),
        // avoiding the self-deadlock that would occur if we went through
        // DestinationType::Link → runtime_encrypt_for_destination → link.lock()
        // while the caller already holds link_arc.lock().
        let ciphertext = self.encrypt(&payload_data)?;

        // Build a Link-type destination (hash = link_id) to get correct routing
        // and link-interface filtering in Transport::outbound. We skip
        // destination.encrypt() by pre-setting packet.ciphertext below.
        let mut dest = self.destination.lock().map_err(|_| "Destination lock poisoned")?.clone();
        dest.dest_type = DestinationType::Link;
        dest.hash = self.link_id.clone();
        dest.hexhash = crate::hexrep(&dest.hash, false);
        // Attach link routing info so Transport::outbound knows the interface.
        dest.link = Some(crate::destination::LinkInfo {
            rtt: self.rtt,
            traffic_timeout_factor: self.traffic_timeout_factor,
            status_closed: self.state == STATE_CLOSED,
            mtu: Some(self.mtu),
            attached_interface: self.attached_interface.clone(),
        });
        let mut packet = Packet::new(
            Some(dest),
            vec![], // data unused — we supply ciphertext manually below
            DATA,
            crate::packet::REQUEST,
            crate::transport::BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            0,
        );
        // Inject the pre-encrypted ciphertext and mark packet as packed so
        // send() won't call pack() and attempt to re-encrypt.
        packet.ciphertext = Some(ciphertext);
        // pack() manually: build raw = flags + hops + link_id + context + ciphertext.
        {
            let mut raw = Vec::new();
            raw.push(packet.flags);
            raw.push(packet.hops);
            raw.extend_from_slice(&self.link_id);
            raw.push(packet.context);
            raw.extend_from_slice(packet.ciphertext.as_ref().unwrap());
            packet.destination_hash = Some(self.link_id.clone());
            packet.raw = raw;
            packet.packed = true;
            packet.update_hash();
        }
        // Python computes request_id = truncated_hash(packet.get_hashable_part())
        // We must compute this BEFORE send() since send() doesn't change the hash
        let request_id = packet.get_truncated_hash();

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
                // Spawn so callback can re-acquire locks (e.g. router) that may
                // already be held by the thread calling request().
                thread::spawn(move || { callback(receipt); });
            }
            return Err(err);
        }

        if let Some(callback) = progress_callback.clone() {
            let mut initial = receipt.clone();
            initial.progress = 0.1;
            // Spawn so the progress callback can re-acquire locks (e.g. router)
            // that may already be held by the calling thread.
            thread::spawn(move || { callback(initial); });
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

                    // Signal that remote_identified callback should fire
                    // OUTSIDE the link lock (in dispatch_runtime_packet)
                    // so the callback receives the original Arc, not a clone.
                    self.pending_remote_identified = true;

                    Ok(())
                } else {
                    Err("LINKIDENTIFY signature validation failed".to_string())
                }
            }
            Err(e) => Err(format!("Failed to create identity from public key: {}", e)),
        }
    }
    
    /// Handle PROOF packets
    fn handle_proof_packet(&mut self, packet: &Packet) -> Result<(), String> {
        if packet.context == crate::packet::RESOURCE_PRF {
            let hash_len = identity::HASHLENGTH / 8;
            if packet.data.len() >= hash_len {
                let resource_hash = packet.data[..hash_len].to_vec();
                // Clone the list of outgoing resource Arcs WITHOUT locking
                // individual resources — avoids AB-BA deadlock with deferred
                // REQ handler thread (resource→link vs link→resource).
                let resources: Vec<Arc<Mutex<Resource>>> = if let Ok(resources) = self.outgoing_resources.lock() {
                    resources.clone()
                } else {
                    Vec::new()
                };

                let proof_data = packet.data.clone();
                thread::spawn(move || {
                    // Find matching resources and validate proof OUTSIDE the link lock
                    for resource in resources.iter() {
                        let matches = if let Ok(guard) = resource.lock() {
                            guard.hash == resource_hash.as_slice()
                        } else {
                            false
                        };
                        if matches {
                            let proof = proof_data.clone();
                            let target = resource.clone();
                            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                if let Ok(mut resource_guard) = target.lock() {
                                    resource_guard.validate_proof(&proof);
                                } else {
                                }
                            }));
                            let _ = result;
                        }
                    }
                });
            }
            return Ok(());
        }

        if !self.initiator || self.state != STATE_PENDING {
            return Ok(());
        }

        let data = &packet.data;
        if data.len() != (identity::SIGLENGTH / 8 + ECPUBSIZE / 2)
            && data.len() != (identity::SIGLENGTH / 8 + ECPUBSIZE / 2 + LINK_MTU_SIZE)
        {
            return Err("Invalid link proof packet length".to_string());
        }

        let mode = mode_from_lp_packet(data);
        if mode != self.mode {
            return Err("Invalid link mode in proof packet".to_string());
        }

        let signature = data[..identity::SIGLENGTH / 8].to_vec();
        let peer_pub_bytes = data[identity::SIGLENGTH / 8..identity::SIGLENGTH / 8 + ECPUBSIZE / 2].to_vec();

        let (peer_sig_pub_bytes, destination_identity) = {
            let destination = self.destination.lock().map_err(|_| "Destination lock poisoned")?;
            let identity = destination.identity.clone().ok_or("Missing destination identity on link")?;
            let public_key = identity.get_public_key()?;
            if public_key.len() != 64 {
                return Err("Invalid destination public key length".to_string());
            }
            (public_key[32..64].to_vec(), identity)
        };

        self.load_peer(peer_pub_bytes.clone(), peer_sig_pub_bytes.clone())?;
        self.handshake()?;

        let mut signed_data = self.link_id.clone();
        signed_data.extend_from_slice(&peer_pub_bytes);
        signed_data.extend_from_slice(&peer_sig_pub_bytes);
        if data.len() == (identity::SIGLENGTH / 8 + ECPUBSIZE / 2 + LINK_MTU_SIZE) {
            signed_data.extend_from_slice(&signalling_bytes(mtu_from_lp_packet(data).unwrap_or(reticulum::MTU), mode)?);
        }

        if !destination_identity.validate(&signature, &signed_data) {
            return Err("Invalid link proof signature".to_string());
        }

        let now = current_time().unwrap_or(0);
        let now_precise = now_seconds();
        if let Some(request_time) = self.request_time {
            self.rtt = Some((now_precise - request_time).max(0.001));
        }
        self.state = STATE_ACTIVE;
        self.status = STATE_ACTIVE;
        self.activated_at = Some(now);
        self.attached_interface = packet.receiving_interface.clone();
        self.last_proof = now;
        self.last_inbound = now;
        self.last_outbound = now;
        if let Some(mtu) = mtu_from_lp_packet(data) {
            self.mtu = mtu;
            self.update_mdu();
        }

        self.update_keepalive();

        crate::log(&format!("Link activated {} rtt={:.3}s keepalive={:.0}s attached_interface={:?}", crate::hexrep(&self.link_id, false), self.rtt.unwrap_or(0.0), self.keepalive, self.attached_interface), crate::LOG_NOTICE, false, false);

        if let Some(rtt) = self.rtt {
            let rtt_data = to_vec(&rtt).map_err(|e| format!("Failed to encode LRRTT payload: {}", e))?;

            let mut link_destination = self
                .destination
                .lock()
                .map_err(|_| "Destination lock poisoned")?
                .clone();
            link_destination.dest_type = DestinationType::Link;
            link_destination.hash = self.link_id.clone();
            link_destination.hexhash = crate::hexrep(&link_destination.hash, false);
            link_destination.link = Some(crate::destination::LinkInfo {
                rtt: self.rtt,
                traffic_timeout_factor: self.traffic_timeout_factor,
                status_closed: self.state == STATE_CLOSED,
                mtu: Some(self.mtu),
                attached_interface: self.attached_interface.clone(),
            });

            thread::spawn(move || {
                let mut rtt_packet = Packet::new(
                    Some(link_destination),
                    rtt_data,
                    DATA,
                    packet::LRRTT,
                    crate::transport::BROADCAST,
                    packet::HEADER_1,
                    None,
                    None,
                    false,
                    0,
                );
                let _ = rtt_packet.send();
            });
            self.had_outbound(false);
        }

        if let Some(callback) = &self.callbacks.link_established {
            let callback = Arc::clone(callback);
            let link_clone = Arc::new(Mutex::new(self.clone()));
            thread::spawn(move || {
                callback(link_clone);
            });
        }

        Ok(())
    }
    
    /// Update keepalive interval based on measured RTT (matches Python __update_keepalive)
    pub fn update_keepalive(&mut self) {
        if let Some(rtt) = self.rtt {
            self.keepalive = (rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)).min(KEEPALIVE_MAX).max(KEEPALIVE_MIN);
            self.stale_time = self.keepalive * STALE_FACTOR;
        }
    }

    /// Prepare keepalive info so the caller can send the packet outside the link lock.
    /// Returns (destination, link_id) if a keepalive should be sent.
    pub fn prepare_keepalive(&mut self) -> Option<(Destination, Vec<u8>)> {
        let mut link_destination = match self.destination.lock() {
            Ok(d) => d.clone(),
            Err(_) => return None,
        };
        link_destination.dest_type = DestinationType::Link;
        link_destination.hash = self.link_id.clone();
        link_destination.hexhash = crate::hexrep(&link_destination.hash, false);
        self.had_outbound(true);
        Some((link_destination, self.link_id.clone()))
    }

    /// Send keep-alive packet (called when link lock is NOT held externally)
    pub fn send_keepalive(&mut self) -> Result<(), String> {
        let info = self.prepare_keepalive();
        if let Some((link_destination, _link_id)) = info {
            thread::spawn(move || {
                let mut keepalive_packet = Packet::new(
                    Some(link_destination),
                    vec![0xFF],
                    DATA,
                    crate::packet::KEEPALIVE,
                    crate::transport::BROADCAST,
                    packet::HEADER_1,
                    None,
                    None,
                    false,
                    0,
                );
                let _ = keepalive_packet.send();
            });
        }
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

        let encrypted_identify = self.encrypt(&proof_data)?;

        // Send identify over the active link destination semantics
        let mut dest = self
            .destination
            .lock()
            .map_err(|_| "Failed to lock destination".to_string())?
            .clone();
        dest.dest_type = crate::destination::DestinationType::Link;
        dest.hash = self.link_id.clone();
        dest.hexhash = crate::hexrep(&dest.hash, false);
        dest.link = Some(crate::destination::LinkInfo {
            rtt: self.rtt,
            traffic_timeout_factor: self.traffic_timeout_factor,
            status_closed: self.state == STATE_CLOSED,
            mtu: Some(self.mtu),
            attached_interface: self.attached_interface.clone(),
        });

        // Create packet with LINKIDENTIFY context
        let packet = Packet::new(
            Some(dest),
            encrypted_identify,
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
        let target_hash = resource.lock().ok().map(|r| r.hash.clone()).unwrap_or_default();
        if let Ok(resources) = self.incoming_resources.lock() {
            resources.iter().any(|r| {
                r.try_lock().ok().map(|r| r.hash == target_hash).unwrap_or(false)
            })
        } else {
            false
        }
    }

    /// Cancel outgoing resource and remove from tracking.
    /// Uses try_lock on individual resources to avoid deadlock when called
    /// from validate_proof (which already holds the resource lock).
    /// If a resource can't be locked, deferred cleanup runs after 100ms.
    pub fn cancel_outgoing_resource(&self, resource: Arc<Mutex<Resource>>) {
        let target_hash = resource.lock().ok().map(|r| r.hash.clone()).unwrap_or_default();
        if target_hash.is_empty() { return; }
        let mut need_deferred = false;
        match self.outgoing_resources.try_lock() {
            Ok(mut resources) => {
                let before = resources.len();
                resources.retain(|r| {
                    match r.try_lock() {
                        Ok(guard) => guard.hash != target_hash,
                        Err(_) => true, // can't lock (possibly held by us), keep for deferred
                    }
                });
                if resources.len() == before {
                    need_deferred = true; // nothing removed, schedule retry
                }
            }
            Err(_) => {
                need_deferred = true;
            }
        }
        if need_deferred {
            let outgoing = Arc::clone(&self.outgoing_resources);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Ok(mut resources) = outgoing.lock() {
                    resources.retain(|r| {
                        r.lock().ok().map(|r| r.hash != target_hash).unwrap_or(true)
                    });
                }
            });
        }
    }

    /// Cancel incoming resource and remove from tracking.
    /// Uses try_lock to avoid deadlock (same pattern as cancel_outgoing_resource).
    pub fn cancel_incoming_resource(&self, resource: Arc<Mutex<Resource>>) {
        let target_hash = resource.lock().ok().map(|r| r.hash.clone()).unwrap_or_default();
        if target_hash.is_empty() { return; }
        let mut need_deferred = false;
        match self.incoming_resources.try_lock() {
            Ok(mut resources) => {
                let before = resources.len();
                resources.retain(|r| {
                    match r.try_lock() {
                        Ok(guard) => guard.hash != target_hash,
                        Err(_) => true,
                    }
                });
                if resources.len() == before {
                    need_deferred = true;
                }
            }
            Err(_) => {
                need_deferred = true;
            }
        }
        if need_deferred {
            let incoming = Arc::clone(&self.incoming_resources);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Ok(mut resources) = incoming.lock() {
                    resources.retain(|r| {
                        r.lock().ok().map(|r| r.hash != target_hash).unwrap_or(true)
                    });
                }
            });
        }
    }

    /// Mark resource concluded and update tracking stats
    /// Returns the resource_concluded callback (if any) so the caller can invoke
    /// it OUTSIDE the link lock, preventing deadlocks on incoming_resources.
    pub fn resource_concluded(&mut self, resource: Arc<Mutex<Resource>>) -> Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>> {
        if let Ok(resource_guard) = resource.lock() {
            self.last_resource_window = Some(resource_guard.window);
            self.last_resource_eifr = resource_guard.eifr;
        }
        let callback = self.callbacks.resource_concluded.clone();
        self.cancel_outgoing_resource(resource.clone());
        self.cancel_incoming_resource(resource);
        callback
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
