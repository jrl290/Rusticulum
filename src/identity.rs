// RNS::Identity equivalent

use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;
use x25519_dalek::{StaticSecret as X25519PrivateKey, PublicKey as X25519PublicKey};
use ed25519_dalek::{SecretKey as Ed25519PrivateKey, PublicKey as Ed25519PublicKey, Signature, Verifier};
use hkdf::Hkdf;
use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use crate::log;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

// Constants
pub const CURVE: &str = "Curve25519";
pub const KEYSIZE: usize = 512; // bits (256 for encryption + 256 for signing)
pub const RATCHETSIZE: usize = 256; // bits
pub const TOKEN_OVERHEAD: usize = 48;
pub const AES128_BLOCKSIZE: usize = 16;
const RATCHET_EXPIRY: u64 = 60 * 60 * 24 * 30; // seconds (30 days)

pub const HASHLENGTH: usize = 256;
pub const SIGLENGTH: usize = KEYSIZE;
pub const NAME_HASH_LENGTH: usize = 80;
pub const TRUNCATED_HASHLENGTH: usize = crate::reticulum::TRUNCATED_HASHLENGTH;

static KNOWN_RATCHETS: Lazy<Mutex<HashMap<Vec<u8>, Vec<u8>>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static RATCHET_PERSIST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static KNOWN_DESTINATIONS: Lazy<Mutex<HashMap<Vec<u8>, KnownDestination>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static KNOWN_DESTINATIONS_LOADED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

/// Token implementation - Modified Fernet without VERSION/TIMESTAMP overhead
pub struct Token {
    signing_key: Vec<u8>,
    encryption_key: Vec<u8>,
}

impl Token {
    /// Create a new Token from a key (32 bytes for AES-128, 64 bytes for AES-256)
    pub fn new(key: &[u8]) -> Result<Self, String> {
        match key.len() {
            32 => {
                // AES-128-CBC: first 16 bytes signing, next 16 encryption
                Ok(Token {
                    signing_key: key[..16].to_vec(),
                    encryption_key: key[16..32].to_vec(),
                })
            }
            64 => {
                // AES-256-CBC: first 32 bytes signing,  next 32 encryption
                Ok(Token {
                    signing_key: key[..32].to_vec(),
                    encryption_key: key[32..64].to_vec(),
                })
            }
            _ => Err(format!("Token key must be 32 or 64 bytes, not {}", key.len())),
        }
    }

    /// Encrypt data with AES-256-CBC and HMAC
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        // Generate random IV
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);

        // Pad plaintext to multiple of 16
        let block_size = 16;
        let pad_len = block_size - (plaintext.len() % block_size);
        let mut padded = plaintext.to_vec();
        padded.extend_from_slice(&vec![pad_len as u8; pad_len]);

        // Encrypt
        let cipher = Aes256CbcEnc::new_from_slices(&self.encryption_key, &iv)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let mut buf = padded.clone();
        let ciphertext = cipher.encrypt_padded_mut::<block_padding::Pkcs7>(&mut buf, padded.len())
            .map_err(|e| format!("Encryption failed: {}", e))?
            .to_vec();

        // Build token: IV + ciphertext
        let mut signed_parts = iv.to_vec();
        signed_parts.extend_from_slice(&ciphertext);

        // Add HMAC
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| format!("HMAC error: {}", e))?;
        mac.update(&signed_parts);
        let hmac_result = mac.finalize().into_bytes();

        signed_parts.extend_from_slice(&hmac_result);
        Ok(signed_parts)
    }

    /// Decrypt and verify AES-256-CBC token
    pub fn decrypt(&self, token: &[u8]) -> Result<Vec<u8>, String> {
        if token.len() <= 32 {
            return Err(format!("Cannot verify HMAC on token of only {} bytes", token.len()));
        }

        // Verify HMAC
        let received_hmac = &token[token.len() - 32..];
        let signed_parts = &token[..token.len() - 32];

        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| format!("HMAC error: {}", e))?;
        mac.update(signed_parts);
        mac.verify_slice(received_hmac)
            .map_err(|_| "Token HMAC was invalid".to_string())?;

        // Extract IV and ciphertext
        let iv = &token[..16];
        let ciphertext = &token[16..token.len() - 32];

        // Decrypt
        let cipher = Aes256CbcDec::new_from_slices(&self.encryption_key, iv)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let mut buffer = ciphertext.to_vec();
        let plaintext = cipher.decrypt_padded_mut::<block_padding::Pkcs7>(&mut buffer)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(plaintext.to_vec())
    }
}

/// Calculates the SHA256 hash of the given data.
pub fn full_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calculates a truncated SHA256 hash of the given data.
pub fn truncated_hash(data: &[u8]) -> Vec<u8> {
    let full = full_hash(data);
    let truncated_length = crate::reticulum::TRUNCATED_HASHLENGTH / 8;
    full[..truncated_length].to_vec()
}

/// Generates a random hash value.
pub fn get_random_hash() -> Vec<u8> {
    let mut buffer = vec![0u8; 10];
    OsRng.fill_bytes(&mut buffer);
    full_hash(&buffer)
}

/// Ratchet data stored on disk
#[derive(Serialize, Deserialize, Clone)]
struct RatchetEntry {
    public_key: Vec<u8>,
    timestamp: u64,
}

/// Known destination data
#[derive(Serialize, Deserialize, Clone)]
struct KnownDestination {
    public_key: Vec<u8>,
    app_data: Option<Vec<u8>>,
}

/// Cryptographic identity for encryption, signing, and authentication
pub struct Identity {
    // X25519 keys for encryption (ECDH)
    encryption_prv_key: Option<X25519PrivateKey>,
    encryption_pub_key: Option<X25519PublicKey>,
    
    // Ed25519 keys for signing
    signing_prv_key: Option<Ed25519PrivateKey>,
    signing_pub_key: Option<Ed25519PublicKey>,
    
    // Hash of public keys
    pub hash: Option<Vec<u8>>,
    
    // Ratchet keys for forward secrecy
    ratchets: HashMap<Vec<u8>, Vec<u8>>,
    
    // Storage paths
    storage_path: Option<PathBuf>,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        let mut cloned = if let Ok(private_key) = self.get_private_key() {
            Identity::from_bytes(&private_key).unwrap_or_else(|_| Identity::new(true))
        } else if let Ok(public_key) = self.get_public_key() {
            Identity::from_public_key(&public_key).unwrap_or_else(|_| Identity::new(false))
        } else {
            Identity::new(false)
        };
        cloned.ratchets = self.ratchets.clone();
        cloned.storage_path = self.storage_path.clone();
        cloned
    }
}

impl Identity {
    // ===== Static hash utilities =====
    
    pub fn get_random_hash() -> Vec<u8> {
        get_random_hash()
    }

    pub fn full_hash(data: &[u8]) -> Vec<u8> {
        full_hash(data)
    }

    pub fn truncated_hash(data: &[u8]) -> Vec<u8> {
        truncated_hash(data)
    }

    // ===== Constructors =====
    
    /// Create a new identity.
    pub fn new(create_keys: bool) -> Self {
        let (encryption_prv_key, encryption_pub_key) = if create_keys {
            let mut enc_key_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut enc_key_bytes);
            let enc_prv = X25519PrivateKey::from(enc_key_bytes);
            let enc_pub = X25519PublicKey::from(&enc_prv);
            (Some(enc_prv), Some(enc_pub))
        } else {
            (None, None)
        };

        let (signing_prv_key, signing_pub_key) = if create_keys {
            let mut sign_key_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut sign_key_bytes);
            let secret = Ed25519PrivateKey::from_bytes(&sign_key_bytes)
                .expect("Failed to create Ed25519 private key");
            let public = Ed25519PublicKey::from(&secret);
            (Some(secret), Some(public))
        } else {
            (None, None)
        };

        let mut identity = Identity {
            encryption_prv_key,
            encryption_pub_key,
            signing_prv_key,
            signing_pub_key,
            hash: None,
            ratchets: HashMap::new(),
            storage_path: None,
        };

        if create_keys {
            identity.update_hashes();
        }
        identity
    }

    /// Generate new encryption and signing keys
    pub fn create_keys(&mut self) {
        let mut enc_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut enc_key_bytes);
        let enc_prv = X25519PrivateKey::from(enc_key_bytes);
        let enc_pub = X25519PublicKey::from(&enc_prv);
        self.encryption_prv_key = Some(enc_prv);
        self.encryption_pub_key = Some(enc_pub);
        
        let mut sign_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sign_key_bytes);
        let secret = Ed25519PrivateKey::from_bytes(&sign_key_bytes)
            .expect("Failed to create Ed25519 private key");
        let public = Ed25519PublicKey::from(&secret);
        self.signing_prv_key = Some(secret);
        self.signing_pub_key = Some(public);
        
        self.update_hashes();
    }

    pub fn load_private_key(&mut self, prv_bytes: &[u8]) -> Result<(), String> {
        if prv_bytes.len() != KEYSIZE / 8 {
            return Err(format!("Private key must be {} bytes", KEYSIZE / 8));
        }

        let enc_key_bytes: [u8; 32] = prv_bytes[..32]
            .try_into()
            .map_err(|_| "Invalid encryption key".to_string())?;
        let enc_prv = X25519PrivateKey::from(enc_key_bytes);
        let enc_pub = X25519PublicKey::from(&enc_prv);

        let sign_key_bytes: [u8; 32] = prv_bytes[32..64]
            .try_into()
            .map_err(|_| "Invalid signing key".to_string())?;
        let sign_prv = Ed25519PrivateKey::from_bytes(&sign_key_bytes)
            .map_err(|e| format!("Invalid Ed25519 key: {}", e))?;
        let sign_pub = Ed25519PublicKey::from(&sign_prv);

        self.encryption_prv_key = Some(enc_prv);
        self.encryption_pub_key = Some(enc_pub);
        self.signing_prv_key = Some(sign_prv);
        self.signing_pub_key = Some(sign_pub);
        self.update_hashes();
        Ok(())
    }

    pub fn load_public_key(&mut self, pub_bytes: &[u8]) -> Result<(), String> {
        if pub_bytes.len() != KEYSIZE / 8 {
            return Err(format!("Public key must be {} bytes", KEYSIZE / 8));
        }

        let enc_pub_bytes: [u8; 32] = pub_bytes[..32]
            .try_into()
            .map_err(|_| "Invalid encryption public key".to_string())?;
        let enc_pub = X25519PublicKey::from(enc_pub_bytes);

        let sign_pub_bytes: [u8; 32] = pub_bytes[32..64]
            .try_into()
            .map_err(|_| "Invalid signing public key".to_string())?;
        let sign_pub = Ed25519PublicKey::from_bytes(&sign_pub_bytes)
            .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?;

        self.encryption_prv_key = None;
        self.encryption_pub_key = Some(enc_pub);
        self.signing_prv_key = None;
        self.signing_pub_key = Some(sign_pub);
        self.update_hashes();
        Ok(())
    }

    /// Create an identity from existing key bytes
    pub fn from_bytes(prv_bytes: &[u8]) -> Result<Self, String> {
        let mut identity = Identity::new(false);
        identity.load_private_key(prv_bytes)?;
        Ok(identity)
    }

    /// Create an identity from public key bytes (64 bytes: 32 X25519 + 32 Ed25519)
    pub fn from_public_key(pub_bytes: &[u8]) -> Result<Self, String> {
        let mut identity = Identity::new(false);
        identity.load_public_key(pub_bytes)?;
        Ok(identity)
    }

    /// Load identity from file
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let data = fs::read(path)
            .map_err(|e| format!("Failed to read identity file: {}", e))?;
        Self::from_bytes(&data)
    }

    /// Save identity to file
    pub fn to_file(&self, path: &Path) -> Result<(), String> {
        let prv_bytes = self.get_private_key()?;
        fs::write(path, prv_bytes)
            .map_err(|e| format!("Failed to write identity file: {}", e))
    }

    // ===== Key accessors =====
    
    /// Get private key bytes (64 bytes: 32 X25519 + 32 Ed25519)
    pub fn get_private_key(&self) -> Result<Vec<u8>, String> {
        let mut key = Vec::with_capacity(64);
        let enc_prv = self.encryption_prv_key.as_ref().ok_or("Identity has no private key")?;
        let sign_prv = self.signing_prv_key.as_ref().ok_or("Identity has no private key")?;
        key.extend_from_slice(&enc_prv.to_bytes());
        key.extend_from_slice(sign_prv.as_bytes());
        Ok(key)
    }

    /// Get public key bytes (64 bytes: 32 X25519 + 32 Ed25519)
    pub fn get_public_key(&self) -> Result<Vec<u8>, String> {
        let mut key = Vec::with_capacity(64);
        let enc_pub = self.encryption_pub_key.as_ref().ok_or("Identity has no public key")?;
        let sign_pub = self.signing_pub_key.as_ref().ok_or("Identity has no public key")?;
        key.extend_from_slice(enc_pub.as_bytes());
        key.extend_from_slice(sign_pub.as_bytes());
        Ok(key)
    }

    /// Update hash based on current public keys
    fn update_hashes(&mut self) {
        if let Ok(pub_key) = self.get_public_key() {
            self.hash = Some(truncated_hash(&pub_key));
        } else {
            self.hash = None;
        }
    }

    // ===== Encryption/Decryption =====
    
    /// Encrypt plaintext for this identity
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let enc_pub = self.encryption_pub_key.as_ref().ok_or("Identity has no public key")?;
        // Generate ephemeral X25519 keypair
        let mut ephemeral_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut ephemeral_bytes);
        let ephemeral_prv = X25519PrivateKey::from(ephemeral_bytes);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_prv);
        
        // Perform ECDH
        let shared_secret = ephemeral_prv.diffie_hellman(enc_pub);
        
        // Derive encryption key using HKDF
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut derived_key = [0u8; 64];
        hkdf.expand(b"", &mut derived_key)
            .map_err(|_| "HKDF expansion failed".to_string())?;
        
        // Encrypt with Token
        let token = Token::new(&derived_key)?;
        let ciphertext = token.encrypt(plaintext)?;
        
        // Return: ephemeral_pub (32) + ciphertext
        let mut result = ephemeral_pub.as_bytes().to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt ciphertext encrypted for this identity (supports ratchets)
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() <= 32 {
            return Err("Ciphertext too short".to_string());
        }

        // Extract ephemeral public key
        let ephemeral_pub_bytes: [u8; 32] = ciphertext[..32].try_into()
            .map_err(|_| "Invalid ephemeral public key".to_string())?;
        let ephemeral_pub = X25519PublicKey::from(ephemeral_pub_bytes);
        let token_data = &ciphertext[32..];

        // Try ratchet keys first
        for (_ratchet_id, ratchet_prv_bytes) in &self.ratchets {
            let ratchet_prv = X25519PrivateKey::from(*<&[u8; 32]>::try_from(ratchet_prv_bytes.as_slice()).unwrap());
            if let Ok(plaintext) = self.decrypt_with_key(&ratchet_prv, &ephemeral_pub, token_data) {
                return Ok(plaintext);
            }
        }

        // Fall back to main encryption key
        let enc_prv = self.encryption_prv_key.as_ref().ok_or("Identity has no private key")?;
        self.decrypt_with_key(enc_prv, &ephemeral_pub, token_data)
    }

    fn decrypt_with_key(
        &self,
        prv_key: &X25519PrivateKey,
        ephemeral_pub: &X25519PublicKey,
        token_data: &[u8]
    ) -> Result<Vec<u8>, String> {
        // Perform ECDH
        let shared_secret = prv_key.diffie_hellman(ephemeral_pub);
        
        // Derive decryption key using HKDF
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut derived_key = [0u8; 64];
        hkdf.expand(b"", &mut derived_key)
            .map_err(|_| "HKDF expansion failed".to_string())?;
        
        // Decrypt with Token
        let token = Token::new(&derived_key)?;
        token.decrypt(token_data)
    }

    // ===== Signing/Verification =====
    
    /// Sign data with this identity's signing key
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let sign_prv = self.signing_prv_key.as_ref().expect("Identity has no private key");
        let kp_secret = ed25519_dalek::Keypair::from_bytes(&sign_prv.to_bytes())
            .expect("Failed to reconstruct keypair from bytes");
        let signature = kp_secret.sign(data);
        signature.to_bytes().to_vec()
    }

    /// Verify a signature against this identity's public key
    pub fn validate(&self, signature: &[u8], data: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }

        let sign_pub = match self.signing_pub_key.as_ref() {
            Some(key) => key,
            None => return false,
        };
        
        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        
        match Signature::from_bytes(&sig_bytes) {
            Ok(sig) => sign_pub.verify(data, &sig).is_ok(),
            Err(_) => false,
        }
    }

    /// Generate proof for packet authentication
    pub fn prove(&self, packet_hash: &[u8], destination_hash: Option<&[u8]>) -> Vec<u8> {
        let mut data = packet_hash.to_vec();
        if let Some(dest_hash) = destination_hash {
            data.extend_from_slice(dest_hash);
        }
        self.sign(&data)
    }

    // ===== Ratchet Management =====
    
    /// Generate a new ratchet key
    pub fn generate_ratchet(&mut self) -> (Vec<u8>, Vec<u8>) {
        let mut ratchet_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut ratchet_bytes);
        let ratchet_prv = X25519PrivateKey::from(ratchet_bytes);
        let ratchet_pub = X25519PublicKey::from(&ratchet_prv);
        
        let ratchet_id = truncated_hash(ratchet_pub.as_bytes());
        self.ratchets.insert(ratchet_id.clone(), ratchet_bytes.to_vec());
        
        (ratchet_id, ratchet_pub.as_bytes().to_vec())
    }

    pub fn ratchet_public_bytes(ratchet_prv: &[u8]) -> Result<Vec<u8>, String> {
        if ratchet_prv.len() != 32 {
            return Err(format!("Invalid ratchet private key length: {}", ratchet_prv.len()));
        }
        let prv = X25519PrivateKey::from(*<&[u8; 32]>::try_from(ratchet_prv).map_err(|_| "Invalid ratchet key")?);
        let pub_key = X25519PublicKey::from(&prv);
        Ok(pub_key.as_bytes().to_vec())
    }

    pub fn ratchet_id_from_pub(ratchet_pub: &[u8]) -> Vec<u8> {
        full_hash(ratchet_pub)[..(NAME_HASH_LENGTH / 8)].to_vec()
    }

    pub fn remember_ratchet(destination_hash: &[u8], ratchet_pub: &[u8]) -> Result<(), String> {
        if ratchet_pub.len() != 32 {
            return Err(format!("Invalid ratchet public key length: {}", ratchet_pub.len()));
        }

        let mut known = KNOWN_RATCHETS.lock().unwrap();
        if let Some(existing) = known.get(destination_hash) {
            if existing == ratchet_pub {
                return Ok(());
            }
        }

        let ratchet_id = Identity::ratchet_id_from_pub(ratchet_pub);
        log(
            &format!("Remembering ratchet {} for {}", crate::hexrep(&ratchet_id, true), crate::hexrep(destination_hash, true)),
            crate::LOG_EXTREME,
            false,
            false,
        );

        known.insert(destination_hash.to_vec(), ratchet_pub.to_vec());
        drop(known);

        if crate::transport::Transport::is_connected_to_shared_instance() {
            return Ok(());
        }

        let destination_hash = destination_hash.to_vec();
        let ratchet_pub = ratchet_pub.to_vec();
        thread::spawn(move || {
            let _lock = RATCHET_PERSIST_LOCK.lock().unwrap();
            let hexhash = crate::hexrep(&destination_hash, false);
            let ratchet_dir = crate::reticulum::storage_path().join("ratchets");
            if fs::create_dir_all(&ratchet_dir).is_err() {
                return;
            }
            let outpath = ratchet_dir.join(format!("{}.out", hexhash));
            let finalpath = ratchet_dir.join(hexhash);
            let entry = RatchetEntry {
                public_key: ratchet_pub,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            };
            if let Ok(data) = rmp_serde::to_vec(&entry) {
                if fs::write(&outpath, data).is_ok() {
                    let _ = fs::rename(outpath, finalpath);
                }
            }
        });

        Ok(())
    }

    pub fn get_ratchet(destination_hash: &[u8]) -> Option<Vec<u8>> {
        if let Some(ratchet) = KNOWN_RATCHETS.lock().unwrap().get(destination_hash).cloned() {
            return Some(ratchet);
        }

        let hexhash = crate::hexrep(destination_hash, false);
        let ratchet_path = crate::reticulum::storage_path().join("ratchets").join(hexhash);
        if !ratchet_path.exists() {
            return None;
        }

        if let Ok(data) = fs::read(&ratchet_path) {
            if let Ok(entry) = rmp_serde::from_slice::<RatchetEntry>(&data) {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                if now > entry.timestamp + RATCHET_EXPIRY {
                    let _ = fs::remove_file(&ratchet_path);
                    return None;
                }
                KNOWN_RATCHETS.lock().unwrap().insert(destination_hash.to_vec(), entry.public_key.clone());
                return Some(entry.public_key);
            }
        }

        None
    }

    /// Remember a ratchet key (persist to disk if storage_path is set)
    pub fn remember_ratchet_local(&mut self, ratchet_id: Vec<u8>, ratchet_pub: Vec<u8>) -> Result<(), String> {
        if ratchet_pub.len() != 32 {
            return Err(format!("Invalid ratchet public key length: {}", ratchet_pub.len()));
        }
        
        self.ratchets.insert(ratchet_id.clone(), ratchet_pub.clone());

        if let Some(ref storage_path) = self.storage_path {
            let hash = self.hash.as_ref().ok_or("Identity hash not available")?;
            let ratchet_dir = storage_path.join("ratchets").join(hex::encode(hash));
            fs::create_dir_all(&ratchet_dir)
                .map_err(|e| format!("Failed to create ratchet directory: {}", e))?;

            let entry = RatchetEntry {
                public_key: ratchet_pub,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            };

            let data = rmp_serde::to_vec(&entry)
                .map_err(|e| format!("Failed to serialize ratchet: {}", e))?;
            
            let ratchet_file = ratchet_dir.join(hex::encode(&ratchet_id));
            fs::write(ratchet_file, data)
                .map_err(|e| format!("Failed to write ratchet: {}", e))?;
        }

        Ok(())
    }

    /// Clean expired ratchets
    pub fn clean_ratchets(&mut self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        if let Some(ref storage_path) = self.storage_path {
            let hash = match self.hash.as_ref() {
                Some(hash) => hash,
                None => return,
            };
            let ratchet_dir = storage_path.join("ratchets").join(hex::encode(hash));
            if let Ok(entries) = fs::read_dir(&ratchet_dir) {
                for entry in entries.flatten() {
                    if let Ok(data) = fs::read(entry.path()) {
                        if let Ok(ratchet_entry) = rmp_serde::from_slice::<RatchetEntry>(&data) {
                            if now - ratchet_entry.timestamp > RATCHET_EXPIRY {
                                let _ = fs::remove_file(entry.path());
                                let ratchet_id = truncated_hash(&ratchet_entry.public_key);
                                self.ratchets.remove(&ratchet_id);
                            }
                        }
                    }
                }
            }
        }
    }

    // ===== Known Destinations =====

    fn load_known_destinations_if_needed() {
        let mut loaded = KNOWN_DESTINATIONS_LOADED.lock().unwrap();
        if *loaded {
            return;
        }

        let storage_path = crate::reticulum::storage_path();
        let mut destinations = KNOWN_DESTINATIONS.lock().unwrap();

        if let Ok(map) = Self::load_known_destinations(&storage_path) {
            *destinations = map;
        }

        *loaded = true;
    }

    pub fn remember_destination(destination_hash: &[u8], public_key: &[u8], app_data: Option<Vec<u8>>) -> Result<(), String> {
        Self::load_known_destinations_if_needed();

        let mut destinations = KNOWN_DESTINATIONS.lock().unwrap();
        let entry = destinations.entry(destination_hash.to_vec()).or_insert(KnownDestination {
            public_key: public_key.to_vec(),
            app_data: None,
        });

        if entry.public_key != public_key {
            entry.public_key = public_key.to_vec();
        }

        if app_data.is_some() {
            entry.app_data = app_data;
        }

        let storage_path = crate::reticulum::storage_path();
        Self::save_known_destinations(&destinations, &storage_path)?;
        Ok(())
    }

    pub fn recall(destination_hash: &[u8]) -> Option<Identity> {
        Self::load_known_destinations_if_needed();
        let destinations = KNOWN_DESTINATIONS.lock().unwrap();
        let entry = destinations.get(destination_hash)?;
        Identity::from_public_key(&entry.public_key).ok()
    }

    pub fn recall_app_data(destination_hash: &[u8]) -> Option<Vec<u8>> {
        Self::load_known_destinations_if_needed();
        let destinations = KNOWN_DESTINATIONS.lock().unwrap();
        destinations.get(destination_hash).and_then(|entry| entry.app_data.clone())
    }

    pub fn recall_public_key(destination_hash: &[u8]) -> Option<Vec<u8>> {
        Self::load_known_destinations_if_needed();
        let destinations = KNOWN_DESTINATIONS.lock().unwrap();
        destinations.get(destination_hash).map(|entry| entry.public_key.clone())
    }

    // ===== Known Destinations Storage =====
    
    /// Save known destinations to disk
    fn save_known_destinations(
        destinations: &HashMap<Vec<u8>, KnownDestination>,
        storage_path: &Path,
    ) -> Result<(), String> {
        let known_file = storage_path.join("known_destinations");
        let data = rmp_serde::to_vec(destinations)
            .map_err(|e| format!("Failed to serialize destinations: {}", e))?;
        fs::write(known_file, data)
            .map_err(|e| format!("Failed to write destinations: {}", e))
    }

    /// Load known destinations from disk
    fn load_known_destinations(storage_path: &Path) -> Result<HashMap<Vec<u8>, KnownDestination>, String> {
        let known_file = storage_path.join("known_destinations");
        if !known_file.exists() {
            return Ok(HashMap::new());
        }

        let data = fs::read(known_file)
            .map_err(|e| format!("Failed to read destinations: {}", e))?;

        if let Ok(map) = rmp_serde::from_slice::<HashMap<Vec<u8>, KnownDestination>>(&data) {
            return Ok(map);
        }

        let legacy = rmp_serde::from_slice::<HashMap<Vec<u8>, Vec<u8>>>(&data)
            .map_err(|e| format!("Failed to deserialize destinations: {}", e))?;
        let mut upgraded = HashMap::new();
        for (hash, public_key) in legacy {
            upgraded.insert(
                hash,
                KnownDestination {
                    public_key,
                    app_data: None,
                },
            );
        }
        Ok(upgraded)
    }

    // ===== Announce Validation =====
    
    /// Validate an announce packet
    pub fn validate_announce(
        packet: &[u8],
        destination_hash: Option<&[u8]>,
        public_key: Option<&[u8]>,
        context_flag: u8,
    ) -> bool {
        // Validate announce packet structure and signature
        // Announce structure: public_key + name_hash + random_hash + [ratchet] + signature + [app_data]
        
        if packet.len() < KEYSIZE / 8 + NAME_HASH_LENGTH / 8 + 10 + SIGLENGTH / 8 {
            return false;
        }

        let Some(dest_hash) = destination_hash else {
            return false;
        };

        let Some(pub_key_bytes) = public_key else {
            return false;
        };

        if pub_key_bytes.len() != KEYSIZE / 8 {
            return false;
        }

        // Parse announce components
        let public_key = &packet[..KEYSIZE / 8];
        let name_hash = &packet[KEYSIZE / 8..KEYSIZE / 8 + NAME_HASH_LENGTH / 8];
        let random_hash = &packet[KEYSIZE / 8 + NAME_HASH_LENGTH / 8..KEYSIZE / 8 + NAME_HASH_LENGTH / 8 + 10];
        
        // Check if ratchet is present based on context_flag
        let has_ratchet = context_flag == crate::packet::FLAG_SET;
        
        let (signature, app_data) = if has_ratchet {
            let sig_start = KEYSIZE / 8 + NAME_HASH_LENGTH / 8 + 10 + RATCHETSIZE / 8;
            let sig_end = sig_start + SIGLENGTH / 8;
            if packet.len() < sig_end {
                return false;
            }
            let signature = &packet[sig_start..sig_end];
            let app_data = if packet.len() > sig_end {
                &packet[sig_end..]
            } else {
                &[]
            };
            (signature, app_data)
        } else {
            let sig_start = KEYSIZE / 8 + NAME_HASH_LENGTH / 8 + 10;
            let sig_end = sig_start + SIGLENGTH / 8;
            if packet.len() < sig_end {
                return false;
            }
            let signature = &packet[sig_start..sig_end];
            let app_data = if packet.len() > sig_end {
                &packet[sig_end..]
            } else {
                &[]
            };
            (signature, app_data)
        };

        let ratchet = if has_ratchet {
            let ratchet_start = KEYSIZE / 8 + NAME_HASH_LENGTH / 8 + 10;
            let ratchet_end = ratchet_start + RATCHETSIZE / 8;
            if packet.len() < ratchet_end {
                return false;
            }
            &packet[ratchet_start..ratchet_end]
        } else {
            &[]
        };

        // Reconstruct signed data: destination_hash + public_key + name_hash + random_hash + ratchet + app_data
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(dest_hash);
        signed_data.extend_from_slice(public_key);
        signed_data.extend_from_slice(name_hash);
        signed_data.extend_from_slice(random_hash);
        signed_data.extend_from_slice(ratchet);
        signed_data.extend_from_slice(app_data);

        // Extract Ed25519 public key (bytes 32-64)
        let signing_pub_bytes: [u8; 32] = match pub_key_bytes[32..64].try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let signing_pub = match Ed25519PublicKey::from_bytes(&signing_pub_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        match Signature::from_bytes(&sig_bytes) {
            Ok(sig) => signing_pub.verify(&signed_data, &sig).is_ok(),
            Err(_) => false,
        }
    }

    /// Set storage path for ratchets and known destinations
    pub fn set_storage_path(&mut self, path: PathBuf) {
        self.storage_path = Some(path);
    }
}

pub fn persist_data() {
    // Placeholder for parity; ratchet persistence happens per identity instance.
}

pub fn exit_handler() {
    persist_data();
}

// Simple hex encoding helper
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}
