//! High-level Reticulum transport client.
//!
//! `ReticulumClient` encapsulates the transport-level lifecycle that every
//! Reticulum-based application shares:
//!
//!   1. Initialize transport (parse config, connect interfaces)
//!   2. Load or create an identity
//!   3. Compute destination hashes
//!   4. Persist / shutdown
//!
//! Protocol layers (LXMF, etc.) compose on top of this.

use crate::ffi;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Everything needed to stand up the Reticulum transport layer.
pub struct ReticulumConfig {
    /// Path to the directory containing the Reticulum `config` file.
    pub config_dir: String,

    /// Path to the identity file.  If it doesn't exist and
    /// `create_identity` is true, a new one is generated and saved.
    pub identity_path: String,

    /// Create a new identity if the file doesn't exist.
    pub create_identity: bool,

    /// Log level (0–7), or -1 for default.
    pub log_level: i32,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A running Reticulum transport instance with an identity.
///
/// Owns the identity handle and provides accessors for derived hashes.
/// Drop / `shutdown()` tears down the transport stack.
pub struct ReticulumClient {
    /// Handle to the loaded identity in the handle registry.
    pub identity_handle: u64,

    /// The 16-byte truncated identity hash.
    pub identity_hash: Vec<u8>,
}

impl ReticulumClient {
    /// Initialize transport and load (or create) an identity.
    pub fn start(config: ReticulumConfig) -> Result<Self, String> {
        // 1. Init transport
        ffi::init(&config.config_dir, config.log_level)?;

        // Re-apply stderr logging so Xcode / logcat can see trace output.
        ffi::set_log_callback(|msg| {
            eprintln!("{}", msg);
        });

        // 2. Load or create identity
        let identity_handle = match ffi::identity_from_file(&config.identity_path) {
            Ok(h) => h,
            Err(_) if config.create_identity => {
                let h = ffi::identity_create()?;
                ffi::identity_to_file(h, &config.identity_path)?;
                h
            }
            Err(e) => return Err(e),
        };

        let identity_hash = ffi::identity_hash(identity_handle)?;

        Ok(ReticulumClient {
            identity_handle,
            identity_hash,
        })
    }

    // -------------------------------------------------------------------
    // Destination helpers
    // -------------------------------------------------------------------

    /// Compute the destination hash for this identity + app_name + aspects.
    pub fn destination_hash(
        &self,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<Vec<u8>, String> {
        ffi::destination_hash_for(self.identity_handle, app_name, aspects)
    }

    // -------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------

    /// Persist path table and cached data to disk.
    pub fn persist(&self) {
        ffi::persist_data();
    }

    /// Shut down: destroy identity handle and tear down transport.
    pub fn shutdown(&self) -> Result<(), String> {
        ffi::identity_destroy(self.identity_handle)?;
        ffi::shutdown()
    }
}
