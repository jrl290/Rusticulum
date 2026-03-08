//! FFI support module for Reticulum.
//!
//! Provides a handle-based registry and safe Rust wrapper functions
//! suitable for calling from C, JNI, or other foreign interfaces.
//! All heavyweight Rust objects are stored in a global handle map and
//! referenced by opaque `u64` handles across the language boundary.

use std::any::Any;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

use once_cell::sync::Lazy;

use crate::destination::{Destination, DestinationType};
use crate::identity::Identity;
use crate::reticulum::Reticulum;
use crate::transport::Transport;

// ---------------------------------------------------------------------------
// Handle registry
// ---------------------------------------------------------------------------

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static HANDLES: Lazy<Mutex<HashMap<u64, Box<dyn Any + Send>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

/// Store a value in the handle registry and return its handle (always ≥ 1).
pub fn store_handle<T: Send + 'static>(val: T) -> u64 {
    let id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    HANDLES.lock().unwrap().insert(id, Box::new(val));
    id
}

/// Clone a value out of the registry.  Works for `Identity`, `Arc<Mutex<_>>`, etc.
pub fn get_handle<T: Clone + 'static>(id: u64) -> Option<T> {
    HANDLES
        .lock()
        .unwrap()
        .get(&id)?
        .downcast_ref::<T>()
        .cloned()
}

/// Remove a value from the registry and return it (transfers ownership).
pub fn take_handle<T: 'static>(id: u64) -> Option<T> {
    let boxed = HANDLES.lock().unwrap().remove(&id)?;
    boxed.downcast::<T>().ok().map(|b| *b)
}

/// Remove and drop a handle.  Returns `true` if the handle existed.
pub fn destroy_handle(id: u64) -> bool {
    HANDLES.lock().unwrap().remove(&id).is_some()
}

/// Return the number of handles currently stored.
pub fn handle_count() -> usize {
    HANDLES.lock().unwrap().len()
}

/// Return all handle IDs currently stored.
pub fn handle_keys() -> Vec<u64> {
    HANDLES.lock().unwrap().keys().cloned().collect()
}

/// Save an error message (thread-local).
pub fn set_error(msg: String) {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(msg));
}

/// Retrieve and clear the last error message.
pub fn take_error() -> Option<String> {
    LAST_ERROR.with(|e| e.borrow_mut().take())
}

// ---------------------------------------------------------------------------
// Reticulum lifecycle
// ---------------------------------------------------------------------------

/// Initialise the Reticulum singleton.
///
/// `config_dir` – path to the directory containing the `config` file.
/// `loglevel`   – 0..7 (LOG_NONE .. LOG_EXTREME), or -1 for default.
///
/// Returns `Ok(())` on success.
pub fn init(config_dir: &str, loglevel: i32) -> Result<(), String> {
    let lvl = if loglevel < 0 { None } else { Some(loglevel) };
    let dir = config_dir.to_string();
    match std::panic::catch_unwind(move || {
        Reticulum::init(
            Some(dir.into()),
            lvl,
            None,  // logdest
            None,  // verbosity
            false, // require_shared_instance
            None,  // shared_instance_type
        )
    }) {
        Ok(result) => result,
        Err(panic) => {
            let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic during init".to_string()
            };
            Err(format!("Reticulum init panicked: {}", msg))
        }
    }
}

/// Shut down Reticulum (best-effort).
pub fn shutdown() -> Result<(), String> {
    crate::reticulum::exit_handler();
    Ok(())
}

/// Set the log destination to LOG_CALLBACK and install the given closure.
pub fn set_log_callback<F: Fn(String) + Send + Sync + 'static>(callback: F) {
    let mut state = crate::LOG_STATE.lock().unwrap();
    state.logdest = crate::LOG_CALLBACK;
    state.logcall = Some(std::sync::Arc::new(callback));
    state.always_override_destination = false;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Create a new random identity.  Returns a handle.
pub fn identity_create() -> Result<u64, String> {
    let id = Identity::new(true);
    Ok(store_handle(id))
}

/// Load an identity from a file.  Returns a handle.
pub fn identity_from_file(path: &str) -> Result<u64, String> {
    let id = Identity::from_file(Path::new(path))?;
    Ok(store_handle(id))
}

/// Load an identity from raw private-key bytes (64 bytes).  Returns a handle.
pub fn identity_from_bytes(bytes: &[u8]) -> Result<u64, String> {
    let id = Identity::from_bytes(bytes)?;
    Ok(store_handle(id))
}

/// Persist an identity to a file.
pub fn identity_to_file(handle: u64, path: &str) -> Result<(), String> {
    let id: Identity =
        get_handle(handle).ok_or_else(|| "invalid identity handle".to_string())?;
    id.to_file(Path::new(path))
}

/// Return the public key bytes (64 bytes: 32 enc ‖ 32 sign).
pub fn identity_public_key(handle: u64) -> Result<Vec<u8>, String> {
    let id: Identity =
        get_handle(handle).ok_or_else(|| "invalid identity handle".to_string())?;
    id.get_public_key()
}

/// Return the truncated identity hash (16 bytes).
pub fn identity_hash(handle: u64) -> Result<Vec<u8>, String> {
    let id: Identity =
        get_handle(handle).ok_or_else(|| "invalid identity handle".to_string())?;
    id.hash
        .clone()
        .ok_or_else(|| "identity has no hash (no keys loaded)".to_string())
}

/// Destroy an identity handle.
pub fn identity_destroy(handle: u64) -> Result<(), String> {
    if destroy_handle(handle) {
        Ok(())
    } else {
        Err("invalid identity handle".to_string())
    }
}

// ---------------------------------------------------------------------------
// Destination helpers
// ---------------------------------------------------------------------------

/// Compute the destination hash for an identity + app_name + aspects
/// without creating a full Destination object.
pub fn destination_hash_for(
    identity_handle: u64,
    app_name: &str,
    aspects: &[&str],
) -> Result<Vec<u8>, String> {
    let id: Identity =
        get_handle(identity_handle).ok_or_else(|| "invalid identity handle".to_string())?;
    let id_hash = id
        .hash
        .as_deref()
        .ok_or_else(|| "identity has no hash".to_string())?;
    Ok(Destination::hash(Some(id_hash), app_name, aspects))
}

/// Create an outbound destination for a known identity and return a handle.
pub fn destination_create_outbound(
    identity_handle: u64,
    app_name: &str,
    aspects: Vec<String>,
) -> Result<u64, String> {
    let id: Identity =
        get_handle(identity_handle).ok_or_else(|| "invalid identity handle".to_string())?;
    let dest = Destination::new_outbound(
        Some(id),
        DestinationType::Single,
        app_name.to_string(),
        aspects,
    )?;
    Ok(store_handle(dest))
}

// ---------------------------------------------------------------------------
// Transport / path queries
// ---------------------------------------------------------------------------

/// Check whether a path to the given destination hash is known.
pub fn transport_has_path(dest_hash: &[u8]) -> bool {
    Transport::has_path(dest_hash)
}

/// Request a path to a destination hash.
pub fn transport_request_path(dest_hash: &[u8]) -> Result<(), String> {
    Transport::request_path(dest_hash, None, None, None, None);
    Ok(())
}

/// Return the number of hops to a destination, or -1 if unknown.
pub fn transport_hops_to(dest_hash: &[u8]) -> i32 {
    let h = Transport::hops_to(dest_hash);
    if h == 255 { -1 } else { h as i32 }
}

// ---------------------------------------------------------------------------
// Announce filtering
// ---------------------------------------------------------------------------

/// Enable or disable early-dropping of inbound announce packets at the
/// transport layer.  When `true`, all ANNOUNCE packets are silently
/// discarded except PATH_RESPONSE replies to our own path requests.
/// This is opt-in (default: `false`).
pub fn set_drop_announces(enabled: bool) {
    Transport::set_drop_announces(enabled);
}

/// Query whether announce dropping is currently enabled.
pub fn get_drop_announces() -> bool {
    Transport::drop_announces_enabled()
}

// ---------------------------------------------------------------------------
// Keepalive tuning
// ---------------------------------------------------------------------------

/// Adjust the keepalive interval (in seconds) for all active links and TCP
/// backbone connections.  Pass `0.0` to restore compiled-in defaults.
pub fn set_keepalive_interval(secs: f64) -> Result<(), String> {
    let instance = Reticulum::get_instance()
        .ok_or_else(|| "Reticulum not initialised".to_string())?;
    let reticulum = instance.lock().unwrap();
    reticulum.set_keepalive_interval(secs);
    Ok(())
}
