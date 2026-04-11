//! Universal C FFI for the Reticulum transport client.
//!
//! This is the **single, authoritative** C interface for any language bridge
//! wanting Reticulum transport without LXMF.  Mirrors the `lxmf_*` pattern
//! in LXMF-rust/cffi.rs.
//!
//! # Naming convention
//!
//! | Prefix              | Scope                          |
//! |---------------------|--------------------------------|
//! | `rns_client_*`      | client-handle operations       |
//! | `rns_transport_*`   | path queries                   |
//! | `rns_packet_*`      | single-shot encrypted packets  |
//! | `rns_link_*`        | blocking link request          |
//! | `rns_*`             | library-level helpers/settings |
//!
//! # Handle convention
//!
//! Opaque `u64` handles.  `0` = error (check [`rns_last_error`]).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

use crate::client::{ReticulumClient, ReticulumConfig};
use crate::ffi;
use crate::ffi::{destroy_handle, get_handle, set_error, store_handle, take_error};

// =========================================================================
// Internal helpers
// =========================================================================

unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

fn string_to_cstr(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

fn slice_from_raw(ptr: *const u8, len: u32) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(ptr, len as usize).to_vec() }
}

/// Lock a client handle or return -1.
macro_rules! with_client {
    ($handle:expr, $name:ident, $body:block) => {{
        let arc: Arc<Mutex<ReticulumClient>> = match get_handle($handle) {
            Some(h) => h,
            None => {
                set_error("invalid client handle".into());
                return -1;
            }
        };
        let $name = arc.lock().unwrap();
        $body
    }};
}

// =========================================================================
// Library helpers
// =========================================================================

/// Get the last error message.  Caller must free with [`rns_free_string`].
/// Returns NULL if no error is set.
#[no_mangle]
pub extern "C" fn rns_last_error() -> *mut c_char {
    match take_error() {
        Some(msg) => string_to_cstr(&msg),
        None => std::ptr::null_mut(),
    }
}

/// Free a string returned by this library.
#[no_mangle]
pub extern "C" fn rns_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); }
    }
}

/// Free bytes returned by this library.
#[no_mangle]
pub extern "C" fn rns_free_bytes(ptr: *mut u8, len: u32) {
    if !ptr.is_null() && len > 0 {
        unsafe { let _ = Vec::from_raw_parts(ptr, len as usize, len as usize); }
    }
}

// =========================================================================
// Client lifecycle
// =========================================================================

/// Start a Reticulum transport client (init transport + load/create identity).
///
/// Returns a client handle (>0) or 0 on error.
#[no_mangle]
pub extern "C" fn rns_client_start(
    config_dir: *const c_char,
    identity_path: *const c_char,
    create_identity: i32,
    log_level: i32,
) -> u64 {
    let config = ReticulumConfig {
        config_dir: unsafe { cstr_to_string(config_dir) },
        identity_path: unsafe { cstr_to_string(identity_path) },
        create_identity: create_identity != 0,
        log_level,
    };

    match ReticulumClient::start(config) {
        Ok(client) => store_handle(Arc::new(Mutex::new(client))),
        Err(e) => {
            set_error(e);
            0
        }
    }
}

/// Shut down a client: destroy identity + tear down transport.
/// Handle is invalidated.  Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rns_client_shutdown(client: u64) -> i32 {
    let arc: Arc<Mutex<ReticulumClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle".into());
            return -1;
        }
    };
    let c = arc.lock().unwrap();
    match c.shutdown() {
        Ok(()) => {
            destroy_handle(client);
            0
        }
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

// =========================================================================
// Client queries
// =========================================================================

/// Get the client's identity handle (for passing to transport-level
/// functions like `rns_link_request`).
/// Returns 0 on error.
#[no_mangle]
pub extern "C" fn rns_client_identity_handle(client: u64) -> u64 {
    let arc: Arc<Mutex<ReticulumClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle".into());
            return 0;
        }
    };
    let c = arc.lock().unwrap();
    c.identity_handle
}

/// Get the client's 16-byte identity hash.
/// Writes to `out_buf`.  Returns bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn rns_client_identity_hash(
    client: u64,
    out_buf: *mut u8,
    buf_len: u32,
) -> i32 {
    with_client!(client, c, {
        let hash = &c.identity_hash;
        if buf_len < hash.len() as u32 {
            set_error("buffer too small".into());
            return -1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, hash.len());
        }
        hash.len() as i32
    })
}

/// Compute a destination hash for this identity + app_name + aspects.
/// `aspects` is comma-separated (e.g. "delivery" or "apns,notify").
/// Writes to `out_buf`.  Returns bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn rns_client_dest_hash(
    client: u64,
    app_name: *const c_char,
    aspects: *const c_char,
    out_buf: *mut u8,
    buf_len: u32,
) -> i32 {
    with_client!(client, c, {
        let app = unsafe { cstr_to_string(app_name) };
        let asp_str = unsafe { cstr_to_string(aspects) };
        let asp_vec: Vec<&str> = asp_str.split(',').map(|s| s.trim()).collect();

        match c.destination_hash(&app, &asp_vec) {
            Ok(hash) => {
                if buf_len < hash.len() as u32 {
                    set_error("buffer too small".into());
                    return -1;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, hash.len());
                }
                hash.len() as i32
            }
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Persist path table and cached data to disk.
#[no_mangle]
pub extern "C" fn rns_client_persist(client: u64) {
    if let Some(arc) = get_handle::<Arc<Mutex<ReticulumClient>>>(client) {
        if let Ok(c) = arc.lock() {
            c.persist();
        }
    }
}

// =========================================================================
// Transport / path queries (stateless — don't need a client handle)
// =========================================================================

/// Check whether transport has a path to the destination.  Returns 1/0.
#[no_mangle]
pub extern "C" fn rns_transport_has_path(dest_hash: *const u8, len: u32) -> i32 {
    let h = slice_from_raw(dest_hash, len);
    if ffi::transport_has_path(&h) { 1 } else { 0 }
}

/// Request a path to a destination.  Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rns_transport_request_path(dest_hash: *const u8, len: u32) -> i32 {
    let h = slice_from_raw(dest_hash, len);
    match ffi::transport_request_path(&h) {
        Ok(()) => 0,
        Err(e) => { set_error(e); -1 }
    }
}

/// Get hop count to a destination.  Returns hops or -1 if unknown.
#[no_mangle]
pub extern "C" fn rns_transport_hops_to(dest_hash: *const u8, len: u32) -> i32 {
    let h = slice_from_raw(dest_hash, len);
    ffi::transport_hops_to(&h)
}

// =========================================================================
// Settings (stateless)
// =========================================================================

/// Enable/disable announce filtering.  1 = drop, 0 = accept.
#[no_mangle]
pub extern "C" fn rns_set_drop_announces(enabled: i32) {
    ffi::set_drop_announces(enabled != 0);
}

/// Set keepalive interval in seconds.  Returns 0 on success.
#[no_mangle]
pub extern "C" fn rns_set_keepalive_interval(secs: f64) -> i32 {
    match ffi::set_keepalive_interval(secs) {
        Ok(()) => 0,
        Err(e) => { set_error(e); -1 }
    }
}

// =========================================================================
// Identity (standalone — outside a client lifecycle)
// =========================================================================

/// Load identity from raw bytes.  Returns handle or 0 on error.
#[no_mangle]
pub extern "C" fn rns_identity_from_bytes(bytes: *const u8, len: u32) -> u64 {
    let b = slice_from_raw(bytes, len);
    match ffi::identity_from_bytes(&b) {
        Ok(h) => h,
        Err(e) => { set_error(e); 0 }
    }
}

/// Get identity public key.  Writes to `out_buf` (>= 64 bytes).
/// Returns byte count written, or -1 on error.
#[no_mangle]
pub extern "C" fn rns_identity_public_key(
    handle: u64,
    out_buf: *mut u8,
    buf_len: u32,
) -> i32 {
    match ffi::identity_public_key(handle) {
        Ok(bytes) => {
            if buf_len < bytes.len() as u32 {
                set_error("buffer too small".into());
                return -1;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
            }
            bytes.len() as i32
        }
        Err(e) => { set_error(e); -1 }
    }
}

/// Destroy a standalone identity handle.  Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rns_identity_destroy(handle: u64) -> i32 {
    match ffi::identity_destroy(handle) {
        Ok(()) => 0,
        Err(e) => { set_error(e); -1 }
    }
}

// =========================================================================
// Raw packet send
// =========================================================================

/// Send a single encrypted DATA packet to a remote destination by hash.
///
/// The remote identity must be in the known-destinations table (announce heard).
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rns_packet_send_to_hash(
    dest_hash: *const u8,
    dest_hash_len: u32,
    app_name: *const c_char,
    aspects: *const c_char,
    payload: *const u8,
    payload_len: u32,
) -> i32 {
    let hash = slice_from_raw(dest_hash, dest_hash_len);
    let app = unsafe { cstr_to_string(app_name) };
    let asp_str = unsafe { cstr_to_string(aspects) };
    let asp_vec: Vec<String> = asp_str.split(',').map(|s| s.trim().to_string()).collect();
    let data = slice_from_raw(payload, payload_len);

    let dest_handle = match ffi::destination_create_outbound_from_hash(&hash, &app, asp_vec) {
        Ok(h) => h,
        Err(e) => { set_error(e); return -1; }
    };

    let pkt_handle = match ffi::packet_create(dest_handle, &data, false) {
        Ok(h) => h,
        Err(e) => {
            destroy_handle(dest_handle);
            set_error(e);
            return -1;
        }
    };
    destroy_handle(dest_handle);

    match ffi::packet_send(pkt_handle) {
        Ok(_) => 0,
        Err(e) => { set_error(e); -1 }
    }
}

// =========================================================================
// Link-based request (synchronous one-shot)
// =========================================================================

/// Open a Link, identify, send a request, wait for response, tear down.
///
/// **Blocking** — call from a background thread.
///
/// Returns response bytes (free with `rns_free_bytes`), or NULL on error
/// (check `rns_last_error`).
#[no_mangle]
pub extern "C" fn rns_link_request(
    dest_hash: *const u8,
    dest_hash_len: u32,
    app_name: *const c_char,
    aspects: *const c_char,
    identity_handle: u64,
    path: *const c_char,
    payload: *const u8,
    payload_len: u32,
    timeout_secs: f64,
    out_len: *mut u32,
) -> *mut u8 {
    let hash = slice_from_raw(dest_hash, dest_hash_len);
    let app = unsafe { cstr_to_string(app_name) };
    let asp_str = unsafe { cstr_to_string(aspects) };
    let asp_vec: Vec<String> = asp_str.split(',').map(|s| s.trim().to_string()).collect();
    let req_path = unsafe { cstr_to_string(path) };
    let data = slice_from_raw(payload, payload_len);

    match ffi::link_request(&hash, &app, asp_vec, identity_handle, &req_path, &data, timeout_secs) {
        Ok(resp) => {
            let len = resp.len() as u32;
            let ptr = resp.leak().as_mut_ptr();
            if !out_len.is_null() {
                unsafe { *out_len = len; }
            }
            ptr
        }
        Err(e) => {
            set_error(e);
            if !out_len.is_null() {
                unsafe { *out_len = 0; }
            }
            std::ptr::null_mut()
        }
    }
}

// =========================================================================
// Network connectivity hint
// =========================================================================

/// Signal that network connectivity has been restored.
///
/// Wakes all TCP client interface reconnect loops so they attempt an
/// immediate connect instead of waiting out the full polling interval.
/// Safe to call at any time; no-op if all interfaces are already online.
#[no_mangle]
pub extern "C" fn rns_nudge_reconnect() {
    crate::interfaces::tcp_interface::nudge_reconnect();
}
