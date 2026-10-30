//! bddkit plugin that runs short Rhai scripts to derive values inside feature
//! files. Written against docs/plugin-authoring.md; it must never need the
//! host's source.

mod script;

use script::steps::{err, fatal, ok};
use std::collections::HashSet;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// Outside `guard`, and safe there only because it provably cannot panic:
/// `CString::new` returns a `Result` and the fallback literal has no interior
/// NUL. Anything added here must keep that property.
fn out(s: String) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| {
            CString::new("{\"ok\":false,\"error\":\"NUL in reply\"}").expect("literal")
        })
        .into_raw()
}

/// Inside `guard` at every call site.
fn input(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the host passes a NUL-terminated string that outlives the call.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// The shape of the reply a panic is turned into.
enum Reply {
    Dispatch,
    Envelope,
}

/// A panic must never unwind across the FFI boundary. Every export is
/// guarded except two that cannot panic: `bddkit_abi_version` returns a
/// constant and `bddkit_free_string` only calls `CString::from_raw` on a
/// non-null pointer.
fn guard(reply: Reply, body: impl FnOnce() -> String) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(text) => out(text),
        Err(_) => out(match reply {
            Reply::Dispatch => r#"{"status":"fatal","error":"the plugin panicked"}"#.to_string(),
            Reply::Envelope => r#"{"ok":false,"error":"the plugin panicked"}"#.to_string(),
        }),
    }
}

pub fn manifest_json() -> String {
    serde_json::json!({
        "name": "script",
        "version": env!("CARGO_PKG_VERSION"),
        "groups": ["script"],
        // No state of any kind lives in an instance.
        "concurrency": "shared",
        "implicit_instance": { "script": {} },
    })
    .to_string()
}

#[unsafe(no_mangle)]
pub extern "C" fn bddkit_abi_version() -> u32 {
    3
}

#[unsafe(no_mangle)]
pub extern "C" fn bddkit_manifest() -> *mut c_char {
    guard(Reply::Envelope, manifest_json)
}

#[unsafe(no_mangle)]
pub extern "C" fn bddkit_list_steps() -> *mut c_char {
    guard(Reply::Envelope, script::steps::steps_json)
}

/// # Safety
/// `s` must be a pointer this library returned and has not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bddkit_free_string(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: per the contract above, `s` came from `CString::into_raw`.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Eager, at startup, for every declared instance. The config is `{}`.
#[unsafe(no_mangle)]
pub extern "C" fn bddkit_validate_config(request: *const c_char) -> *mut c_char {
    guard(Reply::Envelope, move || {
        match serde_json::from_str::<serde_json::Value>(&input(request)) {
            Ok(v) if v["config"].is_object() => ok(),
            Ok(_) => err("the script resource takes an object (it has no settings)"),
            Err(e) => err(&e.to_string()),
        }
    })
}

/// A handle is a key into this table, never a pointer. An instance holds no
/// state, so the table is only the set of handles that are live.
static INSTANCES: LazyLock<Mutex<HashSet<u64>>> = LazyLock::new(Mutex::default);
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

#[unsafe(no_mangle)]
pub extern "C" fn bddkit_init_instance(request: *const c_char) -> *mut c_char {
    guard(Reply::Envelope, move || {
        if let Err(e) = serde_json::from_str::<serde_json::Value>(&input(request)) {
            return err(&e.to_string());
        }
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
        INSTANCES.lock().expect("instances").insert(handle);
        serde_json::json!({"ok": true, "handle": handle}).to_string()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn bddkit_dispatch(
    handle: u64,
    step_index: u32,
    request: *const c_char,
) -> *mut c_char {
    guard(Reply::Dispatch, move || {
        let request = match serde_json::from_str::<serde_json::Value>(&input(request)) {
            Ok(v) => v,
            Err(e) => return fatal(&e.to_string(), &[]),
        };
        if !INSTANCES.lock().expect("instances").contains(&handle) {
            return fatal("unknown handle", &[]);
        }
        script::steps::route(step_index, &request)
    })
}

/// Static check of one step before the first request; no handle.
#[unsafe(no_mangle)]
pub extern "C" fn bddkit_validate_step(step_index: u32, request: *const c_char) -> *mut c_char {
    guard(Reply::Envelope, move || {
        match serde_json::from_str::<serde_json::Value>(&input(request)) {
            Ok(v) => script::steps::validate(step_index, &v),
            Err(e) => err(&e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn bddkit_drop_instance(handle: u64) -> *mut c_char {
    guard(Reply::Envelope, move || {
        if INSTANCES.lock().expect("instances").remove(&handle) {
            ok()
        } else {
            err("unknown handle")
        }
    })
}
