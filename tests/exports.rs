//! The FFI surface, called in-process through the rlib.

use std::ffi::{CStr, CString, c_char};

use bddkit_script::*;
use regex::Regex;
use serde_json::{Value, json};

fn take(p: *mut c_char) -> Value {
    assert!(!p.is_null());
    // SAFETY: `p` is a non-null reply from this library, NUL-terminated by
    // `CString::into_raw`, and not yet freed.
    let text = unsafe { CStr::from_ptr(p) }
        .to_str()
        .expect("utf8")
        .to_owned();
    // SAFETY: `p` came from this library and is freed exactly once, here.
    unsafe { bddkit_free_string(p) };
    serde_json::from_str(&text).expect("JSON reply")
}

fn call(f: extern "C" fn(*const c_char) -> *mut c_char, request: Value) -> Value {
    let c = CString::new(request.to_string()).expect("no NUL");
    take(f(c.as_ptr()))
}

#[test]
fn the_manifest_claims_script_shared_with_an_implicit_instance() {
    let v = take(bddkit_manifest());
    assert_eq!(v["name"], "script");
    assert_eq!(v["groups"], json!(["script"]));
    assert_eq!(v["concurrency"], "shared");
    assert_eq!(v["implicit_instance"], json!({"script": {}}));
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(v, serde_json::from_str::<Value>(&manifest_json()).unwrap());
}

#[test]
fn the_abi_is_three_and_matches_the_plugin_json() {
    let declared: Value = serde_json::from_str(include_str!("../bddkit-plugin.json")).unwrap();
    assert_eq!(bddkit_abi_version(), 3);
    assert_eq!(declared["abi"], bddkit_abi_version());
}

#[test]
fn the_two_steps_are_listed_and_match_their_text() {
    let steps = take(bddkit_list_steps());
    let steps = steps.as_array().expect("array");
    assert_eq!(steps.len(), 2);
    for s in steps {
        assert_eq!(s["group"], "script");
        assert_eq!(s["kind"], "action");
        assert_eq!(s["wants_vars"], true);
        assert_eq!(s["raw_docstring"], true);
        assert!(s["description"].as_str().is_some_and(|d| !d.is_empty()));
    }
    let named = Regex::new(steps[0]["pattern"].as_str().unwrap()).unwrap();
    let bare = Regex::new(steps[1]["pattern"].as_str().unwrap()).unwrap();
    let caps = named
        .captures(r#"I execute script to "jwt":"#)
        .expect("named");
    assert_eq!(&caps["name"], "jwt");
    assert!(bare.is_match("I execute script to variables:"));
    assert!(!named.is_match("I execute the script:"));
    assert!(!bare.is_match("I execute the script:"));
    assert!(!named.is_match("I execute script to variables:"));
}

#[test]
fn dispatch_runs_a_script_through_the_export() {
    let made = call(bddkit_init_instance, json!({"config": {}}));
    let handle = made["handle"].as_u64().expect("handle");
    let req = json!({
        "args": ["joined"], "docstring": "\nlet a = 4;\n`${a}|5`\n", "table": null,
        "vars": {"k": {"value": null, "secret": false}},
    });
    let req = CString::new(req.to_string()).unwrap();
    let r = take(bddkit_dispatch(handle, 0, req.as_ptr()));
    assert_eq!(r["status"], "passed", "{r}");
    assert_eq!(r["vars"], json!({"joined": "4|5"}));
    take(bddkit_drop_instance(handle));
}

#[test]
fn validate_step_answers_ok_or_an_error() {
    let good = json!({"args": ["x"], "docstring": "\nbase64(\"x\")\n", "table": null});
    let c = CString::new(good.to_string()).unwrap();
    assert_eq!(
        take(bddkit_validate_step(0, c.as_ptr())),
        json!({"ok": true})
    );
    let bad = json!({"args": ["x"], "docstring": "\nbase46(\"x\")\n", "table": null});
    let c = CString::new(bad.to_string()).unwrap();
    let r = take(bddkit_validate_step(0, c.as_ptr()));
    assert_eq!(r["ok"], false);
    assert!(r["error"].as_str().unwrap().contains("unknown function"));
    assert_eq!(take(bddkit_validate_step(0, std::ptr::null()))["ok"], false);
    let c = CString::new("not json").unwrap();
    assert_eq!(take(bddkit_validate_step(0, c.as_ptr()))["ok"], false);
}

#[test]
fn validate_config_accepts_an_object_and_refuses_anything_else() {
    assert_eq!(
        call(bddkit_validate_config, json!({"config": {}})),
        json!({"ok": true})
    );
    let bad = call(bddkit_validate_config, json!({"config": [1]}));
    assert_eq!(bad["ok"], false);
    assert!(bad["error"].as_str().is_some_and(|e| !e.is_empty()));
}

#[test]
fn an_instance_is_created_dispatched_to_and_dropped_once() {
    let made = call(bddkit_init_instance, json!({"config": {}}));
    assert_eq!(made["ok"], true);
    let handle = made["handle"].as_u64().expect("handle");

    let req = CString::new("{}").unwrap();
    let r = take(bddkit_dispatch(handle, 99, req.as_ptr()));
    assert_eq!(r["status"], "fatal");
    assert!(r["error"].as_str().unwrap().contains("unknown step"));

    assert_eq!(take(bddkit_drop_instance(handle)), json!({"ok": true}));
    let again = take(bddkit_drop_instance(handle));
    assert_eq!(again["ok"], false);
}

#[test]
fn dispatch_to_an_unknown_handle_is_fatal() {
    let req = CString::new("{}").unwrap();
    let r = take(bddkit_dispatch(0xdead, 0, req.as_ptr()));
    assert_eq!(r["status"], "fatal");
    assert!(r["error"].as_str().unwrap().contains("unknown handle"));
}

#[test]
fn a_null_request_pointer_never_panics() {
    let null = std::ptr::null();
    assert_eq!(take(bddkit_validate_config(null))["ok"], false);
    assert_eq!(take(bddkit_init_instance(null))["ok"], false);
    assert_eq!(take(bddkit_dispatch(1, 0, null))["status"], "fatal");
    // SAFETY: the contract allows a null pointer, which is ignored.
    unsafe { bddkit_free_string(std::ptr::null_mut()) };
}
