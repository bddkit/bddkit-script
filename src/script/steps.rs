//! The two script steps: the step list, the dispatch reply and the static check.

use super::{engine, export, scope::Vars};
use serde_json::{Value, json};

pub fn steps_json() -> String {
    json!([
        {
            "pattern": r#"^I execute script to "(?P<name>[^"]+)":$"#,
            "group": "script",
            "kind": "action",
            "description": "Run the script in the doc string and save its result as the variable <name>",
            "wants_vars": true,
            "raw_docstring": true,
        },
        {
            "pattern": "^I execute script to variables:$",
            "group": "script",
            "kind": "action",
            "description": "Run the script in the doc string and save the fields of its result as variables",
            "wants_vars": true,
            "raw_docstring": true,
        },
    ])
    .to_string()
}

pub(crate) fn fatal(message: &str, secrets: &[String]) -> String {
    json!({"status": "fatal", "error": message, "secrets": secrets}).to_string()
}

pub(crate) fn ok() -> String {
    r#"{"ok":true}"#.to_string()
}

pub(crate) fn err(message: &str) -> String {
    json!({"ok": false, "error": message}).to_string()
}

/// The script, and for step 0 the target name (`args[0]`).
fn parts(step_index: u32, request: &Value) -> Result<(&str, Option<&str>), String> {
    if step_index > 1 {
        return Err(format!("unknown step {step_index}"));
    }
    let script = request["docstring"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or("the step needs a script in a doc string")?;
    if step_index == 1 {
        return Ok((script, None));
    }
    let name = request["args"][0]
        .as_str()
        .ok_or("the step needs a variable name")?;
    Ok((script, Some(name)))
}

/// The dispatch reply for a step.
pub fn route(step_index: u32, request: &Value) -> String {
    let (script, target) = match parts(step_index, request) {
        Ok(p) => p,
        Err(e) => return fatal(&e, &[]),
    };
    if let Some(name) = target
        && let Err(e) = export::check_name(name)
    {
        return fatal(&e, &[]);
    }
    let vars = match Vars::from_request(&request["vars"]) {
        Ok(v) => v,
        Err(e) => return fatal(&e, &[]),
    };
    match engine::run(script, target, vars) {
        Ok(o) => json!({
            "status": "passed",
            "vars": o.vars.into_iter().map(|(k, v)| (k, Value::String(v))).collect::<serde_json::Map<_, _>>(),
            "secrets": o.secrets,
            "diagnostics": [],
        })
        .to_string(),
        Err(e) => fatal(&e.message, &e.secrets),
    }
}

/// The `{"ok":…}` envelope of the static check. The host does not mask this
/// error, so it must not quote an argument (none of ours is a secret).
pub fn validate(step_index: u32, request: &Value) -> String {
    let result = parts(step_index, request).and_then(|(script, target)| {
        if let Some(name) = target
            && !name.contains("<<")
        {
            export::check_name(name)?;
        }
        engine::check(script)
    });
    match result {
        Ok(()) => ok(),
        Err(e) => err(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJBbm4ifQ.92qA8pVES5gosRQTGwzUCHOEfgNXozGuNWWdpnLAL4Y";

    fn req(args: &[&str], script: &str, vars: Value) -> Value {
        json!({"args": args, "docstring": format!("\n{script}\n"), "table": null, "vars": vars})
    }

    fn reply(step: u32, request: &Value) -> Value {
        serde_json::from_str(&route(step, request)).expect("JSON")
    }

    fn check(step: u32, args: &[&str], script: &str) -> Value {
        let r = json!({"args": args, "docstring": format!("\n{script}\n"), "table": null});
        serde_json::from_str(&validate(step, &r)).expect("JSON")
    }

    #[test]
    fn step_zero_saves_the_result_under_the_name() {
        let r = reply(0, &req(&["joined"], "let a = 4;\n`${a}|5`", json!({})));
        assert_eq!(r["status"], "passed");
        assert_eq!(r["vars"], json!({"joined": "4|5"}));
        assert_eq!(r["secrets"], json!([]));
    }

    #[test]
    fn an_array_and_a_map_are_flattened() {
        let r = reply(0, &req(&["ids"], "[7, 8]", json!({})));
        assert_eq!(
            r["vars"],
            json!({"ids_0": "7", "ids_1": "8", "ids_length": "2"})
        );
        let r = reply(
            1,
            &req(&[], r#"#{ token: "t", user: #{ name: "Ann" } }"#, json!({})),
        );
        assert_eq!(r["vars"], json!({"token": "t", "user_name": "Ann"}));
        let r = reply(1, &req(&[], "5", json!({})));
        assert_eq!(r["status"], "fatal");
        assert!(r["error"].as_str().unwrap().contains("expected a map"));
    }

    #[test]
    fn a_jwt_matches_an_independent_implementation() {
        let script = r#"
let h = base64url(`{"alg":"HS256","typ":"JWT"}`);
let p = base64url(`{"sub":"${vars.user}"}`);
let s = base64url(hmac_sha256(vars.jwtSecret, `${h}.${p}`));
`${h}.${p}.${s}`"#;
        let vars = json!({
            "user": {"value": "Ann", "secret": false},
            "jwtSecret": {"value": "s3cret", "secret": true},
        });
        let r = reply(0, &req(&["token"], script, vars));
        assert_eq!(r["status"], "passed", "{r}");
        assert_eq!(r["vars"]["token"], JWT);
        // Reading a secret makes the exported token a secret too.
        assert!(r["secrets"].as_array().unwrap().contains(&json!(JWT)));
    }

    #[test]
    fn reading_only_plain_variables_exports_no_secrets() {
        let vars = json!({"user": {"value": "Ann", "secret": false}});
        let r = reply(0, &req(&["x"], "vars.user", vars));
        assert_eq!(r["status"], "passed", "{r}");
        assert_eq!(r["secrets"], json!([]));
    }

    #[test]
    fn an_hmac_registers_its_key() {
        let script = r#"hex(hmac_sha256("topsecretkey", "payload"))"#;
        let r = reply(0, &req(&["m"], script, json!({})));
        assert_eq!(r["status"], "passed", "{r}");
        let secrets = r["secrets"].as_array().unwrap();
        assert!(secrets.contains(&json!("topsecretkey")));
    }

    #[test]
    fn a_failure_names_the_line_and_never_quotes_a_secret_variable() {
        let vars = json!({"pw": {"value": "hunter2hunter2", "secret": true}});
        let r = reply(0, &req(&["x"], "let a = 1;\nbase64_decode(vars.pw)", vars));
        assert_eq!(r["status"], "fatal");
        let e = r["error"].as_str().unwrap();
        assert!(
            e.contains("script line 2") && e.contains("base64_decode"),
            "{e}"
        );
        assert!(!e.contains("hunter2hunter2"), "{e}");
        let secrets = r["secrets"].as_array().unwrap();
        assert!(secrets.contains(&json!("hunter2hunter2")));
    }

    #[test]
    fn a_bad_name_or_a_missing_script_is_fatal() {
        for name in ["1st", "null"] {
            let r = reply(0, &req(&[name], "1", json!({})));
            assert_eq!(r["status"], "fatal", "{name}");
        }
        for doc in [json!(null), json!("\n  \n")] {
            let r = reply(
                0,
                &json!({"args": ["x"], "docstring": doc, "table": null, "vars": {}}),
            );
            assert_eq!(r["status"], "fatal");
            let e = r["error"].as_str().unwrap();
            assert!(e.contains("needs a script in a doc string"), "{e}");
        }
    }

    #[test]
    fn validate_refuses_what_it_can_see_is_wrong() {
        let r = check(0, &["x"], "base46(\"x\")");
        assert_eq!(r["ok"], false);
        let e = r["error"].as_str().unwrap();
        assert!(
            e.contains("unknown function base46") && e.contains("line 1"),
            "{e}"
        );
        assert_eq!(check(0, &["x"], "hmac_sha256(\"a\")")["ok"], false);
        assert_eq!(check(0, &["x"], "let a = ;")["ok"], false);
        assert_eq!(check(0, &["x"], "vars.user + nope")["ok"], false);
        assert_eq!(check(0, &["x"], "   ")["ok"], false);
        assert_eq!(check(0, &["1st"], "1")["ok"], false);
        assert_eq!(check(0, &["<<name>>"], "1")["ok"], true);
        assert_eq!(check(0, &["x"], "base64(\"x\")")["ok"], true);
        assert_eq!(check(1, &[], "#{a: 1}")["ok"], true);
    }
}
