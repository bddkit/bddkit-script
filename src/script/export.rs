//! A script's result, turned into the `(name, value)` pairs a step writes.

use rhai::{Array, Dynamic, Map};
use std::collections::HashMap;

pub const MAX_VARIABLES: usize = 10_000;
pub const MAX_DEPTH: usize = 16;

/// Names `<<…>>` interpolation treats as its own.
const RESERVED: [&str; 3] = ["null", "run_id", "unique"];

/// A name `<<name>>` can read back: a non-digit first (`vars::PLACEHOLDER`),
/// then word characters, and none of the reserved ones.
pub fn check_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let ok = chars.next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && chars.all(|c| c.is_alphanumeric() || c == '_');
    if !ok {
        return Err(format!(
            "{name:?} is not a variable name <<…>> can read: a letter or _ first, then letters, digits or _"
        ));
    }
    if RESERVED.contains(&name) {
        return Err(format!("{name:?} is reserved by interpolation"));
    }
    Ok(())
}

fn check_key(key: &str) -> Result<(), String> {
    if !key.is_empty() && key.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Ok(())
    } else {
        Err(format!(
            "map key {key:?} cannot be part of a variable name: only letters, digits and _"
        ))
    }
}

struct Entry {
    name: String,
    value: String,
    origin: String,
}

/// Why a result cannot be saved: `message` names the path and the keys, which
/// a script may have computed from a secret; `summary` says the same with
/// neither.
#[derive(Debug)]
pub struct Refusal {
    pub message: String,
    pub summary: String,
}

fn refuse(message: String, summary: &str) -> Refusal {
    Refusal {
        message,
        summary: summary.to_string(),
    }
}

/// `target` names the result (`to "user"`); without one the result must be a
/// map and its top-level keys are the names.
pub fn flatten(target: Option<&str>, value: Dynamic) -> Result<Vec<(String, String)>, Refusal> {
    let mut out = Vec::new();
    match target {
        Some(name) => walk(name, name, &value, 0, &mut out)?,
        None => {
            if !value.is_map() {
                let message = format!("expected a map, got {}", value.type_name());
                return Err(refuse(message.clone(), &message));
            }
            let map: Map = value.cast();
            for (key, item) in &map {
                check_name(key).map_err(|message| {
                    refuse(
                        message,
                        "a key of the map is not a variable name <<…>> can read back",
                    )
                })?;
                walk(key, key, item, 0, &mut out)?;
            }
        }
    }
    let mut seen: HashMap<&str, &str> = HashMap::new();
    for entry in &out {
        // A key joined to its parent can spell one: `run` + `id`.
        if RESERVED.contains(&entry.name.as_str()) {
            return Err(refuse(
                format!(
                    "{:?} is reserved by interpolation, written by {}",
                    entry.name, entry.origin
                ),
                "a part of the result writes a variable name reserved by interpolation",
            ));
        }
        if let Some(first) = seen.insert(&entry.name, &entry.origin) {
            return Err(refuse(
                format!(
                    "variable {:?} is written by both {first} and {}",
                    entry.name, entry.origin
                ),
                "two parts of the result write the same variable",
            ));
        }
    }
    Ok(out.into_iter().map(|e| (e.name, e.value)).collect())
}

fn too_many() -> Refusal {
    let message = format!("more than {MAX_VARIABLES} variables from one step");
    refuse(message.clone(), &message)
}

fn walk(
    name: &str,
    path: &str,
    value: &Dynamic,
    depth: usize,
    out: &mut Vec<Entry>,
) -> Result<(), Refusal> {
    if depth > MAX_DEPTH {
        let why = format!("nesting deeper than {MAX_DEPTH}");
        return Err(refuse(format!("{path}: {why}"), &why));
    }
    if out.len() >= MAX_VARIABLES {
        return Err(too_many());
    }
    if value.is_unit() {
        let why = "the script returned nothing ()";
        return Err(refuse(format!("{path}: {why}"), why));
    }
    if value.is_blob() {
        let why = "bytes cannot be a variable; convert them with hex(…) or base64(…)";
        return Err(refuse(format!("{path}: {why}"), why));
    }
    if value.is_array() {
        let array: Array = value.clone().cast();
        for (i, item) in array.iter().enumerate() {
            walk(
                &format!("{name}_{i}"),
                &format!("{path}[{i}]"),
                item,
                depth + 1,
                out,
            )?;
        }
        if out.len() >= MAX_VARIABLES {
            return Err(too_many());
        }
        out.push(Entry {
            name: format!("{name}_length"),
            value: array.len().to_string(),
            origin: format!("{path} (array length)"),
        });
        return Ok(());
    }
    if value.is_map() {
        let map: Map = value.clone().cast();
        for (key, item) in &map {
            check_key(key).map_err(|message| {
                refuse(
                    message,
                    "a map key cannot be part of a variable name: only letters, digits and _",
                )
            })?;
            walk(
                &format!("{name}_{key}"),
                &format!("{path}.{key}"),
                item,
                depth + 1,
                out,
            )?;
        }
        return Ok(());
    }
    if value.is_string() || value.is_int() || value.is_float() || value.is_bool() || value.is_char()
    {
        out.push(Entry {
            name: name.to_string(),
            value: value.to_string(),
            origin: path.to_string(),
        });
        return Ok(());
    }
    let why = format!("a {} cannot be a variable", value.type_name());
    Err(refuse(format!("{path}: {why}"), &why))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::{Dynamic, Engine};

    fn eval(script: &str) -> Dynamic {
        Engine::new().eval::<Dynamic>(script).expect("script runs")
    }

    fn pairs(target: Option<&str>, script: &str) -> Vec<(String, String)> {
        flatten(target, eval(script)).expect("flattens")
    }

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    #[test]
    fn a_scalar_becomes_one_variable() {
        assert_eq!(pairs(Some("n"), "42"), vec![pair("n", "42")]);
        assert_eq!(pairs(Some("s"), r#""hi""#), vec![pair("s", "hi")]);
        assert_eq!(pairs(Some("b"), "true"), vec![pair("b", "true")]);
        assert_eq!(pairs(Some("f"), "1.5"), vec![pair("f", "1.5")]);
    }

    #[test]
    fn an_array_becomes_indexed_variables_and_a_length() {
        assert_eq!(
            pairs(Some("ids"), "[10, 20]"),
            vec![
                pair("ids_0", "10"),
                pair("ids_1", "20"),
                pair("ids_length", "2")
            ]
        );
    }

    #[test]
    fn an_empty_array_writes_only_its_length() {
        assert_eq!(pairs(Some("ids"), "[]"), vec![pair("ids_length", "0")]);
    }

    #[test]
    fn a_map_nests_to_any_depth() {
        let got = pairs(Some("user"), r#"#{ name: "Ann", roles: ["admin", "dev"] }"#);
        assert_eq!(
            got,
            vec![
                pair("user_name", "Ann"),
                pair("user_roles_0", "admin"),
                pair("user_roles_1", "dev"),
                pair("user_roles_length", "2"),
            ]
        );
    }

    #[test]
    fn without_a_target_the_top_level_keys_are_the_names() {
        let got = pairs(None, r#"#{ token: "t", ids: [1] }"#);
        assert_eq!(
            got,
            vec![
                pair("ids_0", "1"),
                pair("ids_length", "1"),
                pair("token", "t")
            ]
        );
    }

    #[test]
    fn without_a_target_a_non_map_is_refused() {
        let err = flatten(None, eval(r#""text""#)).unwrap_err().message;
        assert!(err.contains("expected a map, got string"), "{err}");
    }

    #[test]
    fn nothing_returned_is_never_an_empty_variable() {
        let err = flatten(Some("x"), eval("()")).unwrap_err().message;
        assert!(err.contains("returned nothing"), "{err}");
    }

    #[test]
    fn bytes_must_be_converted_explicitly() {
        let err = flatten(Some("x"), eval("blob(2)")).unwrap_err().message;
        assert!(err.contains("hex") && err.contains("base64"), "{err}");
    }

    #[test]
    fn two_paths_to_one_name_collide() {
        let err = flatten(Some("a"), eval(r#"#{ roles: [1], roles_length: 7 }"#))
            .unwrap_err()
            .message;
        assert!(err.contains("a_roles_length"), "{err}");
        assert!(err.contains("written by both"), "{err}");
    }

    #[test]
    fn a_name_that_nothing_could_read_back_is_refused() {
        assert!(check_name("1st").is_err());
        assert!(check_name("").is_err());
        assert!(check_name("with space").is_err());
        assert!(check_name("null").unwrap_err().contains("reserved"));
        assert!(check_name("run_id").is_err());
        assert!(check_name("unique").is_err());
        assert!(check_name("token_2").is_ok());
        let err = flatten(None, eval(r#"#{ "1st": "x" }"#))
            .unwrap_err()
            .message;
        assert!(err.contains("1st"), "{err}");
    }

    #[test]
    fn a_flattened_name_may_not_be_reserved_either() {
        for (target, script) in [(None, "#{ run: #{ id: 1 } }"), (Some("run"), "#{ id: 1 }")] {
            let err = flatten(target, eval(script)).unwrap_err();
            assert!(
                err.message.contains("\"run_id\" is reserved"),
                "{}",
                err.message
            );
            assert!(!err.summary.contains("run_id"), "{}", err.summary);
        }
    }

    #[test]
    fn nested_keys_only_need_word_characters() {
        let err = flatten(Some("m"), eval(r#"#{ "a b": 1 }"#))
            .unwrap_err()
            .message;
        assert!(err.contains("a b"), "{err}");
        assert!(flatten(Some("m"), eval(r#"#{ "0": 1 }"#)).is_ok());
    }

    #[test]
    fn nesting_beyond_the_limit_is_refused() {
        // Built directly: the script parser has a nesting cap of its own.
        let mut value = Dynamic::from(1_i64);
        for _ in 0..=MAX_DEPTH {
            value = Dynamic::from_array(vec![value]);
        }
        let err = flatten(Some("deep"), value).unwrap_err().message;
        assert!(err.contains("nesting"), "{err}");
    }

    #[test]
    fn an_array_length_counts_towards_the_limit() {
        let full = Dynamic::from_array((0..MAX_VARIABLES as i64).map(Dynamic::from).collect());
        let err = flatten(Some("big"), full).unwrap_err().message;
        assert!(err.contains("10000"), "{err}");
    }

    #[test]
    fn too_many_variables_are_refused() {
        let big = Dynamic::from_array((0..=MAX_VARIABLES as i64).map(Dynamic::from).collect());
        let err = flatten(Some("big"), big).unwrap_err().message;
        assert!(err.contains("10000") || err.contains("10 000"), "{err}");
    }
}
