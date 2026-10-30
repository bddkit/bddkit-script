//! `vars`, the script's read-only view of the file's variables.

use rhai::{Dynamic, Engine, EvalAltResult, Position};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A snapshot of the visible variables. The host already decided which are
/// secret; reading one is remembered, because a value computed from it is a
/// credential nobody named.
#[derive(Clone)]
pub struct Vars {
    /// `None` is the host's `<<null>>`.
    values: Arc<HashMap<String, (Option<String>, bool)>>,
    read_secret: Arc<AtomicBool>,
}

impl Vars {
    /// Parses the request's `{name: {"value": string|null, "secret": bool}}`.
    pub fn from_request(request: &serde_json::Value) -> Result<Self, String> {
        let entries = request
            .as_object()
            .ok_or("vars: expected an object of variables")?;
        let mut values = HashMap::with_capacity(entries.len());
        for (name, entry) in entries {
            let bad = |why: &str| format!("vars: variable {name:?} {why}");
            let entry = entry.as_object().ok_or_else(|| bad("is not an object"))?;
            let value = match entry.get("value") {
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                Some(serde_json::Value::Null) => None,
                _ => return Err(bad("has a value that is neither a string nor null")),
            };
            let secret = entry
                .get("secret")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| bad("has a secret flag that is not a boolean"))?;
            values.insert(name.clone(), (value, secret));
        }
        Ok(Self {
            values: Arc::new(values),
            read_secret: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Whether the script read a secret value.
    pub fn read_secret(&self) -> bool {
        self.read_secret.load(Ordering::Relaxed)
    }

    /// The value of every secret entry, for masking what an error quotes.
    pub fn secret_values(&self) -> Vec<String> {
        self.values
            .values()
            .filter(|(_, secret)| *secret)
            .filter_map(|(value, _)| value.clone())
            .collect()
    }

    fn get(&mut self, name: &str) -> Result<Dynamic, Box<EvalAltResult>> {
        let (value, secret) = self.values.get(name).ok_or_else(|| {
            Box::new(EvalAltResult::ErrorRuntime(
                format!("vars: no variable named {name:?}").into(),
                Position::NONE,
            ))
        })?;
        if *secret {
            self.read_secret.store(true, Ordering::Relaxed);
        }
        Ok(value.clone().map_or(Dynamic::UNIT, Dynamic::from))
    }
}

pub fn register(engine: &mut Engine) {
    engine.register_type_with_name::<Vars>("Vars");
    // `vars.name` has no getter of its own: Rhai falls back to this indexer.
    engine.register_indexer_get(Vars::get);
    engine.register_fn("contains", |vars: &mut Vars, name: &str| {
        vars.values.contains_key(name)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::{Engine, Scope};
    use serde_json::json;

    fn setup(request: serde_json::Value) -> (Engine, Scope<'static>, Vars) {
        let vars = Vars::from_request(&request).unwrap();
        let mut engine = Engine::new();
        register(&mut engine);
        let mut scope = Scope::new();
        scope.push_constant("vars", vars.clone());
        (engine, scope, vars)
    }

    #[test]
    fn a_name_reads_through_property_and_indexer() {
        let (engine, mut scope, _) = setup(json!({"user_id": {"value": "7", "secret": false}}));
        assert_eq!(
            engine
                .eval_with_scope::<String>(&mut scope, "vars.user_id")
                .unwrap(),
            "7"
        );
        assert_eq!(
            engine
                .eval_with_scope::<String>(&mut scope, r#"vars["user_id"]"#)
                .unwrap(),
            "7"
        );
    }

    #[test]
    fn an_unknown_name_names_itself_in_the_error() {
        let (engine, mut scope, _) = setup(json!({}));
        let err = engine
            .eval_with_scope::<String>(&mut scope, "vars.nope")
            .unwrap_err();
        assert!(err.to_string().contains("nope"), "{err}");
    }

    #[test]
    fn contains_does_not_count_as_a_read() {
        let (engine, mut scope, vars) = setup(json!({"k": {"value": "hunter22", "secret": true}}));
        assert!(
            engine
                .eval_with_scope::<bool>(&mut scope, r#"vars.contains("k")"#)
                .unwrap()
        );
        assert!(!vars.read_secret());
    }

    #[test]
    fn only_reading_a_secret_entry_is_remembered() {
        let (engine, mut scope, vars) = setup(json!({
            "k": {"value": "hunter22", "secret": true},
            "greeting": {"value": "hi", "secret": false},
        }));
        engine
            .eval_with_scope::<String>(&mut scope, "vars.greeting")
            .unwrap();
        assert!(!vars.read_secret());
        engine
            .eval_with_scope::<String>(&mut scope, "vars.k")
            .unwrap();
        assert!(vars.read_secret());
    }

    #[test]
    fn a_null_value_reads_as_unit() {
        let (engine, mut scope, _) = setup(json!({"n": {"value": null, "secret": false}}));
        assert!(engine.eval_with_scope::<()>(&mut scope, "vars.n").is_ok());
    }

    #[test]
    fn secret_values_lists_every_secret_entry_and_nothing_else() {
        let (_, _, vars) = setup(json!({
            "a": {"value": "one", "secret": true},
            "b": {"value": "two", "secret": false},
            "c": {"value": null, "secret": true},
        }));
        assert_eq!(vars.secret_values(), vec!["one".to_string()]);
    }

    #[test]
    fn a_malformed_request_names_the_variable() {
        for bad in [
            json!({"x": {"value": 5, "secret": false}}),
            json!({"x": {"value": "a", "secret": "yes"}}),
            json!({"x": {"value": "a"}}),
            json!({"x": "a"}),
        ] {
            let err = Vars::from_request(&bad).err().unwrap();
            assert!(err.contains("\"x\""), "{err}");
        }
        assert!(Vars::from_request(&json!([])).is_err());
    }
}
