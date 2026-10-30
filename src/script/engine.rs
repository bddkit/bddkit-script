//! The sandboxed Rhai engine: `run` executes a script and flattens its
//! result, `check` reports what can be known without running it.

use super::export;
use super::functions::{self, Secrets};
use super::scope::{self, Vars};
use rhai::{ASTNode, Dynamic, Engine, EvalAltResult, Expr, Position, Scope, Stmt};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

// ponytail: an operation count is not a clock; a heavy built-in call can run
// longer than the count suggests. Make it an option when a suite hits it.
pub const MAX_OPERATIONS: u64 = 1_000_000;

const SLEEP_REFUSED: &str = "sleep is not available in a script";

/// A sandboxed engine for ONE step call: the host functions capture `secrets`.
pub fn engine(secrets: &Secrets) -> Engine {
    let mut engine = Engine::new();
    engine.set_max_operations(MAX_OPERATIONS);
    engine.set_max_expr_depths(64, 32);
    engine.set_max_call_levels(32);
    engine.set_max_string_size(1 << 20);
    engine.set_max_array_size(export::MAX_VARIABLES);
    engine.set_max_map_size(export::MAX_VARIABLES);
    engine.disable_symbol("eval");
    // Rhai's `sleep` holds a host worker for as long as asked, counted as one
    // operation; `disable_symbol` does not reach a function, so these shadow it.
    engine.register_fn("sleep", |_: i64| -> Result<(), Box<EvalAltResult>> {
        Err(SLEEP_REFUSED.into())
    });
    engine.register_fn("sleep", |_: f64| -> Result<(), Box<EvalAltResult>> {
        Err(SLEEP_REFUSED.into())
    });
    engine.on_print(|_| {});
    engine.on_debug(|_, _, _| {});
    functions::register(&mut engine, secrets);
    scope::register(&mut engine);
    engine
}

#[derive(Debug)]
pub struct Outcome {
    pub vars: Vec<(String, String)>,
    pub secrets: Vec<String>,
}

/// A failed run still reports the secrets registered before it failed.
#[derive(Debug)]
pub struct RunError {
    pub message: String,
    pub secrets: Vec<String>,
}

fn line(position: Position) -> String {
    match position.line() {
        Some(n) => format!("script line {n}: "),
        None => String::new(),
    }
}

/// Rhai's text without the ` (line N, position M)` it appends: `line` already
/// said where.
fn without_position(error: &EvalAltResult) -> String {
    let text = error.to_string();
    let suffix = format!(" ({})", error.position());
    match text.strip_suffix(&suffix) {
        Some(stripped) if !error.position().is_none() => stripped.to_string(),
        _ => text,
    }
}

fn describe(error: &EvalAltResult) -> String {
    format!("{}{}", line(error.position()), without_position(error))
}

const HIDDEN: &str = "an error whose text is not shown, because the script used a secret";

/// What failed, for a script that used a secret: never Rhai's text as a whole,
/// which shows a thrown value or an index. A host function's failure is named
/// by its value-free form, recorded where it was raised; the variants listed
/// here quote only names and types from the script's own text. A function
/// name is the exception, as `Fn(…)` can compute one, so it is shown only when
/// the script spells it out.
fn what_failed(error: &EvalAltResult, secrets: &Secrets, script: &str) -> String {
    use EvalAltResult as E;
    match error {
        E::ErrorInFunctionCall(.., inner, _) => what_failed(inner, secrets, script),
        E::ErrorFunctionNotFound(signature, _) => {
            let name = signature.split(" (").next().unwrap_or_default();
            if script.contains(name) {
                without_position(error)
            } else {
                HIDDEN.to_string()
            }
        }
        E::ErrorRuntime(value, _) => value
            .read_lock::<rhai::ImmutableString>()
            .and_then(|text| secrets.operation_of(&text))
            .unwrap_or_else(|| HIDDEN.to_string()),
        E::ErrorVariableNotFound(..)
        | E::ErrorPropertyNotFound(..)
        | E::ErrorUnboundThis(..)
        | E::ErrorMismatchDataType(..)
        | E::ErrorMismatchOutputType(..)
        | E::ErrorIndexingType(..)
        | E::ErrorFor(..)
        | E::ErrorAssignmentToConstant(..)
        | E::ErrorNonPureMethodCallOnConstant(..)
        | E::ErrorTooManyOperations(..)
        | E::ErrorTooManyVariables(..)
        | E::ErrorStackOverflow(..)
        | E::ErrorDataTooLarge(..) => without_position(error),
        _ => HIDDEN.to_string(),
    }
}

/// The doc string arrives with a leading newline; dropping exactly one makes
/// line 1 the first line the author wrote. An empty script is refused.
fn prepare(script: &str) -> Result<&str, String> {
    let script = script
        .strip_prefix("\r\n")
        .or_else(|| script.strip_prefix('\n'))
        .unwrap_or(script);
    if script.trim().is_empty() {
        return Err("the script is empty".to_string());
    }
    Ok(script)
}

// ponytail: nested data recurses in Rhai's eval, drop, comparison, display and
// `to_json` and in `export::flatten`; a host worker has 2 MiB, which about a
// thousand levels overflow into an abort. Rhai's size limits (10000 array and
// 10000 map entries in all) cap the depth at ~20000 levels, which a debug build
// needs more than 64 MiB for and holds in 512 (measured). The stack is reserved
// address space, touched only as deep as a script goes. A 32-bit target or a
// strict-overcommit host may refuse it, so smaller stacks are tried next; on
// one of those the deepest nesting can abort the process again (32 MiB surely
// does, 128 is not measured). The real fix is a nesting cap in Rhai.
const SCRIPT_STACKS: [usize; 3] = [512 << 20, 128 << 20, 32 << 20];

fn on_script_stack<T: Send>(body: impl FnOnce() -> T + Send) -> Result<T, String> {
    on_stack(&SCRIPT_STACKS, body)
}

/// Runs `body` on a thread with the first of `sizes` the system grants; a
/// panic there becomes `Err`. A spawn that fails drops what it was given, so
/// each attempt takes `body` out of a slot only once it runs.
fn on_stack<T: Send>(sizes: &[usize], body: impl FnOnce() -> T + Send) -> Result<T, String> {
    let slot = Mutex::new(Some(body));
    let run = || {
        let body = slot.lock().expect("body").take();
        body.expect("only a started thread takes the body")()
    };
    std::thread::scope(|scope| {
        let mut refused = None;
        for &size in sizes {
            match std::thread::Builder::new()
                .name("script".to_string())
                .stack_size(size)
                .spawn_scoped(scope, run)
            {
                Ok(thread) => return thread.join().map_err(|_| "the script panicked".to_string()),
                Err(e) => refused = Some(e),
            }
        }
        Err(format!(
            "could not start the script thread: {}",
            refused.map_or_else(|| "no stack size".to_string(), |e| e.to_string())
        ))
    })
}

/// Runs `script` and flattens its result. When the script read a secret
/// variable or declared one (`secret(x)`, `hmac_sha256`), every value it
/// exports is reported as a secret: a credential derived from a secret (Basic
/// auth is the common one) is still a credential.
///
/// Everything that touches a script value, its drop included, happens on the
/// script thread.
pub fn run(script: &str, target: Option<&str>, vars: Vars) -> Result<Outcome, RunError> {
    let secrets = Secrets::default();
    for value in vars.secret_values() {
        secrets.add(&value).map_err(|message| RunError {
            message,
            secrets: secrets.list(),
        })?;
    }
    on_script_stack(|| run_here(script, target, vars, &secrets)).unwrap_or_else(|message| {
        Err(RunError {
            message,
            secrets: secrets.list(),
        })
    })
}

fn run_here(
    script: &str,
    target: Option<&str>,
    vars: Vars,
    secrets: &Secrets,
) -> Result<Outcome, RunError> {
    let fail = |message: String| RunError {
        message: secrets.mask(&message),
        secrets: secrets.list(),
    };
    // Once a secret is in play, a value an error would quote may be derived
    // from it, which no mask can know; so the error quotes no value at all,
    // and is not masked either, which would garble it around a short secret.
    let preloaded = secrets.len();
    let used_secret = || vars.read_secret() || secrets.len() > preloaded;
    let hidden = |message: String| RunError {
        message,
        secrets: secrets.list(),
    };
    let script = prepare(script).map_err(&fail)?;
    let mut engine = engine(secrets);
    engine.set_strict_variables(true);
    let mut scope = Scope::new();
    scope.push_constant("vars", vars.clone());
    let value = engine
        .eval_with_scope::<Dynamic>(&mut scope, script)
        .map_err(|e| match used_secret() {
            true => hidden(format!(
                "{}{}",
                line(e.position()),
                what_failed(&e, secrets, script)
            )),
            false => fail(describe(&e)),
        })?;
    let pairs = export::flatten(target, value).map_err(|r| match used_secret() {
        true => hidden(r.summary),
        false => fail(r.message),
    })?;
    if used_secret() {
        for (_, value) in &pairs {
            secrets.add(value).map_err(&hidden)?;
        }
    }
    Ok(Outcome {
        vars: pairs,
        secrets: secrets.list(),
    })
}

/// The number of parameters in a printed signature such as
/// `foo(_: Map<string, i64>, _: i64) -> i64`: the text between the first `(` and
/// its matching `)`, split on commas that are not nested in `()`, `[]` or `<>`.
fn parameter_count(signature: &str) -> Option<usize> {
    let open = signature.find('(')?;
    let mut depth = 0_usize;
    let mut count = 0;
    let mut has_text = false;
    for c in signature[open + 1..].chars() {
        match c {
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' if depth > 0 => depth -= 1,
            ')' => return Some(count + usize::from(has_text)),
            ',' if depth == 0 => {
                count += 1;
                has_text = false;
                continue;
            }
            _ => {}
        }
        has_text |= !c.is_whitespace();
    }
    None
}

/// name -> the argument counts some overload accepts, or `None` for any count
/// when a signature of that name is one `parameter_count` cannot read: a
/// shape Rhai may print one day must not turn a real function into an unknown
/// one. A method call `x.f(a)` is `f` with two arguments, which the signature
/// lists too.
fn arities(
    signatures: impl IntoIterator<Item = String>,
) -> HashMap<String, Option<HashSet<usize>>> {
    let mut known: HashMap<String, Option<HashSet<usize>>> = HashMap::new();
    for signature in signatures {
        let name = signature.split_once('(').map_or(&*signature, |(n, _)| n);
        let entry = known
            .entry(name.trim().to_string())
            .or_insert_with(|| Some(HashSet::new()));
        match (parameter_count(&signature), entry) {
            (Some(count), Some(counts)) => {
                counts.insert(count);
            }
            (None, entry) => *entry = None,
            (Some(_), None) => {}
        }
    }
    known
}

/// Everything about a script that can be known without running it: syntax,
/// misspelled variables (strict mode) and misspelled or wrongly-sized
/// function calls (an AST walk against the registered signatures).
pub fn check(script: &str) -> Result<(), String> {
    // Parsing is depth-capped (`set_max_expr_depths`); the thread is the
    // same guard `run` has, in case a walk over the AST is not.
    on_script_stack(|| check_here(script))?
}

fn check_here(script: &str) -> Result<(), String> {
    let script = prepare(script)?;
    let mut engine = engine(&Secrets::default());
    engine.set_strict_variables(true);
    let mut scope = Scope::new();
    scope.push_constant(
        "vars",
        Vars::from_request(&serde_json::json!({})).expect("an empty object is valid"),
    );
    let ast = engine
        .compile_with_scope(&scope, script)
        .map_err(|e| format!("{}{}", line(e.position()), e.err_type()))?;

    let mut known = arities(engine.gen_fn_signatures(true));
    // Registered only to refuse at run time; the check can refuse it earlier.
    known.remove("sleep");
    for function in ast.iter_functions() {
        if let Some(counts) = known
            .entry(function.name.to_string())
            .or_insert_with(|| Some(HashSet::new()))
        {
            counts.insert(function.params.len());
        }
    }

    let mut problem: Option<String> = None;
    ast.walk(&mut |nodes| {
        // A call standing alone as a statement is `Stmt::FnCall`, not an `Expr`.
        let (call, position, receiver) = match nodes.last() {
            Some(ASTNode::Expr(Expr::FnCall(call, position)))
            | Some(ASTNode::Stmt(Stmt::FnCall(call, position))) => (call, position, 0),
            Some(ASTNode::Expr(Expr::MethodCall(call, position))) => (call, position, 1),
            _ => return true,
        };
        let name = call.name.as_str();
        // Rhai answers these itself, so no signature lists them: `f.call(..)`
        // and `f.curry(..)` on a function pointer, and the two `is_def_*` probes.
        // Skipping arity is safe: a wrong count is a runtime error with its own
        // line, and the names cannot be misspelled into something else here.
        if matches!(name, "call" | "curry" | "is_def_fn" | "is_def_var") {
            return true;
        }
        let args = call.args.len() + receiver;
        match known.get(name) {
            None => {
                problem = Some(format!("{}unknown function {name}", line(*position)));
                false
            }
            Some(Some(arities)) if !arities.contains(&args) => {
                let mut wanted: Vec<_> = arities.iter().copied().collect();
                wanted.sort_unstable();
                let wanted = wanted.iter().map(usize::to_string).collect::<Vec<_>>();
                problem = Some(format!(
                    "{}function {name} takes {} argument(s), not {args}",
                    line(*position),
                    wanted.join(" or ")
                ));
                false
            }
            Some(_) => true,
        }
    });
    problem.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vars(pairs: &[(&str, &str)]) -> Vars {
        let entries: serde_json::Map<_, _> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), json!({"value": v, "secret": false})))
            .collect();
        Vars::from_request(&entries.into()).unwrap()
    }

    fn secret_vars(pairs: &[(&str, &str)]) -> Vars {
        let entries: serde_json::Map<_, _> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), json!({"value": v, "secret": true})))
            .collect();
        Vars::from_request(&entries.into()).unwrap()
    }

    #[test]
    fn the_agreed_example_joins_with_a_separator() {
        let script = "let a = 4;\nlet b = 5;\nlet separator = \"|\";\n`${a}${separator}${b}`";
        let out = run(script, Some("joined"), vars(&[])).unwrap();
        assert_eq!(out.vars, vec![("joined".to_string(), "4|5".to_string())]);
    }

    #[test]
    fn variables_arrive_through_vars() {
        let out = run("vars.who + \"!\"", Some("x"), vars(&[("who", "Ann")])).unwrap();
        assert_eq!(out.vars[0].1, "Ann!");
    }

    #[test]
    fn a_runtime_error_names_the_line() {
        let err = run(
            "let a = 1;\nlet b = base64_decode(\"@@\");",
            Some("x"),
            vars(&[]),
        )
        .unwrap_err();
        assert!(err.message.contains("base64_decode"), "{}", err.message);
        assert!(err.message.contains("line 2"), "{}", err.message);
    }

    #[test]
    fn a_doc_string_starts_counting_at_the_authors_first_line() {
        let err = run(
            "\nlet a = 1;\nlet b = base64_decode(\"@@\");\n",
            Some("x"),
            vars(&[]),
        )
        .unwrap_err();
        assert!(err.message.contains("script line 2"), "{}", err.message);
        let err = check("\nlet a = 1;\nlet = ;\n").unwrap_err();
        assert!(err.contains("script line 2"), "{err}");
        let err = check("\nlet a = 1;\nbse64(a)\n").unwrap_err();
        assert!(err.contains("script line 2"), "{err}");
    }

    #[test]
    fn an_empty_script_is_an_error_in_both() {
        for script in ["", "\n", "\n  \n\t\n"] {
            let err = run(script, Some("x"), vars(&[])).unwrap_err();
            assert!(
                err.message.contains("the script is empty"),
                "{}",
                err.message
            );
            assert_eq!(check(script).unwrap_err(), "the script is empty");
        }
    }

    #[test]
    fn basic_auth_built_from_a_secret_is_reported_as_secret() {
        let out = run(
            r#"base64("user:" + vars.password)"#,
            Some("auth"),
            secret_vars(&[("password", "hunter22")]),
        )
        .unwrap();
        assert!(out.secrets.contains(&out.vars[0].1), "{:?}", out.secrets);
    }

    #[test]
    fn a_value_derived_from_a_declared_secret_or_an_hmac_is_reported_as_secret() {
        for script in [
            r#"let k = secret("tok-12345"); base64(k)"#,
            r#""Bearer " + base64(hmac_sha256("k3y-k3y-k3y", "m"))"#,
        ] {
            let out = run(script, Some("x"), vars(&[])).unwrap();
            assert!(out.secrets.contains(&out.vars[0].1), "{script}: {out:?}");
        }
    }

    #[test]
    fn a_script_that_read_nothing_secret_exports_nothing_secret() {
        let out = run(
            r#"base64("plain")"#,
            Some("x"),
            secret_vars(&[("password", "hunter22")]),
        )
        .unwrap();
        assert!(!out.secrets.contains(&out.vars[0].1), "{:?}", out.secrets);
    }

    #[test]
    fn hmac_forms_and_declared_secrets_are_reported() {
        let out = run(
            r#"hex(hmac_sha256("k3y-k3y-k3y", "m")) + secret("declared")"#,
            Some("x"),
            vars(&[]),
        )
        .unwrap();
        assert!(out.secrets.contains(&"k3y-k3y-k3y".to_string()));
        assert!(out.secrets.contains(&"declared".to_string()));
    }

    #[test]
    fn an_error_after_a_secret_was_read_reports_the_secrets_known_so_far() {
        let err = run(
            r#"let k = secret("tok-12345"); base64_decode(vars.password + "!")"#,
            Some("x"),
            secret_vars(&[("password", "hunter22")]),
        )
        .unwrap_err();
        assert!(!err.message.contains("hunter22"), "{}", err.message);
        assert!(
            err.message.contains("base64_decode: not valid Base64"),
            "{}",
            err.message
        );
        assert!(err.secrets.contains(&"tok-12345".to_string()));
    }

    /// `aHVudGVyMmh1bnRlcjI=` is `base64("hunter2hunter2")`: no secret set
    /// holds it, so only not quoting it keeps it out of the error.
    #[test]
    fn after_a_secret_was_read_an_error_quotes_no_value() {
        let derived = "aHVudGVy";
        let cases = [
            (
                "let a = 1;\nbase64_decode(base64(vars.api_secret) + \"!\")",
                "script line 2: base64_decode: not valid Base64",
            ),
            (
                "let t = base64(vars.api_secret);\nthrow t;",
                "script line 2: ",
            ),
            (
                "let a = 1;\nvars[base64(vars.api_secret)]",
                "script line 2: ",
            ),
            (
                "fn f(x) { base64_decode(x + \"!\") }\nf(base64(vars.api_secret))",
                "script line 2: base64_decode: not valid Base64",
            ),
            ("let a = 1;\nFn(base64(vars.api_secret))", "script line 2: "),
            (
                "let s = vars.api_secret;\ns.trim(1)",
                "script line 2: Function not found: trim (",
            ),
            (
                "let a = 1;\nFn(\"f\" + base64url(vars.api_secret)).call()",
                "script line 2: ",
            ),
        ];
        for (script, shown) in cases {
            let err = run(
                script,
                Some("x"),
                secret_vars(&[("api_secret", "hunter2hunter2")]),
            )
            .unwrap_err();
            assert!(!err.message.contains(derived), "{script}: {}", err.message);
            assert!(err.message.starts_with(shown), "{script}: {}", err.message);
        }
    }

    #[test]
    fn a_secret_the_script_declared_hides_values_too() {
        let err = run(
            "let k = secret(\"tok-12345\");\nthrow base64(k);",
            Some("x"),
            vars(&[]),
        )
        .unwrap_err();
        assert!(!err.message.contains("dG9rLTEy"), "{}", err.message);
        assert!(
            err.message.starts_with("script line 2: "),
            "{}",
            err.message
        );
    }

    #[test]
    fn after_a_secret_was_read_an_export_error_quotes_no_key() {
        let err = run(
            "let m = #{};\nm[base64(vars.api_secret)] = 1;\nm",
            None,
            secret_vars(&[("api_secret", "hunter2hunter2")]),
        )
        .unwrap_err();
        assert!(!err.message.contains("aHVudGVy"), "{}", err.message);
        assert!(err.message.contains("variable name"), "{}", err.message);
    }

    #[test]
    fn a_short_secret_does_not_garble_the_error() {
        let err = run(
            "let p = vars.pin;\nbase64_decode(\"@@\")",
            Some("x"),
            secret_vars(&[("pin", "e")]),
        )
        .unwrap_err();
        assert_eq!(
            err.message,
            "script line 2: base64_decode: not valid Base64"
        );
    }

    #[test]
    fn without_a_secret_an_error_quotes_the_value_and_names_the_line_once() {
        let err = run("let a = 1;\nbase64_decode(\"@@\")", Some("x"), vars(&[])).unwrap_err();
        assert!(err.message.contains("\"@@\""), "{}", err.message);
        assert_eq!(err.message.matches("line 2").count(), 1, "{}", err.message);
        let err = check("let a = 1;\nlet = ;").unwrap_err();
        assert_eq!(err.matches("line 2").count(), 1, "{err}");
    }

    #[test]
    fn an_error_from_flatten_is_masked_too() {
        let err = run(
            r#"#{ "hunter22 x": 1 }"#,
            None,
            secret_vars(&[("password", "hunter22")]),
        )
        .unwrap_err();
        assert!(!err.message.contains("hunter22"), "{}", err.message);
    }

    /// Nested data recurses in eval, drop, comparison, display, `to_json` and
    /// flatten. Without the script thread these abort the process (not a
    /// panic `catch_unwind` could stop): a test thread has the 2 MiB of a host
    /// worker, so an abort here is the bug coming back.
    fn end_cleanly(scripts: &[&str]) {
        for script in scripts {
            if let Err(e) = run(script, Some("x"), vars(&[])) {
                assert!(!e.message.contains("panicked"), "{script}: {}", e.message);
            }
            if let Err(e) = check(script) {
                panic!("{script}: {e}");
            }
        }
    }

    /// Rhai's `sleep` would hold a host worker for as long as the script asks,
    /// counted as one operation.
    #[test]
    fn sleep_is_not_available() {
        let started = std::time::Instant::now();
        for script in ["sleep(1); 1", "sleep(1.0); 1"] {
            let err = run(script, Some("x"), vars(&[])).unwrap_err();
            assert!(err.message.contains("sleep"), "{}", err.message);
            assert!(check(script).is_err(), "{script}");
        }
        assert!(started.elapsed() < std::time::Duration::from_millis(900));
    }

    /// `1 << 50` bytes exceeds a 64-bit user address space, so it cannot be
    /// reserved anywhere: the next size is tried.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_stack_that_cannot_be_reserved_falls_back_to_a_smaller_one() {
        assert_eq!(on_stack(&[1 << 50, 1 << 20], || 7), Ok(7));
        let err = on_stack(&[1 << 50], || 7).unwrap_err();
        assert!(err.contains("could not start the script thread"), "{err}");
    }

    #[test]
    fn deeply_nested_data_ends_cleanly() {
        end_cleanly(&[
            "let m = #{}; for i in 0..1500 { m = #{a: m}; } 1",
            "let m = #{}; for i in 0..1500 { m = #{a: [m]}; } let n = m; `${m == n}${to_json(m).len()}${m}`.len()",
            "let a = []; for i in 0..1500 { a = [a]; } a",
        ]);
    }

    /// The reviewer's scripts, and the deepest nesting Rhai's size limits let a
    /// script build (arrays and maps alternating, ~20000 levels). Slow because
    /// Rhai re-counts the whole value on every assignment:
    /// `cargo test --release -- --ignored nesting`.
    #[test]
    #[ignore = "minutes in a debug build"]
    fn the_deepest_nesting_a_script_can_build_ends_cleanly() {
        end_cleanly(&[
            "let m = #{}; for i in 0..200000 { m = #{a: m}; } 1",
            "let a = []; for i in 0..9990 { a = [a]; } to_json(a)",
            "let a = []; for i in 0..9990 { a = [a]; } let b = a; `${a == b}${a}`.len()",
            "let a = []; for i in 0..9990 { a = [#{a: a}]; } let b = a; `${a == b}${a}`.len()",
            "let m = #{}; for i in 0..9990 { m = #{a: [m]}; } to_json(m).len()",
            "let a = []; for i in 0..9990 { a = [#{a: a}]; } a",
        ]);
    }

    /// Rhai counts bytes against the array limit; it has no limit of its own
    /// for them. The README says so.
    #[test]
    fn bytes_are_limited_to_as_many_as_an_array_holds() {
        let decode = |n: usize| {
            let script =
                format!(r#"let s = ""; s.pad({n}, 'a'); base64_decode_blob(base64(s)).len()"#);
            run(&script, Some("x"), vars(&[]))
        };
        assert_eq!(decode(export::MAX_VARIABLES).unwrap().vars[0].1, "10000");
        let err = decode(export::MAX_VARIABLES + 1).unwrap_err();
        assert!(err.message.contains("too large"), "{}", err.message);
    }

    #[test]
    fn check_accepts_a_good_script_and_reports_a_syntax_error_with_its_line() {
        assert!(check("let a = vars.x;\na").is_ok());
        let err = check("let a = 1;\nlet = ;").unwrap_err();
        assert!(err.contains("line 2"), "{err}");
    }

    #[test]
    fn check_catches_a_misspelled_variable() {
        let err = check("let total = 1;\ntotl").unwrap_err();
        assert!(err.contains("totl"), "{err}");
    }

    #[test]
    fn check_catches_a_misspelled_function() {
        let err = check("base46(\"x\")").unwrap_err();
        assert!(err.contains("base46"), "{err}");
    }

    #[test]
    fn check_accepts_a_function_the_script_defines_and_a_builtin_method() {
        assert!(check("fn twice(x) { x + x }\ntwice(\"a\").trim()").is_ok());
    }

    /// A deliberate ceiling, documented in the README: `check` cannot see a
    /// closure stored in a map, nor that a script `fn` using `this` is called
    /// as a method (the receiver counts as one more argument). Both run;
    /// `check` refuses them.
    #[test]
    fn check_refuses_two_method_shapes_that_would_run() {
        for script in [
            "let obj = #{ n: 1, inc: |x| x + this.n };\nobj.inc(2)",
            "fn twice() { this * 2 }\nlet a = 1;\na.twice()",
            "fn inc(x) { x + this.n }\nlet obj = #{ n: 1 };\nobj.inc(2)",
        ] {
            assert!(run(script, Some("x"), vars(&[])).is_ok(), "{script}");
            assert!(check(script).is_err(), "{script}");
        }
        // The README's way out: pass the value and call a plain function.
        for script in [
            "fn inc(o, x) { x + o.n }\nlet obj = #{ n: 1 };\ninc(obj, 2)",
            "fn twice(a) { a * 2 }\nlet a = 1;\ntwice(a)",
        ] {
            assert!(run(script, Some("x"), vars(&[])).is_ok(), "{script}");
            assert!(check(script).is_ok(), "{script}");
        }
    }

    #[test]
    fn check_catches_a_wrong_count_on_a_script_function() {
        let err = check("fn f(x) { x }\nf(1, 2)").unwrap_err();
        assert!(err.contains("function f takes 1"), "{err}");
    }

    #[test]
    fn check_catches_a_call_with_no_overload_of_that_arity() {
        let err = check("hmac_sha256(\"only one\")").unwrap_err();
        assert!(err.contains("hmac_sha256"), "{err}");
        assert!(err.contains("takes"), "{err}");
        assert!(err.contains("not 1"), "{err}");
    }

    #[test]
    fn check_catches_a_misspelling_wherever_it_sits() {
        let cases = [
            ("let a = 1;\n[1].map(|x| bse64(x))", 2),
            ("let a = 1;\n`${bse64(\"a\")}`", 2),
            ("let a = 1;\nswitch a { 1 => bse64(\"a\"), _ => 2 }", 2),
            ("let a = 1;\nfn f(x) { bse64(x) }\nf(1)", 2),
            ("let a = 1;\nbase64(bse64(\"a\"))", 2),
            ("let a = 1;\nif bse64(\"a\") == \"\" { 1 } else { 2 }", 2),
            ("let a = 1;\nwhile bse64(\"a\") == \"\" { a += 1; }", 2),
            ("let a = 1;\n#{ k: bse64(\"a\") }", 2),
            ("let a = 1;\n[1, bse64(\"a\")]", 2),
            ("let a = 1;\nlet b = bse64(\"a\");", 2),
            ("let a = 1;\nbse64(\"a\").len()", 2),
            ("let a = 1;\n\"x\" + bse64(\"a\")", 2),
            ("let a = 1;\nlet b = 2;\n\"x\" + bse64(\"a\")", 3),
        ];
        for (script, line) in cases {
            let err = check(script).expect_err(script);
            assert!(err.contains("bse64"), "{script:?}: {err}");
            assert!(err.contains("unknown function"), "{script:?}: {err}");
            assert!(
                err.contains(&format!("script line {line}")),
                "{script:?}: {err}"
            );
        }
    }

    #[test]
    fn a_syntax_error_names_its_line() {
        let err = check("let a = 1;\nlet b = 2;\nlet = ;").unwrap_err();
        assert!(err.contains("script line 3"), "{err}");
    }

    #[test]
    fn parameters_are_counted_at_the_top_level() {
        assert_eq!(
            parameter_count("foo(_: Map<string, i64>, _: i64) -> i64"),
            Some(2)
        );
        assert_eq!(parameter_count("foo() -> i64"), Some(0));
        assert_eq!(parameter_count("trim(string: &mut string)"), Some(1));
        assert_eq!(
            parameter_count("f(a: [i64, i64], b: (i64, i64)) -> ()"),
            Some(2)
        );
        assert_eq!(parameter_count("no parens"), None);
    }

    #[test]
    fn rhai_still_prints_signatures_in_the_shape_we_count() {
        let signatures = engine(&Secrets::default()).gen_fn_signatures(true);
        let unread: Vec<_> = signatures
            .iter()
            .filter(|s| parameter_count(s).is_none())
            .collect();
        assert!(unread.is_empty(), "{unread:?}");
        let expected = [
            ("hmac_sha256", 2),
            ("base64", 1),
            ("base64_decode", 1),
            ("url_encode", 1),
            ("sha256", 1),
            ("hex", 1),
            ("secret", 1),
            ("sub_string", 3),
            ("pad", 3),
        ];
        for (name, count) in expected {
            let found: Vec<_> = signatures
                .iter()
                .filter(|s| s.starts_with(&format!("{name}(")))
                .collect();
            assert!(!found.is_empty(), "no signature for {name}");
            assert!(
                found.iter().any(|s| parameter_count(s) == Some(count)),
                "{name}: {found:?}"
            );
            assert!(
                found.iter().all(|s| parameter_count(s).is_some()),
                "{name}: {found:?}"
            );
        }
    }

    #[test]
    fn a_signature_the_counter_cannot_read_accepts_any_arity() {
        let known = arities(["odd(_: [i64".to_string(), "two(a, b)".to_string()]);
        assert_eq!(known["odd"], None);
        assert_eq!(known["two"], Some(HashSet::from([2])));
    }

    #[test]
    fn check_accepts_every_ordinary_construct() {
        let corpus = [
            "1 + 2 - 3 * 4 / 5 % 6",
            "1 == 2 || 3 != 4 && 5 < 6 && 7 > 8 || 9 <= 10 && 11 >= 12",
            "!true",
            "-(1)",
            "let n = 4; `n=${n}`",
            "if vars.a == \"x\" { 1 } else { 2 }",
            "let s = 0; for x in [1, 2, 3] { s += x; } s",
            "let i = 0; while i < 3 { i += 1; } i",
            "let s = 0; for i in 0..3 { s += i; } s",
            "let s = 0; for i in 0..=3 { s += i; } s",
            "let a = [1, 2]; a.push(4); a[0] + a.len()",
            "let m = #{ key: 1, other: \"v\" }; m.key",
            "let m = #{ key: 1 }; m[\"key\"]",
            "[1, 2].map(|x| x * 2)",
            "[1, 2, 3].filter(|x| x > 1)",
            "type_of(1)",
            "(1).to_string()",
            "\"5\".parse_int()",
            "parse_int(\"5\")",
            "\"abc\".contains(\"b\")",
            "[1, 2].contains(1)",
            "vars.some_name",
            "vars[\"some_name\"]",
            "let a = 1; const b = 2; a + b",
            "fn f(x) { return x + 1; }\nf(1)",
            "fn f(x) { x }\nfn g(x) { f(x) }\ng(1)",
            "switch vars.a { \"x\" => 1, _ => 2 }",
            "\"abc\".len() + \"abc\".to_upper().len()",
            "\"abc\".sub_string(1, 1)",
            "let f = |x| x + 1; f.call(2)",
            "let f = Fn(\"g\");\nfn g(x) { x }\nf.call(1)",
            "let x = (); x == ()",
            "let a = 1; a += 2; a -= 1; a *= 2; a",
            "`${vars.a}-${base64(\"x\")}`",
            "to_json(#{ a: 1 })",
            "[1, 2, 3].reduce(|sum, x| sum + x, 0)",
            "let a = 5; a.is_even()",
            "1.5 + 2.0",
            "'c'",
            "\"a\" in \"abc\"",
            "5 in [1, 5]",
            "let f = |x, y| x + y; f.curry(1).call(2)",
            "fn g(x) { x }\nis_def_fn(\"g\", 1)",
            "let a = 1; is_def_var(\"a\")",
            "print(\"x\"); debug(\"y\"); 1",
        ];
        let mut rejected = Vec::new();
        for script in corpus {
            if let Err(e) = check(script) {
                rejected.push(format!("{script:?} -> {e}"));
            }
        }
        assert!(
            rejected.is_empty(),
            "wrongly rejected:\n{}",
            rejected.join("\n")
        );
    }
}
