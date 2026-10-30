//! End-to-end: the real `bddkit` host (plugin ABI 3) and this crate's `cdylib`.
//!
//! The host binary comes from `BDDKIT_BIN`; without it every test skips itself
//! and passes, because no published host speaks ABI 3 yet.
//! `examples/` is what runs first: the example and the proof are one thing.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

macro_rules! require_host {
    () => {
        match std::env::var("BDDKIT_BIN") {
            Ok(p) if Path::new(&p).is_file() => PathBuf::from(p),
            _ => {
                eprintln!("SKIP: set BDDKIT_BIN to a bddkit binary that speaks plugin ABI 3");
                return;
            }
        }
    };
}

/// Builds the plugin once; returns the library path.
fn library() -> &'static Path {
    static LIB: OnceLock<PathBuf> = OnceLock::new();
    LIB.get_or_init(|| {
        let out = Command::new(env!("CARGO"))
            .arg("build")
            .current_dir(root())
            .output()
            .expect("cargo build");
        assert!(
            out.status.success(),
            "plugin build failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // `<target-dir>/tmp`, wherever CARGO_TARGET_DIR or a config put it.
        let target = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .parent()
            .expect("the target directory");
        target.join("debug").join(format!(
            "{}bddkit_script{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ))
    })
}

/// A project in a directory of its own: the lock, the config, the macros and
/// the features. `BDDKIT_DIR` points at it, so no installed plugin interferes.
struct Project(PathBuf);

impl Project {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("bddkit-script-e2e-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("features")).expect("mkdir");
        std::fs::create_dir_all(dir.join("macros")).expect("mkdir");
        let lock = format!(
            "plugin:\n  - name: script\n    path: {}\n",
            library().display()
        );
        std::fs::write(dir.join("plugins.yaml"), lock).expect("lock");
        std::fs::write(
            dir.join("cfg.yaml"),
            "paths: [features]\nmacro_paths: [macros]\nresources:\n  api: {}\n",
        )
        .expect("config");
        Project(dir)
    }

    fn with(self, file: &str, text: &str) -> Self {
        std::fs::write(self.0.join(file), text).expect("write");
        self
    }

    fn run(&self, bin: &Path) -> Output {
        run_in(bin, &self.0, &self.0, "cfg.yaml")
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `bddkit run --config <config>` from `cwd`, with `BDDKIT_DIR` at `dir`.
fn run_in(bin: &Path, cwd: &Path, dir: &Path, config: &str) -> Output {
    Command::new(bin)
        .args(["run", "--config", config])
        .current_dir(cwd)
        .env("BDDKIT_DIR", dir)
        .env("CI", "true")
        .env_remove("BDDKIT_TELEMETRY")
        .env_remove("DO_NOT_TRACK")
        .output()
        .expect("bddkit")
}

fn show(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn feature(body: &str) -> String {
    format!("Feature: script\n\n  Scenario: s\n{body}")
}

#[test]
fn the_examples_pass() {
    let bin = require_host!();
    let lock = Project::new("examples");
    let out = run_in(&bin, &root().join("examples"), &lock.0, "bddkit.yaml");
    assert!(out.status.success(), "{}", show(&out));
}

#[test]
fn a_script_result_is_a_variable() {
    let bin = require_host!();
    let p = Project::new("joined").with(
        "features/a.feature",
        &feature(
            r#"    When I execute script to "joined":
      """
      let a = 4;
      `${a}|5`
      """
    Then variable "joined" should be equal to "4|5"
"#,
        ),
    );
    let out = p.run(&bin);
    assert!(out.status.success(), "{}", show(&out));
}

#[test]
fn an_array_is_flattened() {
    let bin = require_host!();
    let p = Project::new("array").with(
        "features/a.feature",
        &feature(
            r#"    When I execute script to "ids":
      """
      [7, 8]
      """
    Then variable "ids_length" should be equal to "2"
    And variable "ids_1" should be equal to "8"
"#,
        ),
    );
    let out = p.run(&bin);
    assert!(out.status.success(), "{}", show(&out));
}

#[test]
fn a_map_becomes_variables() {
    let bin = require_host!();
    let p = Project::new("map").with(
        "features/a.feature",
        &feature(
            r#"    When I execute script to variables:
      """
      #{ token: "t", user: #{ name: "Ann" } }
      """
    Then variable "token" should be equal to "t"
    And variable "user_name" should be equal to "Ann"
"#,
        ),
    );
    let out = p.run(&bin);
    assert!(out.status.success(), "{}", show(&out));
}

#[test]
fn an_hs256_jwt_matches_the_known_token() {
    let bin = require_host!();
    let p = Project::new("jwt").with(
        "features/a.feature",
        &feature(
            r#"    Given set variable "user" to "Ann"
    And set variable "jwt_secret" to "s3cret"
    When I execute script to "token":
      """
      let h = base64url(`{"alg":"HS256","typ":"JWT"}`);
      let p = base64url(`{"sub":"${vars.user}"}`);
      let s = base64url(hmac_sha256(vars.jwt_secret, `${h}.${p}`));
      `${h}.${p}.${s}`
      """
    Then variable "token" should be equal to "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJBbm4ifQ.92qA8pVES5gosRQTGwzUCHOEfgNXozGuNWWdpnLAL4Y"
"#,
        ),
    );
    let out = p.run(&bin);
    assert!(out.status.success(), "{}", show(&out));
}

#[test]
fn a_misspelled_function_is_refused_before_the_run() {
    let bin = require_host!();
    let p = Project::new("typo").with(
        "features/typo.feature",
        &feature(
            r#"    When I execute script to "x":
      """
      let a = 1;
      base46("x")
      """
"#,
        ),
    );
    let out = p.run(&bin);
    assert_eq!(out.status.code(), Some(2), "{}", show(&out));
    let text = show(&out);
    assert!(text.contains("typo.feature"), "{text}");
    assert!(text.contains("unknown function base46"), "{text}");
    assert!(text.contains("line 2"), "{text}");
}

#[test]
fn a_derived_credential_is_masked_when_a_secret_was_read() {
    let bin = require_host!();
    let p = Project::new("basic").with(
        "features/a.feature",
        &feature(
            r#"    Given set variable "api_secret" to "hunter2hunter2"
    When I execute script to "auth":
      """
      "Basic " + base64("ann:" + vars.api_secret)
      """
    Then variable "auth" should be equal to "nope"
"#,
        ),
    );
    let out = p.run(&bin);
    assert_eq!(out.status.code(), Some(1), "{}", show(&out));
    let text = show(&out);
    assert!(!text.contains("YW5uOmh1bnRlcjJodW50ZXIy"), "{text}");
    assert!(!text.contains("hunter2hunter2"), "{text}");
    assert!(text.contains("***"), "{text}");
}

#[test]
fn an_error_after_a_secret_was_read_shows_no_derived_value() {
    let bin = require_host!();
    for (name, script) in [
        ("decode", r#"base64_decode(base64(vars.api_secret) + "!")"#),
        ("throw", "let t = base64(vars.api_secret);\n      throw t;"),
    ] {
        let p = Project::new(name).with(
            "features/a.feature",
            &feature(&format!(
                r#"    Given set variable "api_secret" to "hunter2hunter2"
    When I execute script to "x":
      """
      {script}
      """
"#
            )),
        );
        let out = p.run(&bin);
        assert_eq!(out.status.code(), Some(1), "{}", show(&out));
        let text = show(&out);
        assert!(!text.contains("aHVudGVy"), "{text}");
        assert!(text.contains("script line"), "{text}");
    }
}

#[test]
fn a_short_macro_secret_is_masked_in_what_is_derived_from_it() {
    let bin = require_host!();
    let p = Project::new("pin")
        .with(
            "macros/pin.yaml",
            r#"- step: 'I derive a credential from pin {pin:secret}'
  exports: [cred]
  do:
    - I execute script to "cred": |
        base64(vars.pin + ":x")
"#,
        )
        .with(
            "features/a.feature",
            &feature(
                r#"    When I derive a credential from pin "1234"
    Then variable "cred" should be equal to "nope"
"#,
            ),
        );
    let out = p.run(&bin);
    assert_eq!(out.status.code(), Some(1), "{}", show(&out));
    let text = show(&out);
    assert!(!text.contains("MTIzNDp4"), "{text}");
    assert!(text.contains("***"), "{text}");
}

#[test]
fn a_runtime_error_names_the_operation_and_the_line() {
    let bin = require_host!();
    let p = Project::new("runtime").with(
        "features/a.feature",
        &feature(
            r#"    When I execute script to "x":
      """
      let a = 1;
      base64_decode("@@")
      """
"#,
        ),
    );
    let out = p.run(&bin);
    assert_eq!(out.status.code(), Some(1), "{}", show(&out));
    let text = show(&out);
    assert!(text.contains("base64_decode"), "{text}");
    assert!(text.contains("script line 2"), "{text}");
}
