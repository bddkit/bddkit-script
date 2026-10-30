//! The host functions a script can call. A fixed set: what a tester needs to
//! derive a credential without a plugin.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rhai::{Blob, Dynamic, Engine, EvalAltResult, ImmutableString, Position};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Everything the script has declared secret, shared by clones. The plugin
/// reports all of it; the host decides what is long enough to hide.
///
/// It also keeps the last host-function failure next to the same text without
/// its value, so an error after a secret was read can still name the operation
/// without telling it apart from a `throw` by parsing the text. Only the last:
/// a `try` loop could raise hundreds of thousands, and an older one rethrown
/// is merely shown without its operation.
#[derive(Clone, Default)]
pub struct Secrets {
    values: Arc<Mutex<Set>>,
    failure: Arc<Mutex<Option<(String, String)>>>,
}

/// The values in the order they were added, which is the order reported.
#[derive(Default)]
struct Set {
    order: Vec<String>,
    seen: HashSet<String>,
    bytes: usize,
}

// ponytail: fixed caps on what one step call may report, above the 10000
// exports a secret-touching script can make plus the hmac forms beside them.
// Make them options when a suite needs more.
pub const MAX_SECRETS: usize = 50_000;
pub const MAX_SECRET_BYTES: usize = 32 << 20;

impl Secrets {
    /// Fails, quoting no value, when the set would pass `MAX_SECRETS` or
    /// `MAX_SECRET_BYTES`: a secret left out would be shown unmasked.
    pub fn add(&self, value: &str) -> Result<(), String> {
        let mut set = self.values.lock().expect("secrets");
        if value.is_empty() || set.seen.contains(value) {
            return Ok(());
        }
        if set.order.len() >= MAX_SECRETS || set.bytes + value.len() > MAX_SECRET_BYTES {
            return Err(format!(
                "more than {MAX_SECRETS} secrets or {MAX_SECRET_BYTES} bytes of them in one step"
            ));
        }
        set.bytes += value.len();
        set.seen.insert(value.to_string());
        set.order.push(value.to_string());
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.values.lock().expect("secrets").order.len()
    }

    pub fn list(&self) -> Vec<String> {
        self.values.lock().expect("secrets").order.clone()
    }

    /// The value-free form of `message`, if a host function raised it.
    pub fn operation_of(&self, message: &str) -> Option<String> {
        let failure = self.failure.lock().expect("failure");
        failure
            .as_ref()
            .filter(|(full, _)| full == message)
            .map(|(_, short)| short.clone())
    }

    /// Longest first, so a secret that contains another is hidden whole.
    pub fn mask(&self, text: &str) -> String {
        let mut all = self.list();
        all.sort_by_key(|s| std::cmp::Reverse(s.len()));
        all.iter()
            .fold(text.to_string(), |t, s| t.replace(s.as_str(), "***"))
    }
}

type Fail = Box<EvalAltResult>;

const SHOWN: usize = 80;

/// A value as an error may quote it: masked FIRST, cut after, so a secret
/// straddling the cut cannot show its first characters.
pub fn quote(secrets: &Secrets, value: &str) -> String {
    let masked = secrets.mask(value);
    if masked.chars().count() > SHOWN {
        let cut: String = masked.chars().take(SHOWN).collect();
        format!("{cut}…")
    } else {
        masked
    }
}

fn fail(secrets: &Secrets, op: &str, value: &str, why: &str) -> Fail {
    let short = format!("{op}: {why}");
    let message = format!("{short}: {:?}", quote(secrets, value));
    *secrets.failure.lock().expect("failure") = Some((message.clone(), short));
    EvalAltResult::ErrorRuntime(message.into(), Position::NONE).into()
}

/// A failure whose text quotes no value, so it is shown as it is.
fn fail_plain(secrets: &Secrets, message: String) -> Fail {
    *secrets.failure.lock().expect("failure") = Some((message.clone(), message.clone()));
    EvalAltResult::ErrorRuntime(message.into(), Position::NONE).into()
}

fn bytes(secrets: &Secrets, op: &str, value: &Dynamic) -> Result<Vec<u8>, Fail> {
    if let Some(s) = value.read_lock::<ImmutableString>() {
        return Ok(s.as_bytes().to_vec());
    }
    if let Some(b) = value.read_lock::<Blob>() {
        return Ok(b.clone());
    }
    Err(fail(
        secrets,
        op,
        &value.to_string(),
        "expected a string or bytes",
    ))
}

fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            let pair = raw.get(i + 1..i + 3)?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    Some(out)
}

fn add(secrets: &Secrets, value: &str) -> Result<(), Fail> {
    secrets.add(value).map_err(|e| fail_plain(secrets, e))
}

fn secret_forms(secrets: &Secrets, mac: &[u8]) -> Result<(), Fail> {
    add(secrets, &hex(mac))?;
    add(secrets, &STANDARD.encode(mac))?;
    add(secrets, &URL_SAFE_NO_PAD.encode(mac))
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn register(engine: &mut Engine, secrets: &Secrets) {
    let r = secrets.clone();
    engine.register_fn("base64", move |x: Dynamic| -> Result<String, Fail> {
        Ok(STANDARD.encode(bytes(&r, "base64", &x)?))
    });
    let r = secrets.clone();
    engine.register_fn("base64url", move |x: Dynamic| -> Result<String, Fail> {
        Ok(URL_SAFE_NO_PAD.encode(bytes(&r, "base64url", &x)?))
    });

    let r = secrets.clone();
    engine.register_fn("base64_decode_blob", move |s: &str| -> Result<Blob, Fail> {
        STANDARD
            .decode(s)
            .map_err(|_| fail(&r, "base64_decode_blob", s, "not valid Base64"))
    });
    let r = secrets.clone();
    engine.register_fn(
        "base64url_decode_blob",
        move |s: &str| -> Result<Blob, Fail> {
            URL_SAFE_NO_PAD
                .decode(s.trim_end_matches('='))
                .map_err(|_| fail(&r, "base64url_decode_blob", s, "not valid URL-safe Base64"))
        },
    );
    let r = secrets.clone();
    engine.register_fn("base64_decode", move |s: &str| -> Result<String, Fail> {
        let raw = STANDARD
            .decode(s)
            .map_err(|_| fail(&r, "base64_decode", s, "not valid Base64"))?;
        String::from_utf8(raw).map_err(|_| {
            fail(
                &r,
                "base64_decode",
                s,
                "the bytes are not UTF-8, use base64_decode_blob",
            )
        })
    });
    let r = secrets.clone();
    engine.register_fn("base64url_decode", move |s: &str| -> Result<String, Fail> {
        let raw = URL_SAFE_NO_PAD
            .decode(s.trim_end_matches('='))
            .map_err(|_| fail(&r, "base64url_decode", s, "not valid URL-safe Base64"))?;
        String::from_utf8(raw).map_err(|_| {
            fail(
                &r,
                "base64url_decode",
                s,
                "the bytes are not UTF-8, use base64url_decode_blob",
            )
        })
    });

    engine.register_fn("url_encode", |s: &str| -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    });
    let r = secrets.clone();
    engine.register_fn("url_decode", move |s: &str| -> Result<String, Fail> {
        let raw = percent_decode(s)
            .ok_or_else(|| fail(&r, "url_decode", s, "invalid percent-encoding"))?;
        String::from_utf8(raw).map_err(|_| fail(&r, "url_decode", s, "the bytes are not UTF-8"))
    });

    let r = secrets.clone();
    engine.register_fn("sha256", move |x: Dynamic| -> Result<Blob, Fail> {
        Ok(Sha256::digest(bytes(&r, "sha256", &x)?).to_vec())
    });
    let r = secrets.clone();
    engine.register_fn(
        "hmac_sha256",
        move |key: Dynamic, msg: Dynamic| -> Result<Blob, Fail> {
            let key_bytes = bytes(&r, "hmac_sha256", &key)?;
            let msg_bytes = bytes(&r, "hmac_sha256", &msg)?;
            // A key is a secret whatever it is called.
            if let Ok(text) = std::str::from_utf8(&key_bytes) {
                add(&r, text)?;
            }
            secret_forms(&r, &key_bytes)?;
            // hmac 0.12 always answers Ok: a key of any length is hashed or padded.
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&key_bytes).expect("HMAC takes a key of any length");
            mac.update(&msg_bytes);
            let out = mac.finalize().into_bytes().to_vec();
            secret_forms(&r, &out)?;
            Ok(out)
        },
    );

    let r = secrets.clone();
    engine.register_fn("hex", move |x: Dynamic| -> Result<String, Fail> {
        Ok(hex(&bytes(&r, "hex", &x)?))
    });
    let r = secrets.clone();
    engine.register_fn("secret", move |x: Dynamic| -> Result<Dynamic, Fail> {
        if x.is_string() || x.is_int() || x.is_float() || x.is_bool() || x.is_char() {
            add(&r, &x.to_string())?;
        } else if let Some(b) = x.read_lock::<Blob>() {
            secret_forms(&r, &b)?;
        } else {
            // The value is what is being hidden, so the error names its type only.
            let message = format!("secret: expected a scalar or bytes, got {}", x.type_name());
            return Err(fail_plain(&r, message));
        }
        Ok(x)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::engine::engine;

    fn run(script: &str) -> Result<Dynamic, String> {
        engine(&Secrets::default())
            .eval::<Dynamic>(script)
            .map_err(|e| e.to_string())
    }

    fn text(script: &str) -> String {
        run(script).expect("script runs").to_string()
    }

    #[test]
    fn base64_in_both_alphabets() {
        assert_eq!(text(r#"base64("hello?>")"#), "aGVsbG8/Pg==");
        assert_eq!(text(r#"base64url("hello?>")"#), "aGVsbG8_Pg");
        assert_eq!(text(r#"base64_decode("aGVsbG8/Pg==")"#), "hello?>");
        assert_eq!(text(r#"base64url_decode("aGVsbG8_Pg")"#), "hello?>");
        assert_eq!(text(r#"base64url_decode("aGVsbG8_Pg==")"#), "hello?>");
    }

    #[test]
    fn invalid_base64_names_the_operation_and_the_value() {
        let err = run(r#"base64_decode("not base64!")"#).unwrap_err();
        assert!(err.contains("base64_decode"), "{err}");
        assert!(err.contains("not base64!"), "{err}");
    }

    #[test]
    fn a_decode_that_is_not_utf8_points_at_the_blob_variant() {
        let err = run(r#"base64_decode("/w==")"#).unwrap_err();
        assert!(err.contains("base64_decode_blob"), "{err}");
        assert_eq!(text(r#"base64_decode_blob("/w==").len()"#), "1");
    }

    #[test]
    fn url_encoding_round_trips_and_uses_percent_20() {
        assert_eq!(text(r#"url_encode("a b&c=d/é")"#), "a%20b%26c%3Dd%2F%C3%A9");
        assert_eq!(text(r#"url_decode("a%20b%26c%3Dd%2F%C3%A9")"#), "a b&c=d/é");
        assert!(
            run(r#"url_decode("%zz")"#)
                .unwrap_err()
                .contains("url_decode")
        );
    }

    #[test]
    fn sha256_and_hmac_match_known_vectors() {
        assert_eq!(
            text(r#"hex(sha256("abc"))"#),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // RFC 4231 test case 2.
        assert_eq!(
            text(r#"hex(hmac_sha256("Jefe", "what do ya want for nothing?"))"#),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn an_hmac_key_may_be_bytes() {
        assert_eq!(
            text(
                r#"hex(hmac_sha256(base64_decode_blob("SmVmZQ=="), "what do ya want for nothing?"))"#
            ),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn standard_string_helpers_are_there() {
        assert_eq!(text(r#"let s = "  Ab c "; s.trim(); s.to_upper()"#), "AB C");
        assert_eq!(text(r#"let s = "a-b"; s.replace("-", "+"); s"#), "a+b");
    }

    #[test]
    fn a_loop_that_never_ends_is_stopped() {
        let err = run("loop { }").unwrap_err();
        assert!(err.to_lowercase().contains("operations"), "{err}");
    }

    #[test]
    fn eval_and_print_do_nothing_harmful() {
        assert!(run(r#"eval("1 + 1")"#).is_err());
        assert!(run(r#"print("x"); 1"#).is_ok());
    }

    #[test]
    fn the_hmac_key_and_result_join_the_secret_set() {
        let redactor = Secrets::default();
        let engine = engine(&redactor);
        let mac = engine
            .eval::<String>(r#"hex(hmac_sha256("topsecretkey", "payload"))"#)
            .unwrap();
        assert_eq!(redactor.mask("key topsecretkey"), "key ***");
        assert_eq!(redactor.mask(&format!("sig {mac}")), "sig ***");
    }

    #[test]
    fn secret_marks_a_value_and_returns_it() {
        let redactor = Secrets::default();
        let got = engine(&redactor)
            .eval::<String>(r#"secret("hunter22")"#)
            .unwrap();
        assert_eq!(got, "hunter22");
        assert_eq!(redactor.mask("pw hunter22"), "pw ***");
    }

    #[test]
    fn secret_takes_any_scalar_and_returns_it_unchanged() {
        let redactor = Secrets::default();
        let engine = engine(&redactor);
        let got = engine
            .eval::<String>(
                r#"`${secret(4242) + 1} ${secret(1.5)} ${secret(true)} ${secret('c')}`"#,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, "4243 1.5 true c");
        assert_eq!(redactor.list(), ["4242", "1.5", "true", "c"]);
        let err = engine
            .eval::<Dynamic>(r#"secret([1234567])"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("secret") && err.contains("array"), "{err}");
        assert!(!err.contains("1234567"), "{err}");
    }

    #[test]
    fn url_encode_follows_rfc_3986() {
        assert_eq!(text(r#"url_encode("a~b*c d")"#), "a~b%2Ac%20d");
    }

    #[test]
    fn url_decode_wants_two_hex_digits() {
        let err = run(r#"url_decode("%+1")"#).unwrap_err();
        assert!(err.contains("url_decode"), "{err}");
    }

    #[test]
    fn a_blob_hmac_key_joins_the_secret_set_in_every_form() {
        let redactor = Secrets::default();
        let engine = engine(&redactor);
        let mac = engine
            .eval::<Dynamic>(
                r#"hmac_sha256(base64_decode_blob("/////////////////w=="), "payload")"#,
            )
            .unwrap();
        assert!(mac.is_blob());
        let key_hex = "ff".repeat(13);
        assert_eq!(redactor.mask(&format!("k {key_hex}")), "k ***");
        assert_eq!(redactor.mask("k /////////////////w=="), "k ***");
        assert_eq!(redactor.mask("k _________________w"), "k ***");
    }

    #[test]
    fn an_error_masks_a_secret_before_it_cuts() {
        let redactor = Secrets::default();
        redactor
            .add(&format!("{}SECRETTAIL", "x".repeat(78)))
            .unwrap();
        let value = format!("{}SECRETTAIL", "x".repeat(78));
        let shown = quote(&redactor, &value);
        assert!(
            !shown.contains('x'),
            "a cut-first filter would leave 78 x's: {shown}"
        );
    }

    #[test]
    fn a_secret_is_listed_masked_and_cloned_by_handle() {
        let s = Secrets::default();
        let c = s.clone();
        c.add("hunter22").unwrap();
        c.add("").unwrap();
        assert_eq!(s.list(), vec!["hunter22".to_string()]);
        assert_eq!(s.mask("pw hunter22 hunter22"), "pw *** ***");
    }

    #[test]
    fn the_secret_set_is_capped_by_count_and_by_size() {
        let s = Secrets::default();
        for i in 0..MAX_SECRETS {
            s.add(&i.to_string()).unwrap();
        }
        s.add("0").unwrap();
        assert_eq!(s.len(), MAX_SECRETS);
        let err = s.add("one more").unwrap_err();
        assert!(err.contains("secrets"), "{err}");
        assert!(!err.contains("one more"), "{err}");

        let s = Secrets::default();
        assert!(s.add(&"x".repeat(MAX_SECRET_BYTES + 1)).is_err());
        assert!(s.add(&"x".repeat(MAX_SECRET_BYTES)).is_ok());
    }

    #[test]
    fn a_script_that_declares_too_many_secrets_fails() {
        let err = run("for i in 0..60000 { secret(i); } 1").unwrap_err();
        assert!(err.contains("secrets"), "{err}");
    }

    #[test]
    fn the_longer_secret_wins_when_one_contains_the_other() {
        let s = Secrets::default();
        s.add("abc").unwrap();
        s.add("abcdef").unwrap();
        assert_eq!(s.mask("x abcdef y"), "x *** y");
    }
}
