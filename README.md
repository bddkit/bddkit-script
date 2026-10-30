# bddkit-script

A `bddkit` plugin that runs short Rhai scripts to derive values (Base64, HMAC, JWT) inside feature files, in the same scenario as the API and DB steps `bddkit` already provides.

## Steps

`script` adds two steps. Both take the script as a doc string.

`I execute script to "<name>":` runs the script and saves its result as the variable `<name>`.

```gherkin
When I execute script to "joined":
  """
  let a = 4;
  `${a}|5`
  """
Then variable "joined" should be equal to "4|5"
```

An HS256 JWT:

```gherkin
Given set variable "user" to "Ann"
And set variable "jwt_secret" to "s3cret"
When I execute script to "token":
  """
  let h = base64url(`{"alg":"HS256","typ":"JWT"}`);
  let p = base64url(`{"sub":"${vars.user}"}`);
  let s = base64url(hmac_sha256(vars.jwt_secret, `${h}.${p}`));
  `${h}.${p}.${s}`
  """
```

`I execute script to variables:` runs the script, which must return a map, and saves each top-level key as a variable.

```gherkin
Given set variable "user" to "Ann"
When I execute script to variables:
  """
  #{ greeting: `Hello, ${vars.user}`, ids: [7, 8] }
  """
Then variable "greeting" should be equal to "Hello, Ann"
And variable "ids_length" should be equal to "2"
```

Both steps write ordinary variables. There is no `global` form of either: a plugin cannot write a file-level variable.

The scripts are written in [Rhai](https://rhai.rs). The value of a script is its last expression.

## The script environment

A script reads the variables of the feature file through `vars`: `vars.user` or `vars["user"]`. `vars.contains("user")` tells whether a variable exists. Reading a variable that does not exist is an error.

Every value is a string, whatever the step that saved it stored. A variable holding `<<null>>` reads as `()`.

The doc string reaches the plugin with a leading newline. The plugin drops exactly that one, so `script line 1` in an error is the first line you wrote.

`<<…>>` interpolation is not available inside a script: the steps declare a raw doc string, which the host passes on without interpolating, and a script reads variables through `vars` instead. To use `<<unique()>>`, set a variable first and read it:

```gherkin
Given set variable "id" to "<<unique()>>"
When I execute script to "key":
  """
  base64(vars.id)
  """
```

## Host functions

Functions that take "a string or bytes" accept either; anything else is an error naming the function.

- `base64(x)`, `base64url(x)`: encode a string or bytes. `base64url` is URL-safe and unpadded. `base64("hello?>")` is `aGVsbG8/Pg==`.
- `base64_decode(s)`, `base64url_decode(s)`: decode to a string. `base64url_decode` accepts input with or without `=` padding. The bytes must be UTF-8, otherwise the error points at the `_blob` variant.
- `base64_decode_blob(s)`, `base64url_decode_blob(s)`: decode to bytes, for data that is not text.
- `url_encode(s)`, `url_decode(s)`: percent-encoding. `url_encode("a b&c")` is `a%20b%26c`; only letters, digits and `-` `.` `_` `~` stay as they are.
- `sha256(x)`: the SHA-256 digest, as bytes. `hex(sha256("abc"))` is `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
- `hmac_sha256(key, message)`: the HMAC-SHA-256, as bytes. The key and the message are each a string or bytes. `hex(hmac_sha256("Jefe", "what do ya want for nothing?"))` is `5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843`.
- `hex(x)`: the bytes of a string or bytes as lower-case hexadecimal.
- `secret(x)`: returns `x` unchanged and marks it as a secret, see Secrets. `x` is a string, number, boolean or character, marked as its text, or bytes, marked in hex, Base64 and URL-safe Base64. An array or a map is an error.

A result of bytes cannot be saved as a variable, so convert it: `hex(sha256("abc"))` or `base64(sha256("abc"))`.

Rhai's own string methods are there too. Those such as `trim()` and `replace()` change the string in place and return `()`, so write `let s = "  Ab c "; s.trim(); s`, not `"  Ab c ".trim()`.

## Exporting results

What the script returns becomes variables, readable as `<<name>>`.

- A string, integer, float, boolean or character is one variable, written as text.
- An array `ids` is `ids_0`, `ids_1`, … and `ids_length`.
- A map `user` is one variable per key, `user_name`, and nests: `#{ name: "Ann", roles: ["a", "b"] }` under `user` gives `user_name`, `user_roles_0`, `user_roles_1` and `user_roles_length`.
- With `I execute script to variables:` the top-level keys of the map are the names, with the same rules below them.
- `()` is an error: the script returned nothing. Bytes are an error too, convert them with `hex(…)` or `base64(…)`. Any other type is an error.
- A name must be one that `<<…>>` can read back: a letter or `_` first, then letters, digits or `_`. `null`, `run_id` and `unique` are reserved, also as a name a nested value would write: `#{ run: #{ id: 1 } }` is refused. A map key below the top level may be digits, letters and `_` only.
- Two paths that lead to one name are an error, for example the key `roles_length` next to an array `roles`.
- The step overwrites a variable of the same name. It never removes one: if an array shrinks between two runs, `ids_3` from the earlier run is still there, so read `ids_length`.
- At most 10000 variables from one step, and nesting at most 16 deep.

## Secrets

The host decides which variables are secret: by their name (the default privacy word is `secret` only, so `jwt_secret` is secret and `db_password` is not), because they came through a `{name:secret}` macro parameter, or because their value is already in the file's secret set. The plugin is told which variables are secret.

- When a script reads a secret variable, or declares a secret with `secret(x)` or `hmac_sha256`, every value it exports is reported to the host as a secret. A Basic authorization header built from a secret is a credential too, and is masked in the console, the reports and the stream.
- `secret(x)` marks any value a script computes as a secret.
- The key and the result of `hmac_sha256` are registered as secrets, the result in hex, Base64 and URL-safe Base64.
- An error after the script read a secret variable, or declared a secret with `secret(x)` or `hmac_sha256`, shows no values: only its line and what failed (`script line 2: base64_decode: not valid Base64`), and a thrown value is not shown at all. A value derived from a secret is in no secret set, so no mask could hide it.
- Otherwise the text of an error is masked before it is cut. Either way the secrets known so far are reported with a failed step.
- A secret typed as a literal in the script itself is not known to the plugin. It is hidden only if the host sees it by position, for example when it is sent under a sensitive name.

## Limits

A script is stopped after one million operations, which ends a loop that never ends. An operation count is not a clock: a single call of a built-in function can take longer than the count suggests. Strings are limited to 1 MiB, and arrays and maps to 10000 entries. Bytes count against the array limit, so `base64_decode_blob` and `base64url_decode_blob` decode at most 10000 bytes; text up to 1 MiB decodes with `base64_decode`. One step reports at most 50000 secrets, 32 MiB of them in all; a script that would pass either fails. `eval` and `sleep` are disabled, and `print` and `debug` do nothing.

## Checked before the run

Before the first request, `bddkit` asks the plugin to check every script step. It refuses, with the line number, a syntax error, a misspelled variable or function (`unknown function base46`), a call with the wrong number of arguments (`function hmac_sha256 takes 2 argument(s), not 1`), an empty script, and a target name that `<<…>>` could not read back. A target name with `<<` in it is left to the run. What depends on the values of variables, such as a missing `vars.name` or an invalid Base64 input, can only fail during the run.

The check is strict on purpose, and refuses two kinds of script that would run: a closure stored in a map and called as a method (`obj.inc(2)` where `obj` is `#{ n: 1, inc: |x| x + this.n }`), and a script `fn` that uses `this`, called as a method (`fn twice() { this * 2 }` then `a.twice()`), because the check counts the value before the dot as one more argument. For both, pass the value to a plain function instead: `fn inc(o, x) { x + o.n }` then `inc(obj, 2)`.

## Compatibility

Needs a `bddkit` host that speaks plugin ABI 3.

## Building

```bash
cargo build --release
```

The library is written to `target/release/`.

## Installing

```bash
bddkit plugin install script
```

## License

Apache-2.0.
