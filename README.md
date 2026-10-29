# bddkit-script

A `bddkit` plugin that runs short Rhai scripts to derive values (Base64, HMAC, JWT) inside feature files, in the same scenario as the API and DB steps `bddkit` already provides.

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
