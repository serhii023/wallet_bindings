# wallet_bindings

Zcash Rust wallet bindings to go

## Build

Compile the C library (in `target/release/wallet_bindings.dylib` for mac)

```sh
cargo build --release
```

Generate the C header (in 'include/rust_points.h')

```sh
cargo run --features headers --bin generate-headers
```

