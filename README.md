# qsb-did-resolver workspace

## Structure

```text
core/
  Cargo.toml
  src/
    lib.rs
    did.rs
    resolver.rs
    document.rs
    error.rs
    rpc.rs

cli/
  Cargo.toml
  src/main.rs

server/
  Cargo.toml
  src/main.rs
```

## What each crate does

- `core`: DID domain models, RPC client, mapping `DidDetails -> DID Resolution result`.
- `server`: HTTP DID resolver (`GET /1.0/identifiers/{did}`).
- `cli`: CLI utility for ad-hoc DID resolution from terminal.

## Build

```bash
cargo check --workspace
```

## Run server

```bash
cargo run -p qsb-did-resolver-server -- \
  --listen-addr 127.0.0.1:8080 \
  --node-rpc-url http://127.0.0.1:9944
```

## Resolve from CLI

```bash
cargo run -p qsb-did-resolver-cli -- \
  --node-rpc-url http://127.0.0.1:9944 \
  --did did:qsb:YOUR_DID_ID \
  --pretty
```

## Endpoints

- `GET /health`
- `GET /1.0/identifiers/{did}`

The resolver calls node JSON-RPC method:

- `did_getByString`

## DID validation behavior

Resolver validates DID input before RPC call:

- prefix must be `did:qsb:`
- identifier part must be valid Base58
- decoded identifier length must be exactly 32 bytes
- invalid input returns DID Resolution error `invalidDid`
