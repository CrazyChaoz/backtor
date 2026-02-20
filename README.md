# backtor

A Tor-native remote shell. Expose a local shell through a Tor hidden service
and connect to it from anywhere, with no open ports and no SSH infrastructure
required.

Tor's end-to-end encryption and the onion address itself serve as both the
secure channel and the shared secret. The intended use case is machines behind
NAT, firewalls, or restrictive networks where exposing a port is not possible.

---

## How it works

**Server side** — backtor registers a Tor onion service and accepts incoming
connections on port 22. Each connection is handed a freshly spawned login shell
through a PTY. The onion address is printed to stdout once the service is
reachable.

**Client side** — backtor connects to the onion address through Tor, puts the
local terminal in raw mode, and bridges stdin/stdout to the remote PTY. The
session behaves like an interactive SSH session.

---

## Usage

### Start a server

```sh
backtor
```

An ephemeral onion address is generated on each run. Once bootstrapped, the
address is printed:

```
Shell service available at: <address>.onion:22
```

#### Start a server with a stable address

Supply a 32-byte secret key as 64 hex characters. The same key always produces
the same onion address.

```sh
backtor serve --key <64 hex chars>
```

### Connect to a server

```sh
backtor connect <address>.onion
```

The `.onion` suffix is optional. Type `exit` or press `Ctrl-D` to end the
session.

---

## Security considerations

- The onion address functions as the only credential. Anyone who knows it can
  connect and will receive an interactive shell as the user running `backtor`.
  Keep the address private.
- Traffic is encrypted end-to-end by the Tor protocol. No additional TLS or
  SSH layer is required.
- Tor bootstrapping requires network access and a few seconds on first run.

---

## Building

Requires a Rust toolchain (edition 2024) and a C compiler for the OpenSSL
dependency pulled in by arti.

```sh
cargo build --release
```

The compiled binary is at `target/release/backtor`.

---

## Logging

Log verbosity is controlled with the `RUST_LOG` environment variable.

```sh
RUST_LOG=debug backtor
```

---

## License

This project is licensed under the EUPL License. See the [LICENSE](LICENSE) file for details.
