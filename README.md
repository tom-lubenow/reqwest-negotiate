# reqwest-negotiate

Kerberos/SPNEGO Negotiate authentication for [reqwest](https://crates.io/crates/reqwest).

This crate provides an extension trait for `reqwest::RequestBuilder` that adds HTTP Negotiate (SPNEGO/Kerberos) authentication, similar to `curl --negotiate`.

## Platform Support

| Platform | Status |
|----------|--------|
| Linux | Supported (MIT Kerberos) |
| macOS | Supported (Heimdal) |
| Windows | Not supported (contributions welcome) |

Windows would require SSPI integration instead of GSSAPI. Contributions are welcome.

## Prerequisites

### System Dependencies

**Linux (Debian/Ubuntu):**
```bash
sudo apt install libkrb5-dev
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install krb5-devel
```

**macOS:**
```bash
brew install krb5
```

### Kerberos Ticket

You need a valid Kerberos ticket before making requests:
```bash
kinit user@REALM.COM
```

## Installation

```toml
[dependencies]
reqwest-negotiate = "0.1"
reqwest = "0.13"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Usage

### Basic Authentication

```rust
use reqwest_negotiate::NegotiateAuthExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let response = client
        .get("https://api.example.com/protected")
        .negotiate_auth()?
        .send()
        .await?;

    println!("Status: {}", response.status());
    Ok(())
}
```

### Mutual Authentication

For high-security environments, verify the server's identity:

```rust
use reqwest_negotiate::NegotiateAuthExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let (builder, mut ctx) = client
        .get("https://api.example.com/protected")
        .negotiate_auth_mutual()?;

    let response = builder.send().await?;

    // Verify the server proved its identity
    ctx.verify_response(&response)?;

    println!("Status: {}", response.status());
    Ok(())
}
```

### Custom Service Principal

If the service principal name differs from `HTTP/<hostname>`:

```rust
use reqwest_negotiate::NegotiateAuthExt;

let response = client
    .get("https://api.example.com/protected")
    .negotiate_auth_with_spn("HTTP/custom.principal@REALM.COM")?
    .send()
    .await?;
```

## API

### Extension Trait Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `negotiate_auth()` | `Result<RequestBuilder>` | Add Negotiate auth, SPN derived from URL |
| `negotiate_auth_with_spn(spn)` | `Result<RequestBuilder>` | Add Negotiate auth with custom SPN |
| `negotiate_auth_mutual()` | `Result<(RequestBuilder, NegotiateContext)>` | Add auth + return context for verification |
| `negotiate_auth_mutual_with_spn(spn)` | `Result<(RequestBuilder, NegotiateContext)>` | Custom SPN + mutual auth |

### NegotiateContext Methods

| Method | Description |
|--------|-------------|
| `verify_response(&response)` | Verify server's token from `WWW-Authenticate` header |
| `is_complete()` | Check if security context is fully established |

## How It Works

1. The crate uses [libgssapi](https://crates.io/crates/libgssapi) to interface with your system's GSSAPI library
2. It acquires credentials from your Kerberos credential cache (from `kinit`)
3. Generates a SPNEGO token and sets the `Authorization: Negotiate <token>` header
4. For mutual auth, verifies the server's response token from `WWW-Authenticate`

## Comparison with curl

This crate aims to provide equivalent functionality to:
```bash
curl --negotiate -u : https://api.example.com/protected
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contributing

Contributions are welcome! Areas of interest:

- Windows SSPI support
- Additional test coverage
- Real-world testing reports

## Pure Rust backend (existing kinit cache)

An optional async client uses `rskrb5` instead of system GSSAPI/SSPI. Disable
**default features** to remove the native Kerberos dependency:

```toml
reqwest-negotiate = { version = "0.1", default-features = false, features = ["pure-rust"] }
reqwest = { version = "0.13", default-features = false, features = ["rustls"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use reqwest_negotiate::pure_rust::NegotiateClient;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let mut auth = NegotiateClient::from_default_cache()?;
let response = auth
    .send(reqwest::Client::new().get("https://service.example.com/protected"))
    .await?;
// The server's Kerberos mutual-authentication reply has been verified.
println!("{}", response.text().await?);
# Ok(())
# }
```

Run `kinit` before starting the application. `KRB5CCNAME` selects the cache;
otherwise the backend uses `default_ccache_name` from Kerberos configuration.
Set `KRB5_CONFIG` when configuration is not at the platform's default location.
For example, in a POSIX shell, using a private directory:

```sh
cache_dir=$(mktemp -d)
export KRB5CCNAME="FILE:$cache_dir/ccache"
kinit
cargo run --no-default-features --features pure-rust --example pure_rust -- https://service.example.com/protected
# Once finished with this cache:
kdestroy
rmdir "$cache_dir"
```

`NegotiateClient::from_cache(config, "FILE:/path/to/cache")` accepts explicit
configuration and cache names. FILE/WRFILE and MIT DIR caches are supported by
the backend. KCM, KEYRING, API and MSLSA stores are not supported; valid output
from `klist` alone does not guarantee the cache is compatible. Unsupported
stores return an error and never silently fall back to native authentication.

This initial backend supports preemptive, Kerberos-only HTTP Negotiate with a
verified AP-REP. It requires mutual authentication and rejects incomplete
negotiation, mechanism-list MICs and unsupported mechanisms. General multi-leg
SPNEGO, NTLM, proxies requiring authentication, and TLS channel binding are not
implemented. Unsupported server negotiation responses produce errors rather
than authentication success. Use the default native backend when its platform integration is needed.

Requests are sent once; streaming bodies need no cloning or replay. Redirects
are disabled to keep authentication scoped to the requested URL. Transport
settings come from the authentication client's HTTP client, not the client used
to create the request builder. Customize them with `with_http_builder`; this
always disables redirects. Normal reqwest TLS verification remains enabled.

The cache is read at construction, and service tickets are reused in memory.
Recreate the client after replacing the cache with another `kinit`. Ticket
acquisition may contact a KDC. The protocol backend is pre-1.0; deployment
compatibility should be tested against your realm. This feature removes native
Kerberos libraries, not every possible native dependency selected by TLS features.

### Validation

```sh
cargo test --no-default-features --features pure-rust --all-targets
# Optional real-realm test (uses the selected kinit cache):
NEGOTIATE_TEST_URL=https://service.example.com/protected \
  cargo test --no-default-features --features pure-rust --test pure_rust live_kinit_cache -- --ignored
```

Automated tests use synthetic cache credentials and a local server to verify
AP-REQ/AP-REP exchange, reject forged or incomplete responses, and check redirect
handling. They do not substitute for MIT/Heimdal/Active Directory KDC testing.
