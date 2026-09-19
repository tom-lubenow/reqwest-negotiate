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

## Credential-cache backend

To use existing `kinit` tickets without linking system Kerberos libraries, select
this Cargo configuration:

```toml
reqwest-negotiate = { version = "0.1", default-features = false, features = ["pure-rust"] }
```

The feature changes the implementation, not the API. Use the same
`NegotiateAuthExt`, `NegotiateContext`, and `NegotiateError` types:

```rust,no_run
use reqwest_negotiate::NegotiateAuthExt;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()?;
let (request, mut context) = client
    .get("https://service.example.com/protected")
    .negotiate_auth_mutual()?;
let response = request.send().await?;
context.verify_response(&response)?;
println!("{}", response.text().await?);
# Ok(())
# }
```

The shorter `.negotiate_auth()?.send().await?` flow and custom-SPN methods
also work unchanged. As with the native implementation, use the mutual methods
and `verify_response` when you need to verify the server's identity.

The caller's reqwest client controls TLS, proxy settings, timeouts, connection
pooling and redirects. Disable redirects when authenticating a particular
service. Request bodies are not cloned or replayed. Both backends prepare tokens
synchronously and may block while contacting a KDC; the cache backend manages its
own runtime internally and works inside Tokio, including a current-thread runtime.
HTTP request timeouts do not govern this credential-acquisition step.

`KRB5CCNAME` selects the existing cache, otherwise `default_ccache_name` in
Kerberos configuration is used. Set `KRB5_CONFIG` for a non-default config file.
A new cache snapshot is loaded for each authentication attempt, so a later
`kinit` is picked up without recreating your HTTP client. Example:

```sh
cache_dir=$(mktemp -d)
export KRB5CCNAME="FILE:$cache_dir/ccache"
kinit
cargo run --no-default-features --features pure-rust --example mutual_auth -- https://service.example.com/protected
kdestroy
rmdir "$cache_dir"
```

The backend supports FILE/WRFILE and MIT DIR caches. KCM, KEYRING, API and MSLSA
stores are unsupported and produce credential errors. This initial implementation
supports Kerberos HTTP Negotiate and AP-REP verification; it rejects additional
SPNEGO exchanges, mechanism-list MICs and unsupported mechanisms during response
verification. NTLM, proxy authentication and TLS channel binding are unsupported.
The implementation uses pre-1.0 `rskrb5`; test your realm's policies before deployment.
Its cache validity checks do not allow clock skew: a newly issued ticket can be
rejected while the client clock is behind the KDC, even when native Kerberos
accepts it. Keep clocks synchronized; this backend does not yet match native
Kerberos's clock-skew tolerance.

The default `native` feature retains system GSSAPI/SSPI integration. If both
features are enabled, the credential-cache implementation is selected. Disable
default features to exclude the native dependency. This choice removes native
Kerberos dependencies; TLS features can independently select native dependencies.

### Validation

```sh
cargo test --no-default-features --features pure-rust --all-targets
# Optional deployment test using your current cache:
NEGOTIATE_TEST_URL=https://service.example.com/protected \
  cargo test --no-default-features --features pure-rust --test credential_cache live_kinit_cache -- --ignored
```

Synthetic cache tests exercise the public extension methods in isolated processes,
including a current-thread Tokio runtime, custom SPNs, forged/missing/incomplete
server replies, and the caller's redirect policy.

### NixOS VM integration test

CI also runs a two-machine NixOS test against an MIT Kerberos KDC and a Python
HTTP acceptor backed by MIT GSSAPI, independent of the Rust protocol backend.
It runs `kinit`, verifies that the fresh FILE cache contains only a TGT (no HTTP
service ticket), and authenticates with the compiled pure Rust example. This
exercises service-ticket acquisition and server mutual authentication. Native
`curl --negotiate -u :` must authenticate to the same endpoint, and the Rust
client must fail after `kdestroy`.

```sh
# x86_64 Linux with KVM, or a configured Linux remote builder with KVM:
nix build -L .#checks.x86_64-linux.kerberos
```

Nixpkgs is pinned in `flake.lock`; Cargo dependencies come from `Cargo.lock`.
All principals, passwords, keys and caches are created inside disposable test
VMs. No enterprise credentials or CI secrets are needed. This covers MIT
Kerberos and FILE caches; it does not establish Active Directory, Heimdal or
KCM compatibility.
