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
