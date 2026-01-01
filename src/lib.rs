//! Kerberos/SPNEGO Negotiate authentication for reqwest.
//!
//! This crate provides an extension trait for [`reqwest::RequestBuilder`] that adds
//! Kerberos SPNEGO (Negotiate) authentication support using the system's GSSAPI library.
//!
//! # Prerequisites
//!
//! - A valid Kerberos ticket (obtained via `kinit` or similar)
//! - GSSAPI libraries installed on your system (`libgssapi_krb5` on Linux, Heimdal on macOS)
//!
//! # Example
//!
//! ```no_run
//! use reqwest_negotiate::NegotiateAuthExt;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = reqwest::Client::new();
//!
//!     let response = client
//!         .get("https://api.example.com/protected")
//!         .negotiate_auth()? // Uses default credentials and derives SPN from URL
//!         .send()
//!         .await?;
//!
//!     println!("Status: {}", response.status());
//!     Ok(())
//! }
//! ```
//!
//! # Custom Service Principal
//!
//! If the service principal name (SPN) differs from the standard `HTTP/<hostname>`:
//!
//! ```no_run
//! use reqwest_negotiate::NegotiateAuthExt;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = reqwest::Client::new();
//!
//! let response = client
//!     .get("https://api.example.com/protected")
//!     .negotiate_auth_with_spn("HTTP/custom.principal@REALM.COM")?
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use libgssapi::context::{ClientCtx, CtxFlags};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE, OidSet};
use reqwest::RequestBuilder;
use reqwest::header::{AUTHORIZATION, HeaderValue};

/// Errors that can occur during Negotiate authentication.
#[derive(Debug, thiserror::Error)]
pub enum NegotiateError {
    /// Failed to create the service principal name.
    #[error("failed to create service name: {0}")]
    NameError(String),

    /// Failed to acquire Kerberos credentials.
    #[error("failed to acquire credentials: {0}")]
    CredentialError(String),

    /// Failed to initialize or step the security context.
    #[error("failed to initialize security context: {0}")]
    ContextError(String),

    /// The request URL is missing a host component.
    #[error("request URL is missing host")]
    MissingHost,

    /// The request could not be built.
    #[error("failed to build request: {0}")]
    BuildError(#[from] reqwest::Error),
}

/// Extension trait that adds Negotiate authentication to [`reqwest::RequestBuilder`].
pub trait NegotiateAuthExt {
    /// Adds Negotiate authentication using the default Kerberos credentials.
    ///
    /// The service principal name (SPN) is derived from the request URL as `HTTP/<hostname>`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The URL has no host component
    /// - No valid Kerberos credentials are available
    /// - The GSSAPI context initialization fails
    fn negotiate_auth(self) -> Result<RequestBuilder, NegotiateError>;

    /// Adds Negotiate authentication with a custom service principal name.
    ///
    /// Use this when the service is registered with a non-standard SPN.
    ///
    /// # Arguments
    ///
    /// * `spn` - The service principal name (e.g., `HTTP/service.example.com@REALM.COM`)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No valid Kerberos credentials are available
    /// - The GSSAPI context initialization fails
    fn negotiate_auth_with_spn(self, spn: &str) -> Result<RequestBuilder, NegotiateError>;
}

impl NegotiateAuthExt for RequestBuilder {
    fn negotiate_auth(self) -> Result<RequestBuilder, NegotiateError> {
        // Build a temporary copy to inspect the URL
        let request = self
            .try_clone()
            .ok_or_else(|| NegotiateError::ContextError("request body not clonable".into()))?
            .build()?;

        let host = request.url().host_str().ok_or(NegotiateError::MissingHost)?;
        let spn = format!("HTTP@{}", host);

        add_negotiate_header(self, &spn)
    }

    fn negotiate_auth_with_spn(self, spn: &str) -> Result<RequestBuilder, NegotiateError> {
        add_negotiate_header(self, spn)
    }
}

fn add_negotiate_header(
    builder: RequestBuilder,
    spn: &str,
) -> Result<RequestBuilder, NegotiateError> {
    let token = generate_negotiate_token(spn)?;
    let header_value = format!("Negotiate {}", BASE64.encode(&token));

    Ok(builder.header(
        AUTHORIZATION,
        HeaderValue::from_str(&header_value)
            .map_err(|e| NegotiateError::ContextError(e.to_string()))?,
    ))
}

fn generate_negotiate_token(spn: &str) -> Result<Vec<u8>, NegotiateError> {
    // Create the service principal name
    let name = Name::new(spn.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
        .map_err(|e| NegotiateError::NameError(e.to_string()))?;

    // Acquire default credentials for the current user
    let mut mechs = OidSet::new().map_err(|e| NegotiateError::CredentialError(e.to_string()))?;
    mechs
        .add(&GSS_MECH_KRB5)
        .map_err(|e| NegotiateError::CredentialError(e.to_string()))?;

    let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&mechs))
        .map_err(|e| NegotiateError::CredentialError(e.to_string()))?;

    // Initialize the client context
    let mut ctx = ClientCtx::new(
        Some(cred),
        name,
        CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
        Some(&GSS_MECH_KRB5),
    );

    // Generate the initial token
    match ctx.step(None, None) {
        Ok(Some(token)) => Ok(token.to_vec()),
        Ok(None) => Err(NegotiateError::ContextError(
            "no token generated".to_string(),
        )),
        Err(e) => Err(NegotiateError::ContextError(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spn_format() {
        // Just a basic sanity check that the SPN format is correct
        let host = "api.example.com";
        let spn = format!("HTTP@{}", host);
        assert_eq!(spn, "HTTP@api.example.com");
    }
}
