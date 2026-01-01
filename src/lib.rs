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
//! # Basic Example
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
//! # Mutual Authentication
//!
//! For high-security environments, you can verify the server's identity:
//!
//! ```no_run
//! use reqwest_negotiate::NegotiateAuthExt;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = reqwest::Client::new();
//!
//!     let (builder, mut ctx) = client
//!         .get("https://api.example.com/protected")
//!         .negotiate_auth_mutual()?;
//!
//!     let response = builder.send().await?;
//!
//!     // Verify the server proved its identity
//!     ctx.verify_response(&response)?;
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

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE, OidSet};
use reqwest::header::{HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{RequestBuilder, Response};

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

    /// Server did not provide a mutual authentication token.
    #[error("server did not provide mutual authentication token")]
    MissingMutualAuthToken,

    /// Failed to verify the server's authentication token.
    #[error("failed to verify server token: {0}")]
    MutualAuthFailed(String),

    /// Invalid token format in server response.
    #[error("invalid token format in WWW-Authenticate header")]
    InvalidTokenFormat,
}

/// Holds the GSSAPI context for mutual authentication verification.
///
/// After sending a request with [`NegotiateAuthExt::negotiate_auth_mutual`],
/// use this context to verify the server's response token.
pub struct NegotiateContext {
    ctx: ClientCtx,
}

impl NegotiateContext {
    /// Verifies the server's mutual authentication token from the response.
    ///
    /// Call this after receiving a response to confirm the server's identity.
    /// The server's token is extracted from the `WWW-Authenticate: Negotiate <token>` header.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The response doesn't contain a `WWW-Authenticate: Negotiate` header
    /// - The token is malformed
    /// - The server's identity cannot be verified
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqwest_negotiate::NegotiateAuthExt;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = reqwest::Client::new();
    ///
    /// let (builder, mut ctx) = client
    ///     .get("https://api.example.com/protected")
    ///     .negotiate_auth_mutual()?;
    ///
    /// let response = builder.send().await?;
    /// ctx.verify_response(&response)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify_response(&mut self, response: &Response) -> Result<(), NegotiateError> {
        let header = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .ok_or(NegotiateError::MissingMutualAuthToken)?;

        let header_str = header
            .to_str()
            .map_err(|_| NegotiateError::InvalidTokenFormat)?;

        let token_b64 = header_str
            .strip_prefix("Negotiate ")
            .ok_or(NegotiateError::InvalidTokenFormat)?;

        if token_b64.is_empty() {
            return Err(NegotiateError::MissingMutualAuthToken);
        }

        let token = BASE64
            .decode(token_b64)
            .map_err(|_| NegotiateError::InvalidTokenFormat)?;

        // Verify the server's token
        match self.ctx.step(Some(&token), None) {
            Ok(_) => Ok(()),
            Err(e) => Err(NegotiateError::MutualAuthFailed(e.to_string())),
        }
    }

    /// Checks if the security context is fully established.
    ///
    /// Returns `true` if mutual authentication is complete.
    pub fn is_complete(&self) -> bool {
        self.ctx.is_complete()
    }
}

/// Extension trait that adds Negotiate authentication to [`reqwest::RequestBuilder`].
pub trait NegotiateAuthExt {
    /// Adds Negotiate authentication using the default Kerberos credentials.
    ///
    /// The service principal name (SPN) is derived from the request URL as `HTTP/<hostname>`.
    ///
    /// This method does not verify the server's identity. For mutual authentication,
    /// use [`negotiate_auth_mutual`](Self::negotiate_auth_mutual) instead.
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
    /// This method does not verify the server's identity. For mutual authentication,
    /// use [`negotiate_auth_mutual_with_spn`](Self::negotiate_auth_mutual_with_spn) instead.
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

    /// Adds Negotiate authentication and returns a context for mutual authentication.
    ///
    /// The service principal name (SPN) is derived from the request URL as `HTTP/<hostname>`.
    ///
    /// After sending the request, call [`NegotiateContext::verify_response`] to verify
    /// the server's identity.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The URL has no host component
    /// - No valid Kerberos credentials are available
    /// - The GSSAPI context initialization fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqwest_negotiate::NegotiateAuthExt;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = reqwest::Client::new();
    ///
    /// let (builder, mut ctx) = client
    ///     .get("https://api.example.com/protected")
    ///     .negotiate_auth_mutual()?;
    ///
    /// let response = builder.send().await?;
    /// ctx.verify_response(&response)?;
    /// # Ok(())
    /// # }
    /// ```
    fn negotiate_auth_mutual(self) -> Result<(RequestBuilder, NegotiateContext), NegotiateError>;

    /// Adds Negotiate authentication with a custom SPN and returns a context for mutual authentication.
    ///
    /// After sending the request, call [`NegotiateContext::verify_response`] to verify
    /// the server's identity.
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
    fn negotiate_auth_mutual_with_spn(
        self,
        spn: &str,
    ) -> Result<(RequestBuilder, NegotiateContext), NegotiateError>;
}

impl NegotiateAuthExt for RequestBuilder {
    fn negotiate_auth(self) -> Result<RequestBuilder, NegotiateError> {
        let (builder, _ctx) = self.negotiate_auth_mutual()?;
        Ok(builder)
    }

    fn negotiate_auth_with_spn(self, spn: &str) -> Result<RequestBuilder, NegotiateError> {
        let (builder, _ctx) = self.negotiate_auth_mutual_with_spn(spn)?;
        Ok(builder)
    }

    fn negotiate_auth_mutual(self) -> Result<(RequestBuilder, NegotiateContext), NegotiateError> {
        // Build a temporary copy to inspect the URL
        let request = self
            .try_clone()
            .ok_or_else(|| NegotiateError::ContextError("request body not clonable".into()))?
            .build()?;

        let host = request
            .url()
            .host_str()
            .ok_or(NegotiateError::MissingHost)?;
        let spn = format!("HTTP@{}", host);

        add_negotiate_header_with_ctx(self, &spn)
    }

    fn negotiate_auth_mutual_with_spn(
        self,
        spn: &str,
    ) -> Result<(RequestBuilder, NegotiateContext), NegotiateError> {
        add_negotiate_header_with_ctx(self, spn)
    }
}

fn add_negotiate_header_with_ctx(
    builder: RequestBuilder,
    spn: &str,
) -> Result<(RequestBuilder, NegotiateContext), NegotiateError> {
    let (token, ctx) = generate_negotiate_token_with_ctx(spn)?;
    let header_value = format!("Negotiate {}", BASE64.encode(&token));

    let builder = builder.header(
        AUTHORIZATION,
        HeaderValue::from_str(&header_value)
            .map_err(|e| NegotiateError::ContextError(e.to_string()))?,
    );

    Ok((builder, NegotiateContext { ctx }))
}

fn generate_negotiate_token_with_ctx(
    spn: &str,
) -> Result<(Vec<u8>, ClientCtx), NegotiateError> {
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

    // Initialize the client context with mutual auth flag
    let mut ctx = ClientCtx::new(
        Some(cred),
        name,
        CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
        Some(&GSS_MECH_KRB5),
    );

    // Generate the initial token
    match ctx.step(None, None) {
        Ok(Some(token)) => Ok((token.to_vec(), ctx)),
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
