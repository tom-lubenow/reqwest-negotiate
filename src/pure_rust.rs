//! Async HTTP Negotiate using tickets from a FILE/WRFILE or MIT DIR cache.
//!
//! This backend never prompts for a password or calls system GSSAPI. It requires
//! a Tokio runtime, a valid cache, and Kerberos configuration/KDC connectivity
//! when the cache does not already contain a usable service ticket.
//!
//! Requests carry a preemptive Kerberos token. Mutual authentication is required.
//! Redirects are disabled, and unsupported SPNEGO continuations are errors.
//! KCM, KEYRING, API and MSLSA caches, NTLM and TLS channel binding are unsupported.
//!
//! ```no_run
//! use reqwest_negotiate::pure_rust::NegotiateClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut auth = NegotiateClient::from_default_cache()?;
//! let response = auth.send(reqwest::Client::new().get("https://service.example.com")).await?;
//! println!("{}", response.status());
//! # Ok(())
//! # }
//! ```

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, WWW_AUTHENTICATE};
use reqwest::{Client, ClientBuilder, RequestBuilder, Response, StatusCode};
use rskrb5::spnego::{self, InitiatorContextOptions, NegState, ObjectIdentifier, SpnegoToken};

pub use rskrb5::Config;

/// Errors from cache loading, HTTP transport or authentication.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Kerberos configuration: {0}")]
    Config(#[from] rskrb5::config::Error),
    #[error("Kerberos credentials or ticket acquisition: {0}")]
    Kerberos(#[from] rskrb5::client::Error),
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("SPNEGO authentication failed: {0}")]
    Spnego(#[from] spnego::Error),
    #[error("invalid authentication header")]
    InvalidHeader,
    #[error("request must use HTTP or HTTPS and have a hostname")]
    InvalidUrl,
    #[error("server rejected authentication ({0})")]
    Rejected(StatusCode),
    #[error("server did not provide a mutual authentication token")]
    MissingMutualAuth,
    #[error("unsupported SPNEGO continuation, mechanism or mechanism-list MIC")]
    UnsupportedNegotiation,
}

/// A reusable, cache-backed Kerberos client.
///
/// Cache credentials are loaded on construction. Recreate this client to pick
/// up a newly replaced cache after `kinit`. Redirects are always disabled.
pub struct NegotiateClient {
    kerberos: rskrb5::NegotiateClient,
    http: Client,
}

impl NegotiateClient {
    /// Load default Kerberos configuration and the default credential cache.
    /// `KRB5CCNAME` takes precedence over `default_ccache_name` in the config.
    pub fn from_default_cache() -> Result<Self, Error> {
        let kerberos = rskrb5::NegotiateClient::from_default_ccache(Config::load_default()?)?;
        Self::new(kerberos)
    }

    /// Load a named cache, e.g. `FILE:/tmp/krb5cc_1000`, with explicit config.
    pub fn from_cache(config: Config, cache_name: &str) -> Result<Self, Error> {
        Self::new(rskrb5::NegotiateClient::from_ccache_name(
            config, cache_name,
        )?)
    }

    fn new(kerberos: rskrb5::NegotiateClient) -> Result<Self, Error> {
        Ok(Self {
            kerberos,
            http: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    /// Customize timeouts, TLS and other HTTP settings. Redirects remain disabled.
    pub fn with_http_builder(mut self, builder: ClientBuilder) -> Result<Self, Error> {
        self.http = builder
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(self)
    }

    /// Send a request once with a Kerberos token for its URL's `HTTP/hostname`.
    ///
    /// Build requests with a regular reqwest client. They are executed using this
    /// client's transport settings. Bodies are neither cloned nor replayed.
    /// Existing Authorization headers are replaced. The response is returned only
    /// after its AP-REP has been verified; HTTP error statuses other than 401/407
    /// remain available to the caller if mutual authentication succeeds.
    pub async fn send(&mut self, builder: RequestBuilder) -> Result<Response, Error> {
        let mut request = builder.build()?;
        if !matches!(request.url().scheme(), "http" | "https") {
            return Err(Error::InvalidUrl);
        }
        let host = request
            .url()
            .host_str()
            .ok_or(Error::InvalidUrl)?
            .to_owned();
        // RFC 4120 APOptions mutual-required is bit 2, represented MSB-first.
        let options = InitiatorContextOptions::new()
            .with_context_flags(vec![
                spnego::CONTEXT_FLAG_MUTUAL,
                spnego::CONTEXT_FLAG_INTEG,
            ])
            .with_ap_option_bits(1 << 29);
        let service = rskrb5::Principal::host_based_service("HTTP", host)?;
        let context = self
            .kerberos
            .authorization_context_with_options(service, options)
            .await?;
        let mut authorization =
            HeaderValue::from_str(&context.header).map_err(|_| Error::InvalidHeader)?;
        authorization.set_sensitive(true);
        request.headers_mut().insert(AUTHORIZATION, authorization);
        let response = self.http.execute(request).await?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::PROXY_AUTHENTICATION_REQUIRED
        ) {
            return Err(Error::Rejected(response.status()));
        }
        let header = mutual_auth_header(response.headers())?;
        validate_response_token(header)?;
        context.verify_ap_rep_response_header(header)?;
        Ok(response)
    }
}

fn mutual_auth_header(headers: &HeaderMap) -> Result<&str, Error> {
    // Negotiate tokens are base64 and contain no commas. Other schemes can have
    // quoted commas; scan only outside quotes so their parameters cannot spoof
    // a Negotiate challenge.
    for value in headers.get_all(WWW_AUTHENTICATE) {
        let value = value.to_str().map_err(|_| Error::InvalidHeader)?;
        let mut quoted = false;
        let mut escaped = false;
        let mut start = 0;
        for (index, ch) in value
            .char_indices()
            .chain(std::iter::once((value.len(), ',')))
        {
            if escaped {
                escaped = false;
                continue;
            }
            if quoted && ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == '"' {
                quoted = !quoted;
            }
            if ch == ',' && !quoted {
                let part = value[start..index].trim();
                let scheme = part.split_whitespace().next().unwrap_or("");
                if scheme.eq_ignore_ascii_case("Negotiate") {
                    if part.len() == scheme.len() {
                        return Err(Error::MissingMutualAuth);
                    }
                    return Ok(part);
                }
                start = index + 1;
            }
        }
    }
    Err(Error::MissingMutualAuth)
}

fn validate_response_token(header: &str) -> Result<(), Error> {
    let SpnegoToken::Resp(response) = spnego::parse_negotiate_header(header)? else {
        return Err(Error::UnsupportedNegotiation);
    };
    if matches!(
        response.neg_state,
        Some(NegState::Reject | NegState::AcceptIncomplete | NegState::RequestMic)
    ) || response.mech_list_mic.is_some()
        || response
            .supported_mech
            .as_ref()
            .is_some_and(|mech| *mech != ObjectIdentifier::krb5())
    {
        return Err(Error::UnsupportedNegotiation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_case_insensitive_challenge_across_headers_and_quoted_commas() {
        let mut headers = HeaderMap::new();
        headers.append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"example, Negotiate bogus\""),
        );
        headers.append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Digest realm=\"test\", nEgOtIaTe YQ=="),
        );
        assert_eq!(mutual_auth_header(&headers).unwrap(), "nEgOtIaTe YQ==");
    }

    #[test]
    fn missing_or_bare_challenge_does_not_authenticate() {
        for value in ["Basic realm=\"Negotiate YQ==\"", "Negotiate"] {
            let mut headers = HeaderMap::new();
            headers.insert(WWW_AUTHENTICATE, HeaderValue::from_str(value).unwrap());
            assert!(matches!(
                mutual_auth_header(&headers),
                Err(Error::MissingMutualAuth)
            ));
        }
    }

    #[test]
    fn incomplete_rejected_and_mic_exchanges_fail_closed() {
        for state in [
            NegState::Reject,
            NegState::AcceptIncomplete,
            NegState::RequestMic,
        ] {
            let mut response = spnego::NegTokenResp::accept_completed();
            response.neg_state = Some(state);
            let header = spnego::negotiate_header(&SpnegoToken::Resp(response)).unwrap();
            assert!(matches!(
                validate_response_token(&header),
                Err(Error::UnsupportedNegotiation)
            ));
        }
    }

    #[test]
    fn unsupported_cache_has_actionable_error() {
        let result = NegotiateClient::from_cache(Config::new(), "KCM:123");
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("KCM unexpectedly accepted"),
        };
        assert!(error.to_string().contains("KCM"), "{error}");
    }
}
