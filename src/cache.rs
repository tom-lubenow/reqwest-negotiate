use crate::NegotiateError;
use base64::Engine;
use rskrb5::spnego::{self, InitiatorContextOptions, NegState, ObjectIdentifier, SpnegoToken};

pub(crate) struct Context(spnego::InitiatorContext);

pub(crate) fn generate(spn: &str) -> Result<(Vec<u8>, Context), NegotiateError> {
    // A separate thread keeps the backend's blocking Tokio runtime from nesting
    // inside the caller's runtime. The public API remains synchronous.
    let spn = spn.to_owned();
    std::thread::spawn(move || {
        let config = rskrb5::Config::load_default()
            .map_err(|e| NegotiateError::CredentialError(e.to_string()))?;
        let mut client = rskrb5::BlockingNegotiateClient::from_default_ccache(config)
            .map_err(|e| NegotiateError::CredentialError(e.to_string()))?;
        let service = if spn.contains('@') {
            rskrb5::Principal::parse_service(&spn)
        } else {
            let (service, host) = spn
                .split_once('/')
                .ok_or_else(|| NegotiateError::NameError("expected service/hostname".into()))?;
            rskrb5::Principal::host_based_service(service, host)
        }
        .map_err(|e| NegotiateError::NameError(e.to_string()))?;
        let options = InitiatorContextOptions::new()
            .with_context_flags(vec![
                spnego::CONTEXT_FLAG_MUTUAL,
                spnego::CONTEXT_FLAG_INTEG,
            ])
            .with_ap_option_bits(1 << 29);
        let context = client
            .authorization_context_with_options(service, options)
            .map_err(|e| NegotiateError::ContextError(e.to_string()))?;
        let token = base64::engine::general_purpose::STANDARD
            .decode(
                context
                    .header
                    .strip_prefix("Negotiate ")
                    .ok_or(NegotiateError::InvalidTokenFormat)?,
            )
            .map_err(|_| NegotiateError::InvalidTokenFormat)?;
        Ok((token, Context(context)))
    })
    .join()
    .map_err(|_| NegotiateError::ContextError("credential worker panicked".into()))?
}

impl Context {
    pub(crate) fn verify(&mut self, header: &str) -> Result<(), NegotiateError> {
        validate_response_token(header)?;
        self.0
            .verify_ap_rep_response_header(header)
            .map_err(|e| NegotiateError::MutualAuthFailed(e.to_string()))?;
        Ok(())
    }
}

fn validate_response_token(header: &str) -> Result<(), NegotiateError> {
    let SpnegoToken::Resp(response) = spnego::parse_negotiate_header(header)
        .map_err(|e| NegotiateError::MutualAuthFailed(e.to_string()))?
    else {
        return Err(NegotiateError::MutualAuthFailed(
            "unsupported SPNEGO negotiation".into(),
        ));
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
        return Err(NegotiateError::MutualAuthFailed(
            "unsupported SPNEGO negotiation".into(),
        ));
    }
    Ok(())
}
