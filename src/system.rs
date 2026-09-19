use crate::{NegotiateError, parse_negotiate_header};
use cross_krb5::{ClientCtx, InitiateFlags, PendingClientCtx, Step};

pub(crate) struct Context(Option<PendingClientCtx>);

pub(crate) fn generate(spn: &str) -> Result<(Vec<u8>, Context), NegotiateError> {
    let (pending, token) = ClientCtx::new(InitiateFlags::empty(), None, spn, None)
        .map_err(|e| NegotiateError::ContextError(e.to_string()))?;
    Ok((token.to_vec(), Context(Some(pending))))
}

impl Context {
    pub(crate) fn verify(&mut self, header: &str) -> Result<(), NegotiateError> {
        let token = parse_negotiate_header(header)?;
        let pending = self
            .0
            .take()
            .ok_or_else(|| NegotiateError::ContextError("context already consumed".into()))?;
        match pending
            .step(&token)
            .map_err(|e| NegotiateError::MutualAuthFailed(e.to_string()))?
        {
            Step::Finished((_, token)) if token.as_ref().is_none_or(|t| t.is_empty()) => Ok(()),
            _ => Err(NegotiateError::MutualAuthFailed(
                "additional authentication exchange required".into(),
            )),
        }
    }
}
