use super::context::HostContext;
use super::invocation::{HOST_CONTEXT_ENV_VAR, HostInvocationContext};
use crate::BsuiteCoreError;

pub fn parse_host_invocation_context(
    value: Option<&str>,
) -> Result<Option<HostInvocationContext>, BsuiteCoreError> {
    let json = match value {
        None | Some("") => return Ok(None),
        Some(s) => s,
    };
    let ctx: HostInvocationContext = serde_json::from_str(json)
        .map_err(|e| BsuiteCoreError::HostContextParseFailed(e.to_string()))?;
    if HostContext::from_stable_name(&ctx.host_id).is_none() {
        return Err(BsuiteCoreError::UnknownHostId(ctx.host_id));
    }
    Ok(Some(ctx))
}

pub fn parse_host_invocation_context_from_env()
-> Result<Option<HostInvocationContext>, BsuiteCoreError> {
    match std::env::var(HOST_CONTEXT_ENV_VAR) {
        Ok(value) => parse_host_invocation_context(Some(&value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(raw)) => Err(BsuiteCoreError::HostContextParseFailed(
            format!("environment variable contains non-UTF-8 bytes: {raw:?}"),
        )),
    }
}
