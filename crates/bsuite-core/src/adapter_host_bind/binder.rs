use super::binding::{AdapterBinding, AdapterHostBinder};
use super::context::HostContext;
use super::env_parse::parse_host_invocation_context_from_env;
use super::invocation::HostInvocationContext;
use super::package::canonical_package_name;
use crate::BsuiteCoreError;

pub struct FullAdapterHostBinder {
    invocation_context: Option<HostInvocationContext>,
}

impl FullAdapterHostBinder {
    pub fn from_env() -> Result<Self, BsuiteCoreError> {
        let invocation_context = parse_host_invocation_context_from_env()?;
        Ok(Self { invocation_context })
    }

    pub fn with_context(ctx: Option<HostInvocationContext>) -> Self {
        Self {
            invocation_context: ctx,
        }
    }

    pub fn invocation_context(&self) -> Option<&HostInvocationContext> {
        self.invocation_context.as_ref()
    }

    pub fn resolved_host_context(&self) -> HostContext {
        self.invocation_context
            .as_ref()
            .and_then(|ctx| HostContext::from_stable_name(&ctx.host_id))
            .unwrap_or(HostContext::L2a)
    }
}

impl AdapterHostBinder for FullAdapterHostBinder {
    fn bind(&self, host: HostContext) -> Result<AdapterBinding, BsuiteCoreError> {
        Ok(AdapterBinding::new(host, canonical_package_name(host)))
    }
}
