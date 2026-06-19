use super::context::HostContext;
use crate::BsuiteCoreError;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AdapterBinding {
    pub host: HostContext,
    pub package_name: String,
}

impl AdapterBinding {
    pub fn new(host: HostContext, package_name: impl Into<String>) -> Self {
        Self {
            host,
            package_name: package_name.into(),
        }
    }
}

pub trait AdapterHostBinder {
    fn bind(&self, host: HostContext) -> Result<AdapterBinding, BsuiteCoreError>;
}
