use serde::{Deserialize, Serialize};

pub const HOST_CONTEXT_ENV_VAR: &str = "BSUITE_HOST_CONTEXT";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostInvocationContext {
    pub host_id: String,
    pub host_version: String,
    pub cycle_id: String,
    pub directive_field: String,
    pub document_id: String,
    pub collection: String,
}
