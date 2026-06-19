use super::context::HostContext;

pub(super) fn canonical_package_name(host: HostContext) -> &'static str {
    match host {
        HostContext::L2a => "b",
        HostContext::PayloadV3 => "bpayload",
        HostContext::StrapiV5 => "bstrapi",
        HostContext::SanityV3 => "bsanity",
        HostContext::DirectusV10 => "bdirectus",
    }
}
