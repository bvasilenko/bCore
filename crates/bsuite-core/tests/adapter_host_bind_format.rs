use bsuite_core::{HostContext, HostInvocationContext, format_context_tag};
use proptest::prelude::*;

fn invocation_context(host_id: &str) -> HostInvocationContext {
    HostInvocationContext {
        host_id: host_id.to_string(),
        host_version: "1.2.3".to_string(),
        cycle_id: "01JXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
        directive_field: "_bsuiteDirective".to_string(),
        document_id: "doc-42".to_string(),
        collection: "posts".to_string(),
    }
}

#[test]
fn format_context_tag_has_stable_output_per_host() {
    let cases = [
        (
            HostContext::L2a,
            "host:l2a;version:1.2.3;cycle-id:01JXXXXXXXXXXXXXXXXXXXXXXXXX",
        ),
        (
            HostContext::PayloadV3,
            "host:payload-v3;version:1.2.3;cycle-id:01JXXXXXXXXXXXXXXXXXXXXXXXXX",
        ),
        (
            HostContext::StrapiV5,
            "host:strapi-v5;version:1.2.3;cycle-id:01JXXXXXXXXXXXXXXXXXXXXXXXXX",
        ),
        (
            HostContext::SanityV3,
            "host:sanity-v3;version:1.2.3;cycle-id:01JXXXXXXXXXXXXXXXXXXXXXXXXX",
        ),
        (
            HostContext::DirectusV10,
            "host:directus-v10;version:1.2.3;cycle-id:01JXXXXXXXXXXXXXXXXXXXXXXXXX",
        ),
    ];
    for (host, expected) in cases {
        let ctx = invocation_context(host.stable_name());
        assert_eq!(
            format_context_tag(&ctx),
            expected,
            "wrong tag output for {host:?}",
        );
    }
}

proptest! {
    #[test]
    fn format_context_tag_produces_exact_semicolon_delimited_output(
        host_id in ".*",
        host_version in ".*",
        cycle_id in ".*",
    ) {
        let ctx = HostInvocationContext {
            host_id: host_id.clone(),
            host_version: host_version.clone(),
            cycle_id: cycle_id.clone(),
            directive_field: String::new(),
            document_id: String::new(),
            collection: String::new(),
        };
        let expected = format!("host:{host_id};version:{host_version};cycle-id:{cycle_id}");
        prop_assert_eq!(format_context_tag(&ctx), expected);
    }

    #[test]
    fn format_context_tag_depends_only_on_host_id_version_and_cycle_id(
        directive_field in ".*",
        document_id in ".*",
        collection in ".*",
    ) {
        let base = HostInvocationContext {
            host_id: "payload-v3".to_string(),
            host_version: "1.0.0".to_string(),
            cycle_id: "01JXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            directive_field: "baseline".to_string(),
            document_id: "baseline".to_string(),
            collection: "baseline".to_string(),
        };
        let variant = HostInvocationContext {
            directive_field,
            document_id,
            collection,
            ..base.clone()
        };
        prop_assert_eq!(
            format_context_tag(&base),
            format_context_tag(&variant),
            "tag must not change when directive_field, document_id, or collection change",
        );
    }
}
