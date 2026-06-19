use bsuite_core::{
    AdapterBinding, AdapterHostBinder, FullAdapterHostBinder, HostContext, HostInvocationContext,
};
use proptest::prelude::*;

fn invocation_context(host_id: &str) -> HostInvocationContext {
    HostInvocationContext {
        host_id: host_id.to_string(),
        host_version: "3.0.0".to_string(),
        cycle_id: "01JXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
        directive_field: "_bsuiteDirective".to_string(),
        document_id: "doc-1".to_string(),
        collection: "articles".to_string(),
    }
}

fn any_host_context() -> impl Strategy<Value = HostContext> {
    prop_oneof![
        Just(HostContext::L2a),
        Just(HostContext::PayloadV3),
        Just(HostContext::StrapiV5),
        Just(HostContext::SanityV3),
        Just(HostContext::DirectusV10),
    ]
}

#[test]
fn with_context_none_resolves_to_l2a() {
    let binder = FullAdapterHostBinder::with_context(None);
    assert_eq!(binder.resolved_host_context(), HostContext::L2a);
    assert!(binder.invocation_context().is_none());
}

#[test]
fn all_known_host_ids_resolve_to_expected_host_context() {
    let cases = [
        ("l2a", HostContext::L2a),
        ("payload-v3", HostContext::PayloadV3),
        ("strapi-v5", HostContext::StrapiV5),
        ("sanity-v3", HostContext::SanityV3),
        ("directus-v10", HostContext::DirectusV10),
    ];
    for (host_id, expected) in cases {
        let binder = FullAdapterHostBinder::with_context(Some(invocation_context(host_id)));
        assert_eq!(
            binder.resolved_host_context(),
            expected,
            "host_id {host_id:?} must resolve to {expected:?}",
        );
    }
}

#[test]
fn bind_returns_adapter_binding_with_correct_package_name() {
    let binder = FullAdapterHostBinder::with_context(None);

    let cases = [
        (HostContext::L2a, "b"),
        (HostContext::PayloadV3, "bpayload"),
        (HostContext::StrapiV5, "bstrapi"),
        (HostContext::SanityV3, "bsanity"),
        (HostContext::DirectusV10, "bdirectus"),
    ];

    for (host, expected_package) in cases {
        let binding = binder
            .bind(host)
            .expect("bind must succeed for all known hosts");
        assert_eq!(
            binding,
            AdapterBinding::new(host, expected_package),
            "wrong package name for {host:?}",
        );
    }
}

#[test]
fn invocation_context_accessor_returns_stored_context() {
    let ctx = invocation_context("strapi-v5");
    let binder = FullAdapterHostBinder::with_context(Some(ctx.clone()));
    assert_eq!(binder.invocation_context(), Some(&ctx));
}

#[test]
fn adapter_binding_preserves_fields() {
    let binding = AdapterBinding::new(HostContext::DirectusV10, "bdirectus");
    assert_eq!(binding.host, HostContext::DirectusV10);
    assert_eq!(binding.package_name, "bdirectus");
}

proptest! {
    #[test]
    fn bind_succeeds_for_every_host_context(host in any_host_context()) {
        let binder = FullAdapterHostBinder::with_context(None);
        prop_assert!(
            binder.bind(host).is_ok(),
            "bind must not fail for any known HostContext; failed for {:?}",
            host,
        );
    }

    #[test]
    fn resolved_host_context_is_independent_of_non_host_id_invocation_fields(
        host in any_host_context(),
        host_version in ".*",
        cycle_id in ".*",
        directive_field in ".*",
        document_id in ".*",
        collection in ".*",
    ) {
        let ctx = HostInvocationContext {
            host_id: host.stable_name().to_string(),
            host_version,
            cycle_id,
            directive_field,
            document_id,
            collection,
        };
        let binder = FullAdapterHostBinder::with_context(Some(ctx));
        prop_assert_eq!(binder.resolved_host_context(), host);
    }
}
