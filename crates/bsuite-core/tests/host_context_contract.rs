mod common;

use bsuite_core::HostContext;
use common::{assert_projection_contains, assert_stable_mappings, assert_unique_projection};
use proptest::prelude::*;

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
fn host_contexts_have_stable_public_names() {
    assert_stable_mappings(
        HostContext::ALL.map(|host| (host, host.stable_name())),
        [
            (HostContext::L2a, "l2a"),
            (HostContext::PayloadV3, "payload-v3"),
            (HostContext::StrapiV5, "strapi-v5"),
            (HostContext::SanityV3, "sanity-v3"),
            (HostContext::DirectusV10, "directus-v10"),
        ],
    );
}

#[test]
fn display_output_matches_stable_name_for_all_variants() {
    for host in HostContext::ALL {
        assert_eq!(
            host.to_string(),
            host.stable_name(),
            "Display must match stable_name for {host:?}",
        );
    }
}

#[test]
fn from_stable_name_round_trips_all_known_names() {
    for host in HostContext::ALL {
        let name = host.stable_name();
        assert_eq!(
            HostContext::from_stable_name(name),
            Some(host),
            "from_stable_name must recover the original variant for name {name:?}",
        );
    }
}

#[test]
fn host_context_serde_json_round_trips_all_variants() {
    for host in HostContext::ALL {
        let serialized =
            serde_json::to_string(&host).unwrap_or_else(|e| panic!("serialize {host:?}: {e}"));
        let recovered: HostContext = serde_json::from_str(&serialized)
            .unwrap_or_else(|e| panic!("deserialize {host:?} from {serialized:?}: {e}"));
        assert_eq!(recovered, host);
    }
}

proptest! {
    #[test]
    fn host_context_names_are_unique_and_complete(host in any_host_context()) {
        assert_unique_projection(HostContext::ALL, HostContext::stable_name);
        assert_projection_contains(HostContext::ALL, HostContext::stable_name, host.stable_name());
    }

    #[test]
    fn from_stable_name_recognizes_exactly_the_names_in_all(name in ".*") {
        let in_all = HostContext::ALL.iter().any(|h| h.stable_name() == name);
        prop_assert_eq!(
            HostContext::from_stable_name(&name).is_some(),
            in_all,
            "from_stable_name({:?}) must return Some iff name is a known stable name",
            name,
        );
    }
}
