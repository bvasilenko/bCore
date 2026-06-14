use bsuite_core::{TierEvidence, TierProbes};
use proptest::prelude::*;

fn probes(cff: f64, isc: f64, bcf: u32, bbs: f64, adh: f64) -> TierProbes {
    TierProbes {
        control_flow_flattening_density: cff,
        instruction_substitution_coverage: isc,
        bogus_control_flow_blocks: bcf,
        basic_block_splitting_ratio: bbs,
        anti_debug_heuristic_score: adh,
    }
}

proptest! {
    #[test]
    fn tier_evidence_toml_round_trips_exactly(
        tier_id in "[a-zA-Z0-9_-]{1,64}",
        build_sha in "[0-9a-f]{40}",
        signing_key_id in "[a-zA-Z0-9_-]{1,64}",
        cff in proptest::num::f64::NORMAL,
        isc in proptest::num::f64::NORMAL,
        bcf in 0u32..10_000u32,
        bbs in proptest::num::f64::NORMAL,
        adh in proptest::num::f64::NORMAL,
    ) {
        let original = TierEvidence::new(
            tier_id,
            build_sha,
            signing_key_id,
            probes(cff, isc, bcf, bbs, adh),
        );
        let serialized = toml::to_string(&original).unwrap();
        let deserialized: TierEvidence = toml::from_str(&serialized).unwrap();
        prop_assert_eq!(original, deserialized);
    }
}

#[test]
fn malformed_toml_fails_to_deserialize_as_tier_evidence() {
    let result: Result<TierEvidence, _> = toml::from_str("[[[not valid TOML");
    assert!(
        result.is_err(),
        "malformed TOML must return a parse error, not panic"
    );
}

#[test]
fn tier_evidence_new_always_sets_schema_version_to_one() {
    let e = TierEvidence::new("T1", "sha", "key", probes(0.5, 0.5, 1, 0.5, 0.5));
    assert_eq!(e.schema_version, 1);
}
