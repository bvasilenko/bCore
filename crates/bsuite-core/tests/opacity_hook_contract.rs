use bsuite_core::{BsuiteCoreError, OpacityHookPublisher, TierEvidence, TierProbes};

struct PendingOpacityHookPublisher;

impl OpacityHookPublisher for PendingOpacityHookPublisher {
    fn publish(&self, _evidence: TierEvidence) -> Result<(), BsuiteCoreError> {
        unimplemented!("not yet implemented")
    }
}

fn sample_evidence() -> TierEvidence {
    TierEvidence::new(
        "release",
        "abc123def456abc123def456abc123def456abc123",
        "signing-key-01",
        TierProbes {
            control_flow_flattening_density: 0.87,
            instruction_substitution_coverage: 0.72,
            bogus_control_flow_blocks: 143,
            basic_block_splitting_ratio: 1.24,
            anti_debug_heuristic_score: 0.95,
        },
    )
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn placeholder_visibility_publisher_is_explicitly_pending() {
    let publisher = PendingOpacityHookPublisher;
    let _ = publisher.publish(sample_evidence());
}

#[test]
fn tier_evidence_preserves_fields() {
    let evidence = sample_evidence();
    assert_eq!(evidence.schema_version, 1);
    assert_eq!(evidence.tier_id, "release");
    assert_eq!(evidence.build_sha, "abc123def456abc123def456abc123def456abc123");
    assert_eq!(evidence.signing_key_id, "signing-key-01");
    assert_eq!(evidence.probes.bogus_control_flow_blocks, 143);
}

#[test]
fn tier_evidence_new_always_stamps_schema_version_one() {
    let e = sample_evidence();
    assert_eq!(e.schema_version, 1);
}
