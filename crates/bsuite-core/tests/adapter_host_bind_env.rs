use bsuite_core::{BsuiteCoreError, HostContext, parse_host_invocation_context};
use proptest::prelude::*;

fn valid_json(host_id: &str) -> String {
    format!(
        r#"{{"host_id":"{host_id}","host_version":"3.0.0","cycle_id":"01JXXXXXXXXXXXXXXXXXXXXXXXXX","directive_field":"_bsuiteDirective","document_id":"doc-1","collection":"articles"}}"#
    )
}

#[test]
fn absent_value_yields_none() {
    assert_eq!(parse_host_invocation_context(None), Ok(None));
}

#[test]
fn empty_string_yields_none() {
    assert_eq!(parse_host_invocation_context(Some("")), Ok(None));
}

#[test]
fn whitespace_only_string_yields_host_context_parse_failed() {
    for input in &[" ", "\t", "\n", "   "] {
        let result = parse_host_invocation_context(Some(input));
        assert!(
            matches!(result, Err(BsuiteCoreError::HostContextParseFailed(_))),
            "expected HostContextParseFailed for whitespace-only input {input:?}, got {result:?}",
        );
    }
}

#[test]
fn valid_json_with_known_host_id_yields_context() {
    let json = valid_json("payload-v3");
    let result = parse_host_invocation_context(Some(&json));
    let ctx = result
        .expect("valid JSON with known host_id must succeed")
        .expect("must be Some");
    assert_eq!(ctx.host_id, "payload-v3");
    assert_eq!(ctx.host_version, "3.0.0");
    assert_eq!(ctx.cycle_id, "01JXXXXXXXXXXXXXXXXXXXXXXXXX");
    assert_eq!(ctx.directive_field, "_bsuiteDirective");
    assert_eq!(ctx.document_id, "doc-1");
    assert_eq!(ctx.collection, "articles");
}

#[test]
fn malformed_json_yields_host_context_parse_failed() {
    let result = parse_host_invocation_context(Some("{not valid json}"));
    assert!(
        matches!(result, Err(BsuiteCoreError::HostContextParseFailed(_))),
        "expected HostContextParseFailed, got {result:?}",
    );
}

#[test]
fn valid_json_with_unknown_host_id_yields_unknown_host_id_error() {
    let json = valid_json("unknown-cms-v99");
    let result = parse_host_invocation_context(Some(&json));
    assert!(
        matches!(result, Err(BsuiteCoreError::UnknownHostId(ref id)) if id == "unknown-cms-v99"),
        "expected UnknownHostId(\"unknown-cms-v99\"), got {result:?}",
    );
}

#[test]
fn missing_required_json_field_yields_host_context_parse_failed() {
    let cases = [
        r#"{"host_version":"3.0.0","cycle_id":"c","directive_field":"d","document_id":"e","collection":"f"}"#,
        r#"{"host_id":"l2a","cycle_id":"c","directive_field":"d","document_id":"e","collection":"f"}"#,
        r#"{"host_id":"l2a","host_version":"3.0.0","directive_field":"d","document_id":"e","collection":"f"}"#,
        r#"{"host_id":"l2a","host_version":"3.0.0","cycle_id":"c","document_id":"e","collection":"f"}"#,
        r#"{"host_id":"l2a","host_version":"3.0.0","cycle_id":"c","directive_field":"d","collection":"f"}"#,
        r#"{"host_id":"l2a","host_version":"3.0.0","cycle_id":"c","directive_field":"d","document_id":"e"}"#,
    ];
    for json in cases {
        let result = parse_host_invocation_context(Some(json));
        assert!(
            matches!(result, Err(BsuiteCoreError::HostContextParseFailed(_))),
            "expected HostContextParseFailed for incomplete JSON, got {result:?}",
        );
    }
}

#[test]
fn all_known_host_ids_are_accepted() {
    for host in HostContext::ALL {
        let json = valid_json(host.stable_name());
        let result = parse_host_invocation_context(Some(&json));
        assert!(
            result.as_ref().is_ok_and(Option::is_some),
            "expected Ok(Some(_)) for host_id={:?}, got {result:?}",
            host.stable_name(),
        );
    }
}

proptest! {
    #[test]
    fn unknown_host_id_error_carries_the_exact_id_string(
        host_id in "[a-z][a-z0-9-]{1,30}"
    ) {
        if HostContext::from_stable_name(&host_id).is_some() {
            return Ok(());
        }
        let json = valid_json(&host_id);
        let result = parse_host_invocation_context(Some(&json));
        prop_assert!(
            matches!(result, Err(BsuiteCoreError::UnknownHostId(ref id)) if id == &host_id),
            "UnknownHostId must carry the exact unrecognized id string; got {:?}",
            result,
        );
    }
}
