mod common;

use bsuite_core::{
    BsuiteCoreError, DirectiveString, EmitFormat, ExitCode, OverlayValidationError,
    ProcessExitEmitter, RoutingKey,
};
use common::{SharedBuf, buf_emitter};
use serde_json::Value;

fn json_emitter() -> (ProcessExitEmitter, SharedBuf, SharedBuf) {
    buf_emitter(EmitFormat::Json)
}

fn parsed(raw: &str) -> Value {
    let line = raw.trim_end_matches('\n');
    serde_json::from_str(line).expect("single JSON line")
}

#[test]
fn ok_success_produces_outcome_ok_envelope() {
    let (mut emitter, out, err) = json_emitter();
    let directive = DirectiveString::new("GROUNDED - proceed");
    let code = emitter.emit_directive(Ok((directive, ExitCode::Success)));

    assert_eq!(code, ExitCode::Success);
    let v = parsed(&out.string());
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["outcome"], "ok");
    assert_eq!(v["directive"], "GROUNDED - proceed");
    assert!(v["error"].is_null());
    assert_eq!(err.bytes(), b"");
}

#[test]
fn ok_finding_produces_outcome_finding_envelope_with_directive() {
    let (mut emitter, out, err) = json_emitter();
    let directive = DirectiveString::new("UNGROUNDED - supply evidence");
    let code = emitter.emit_directive(Ok((directive, ExitCode::Finding)));

    assert_eq!(code, ExitCode::Finding);
    let v = parsed(&out.string());
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["outcome"], "finding");
    assert_eq!(v["directive"], "UNGROUNDED - supply evidence");
    assert!(v["error"].is_null());
    assert_eq!(err.bytes(), b"");
}

#[test]
fn err_internal_error_produces_outcome_internal_error_envelope() {
    let (mut emitter, out, err) = json_emitter();
    let error = BsuiteCoreError::CorpusKeyMissing(RoutingKey::BGround);
    let code = emitter.emit_directive(Err(error));

    assert_eq!(code, ExitCode::InternalError);
    let v = parsed(&out.string());
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["outcome"], "internal_error");
    assert!(v["directive"].is_null());
    assert_eq!(v["error"]["kind"], "CorpusKeyMissing");
    assert!(!v["error"]["message"].as_str().unwrap_or("").is_empty());
    assert_eq!(err.bytes(), b"");
}

#[test]
fn err_usage_produces_outcome_usage_error_envelope() {
    let (mut emitter, out, err) = json_emitter();
    let inner = OverlayValidationError::SignatureMissing;
    let error = BsuiteCoreError::ManifestOverlay(inner);
    let code = emitter.emit_directive(Err(error));

    assert_eq!(code, ExitCode::Usage);
    let v = parsed(&out.string());
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["outcome"], "usage_error");
    assert!(v["directive"].is_null());
    assert_eq!(v["error"]["kind"], "ManifestOverlay");
    assert!(!v["error"]["message"].as_str().unwrap_or("").is_empty());
    assert_eq!(err.bytes(), b"");
}

#[test]
fn schema_version_is_stable_across_all_outcome_classes() {
    let cases: Vec<Result<(DirectiveString, ExitCode), BsuiteCoreError>> = vec![
        Ok((DirectiveString::new("d"), ExitCode::Success)),
        Ok((DirectiveString::new("d"), ExitCode::Finding)),
        Err(BsuiteCoreError::CorpusKeyMissing(RoutingKey::BAnchor)),
        Err(BsuiteCoreError::ManifestOverlay(
            OverlayValidationError::SignatureInvalid,
        )),
    ];
    for case in cases {
        let (mut emitter, out, _err) = json_emitter();
        let _ = emitter.emit_directive(case);
        let v = parsed(&out.string());
        assert_eq!(v["schema_version"], 1, "schema_version must always be 1");
    }
}

#[test]
fn err_message_field_equals_error_display_string() {
    let (mut emitter, out, _err) = json_emitter();
    let error = BsuiteCoreError::CorpusKeyMissing(RoutingKey::BAnchor);
    let expected_message = error.to_string();
    let _ = emitter.emit_directive(Err(error));
    let v = parsed(&out.string());
    assert_eq!(v["error"]["message"], expected_message);
}

#[test]
fn sequential_calls_each_produce_one_independent_json_line() {
    let (mut emitter, out, _err) = json_emitter();
    let _ = emitter.emit_directive(Ok((DirectiveString::new("first"), ExitCode::Success)));
    let _ = emitter.emit_directive(Err(BsuiteCoreError::CorpusKeyMissing(RoutingKey::BGround)));

    let raw = out.string();
    let lines: Vec<&str> = raw.trim_end_matches('\n').lines().collect();
    assert_eq!(lines.len(), 2, "two calls must produce exactly two lines");
    for line in &lines {
        serde_json::from_str::<serde_json::Value>(line)
            .expect("each line must be individually valid JSON");
    }
    let first: Value = serde_json::from_str(lines[0]).unwrap();
    let second: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(first["outcome"], "ok");
    assert_eq!(second["outcome"], "internal_error");
}

#[test]
fn all_error_variants_produce_non_empty_kind_and_message_in_json_envelope() {
    for err in common::all_bsuite_core_error_variants() {
        let expected_message = err.to_string();
        let (mut emitter, out, _err_buf) = json_emitter();
        let _ = emitter.emit_directive(Err(err));
        let v = parsed(&out.string());
        let kind = v["error"]["kind"].as_str().unwrap_or("");
        let message = v["error"]["message"].as_str().unwrap_or("");
        assert!(
            !kind.is_empty(),
            "kind must be non-empty for every error variant"
        );
        assert_eq!(
            message, expected_message,
            "message must match Display output"
        );
    }
}

#[test]
fn json_ok_envelope_includes_directive_key_and_excludes_error_key() {
    let (mut emitter, out, _) = json_emitter();
    let _ = emitter.emit_directive(Ok((DirectiveString::new("d"), ExitCode::Success)));
    let obj = parsed(&out.string());
    let obj = obj.as_object().expect("envelope is a JSON object");
    assert!(
        obj.contains_key("directive"),
        "ok envelope must include directive key"
    );
    assert!(
        !obj.contains_key("error"),
        "ok envelope must exclude error key"
    );
}

#[test]
fn json_err_envelope_includes_error_key_and_excludes_directive_key() {
    let (mut emitter, out, _) = json_emitter();
    let _ = emitter.emit_directive(Err(BsuiteCoreError::CorpusSignatureInvalid));
    let obj = parsed(&out.string());
    let obj = obj.as_object().expect("envelope is a JSON object");
    assert!(
        !obj.contains_key("directive"),
        "err envelope must exclude directive key"
    );
    assert!(
        obj.contains_key("error"),
        "err envelope must include error key"
    );
}

proptest::proptest! {
    #[test]
    fn directive_content_is_transmitted_verbatim_in_json_mode(text in ".*") {
        let (mut emitter, out, _) = json_emitter();
        let _ = emitter.emit_directive(Ok((DirectiveString::new(text.clone()), ExitCode::Success)));
        let v = parsed(&out.string());
        assert_eq!(v["directive"].as_str().unwrap_or(""), text.as_str());
    }
}
