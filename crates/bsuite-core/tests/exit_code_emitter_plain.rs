mod common;

use bsuite_core::{
    BsuiteCoreError, DirectiveString, EmitFormat, ExitCode, OverlayValidationError,
    ProcessExitEmitter, RoutingKey,
};
use common::{SharedBuf, buf_emitter};

fn plain_emitter() -> (ProcessExitEmitter, SharedBuf, SharedBuf) {
    buf_emitter(EmitFormat::Plain)
}

#[test]
fn ok_success_writes_directive_to_stdout_and_nothing_to_stderr() {
    let (mut emitter, out, err) = plain_emitter();
    let code = emitter.emit_directive(Ok((DirectiveString::new("GROUNDED"), ExitCode::Success)));

    assert_eq!(code, ExitCode::Success);
    assert_eq!(
        out.string(),
        "GROUNDED
"
    );
    assert_eq!(err.bytes(), b"");
}

#[test]
fn ok_finding_writes_directive_to_stdout_and_nothing_to_stderr() {
    let (mut emitter, out, err) = plain_emitter();
    let code = emitter.emit_directive(Ok((DirectiveString::new("UNGROUNDED"), ExitCode::Finding)));

    assert_eq!(code, ExitCode::Finding);
    assert_eq!(
        out.string(),
        "UNGROUNDED
"
    );
    assert_eq!(err.bytes(), b"");
}

#[test]
fn err_internal_error_writes_message_to_stderr_and_nothing_to_stdout() {
    let (mut emitter, out, err) = plain_emitter();
    let error = BsuiteCoreError::CorpusKeyMissing(RoutingKey::BGround);
    let expected_message = error.to_string();
    let code = emitter.emit_directive(Err(error));

    assert_eq!(code, ExitCode::InternalError);
    assert_eq!(out.bytes(), b"");
    assert_eq!(
        err.string(),
        format!(
            "{expected_message}
"
        )
    );
}

#[test]
fn err_usage_writes_message_to_stderr_and_nothing_to_stdout() {
    let (mut emitter, out, err) = plain_emitter();
    let inner = OverlayValidationError::UnknownKey {
        key: "bad-key".into(),
    };
    let error = BsuiteCoreError::ManifestOverlay(inner);
    let expected_message = error.to_string();
    let code = emitter.emit_directive(Err(error));

    assert_eq!(code, ExitCode::Usage);
    assert_eq!(out.bytes(), b"");
    assert_eq!(
        err.string(),
        format!(
            "{expected_message}
"
        )
    );
}

#[test]
fn sequential_ok_calls_accumulate_on_stdout_without_affecting_stderr() {
    let (mut emitter, out, err) = plain_emitter();
    let _ = emitter.emit_directive(Ok((DirectiveString::new("FIRST"), ExitCode::Success)));
    let _ = emitter.emit_directive(Ok((DirectiveString::new("SECOND"), ExitCode::Finding)));

    assert_eq!(
        out.string(),
        "FIRST
SECOND
"
    );
    assert_eq!(err.bytes(), b"");
}

#[test]
fn sequential_err_calls_accumulate_on_stderr_without_affecting_stdout() {
    let (mut emitter, out, err) = plain_emitter();
    let e1 = BsuiteCoreError::CorpusKeyMissing(RoutingKey::BAnchor);
    let e2 = BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureInvalid);
    let m1 = e1.to_string();
    let m2 = e2.to_string();
    let _ = emitter.emit_directive(Err(e1));
    let _ = emitter.emit_directive(Err(e2));

    assert_eq!(out.bytes(), b"");
    assert_eq!(
        err.string(),
        format!(
            "{m1}
{m2}
"
        )
    );
}

#[test]
fn mixed_ok_then_err_does_not_cross_contaminate_streams() {
    let (mut emitter, out, err) = plain_emitter();
    let _ = emitter.emit_directive(Ok((DirectiveString::new("ok-first"), ExitCode::Success)));
    let error = BsuiteCoreError::CorpusKeyMissing(RoutingKey::BGround);
    let error_msg = error.to_string();
    let _ = emitter.emit_directive(Err(error));

    assert_eq!(out.string(), "ok-first\n");
    assert_eq!(err.string(), format!("{error_msg}\n"));
}

#[test]
fn mixed_err_then_ok_does_not_cross_contaminate_streams() {
    let (mut emitter, out, err) = plain_emitter();
    let error = BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureMissing);
    let error_msg = error.to_string();
    let _ = emitter.emit_directive(Err(error));
    let _ = emitter.emit_directive(Ok((DirectiveString::new("ok-second"), ExitCode::Finding)));

    assert_eq!(out.string(), "ok-second\n");
    assert_eq!(err.string(), format!("{error_msg}\n"));
}

#[test]
fn all_error_variants_write_non_empty_message_to_stderr_in_plain_mode() {
    for err in common::all_bsuite_core_error_variants() {
        let expected = format!("{err}\n");
        let (mut emitter, out, err_buf) = plain_emitter();
        let _ = emitter.emit_directive(Err(err));
        assert_eq!(
            out.bytes(),
            b"",
            "stdout must be empty for every error variant"
        );
        assert_eq!(
            err_buf.string(),
            expected,
            "stderr must hold Display output"
        );
    }
}

proptest::proptest! {
    #[test]
    fn directive_content_is_transmitted_verbatim_in_plain_mode(text in ".*") {
        let (mut emitter, out, err) = plain_emitter();
        let _ = emitter.emit_directive(Ok((DirectiveString::new(text.clone()), ExitCode::Success)));
        assert_eq!(out.string(), format!("{text}\n"));
        assert_eq!(err.bytes(), b"");
    }
}
