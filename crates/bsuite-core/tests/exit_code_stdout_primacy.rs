mod common;

use bsuite_core::{DirectiveString, EmitFormat, ExitCode};
use common::buf_emitter;

fn is_single_json_line(raw: &[u8]) -> bool {
    let s = std::str::from_utf8(raw).expect("valid utf8");
    let trimmed = s.strip_suffix('\n').expect("must end with newline");
    serde_json::from_str::<serde_json::Value>(trimmed).is_ok() && !trimmed.contains('\n')
}

#[test]
fn json_ok_outcomes_always_write_one_json_line_to_stdout_and_nothing_to_stderr() {
    for exit_code in [ExitCode::Success, ExitCode::Finding] {
        let (mut e, out, err) = buf_emitter(EmitFormat::Json);
        let _ = e.emit_directive(Ok((DirectiveString::new("d"), exit_code)));
        assert!(
            is_single_json_line(&out.bytes()),
            "stdout must be exactly one JSON line for {exit_code:?}",
        );
        assert_eq!(err.bytes(), b"");
    }
}

#[test]
fn json_err_outcomes_always_write_one_json_line_to_stdout_and_nothing_to_stderr() {
    for err_case in common::all_bsuite_core_error_variants() {
        let (mut e, out, err) = buf_emitter(EmitFormat::Json);
        let _ = e.emit_directive(Err(err_case));
        assert!(
            is_single_json_line(&out.bytes()),
            "stdout must be exactly one JSON line for every error variant",
        );
        assert_eq!(err.bytes(), b"");
    }
}
