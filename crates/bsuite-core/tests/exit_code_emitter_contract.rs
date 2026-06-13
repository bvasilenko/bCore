mod common;

use bsuite_core::{BsuiteCoreError, EmitFormat, ExitCode, ExitCodeEmitter, ExitCodeRouting};
use common::buf_emitter;

struct ProbeEmitter;

impl ExitCodeEmitter for ProbeEmitter {
    fn exit_code_for(&self, err: &BsuiteCoreError) -> ExitCode {
        BsuiteCoreError::route(err)
    }
}

#[test]
fn exit_code_emitter_trait_delegates_routing_consistently_for_all_error_variants() {
    let emitter = ProbeEmitter;
    for err in common::all_bsuite_core_error_variants() {
        assert_eq!(
            emitter.exit_code_for(&err),
            BsuiteCoreError::route(&err),
            "ProbeEmitter must delegate to routing for {err:?}",
        );
    }
}

#[test]
fn process_exit_emitter_exit_code_for_delegates_to_routing_for_all_error_variants() {
    let (emitter, _, _) = buf_emitter(EmitFormat::Plain);
    for err in common::all_bsuite_core_error_variants() {
        assert_eq!(
            emitter.exit_code_for(&err),
            BsuiteCoreError::route(&err),
            "ProcessExitEmitter must delegate to routing for {err:?}",
        );
    }
}

#[test]
fn process_exit_emitter_is_a_valid_exit_code_emitter_impl() {
    fn accepts_emitter(_: &dyn ExitCodeEmitter) {}
    let (emitter, _out, _err) = buf_emitter(EmitFormat::Plain);
    accepts_emitter(&emitter as &dyn ExitCodeEmitter);
}
