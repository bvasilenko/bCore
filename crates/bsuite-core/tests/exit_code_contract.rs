mod common;

use bsuite_core::ExitCode;
use common::{assert_projection_contains, assert_stable_mappings, assert_unique_projection};
use proptest::prelude::*;

fn any_exit_code() -> impl Strategy<Value = ExitCode> {
    prop_oneof![
        Just(ExitCode::Success),
        Just(ExitCode::Finding),
        Just(ExitCode::InternalError),
        Just(ExitCode::Usage),
    ]
}

#[test]
fn exit_codes_reserve_expected_values() {
    assert_stable_mappings(
        ExitCode::ALL.map(|code| (code, code.as_i32())),
        [
            (ExitCode::Success, 0),
            (ExitCode::Finding, 1),
            (ExitCode::InternalError, 2),
            (ExitCode::Usage, 64),
        ],
    );
}

#[test]
fn exit_code_all_enumerates_each_variant_exactly_once() {
    assert!(ExitCode::ALL.contains(&ExitCode::Success));
    assert!(ExitCode::ALL.contains(&ExitCode::Finding));
    assert!(ExitCode::ALL.contains(&ExitCode::InternalError));
    assert!(ExitCode::ALL.contains(&ExitCode::Usage));
    assert_eq!(ExitCode::ALL.len(), 4);
}

#[test]
fn exit_code_ord_ordering_is_consistent_with_i32_ordering() {
    let mut codes = ExitCode::ALL.to_vec();
    codes.sort();
    assert_eq!(codes, ExitCode::ALL.to_vec());
    for window in codes.windows(2) {
        assert!(window[0].as_i32() < window[1].as_i32());
    }
}

#[test]
fn exit_code_copy_and_equality_are_consistent() {
    for &code in &ExitCode::ALL {
        let copied = code;
        assert_eq!(copied, code);
        assert_eq!(code.clone(), code);
    }
}

#[test]
fn exit_code_debug_output_is_non_empty_and_unique_per_variant() {
    assert_unique_projection(ExitCode::ALL, |c| format!("{c:?}"));
    for code in ExitCode::ALL {
        assert!(!format!("{code:?}").is_empty());
    }
}

proptest! {
    #[test]
    fn any_exit_code_has_unique_i32_within_all(code in any_exit_code()) {
        assert_unique_projection(ExitCode::ALL, ExitCode::as_i32);
        assert_projection_contains(ExitCode::ALL, ExitCode::as_i32, code.as_i32());
    }
}
