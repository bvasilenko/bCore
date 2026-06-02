use std::collections::BTreeSet;
use std::fmt::Debug;

pub fn assert_stable_mappings<T, U, const N: usize>(actual: [(T, U); N], expected: [(T, U); N])
where
    T: Debug + Eq,
    U: Debug + Eq,
{
    assert_eq!(actual, expected);
}

pub fn assert_unique_projection<T, U, const N: usize>(items: [T; N], projection: impl Fn(T) -> U)
where
    T: Copy,
    U: Ord + Debug,
{
    let values = items.into_iter().map(projection).collect::<BTreeSet<_>>();

    assert_eq!(values.len(), N);
}

pub fn assert_projection_contains<T, U, const N: usize>(
    items: [T; N],
    projection: impl Fn(T) -> U,
    expected: U,
) where
    T: Copy,
    U: Ord + Debug,
{
    let values = items.into_iter().map(projection).collect::<BTreeSet<_>>();

    assert!(values.contains(&expected));
}
