use serde::de::DeserializeOwned;

use crate::{Error, Result, Snapshot, SnapshotKind};

/// Caller-authenticated scope and freshness requirements, never peer input.
pub struct SnapshotExpectation<'a> {
    /// Expected community and ring issuer.
    pub community: &'a str,
    /// Expected protected COSE kind.
    pub kind: SnapshotKind,
    /// Lowest acceptable publication revision for this kind.
    pub minimum_revision: u64,
    /// Exact current policy epoch from an authenticated authority.
    pub policy_epoch: u64,
    /// Trusted current Unix seconds.
    pub now: u64,
}

/// Authenticate and decode a typed snapshot, rejecting wrong scope, kind, time,
/// epoch and revision. The caller authenticates the ring and freshness floors.
/// Validate content semantics with the appropriate leaf before relying on it.
pub fn verify_snapshot<T: DeserializeOwned>(
    ring: &csgn::KeyRing,
    cose: &[u8],
    expected: SnapshotExpectation<'_>,
) -> Result<Snapshot<T>> {
    if ring.issuer() != expected.community || expected.policy_epoch == 0 {
        return Err(Error::Verification);
    }
    let verified = ring
        .verify(cose, expected.kind.signing_kind(), expected.now)
        .map_err(|_| Error::Verification)?;
    let snapshot: Snapshot<T> =
        serde_json::from_slice(verified.payload()).map_err(|_| Error::Verification)?;
    if snapshot.community != expected.community
        || snapshot.revision == 0
        || snapshot.revision > i64::MAX as u64
        || snapshot.revision < expected.minimum_revision
        || snapshot.policy_epoch != expected.policy_epoch
    {
        return Err(Error::Verification);
    }
    Ok(snapshot)
}
