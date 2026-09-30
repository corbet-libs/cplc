use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Result, identifier};

/// Maximum size of a facade state document or signed JSON payload.
pub const MAX_DOCUMENT_BYTES: usize = 1 << 20;
/// Maximum count per public policy or credential collection.
pub const MAX_ENTRIES: usize = 256;
/// Maximum lifetime of a newly admitted member's credential, in seconds.
pub const NEW_MEMBER_VALIDITY: u64 = 86_400;
/// Maximum lifetime of an established member's credential, in seconds.
pub const ESTABLISHED_MEMBER_VALIDITY: u64 = 30 * NEW_MEMBER_VALIDITY;

/// Trusted service configuration, persisted once for this policy scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Action evaluated by credential issuance; never selected by a member request.
    pub credential_action: String,
    /// Maximum lifetime of public snapshots, in seconds.
    pub snapshot_validity: u64,
}

impl Config {
    pub(crate) fn validate(&self) -> Result<()> {
        identifier(&self.credential_action)?;
        if self.credential_action.len() > 200
            || !self
                .credential_action
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            || self.snapshot_validity == 0
            || self.snapshot_validity > i64::MAX as u64
        {
            return Err(crate::Error::Invalid("configuration"));
        }
        Ok(())
    }
}

/// The four public policy documents. The COSE protected header binds the kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    /// Flat resolved crbk values; no member overrides or proof metadata.
    Settings,
    /// Validated cshm profile schema.
    Schema,
    /// Explicitly supplied public community identifiers, never memberships.
    Communities,
    /// Current community revocations, never global suspension data.
    RevocationList,
}

impl SnapshotKind {
    /// Corresponding authenticated csgn content kind.
    pub fn signing_kind(self) -> csgn::Kind {
        match self {
            Self::Settings => csgn::Kind::SettingsSnapshot,
            Self::Schema => csgn::Kind::SchemaSnapshot,
            Self::Communities => csgn::Kind::CommunitiesSnapshot,
            Self::RevocationList => csgn::Kind::RevocationListSnapshot,
        }
    }
}

/// Typed JSON inside COSE. Issued time, expiry, kind and key ID are in its
/// authenticated csgn envelope, so they cannot disagree with duplicate fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot<T> {
    /// Community namespace, also the csgn issuer.
    pub community: String,
    /// Positive publication sequence, independent for each kind.
    pub revision: u64,
    /// Policy epoch applying to this document.
    pub policy_epoch: u64,
    /// Resolved settings, schema, public communities or revocations.
    pub content: T,
}

/// Current revocations for this community only, with no event history or times.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocations {
    /// Revoked community pseudonyms.
    pub members: BTreeSet<String>,
    /// Revoked public device keys.
    pub devices: BTreeSet<[u8; 32]>,
}

/// Lifetime class obtained from trusted membership state, not from a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberClass {
    /// Newly admitted: at most one day.
    New,
    /// Established: at most thirty days.
    Established,
}

impl MemberClass {
    pub(crate) fn validity(self) -> u64 {
        match self {
            Self::New => NEW_MEMBER_VALIDITY,
            Self::Established => ESTABLISHED_MEMBER_VALIDITY,
        }
    }
}

/// A pin fingerprint supplied by the membership facade; never an opening/salt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// Stable schema field ID.
    pub field: String,
    /// cpns fingerprint, already authorized and checked by membership.
    pub fingerprint: [u8; 32],
}

/// Community proof metadata inside a credential. Subject and level are implied
/// by the enclosing credential, and no proof time or raw evidence is included.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialGate {
    /// Gate identifier.
    pub gate: String,
    /// Provider identifier.
    pub provider: String,
    /// Exclusive proof expiry in Unix seconds.
    pub valid_until: u64,
}

/// Credential payload; never stored by cplc. COSE binds issuance, expiry and key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    /// Community namespace.
    pub community: String,
    /// Community pseudonym, never a global identity.
    pub member: String,
    /// Canonical, reserved handle supplied by membership.
    pub handle: String,
    /// Profile schema version.
    pub schema_version: u32,
    /// Effective policy epoch.
    pub policy_epoch: u64,
    /// Community gates only; global results remain transient.
    pub gates: Vec<CredentialGate>,
    /// Restricted-field fingerprints.
    pub pins: Vec<Pin>,
    /// Public device keys authorized by membership.
    pub devices: Vec<[u8; 32]>,
}

/// Trusted inputs assembled by cmnt from membership and gatekeeping.
/// This is deliberately not deserializable as an untrusted request body.
pub struct CredentialRequest<'a> {
    /// Verified subject and current membership state.
    pub subject: crbk::Subject<'a>,
    /// Canonical handle already validated/reserved by the membership leaf.
    pub handle: &'a str,
    /// Current schema version checked by the profile gate.
    pub schema_version: u32,
    /// Trusted membership lifetime classification.
    pub class: MemberClass,
    /// Verified, subject-bound gate metadata (global presentations already bound).
    pub gates: &'a [crbk::GateResult],
    /// Authorized pins; no values, salts or openings.
    pub pins: &'a [Pin],
    /// Authorized public device keys, never passkey secrets.
    pub devices: &'a [[u8; 32]],
}

/// Signed transport manifest. The fixed purpose separates it from flat settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustManifest {
    /// Always the single supported manifest format.
    pub purpose: TrustPurpose,
    /// Canonical community and signer issuer.
    pub community: String,
    /// Durable policy-state revision.
    pub revision: u64,
    /// Effective policy epoch, including activated rulebook changes.
    pub policy_epoch: u64,
    /// Current public key ring, in csgn's canonical encoding.
    pub key_ring: Vec<u8>,
    /// Current schema version.
    pub schema_version: u32,
}
/// Domain separation for the signed manifest payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustPurpose {
    /// Version-one community trust publication.
    #[serde(rename = "cplc.trust.v1")]
    CommunityTrustV1,
}
/// A sparse setting edit. The outer service authenticates the allowed layer.
pub enum SettingEdit {
    /// Community deviation; None removes the row, Some(Null) terminates resolution.
    Community(Option<serde_json::Value>),
    /// Root-only platform value and force flag.
    Platform(Option<crbk::PlatformValue>),
}
