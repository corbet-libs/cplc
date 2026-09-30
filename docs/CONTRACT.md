# cplc implemented contract

## Binding scope

Policy facade over `crbk` (rulebook), `cshm` (profile schema) and `csgn`
(community signing keys), under `cmnt` in cvld v0.4. Policy reaches the global
service only as signed snapshots. Global issuance, keys, suspension and databases
remain separate. Rust on current stable; FSL-1.1-ALv2; no registry publication.
No own cryptographic primitives. No login dates, request logs or raw gate data.
Use maintained leaves pinned by revision. Storage goes through `crlt`, with one
database per community, a community key in every table and indexed queries.
Tests exercise real leaf operations and real local libSQL on GitHub Actions.

## Composition and trust boundary

`Policy<R, S, K>` owns a crbk storage implementation, a cplc storage implementation
and a csgn `PersistentSigner<K>`. Run one writer per community. Serialize all
configuration changes, issuance, rotation and public-ring delivery through that
writer. All mutating facade methods require exclusive access. Revision fencing
is defense against stale writers, not a distributed publication protocol.

The composition root supplies authenticated community routing, trusted Unix
seconds, administrator authorization, verified gate metadata, membership state,
a canonical reserved handle, authorized pins and public device keys. None of
these Rust inputs is evidence of remote authentication. In particular, exposing
`CredentialRequest` directly as a member-facing signing endpoint is unsafe.
The admission action is persisted in configuration and cannot be selected by an
issuance request. The facade evaluates that action itself using crbk; it never
accepts a caller-provided verdict.

The signer issuer must exactly equal the community identifier. Global issuers
must use another scope and separate keys. Seeds are provisioned in the service's
secret store, never Turso. csgn alone performs signing, key rotation, key retention,
canonical COSE verification and durable signing-state updates.

## Configuration and epochs

crbk owns sparse resolution, immutable revisions, template/catalogue rules,
prospective activation and minimum notice. `schedule_rules` delegates its write
and validation to that leaf. Each rulebook revision must advance its policy epoch by exactly one, beginning
at one. An administrator cannot jump to an epoch that exhausts later revocations. Only `Selection::At(now)` is used for decisions; future revisions never activate
early. The effective epoch is the checked sum of the facade counter and the active
rulebook epoch. Both components only increase. Immediate edits advance the facade
counter; each scheduled revision advances the other component when it activates.
Thus an immediate revocation cannot mask a later scheduled epoch transition.
Overflow fails closed; epochs fit positive signed 64-bit integers.

cshm owns schema validation and change classification. The facade persists one
current schema and requires increasing versions. Schema edits, public community
list edits, revocations and explicit epoch bumps are immediate administrative
operations and invalidate older epochs. The caller must review classification
before authorizing an edit; migration/grandfathering and notice delivery are
upstream responsibilities. The public community list is explicit input, never
inferred from member activity or cross-community joins.

## Signed publications and credentials

Four kinds are published: settings (flat `crbk::Values`), schema (`cshm::Schema`),
communities (ordered public identifier set), and revocation list (`Revocations`).
JSON `Snapshot<T>` contains community, positive publication revision, policy epoch
and content. Protected COSE headers carry kind, issued time, exclusive expiry,
issuer and key ID. These authenticated fields are not duplicated in JSON.
Publication revisions are independent per kind and increase even on refresh.
Only the latest signed bytes of each kind are retained; policy edits clear cached
bytes while preserving revision counters. Snapshot lifetime is bounded by config,
csgn's maximum and the next scheduled rulebook activation.

Credentials carry community, member pseudonym, canonical handle, community gates
with expiries, pin fingerprints, authorized device keys, schema version and epoch.
The enclosing COSE supplies issuance, expiry and key ID. Global proof metadata
participates in the decision but is never copied into the credential or storage.
Credential issuance stores no credential, pseudonym, proof or login history.
Current revocations are explicit policy state, not an activity log.

New-member credentials last at most one day; established credentials at most
thirty days. Both are shortened to csgn's lifetime limit, proof expiry and the next
announced policy activation. Maximum-proof-age expiry is determined by asking
crbk at future times within this fixed policy interval, not by another policy
engine. Every included gate covers the entire signed lifetime. Subject/scope
mismatches, duplicate community gates, revoked members/devices, invalid pins,
missing schema, wrong schema version and any membership other than Admitted fail closed, even
when the action has no membership requirement. Credential Debug output is redacted.
Community signer namespaces contain only ASCII letters, digits, dot, dash and
underscore; the global cglb: namespace is reserved.

## Durability

The cplc storage trait atomically loads/replaces one community document with a
revision comparison. Both memory and crlt/libSQL implementations enforce the same
state validation and counter/epoch monotonicity. The libSQL row uses primary key
`(community_id, slot)` and stores current schema, config, public communities,
revocations, aggregate epochs and publication counters/latest policy COSE.
No signing secret or member credential is stored. Application read/write query
plans are checked by crlt and by adapter tests. The service owns migration numbers
and supplies complete migration history for cplc, crbk and csgn.

Publication ordering is sign and persist csgn retention, then persist publication,
then return bytes. Failed publication never returns a signature. An uncertain or
cancelled cplc mutation disables that facade until reopening. csgn applies its
own fail-closed rule to signing-state mutations. These stores are not one SQL
transaction: an orphaned signing retention update is safe over-retention, not a
published credential. Rulebook writes have their own atomic leaf transaction;
uncertain outcomes require reconciliation, never automatic retry.

## Verification and limits

`verify_snapshot` uses an authenticated csgn ring, expected scope/kind, exact
expected epoch and a caller-held revision floor. Signature authenticity does not
make an old epoch current; callers must obtain fresh authenticated floors and
revocations. Consumers validate typed content semantics (cshm for schema, crbk
for settings). cplc is not a replacement for cgrd's profile/bundle checks.

Facade documents are limited to 1 MiB; public sets, fields and credential
collections to 256 entries; identifiers to 256 bytes. Services must bound
transport allocation before parsing. Errors omit SQL, credentials and input
values. Do not enable dependency SQL/HTTP debug tracing for member traffic.

## Integration limits

crbk, csgn and cplc use one revision of crlt and clones of one database handle.
CI rejects duplicate or floating Corbet dependencies, including transitive ones.

cgrd currently consumes a narrower settings vocabulary (conjunctive gate lists
and embedded revocations), while crbk publishes the full flat action policies.
A consumer adapter must preserve all/any/k-of-n semantics and revocations; feeding
a flat settings snapshot directly to cgrd is not supported. No lossy translation
or silent empty-gate fallback is provided. Cross-facade wire integration remains
an explicit downstream task. Emergency signing-key revocation and rollback-proof
recovery remain csgn/service boundaries. The development test gate is test-only;
there are no provider calls or production test-gate features.

## Door integration

`edit_setting` changes one community deviation or root platform value through
crbk, preserving all other sparse layers and advancing the policy epoch.
The service authorizes the requested layer and supplies notice timing.
`revocations` exposes current policy state to coordinated service writers.

`trust_manifest` signs a typed `TrustManifest` with a fixed `cplc.trust.v1`
purpose, community, durable policy revision, effective epoch, current schema
version and canonical public key ring. Its COSE kind is SettingsSnapshot, but
its distinct strict top-level shape prevents decoding as a flat settings
snapshot. It is an aggregate trust publication, never a member query. Signatures
use csgn's durable retention path. Consumers still need an authenticated initial
key ring and freshness floors; a self-signed ring is not a bootstrap trust root.

## Verified settings and revocation storage

`verified_settings` and `verify_settings` return an opaque `VerifiedSnapshot`.
Its immutable crbk view retains the authenticated issuance time and effective
epoch; its exclusive expiry stays attached to the witness. `validate_snapshot`
requires the current publication revision, content, epoch and validity. A raw
snapshot cannot be converted into this type; a compile-fail doctest enforces it.

Revocations use indexed `cplc_revocation` rows, committed atomically with the
policy epoch. Reads page over the primary key in batches of 256; that batch size
is not a revocation capacity limit. Memory storage enforces the same unbounded
set semantics. Published documents retain their transport size bound. A large
revocation set cannot prevent committing further revocations or advancing epochs.

`Policy::settings(now)` returns the active flattened crbk snapshot without
publishing, advancing the epoch, or recording that a caller read it. The door
uses it for checks such as reserved-handle validation, independently of the
fresh global passport proof needed for admission.
