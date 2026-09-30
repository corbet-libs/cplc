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
and validation to that leaf. Each subsequent rulebook revision must increase its
policy epoch. Only `Selection::At(now)` is used for decisions; future revisions never activate
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
missing schema, wrong schema version and released membership fail closed.

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

The pinned crbk still depends on an older crlt revision than csgn. Its concrete
libSQL adapter therefore needs the matching crlt type; tests use two handles to
the same physical database. The facade's generic rulebook port avoids copying
leaf logic. Align that upstream pin to obtain a single shared pool across all
three stores. No leaf source is vendored or replaced here.

cgrd currently consumes a narrower settings vocabulary (conjunctive gate lists
and embedded revocations), while crbk publishes the full flat action policies.
A consumer adapter must preserve all/any/k-of-n semantics and revocations; feeding
a flat settings snapshot directly to cgrd is not supported. No lossy translation
or silent empty-gate fallback is provided. Cross-facade wire integration remains
an explicit downstream task. Emergency signing-key revocation and rollback-proof
recovery remain csgn/service boundaries. The development test gate is test-only;
there are no provider calls or production test-gate features.
