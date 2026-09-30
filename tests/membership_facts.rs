//! Issuance derives lifetime and eligibility from the authoritative source.
mod common;
use common::*;
use cplc::*;

async fn issue(policy: &mut MemoryPolicy, source: &FixtureMembership, now: u64) -> Result<Vec<u8>> {
    let snapshot = policy.verified_settings(now).await?;
    let gates = checked(&snapshot, MEMBER, "admit", &[], now).await?;
    policy
        .issue(
            source,
            CredentialRequest {
                subject: subject(),
                handle: "testmember",
                schema_version: 1,
                snapshot: &snapshot,
                gates: &gates,
                pins: &[],
                devices: DEVICES,
            },
            now,
        )
        .await
}
fn source() -> FixtureMembership {
    FixtureMembership {
        member: MEMBER.into(),
        state: crbk::MembershipState::Admitted,
        probation_until: Some(14 * DAY),
        lease_end: 90 * DAY,
    }
}

#[tokio::test]
async fn stored_probation_and_rulebook_caps_select_lifetime() {
    let mut rules = book(crbk::ActionPolicy::default());
    crbk::define_membership_settings(&mut rules).unwrap();
    rules
        .set_community(crbk::NEW_CREDENTIAL_DAYS, Some(2.into()))
        .unwrap();
    rules
        .set_community(crbk::ESTABLISHED_CREDENTIAL_DAYS, Some(7.into()))
        .unwrap();
    let mut policy = memory_with(rules).await;
    let mut member = source();
    let cose = issue(&mut policy, &member, NOW).await.unwrap();
    assert_eq!(
        decode_credential(policy.key_ring().unwrap(), &cose, NOW).1,
        2 * DAY
    );
    member.probation_until = None;
    let cose = issue(&mut policy, &member, NOW + 1).await.unwrap();
    assert_eq!(
        decode_credential(policy.key_ring().unwrap(), &cose, NOW + 1).1,
        7 * DAY
    );
    member.probation_until = Some(0);
    let cose = issue(&mut policy, &member, NOW + 2).await.unwrap();
    assert_eq!(
        decode_credential(policy.key_ring().unwrap(), &cose, NOW + 2).1,
        7 * DAY
    );
}

#[tokio::test]
async fn lease_is_an_upper_bound_and_signing_times_are_day_buckets() {
    let mut policy = memory_with(book(crbk::ActionPolicy::default())).await;
    let mut member = source();
    member.probation_until = None;
    member.lease_end = 3 * DAY;
    let cose = issue(&mut policy, &member, 12345).await.unwrap();
    let verified = policy
        .key_ring()
        .unwrap()
        .verify(&cose, csgn::Kind::Credential, 12345)
        .unwrap();
    assert_eq!(verified.issued_at(), 0);
    assert_eq!(verified.valid_until(), 3 * DAY);
    member.lease_end = DAY + 1;
    assert!(issue(&mut policy, &member, 12346).await.is_err());
    member.lease_end = 0;
    assert!(issue(&mut policy, &member, 12346).await.is_err());
}

#[tokio::test]
async fn caller_admitted_claim_cannot_override_current_member_state() {
    let mut policy = memory_with(book(crbk::ActionPolicy::default())).await;
    let mut member = source();
    for state in [
        crbk::MembershipState::Pending,
        crbk::MembershipState::Lapsed,
        crbk::MembershipState::Released,
    ] {
        member.state = state;
        assert!(issue(&mut policy, &member, NOW).await.is_err());
    }
    member.state = crbk::MembershipState::Admitted;
    member.member = "somebody-else".into();
    assert!(issue(&mut policy, &member, NOW).await.is_err());
}

#[tokio::test]
async fn issuance_rejects_stale_publication_and_rebound_gate_context() {
    let mut policy = memory_with(book(crbk::ActionPolicy::default())).await;
    let old = policy.verified_settings(NOW).await.unwrap();
    let gates = checked(&old, MEMBER, "admit", &[], NOW).await.unwrap();
    policy.publish(SnapshotKind::Settings, NOW).await.unwrap();
    let input = CredentialRequest {
        subject: subject(),
        handle: "testmember",
        schema_version: 1,
        snapshot: &old,
        gates: &gates,
        pins: &[],
        devices: DEVICES,
    };
    assert!(matches!(
        policy.issue(&source(), input, NOW).await,
        Err(Error::Verification)
    ));
    let current = policy.verified_settings(NOW).await.unwrap();
    let input = CredentialRequest {
        subject: subject(),
        handle: "testmember",
        schema_version: 1,
        snapshot: &current,
        gates: &gates,
        pins: &[],
        devices: DEVICES,
    };
    assert!(matches!(
        policy.issue(&source(), input, NOW).await,
        Err(Error::Verification)
    ));
}

#[tokio::test]
async fn community_device_keys_are_preserved_without_a_global_wallet_key() {
    let mut policy = memory_with(book(crbk::ActionPolicy::default())).await;
    let a = [11; 32];
    let b = [12; 32];
    assert_ne!(a, b); // Independently generated per-community public keys.
    let snapshot = policy.verified_settings(NOW).await.unwrap();
    let gates = checked(&snapshot, MEMBER, "admit", &[], NOW).await.unwrap();
    let cose = policy
        .issue(
            &source(),
            CredentialRequest {
                subject: subject(),
                handle: "testmember",
                schema_version: 1,
                snapshot: &snapshot,
                gates: &gates,
                pins: &[],
                devices: &[a],
            },
            NOW,
        )
        .await
        .unwrap();
    let credential = decode_credential(policy.key_ring().unwrap(), &cose, NOW).0;
    assert_eq!(credential.devices, [a]);
    assert!(!credential.devices.contains(&b));
}
