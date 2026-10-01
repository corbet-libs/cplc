//! Original csgn proofs survive actual durable-owner handoff and process reopen.
mod common;
use common::*;
use cplc::*;
use serde_json::json;

#[tokio::test]
async fn interrupted_key_handoff_recovers_before_and_after_policy_retention() {
    for phase in 0..3 {
        let rules = crbk::MemoryStore::default();
        let store = MemoryStore::new(COMMUNITY).unwrap();
        let keys = csgn::MemoryStore::default();
        let signer = csgn::PersistentSigner::create(
            keys.clone(), COMMUNITY, key(1), day(NOW), ESTABLISHED_MEMBER_VALIDITY,
        ).await.unwrap();
        let root = signer.key_ring().unwrap().clone();
        let mut policy = Policy::create(rules.clone(), store.clone(), signer, config()).await.unwrap();
        configure(&mut policy, book(admission())).await;
        let initial = policy.trust_feed(NOW).await.unwrap();
        drop(policy);

        // The real signer commits its successor and original endorsement first.
        let mut signer = csgn::PersistentSigner::open(keys.clone(), COMMUNITY, key(1), day(NOW)).await.unwrap();
        let proof = signer.rotate_with_proof(key(2), day(NOW), ESTABLISHED_MEMBER_VALIDITY).await.unwrap();
        assert_eq!(signer.ring_revision().unwrap(), 1);
        if phase > 0 {
            // Persist the exact handoff through the actual Policy store, then
            // simulate interruption before or after the signer acknowledgement.
            let old = store.load().await.unwrap().unwrap();
            let mut next = serde_json::to_value(&old).unwrap();
            next["revision"] = json!(old.revision() + 1);
            next["key_transitions"] = json!([{"revision":1,"proof":proof}]);
            let next: StoredPolicy = serde_json::from_value(next).unwrap();
            store.compare_exchange(Some(old.revision()), &next).await.unwrap();
        }
        if phase == 2 {
            signer.acknowledge_transition(1).await.unwrap();
        }
        drop(signer);
        let signer = csgn::PersistentSigner::open(keys.clone(), COMMUNITY, key(2), day(NOW)).await.unwrap();
        let mut reopened = Policy::open(rules, store, signer).await.unwrap();
        assert_eq!(reopened.key_transitions().unwrap().len(), 1);
        assert_eq!(reopened.key_transitions().unwrap()[0].proof, proof);
        let verified = csgn::verify_transition(&root, &proof, NOW).unwrap();
        assert_eq!(verified.revision(), 1);
        assert_eq!(verified.previous(), &root);
        assert_eq!(verified.next(), reopened.key_ring().unwrap());
        let refreshed = reopened.trust_feed(NOW).await.unwrap();
        assert_eq!(refreshed.key_transitions, reopened.key_transitions().unwrap());
        assert_eq!(refreshed.policy_epoch, initial.policy_epoch);
        // Ordinary issuance and publication may update private CAS state only.
        reopened.issue_test(request(&[development_gate(500)]), NOW).await.unwrap();
        assert_eq!(reopened.key_transitions().unwrap()[0].proof, proof);
        drop(reopened);
        let signer = csgn::PersistentSigner::open(keys, COMMUNITY, key(2), day(NOW)).await.unwrap();
        assert_eq!(signer.ring_revision().unwrap(), 1);
        assert!(signer.pending_transition().unwrap().is_none());
    }
}

#[tokio::test]
async fn real_sql_rotation_and_pruning_publish_original_monotonic_proofs() {
    let (_directory, db, rules_db, mut policy) = local().await;
    let root = policy.key_ring().unwrap().clone();
    let initial = policy.trust_feed(NOW).await.unwrap();
    policy.rotate(key(2), NOW).await.unwrap();
    let rotated = policy.trust_feed(NOW).await.unwrap();
    assert_eq!(rotated.key_transitions.len(), 1);
    assert_eq!(rotated.policy_epoch, initial.policy_epoch);
    let transition = csgn::verify_transition(&root, &rotated.key_transitions[0].proof, NOW).unwrap();
    let intermediate = transition.next().clone();
    // A no-op prune does not expose a new public ring revision.
    policy.prune_keys(NOW).await.unwrap();
    assert_eq!(policy.key_transitions().unwrap(), rotated.key_transitions);
    policy.prune_keys(ESTABLISHED_MEMBER_VALIDITY).await.unwrap();
    assert_eq!(policy.key_transitions().unwrap().len(), 2);
    let original = policy.key_transitions().unwrap().to_vec();
    let pruned = csgn::verify_transition(&intermediate, &original[1].proof, ESTABLISHED_MEMBER_VALIDITY).unwrap();
    assert_eq!(pruned.revision(), 2);
    assert_eq!(pruned.previous(), &intermediate);
    assert_eq!(pruned.next(), policy.key_ring().unwrap());
    drop(policy);
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY, key(2), ESTABLISHED_MEMBER_VALIDITY,
    ).await.unwrap();
    let reopened = Policy::open(
        crbk::LibsqlStore::new(rules_db), LibsqlStore::new(&db, COMMUNITY).unwrap(), signer,
    ).await.unwrap();
    assert_eq!(reopened.key_transitions().unwrap(), original);
}
