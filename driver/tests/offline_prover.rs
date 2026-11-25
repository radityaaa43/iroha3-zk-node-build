//! Offline integration test (no node): real v2 proofs through the driver's glue.
//! "A sends 100 of 250 to B with change", then B unshields its note, then BI audits the whole history.
//! Run: `.work/dev-cargo.sh test --release -p rd_driver --test offline_prover` (proving, a few minutes).

use std::path::PathBuf;

use iroha_core::zk::{ZK_BACKEND_HALO2_IPA, verify_backend};
use rd_driver::{
    audit::{AuditKeys, audit},
    envelope::{self, BindingCtx, Bytes32, Envelope},
    events::{Event, Kind, Ledger},
    proto::{self, Address, OutSpec, address_of, commitment, nullifier},
    wallet::{Me, scan_notes},
};
use sha2::{Digest, Sha256};

const CHAIN: &str = "rd2-offline-test";
const ASSET: &str = "rd#rd";

fn k(tag: &str) -> Bytes32 {
    Sha256::digest(tag.as_bytes()).into()
}

fn me(party: &str, spend: Bytes32) -> Me {
    let view_secret = k(&format!("{party}.view"));
    Me {
        party: party.into(),
        dir: PathBuf::new(),
        public_key: String::new(),
        private_key: String::new(),
        view_secret,
        view_pk: envelope::public_from_secret(&view_secret),
        spend_key: spend,
    }
}

fn ev(block: u64, kind: Kind, authority: &str, from: Option<&str>, inputs: Vec<Bytes32>, outputs: Vec<Bytes32>, public_amount: u128, envelope: Option<Vec<u8>>) -> Event {
    Event {
        block,
        tx: format!("tx{block}"),
        authority: authority.into(),
        kind,
        asset: ASSET.into(),
        from: from.map(Into::into),
        inputs,
        outputs,
        public_amount,
        root_hint: None,
        envelope,
        signers: vec![],
        leaf_start: 0,
    }
}

#[test]
fn transfer_with_change_unshield_and_audit() {
    let audit_sk = k("bi.audit.v1");
    let audit_pk = envelope::public_from_secret(&audit_sk);
    let keys: AuditKeys = [(1u32, audit_sk)].into();
    let (a, b) = (me("bank-a", k("a.spend")), me("bank-b", k("b.spend")));
    let (a_addr, b_addr): (Address, Address) = (a.address(), b.address());
    let seal = |pt: &envelope::Plaintext, ctx: &BindingCtx<'_>, rc_pk: Bytes32| -> Envelope { proto::make_envelope(pt, ctx, 1, audit_pk, rc_pk).unwrap() };

    // --- issue: BI shields 250 to bank-a (envelope rc = bank-a) ---
    let rho0 = k("rho0");
    let c0 = commitment(ASSET, 250, rho0, a_addr.owner_tag).unwrap();
    let n0 = proto::NoteOut { amount: 250, rho: rho0, diversifier: a_addr.diversifier, owner_tag: a_addr.owner_tag, owner: "bank-a".into(), commitment: c0 };
    let outs0 = [c0];
    let pt0 = proto::plaintext("shield", ASSET, "bi", "issue", &[], std::slice::from_ref(&n0), Some(250));
    let e0 = seal(&pt0, &BindingCtx { asset: ASSET, inputs: &[], outputs: &outs0, public_amount: 250 }, a.view_pk);
    let mut ledger = Ledger::default();
    ledger.push(ev(1, Kind::Shield, "bi", Some("bi"), vec![], vec![c0], 250, Some(e0.encode())));

    // --- bank-a scans: finds the 250 note at leaf 0 ---
    let (notes_a, anomalies) = scan_notes(&ledger, &a, ASSET, CHAIN, vec![]);
    assert!(anomalies.is_empty());
    assert_eq!(notes_a.len(), 1);
    assert_eq!((notes_a[0].amount(), notes_a[0].leaf_index, notes_a[0].spent), (250, Some(0), false));
    assert_eq!(hex::encode(nullifier(CHAIN, ASSET, &a.spend_key, rho0)), notes_a[0].nullifier);

    // --- transfer: 100 to bank-b, change 150 ---
    let ins = [notes_a[0].in_note().unwrap()];
    let outs = [
        OutSpec { amount: 100, addr: b_addr, owner: "bank-b".into() },
        OutSpec { amount: 150, addr: a_addr, owner: "bank-a".into() },
    ];
    let t = std::time::Instant::now();
    let built = proto::build_transfer(CHAIN, ASSET, &a.spend_key, &ledger.leaves, &ins, &outs).expect("prove transfer");
    eprintln!("transfer prove_ms={} proof_bytes={}", t.elapsed().as_millis(), built.proof.bytes.len());
    assert_eq!(built.nullifiers, vec![nullifier(CHAIN, ASSET, &a.spend_key, rho0)]);
    // the commitments the chain will see equal what the envelope recomputes
    for (i, n) in built.notes.iter().enumerate() {
        assert_eq!(built.outputs[i], commitment(ASSET, n.amount, n.rho, n.owner_tag).unwrap());
    }
    let pt1 = proto::plaintext("transfer", ASSET, "bank-a", "ref-1", &built.nullifiers, &built.notes, None);
    let ctx1 = BindingCtx { asset: ASSET, inputs: &built.nullifiers, outputs: &built.outputs, public_amount: 0 };
    let e1 = seal(&pt1, &ctx1, b.view_pk);
    // carrier: envelope in OpenVerifyEnvelope.aux; the proof still verifies and aux reads back
    let mut proof = built.proof.clone();
    proto::set_aux(&mut proof, &e1.encode()).unwrap();
    assert_eq!(proto::get_aux(&proof).unwrap(), e1.encode());
    assert!(verify_backend(ZK_BACKEND_HALO2_IPA, &proof, Some(&proto::transfer_vk().unwrap())), "proof with aux verifies");
    let mut tampered = proof.clone();
    proto::tamper_proof(&mut tampered).unwrap();
    assert!(!verify_backend(ZK_BACKEND_HALO2_IPA, &tampered, Some(&proto::transfer_vk().unwrap())), "tampered proof rejected");

    let transfer_ev = ev(2, Kind::Transfer, "bank-a", None, built.nullifiers.clone(), built.outputs.clone(), 0, Some(e1.encode()));

    // BI audit of [issue, transfer]: clean and supply reconciles
    let mut audited = ledger.events.clone();
    audited.push(transfer_ev.clone());
    let rep = audit(&audited, &keys);
    assert_eq!(rep["summary"]["violations"], 0, "{rep:#}");
    assert_eq!(rep["summary"]["supply_reconciles"], true, "{rep:#}");

    // BI audit of a lying envelope (amount 151 for the change note): commitment mismatch is detected
    let mut lie = built.notes.clone();
    lie[1].amount = 151;
    let pt_lie = proto::plaintext("transfer", ASSET, "bank-a", "ref-1", &built.nullifiers, &lie, None);
    let e_lie = seal(&pt_lie, &ctx1, b.view_pk);
    let mut bad = audited.clone();
    bad[1].envelope = Some(e_lie.encode());
    let rep = audit(&bad, &keys);
    let codes: Vec<String> = rep["events"][1]["violations"].as_array().unwrap().iter().map(|v| v["code"].as_str().unwrap().to_owned()).collect();
    assert!(codes.contains(&"commitment_mismatch".to_owned()), "{codes:?}");
    // missing envelope and wrong signer are detected too
    let mut missing = audited.clone();
    missing[1].envelope = None;
    assert_eq!(audit(&missing, &keys)["events"][1]["violations"][0]["code"], "envelope_missing");
    let mut forged = audited.clone();
    forged[1].authority = "bank-c".into();
    let rep = audit(&forged, &keys);
    let codes: Vec<String> = rep["events"][1]["violations"].as_array().unwrap().iter().map(|v| v["code"].as_str().unwrap().to_owned()).collect();
    assert!(codes.contains(&"sender_mismatch".to_owned()) && codes.contains(&"conservation_unmatched_inputs".to_owned()), "{codes:?}");

    // --- bank-b scans and finds its 100 note at the sorted leaf position; node appends sorted outputs ---
    ledger.push(transfer_ev);
    let (notes_b, anomalies) = scan_notes(&ledger, &b, ASSET, CHAIN, vec![]);
    assert!(anomalies.is_empty());
    assert_eq!(notes_b.len(), 1);
    assert_eq!(notes_b[0].amount(), 100);
    let li = notes_b[0].leaf_index.expect("leaf");
    assert_eq!(ledger.leaves[li], hex::decode(&notes_b[0].commitment).unwrap().as_slice());
    assert!(!notes_b[0].spent);
    // bank-a sees its input spent
    let (notes_a2, _) = scan_notes(&ledger, &a, ASSET, CHAIN, notes_a);
    assert!(notes_a2[0].spent);

    // --- bank-b unshields 100 (whole note) ---
    let bin = [notes_b[0].in_note().unwrap()];
    let t = std::time::Instant::now();
    let u = proto::build_unshield(CHAIN, ASSET, &b.spend_key, &ledger.leaves, &bin).expect("prove unshield");
    eprintln!("unshield prove_ms={}", t.elapsed().as_millis());
    assert_eq!(u.public_amount, 100);
    let pt2 = proto::plaintext("unshield", ASSET, "bank-b", "exit", &u.nullifiers, &[], Some(100));
    let ctx2 = BindingCtx { asset: ASSET, inputs: &u.nullifiers, outputs: &[], public_amount: 100 };
    let e2 = seal(&pt2, &ctx2, b.view_pk);
    let mut uproof = u.proof.clone();
    proto::set_aux(&mut uproof, &e2.encode()).unwrap();
    assert!(verify_backend(ZK_BACKEND_HALO2_IPA, &uproof, Some(&proto::unshield_vk().unwrap())));
    ledger.push(ev(3, Kind::Unshield, "bank-b", None, u.nullifiers.clone(), vec![], 100, Some(e2.encode())));
    let rep = audit(&ledger.events, &keys);
    assert_eq!(rep["summary"]["violations"], 0, "{rep:#}");
    assert_eq!(rep["summary"]["unshielded"], "100");
    assert_eq!(rep["summary"]["shielded_outstanding"], "150");
    assert_eq!(rep["summary"]["supply_reconciles"], true, "{rep:#}");
    let (notes_b2, _) = scan_notes(&ledger, &b, ASSET, CHAIN, notes_b);
    assert!(notes_b2[0].spent);
}
