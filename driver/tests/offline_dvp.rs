//! Offline DvP test (no node): the two-party `rd2 dvp` flow with real v2 proofs, through the same trade.json files the CLI uses.
//! UC-06 (interbank: DFABI bank-a -> bank-b, RD bank-b -> bank-a) and UC-03 (award: DFABI bi -> bank-a, RD bank-a -> bi).
//! Run: `cargo test --release -p rd_driver --test offline_dvp` (CI only; proving).

use std::path::PathBuf;

use iroha_core::rd_dvp::{award_digest, settlement_digest};
use iroha_data_model::{
    asset::AssetDefinitionId,
    isi::zk::DvpKind,
    prelude::DomainId,
};
use rd_driver::{
    audit::{AuditKeys, audit},
    cmd::{self, Ctx},
    dvp::{self, AwardArgs, Leg, ProposeArgs, Trade},
    envelope::{BindingCtx, Bytes32},
    events::{Event, Kind, Ledger},
    proto::{self, NoteOut, commitment},
    wallet::{Me, Parties, load_audit_keys, scan_notes},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CHAIN: &str = "rd2-offline-dvp";

fn k(tag: &str) -> Bytes32 {
    Sha256::digest(tag.as_bytes()).into()
}

fn asset(name: &str) -> String {
    AssetDefinitionId::new(DomainId::try_new("rd", "universal").unwrap(), name.parse().unwrap()).to_string()
}

struct World {
    dir: PathBuf,
    pj: Value,
    audit: AuditKeys,
}

impl World {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rd2-dvp-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut pj = json!({"assets": {"rd": asset("rd"), "dfabi_2026_01": asset("dfabi_2026_01")}});
        for p in ["bi", "bank-a", "bank-b"] {
            let out = cmd::keygen(&dir.join(p), p, p == "bi").unwrap();
            pj[p] = json!({"account_id": out["account_id"], "view_pk": out["view_pk"], "address": out["address"]});
            if p == "bi" {
                pj["bi_audit"] = out["bi_audit"].clone();
            }
        }
        let audit = load_audit_keys(&dir.join("bi")).unwrap();
        Self { dir, pj, audit }
    }

    fn ctx(&self, party: &str) -> Ctx {
        Ctx { torii: String::new(), chain: CHAIN.into(), parties: Parties(self.pj.clone()), me: Me::load(&self.dir.join(party), party).unwrap() }
    }

    /// BI shields `amount` of `asset` to `to` (UC-02 when `to` is bi): same note and envelope as `rd2 issue`.
    fn shield(&self, ledger: &mut Ledger, asset: &str, to: &str, amount: u128, block: u64) {
        let c = self.ctx("bi");
        let addr = c.parties.address(to).unwrap();
        let rho = k(&format!("rho.{asset}.{to}.{block}"));
        let cm = commitment(asset, amount, rho, addr.owner_tag).unwrap();
        let note = NoteOut { amount, rho, diversifier: addr.diversifier, owner_tag: addr.owner_tag, owner: c.parties.account_id(to).unwrap(), commitment: cm };
        let bi = c.own_account().unwrap();
        let pt = proto::plaintext("shield", asset, &bi, "issue", &[], std::slice::from_ref(&note), Some(amount));
        let (ver, bi_pk) = c.parties.audit_key().unwrap();
        let outs = [cm];
        let ctx = BindingCtx { asset, inputs: &[], outputs: &outs, public_amount: amount };
        let env = proto::make_envelope(&pt, &ctx, ver, bi_pk, c.parties.view_pk(to).unwrap()).unwrap();
        ledger.push(Event {
            block,
            tx: format!("shield{block}"),
            authority: bi.clone(),
            kind: Kind::Shield,
            asset: asset.into(),
            from: Some(bi),
            inputs: vec![],
            outputs: vec![cm],
            public_amount: amount,
            root_hint: None,
            envelope: Some(env.encode()),
            signers: vec![],
            leaf_start: 0,
        });
    }
}

/// What the node does with a DvP leg, as the driver's block replay sees it (`chain.rs::to_event`).
fn leg_event(z: &iroha_data_model::isi::zk::ZkTransfer, authority: &str, signers: &[String]) -> Event {
    Event {
        block: 10,
        tx: "dvp".into(),
        authority: authority.into(),
        kind: Kind::Transfer,
        asset: z.asset.to_string(),
        from: None,
        inputs: z.inputs.clone(),
        outputs: z.outputs.clone(),
        public_amount: 0,
        root_hint: z.root_hint,
        envelope: proto::get_aux(&z.proof.proof),
        signers: signers.to_vec(),
        leaf_start: 0,
    }
}

fn codes(rep: &Value, ev: usize) -> Vec<String> {
    rep["events"][ev]["violations"].as_array().unwrap().iter().map(|v| v["code"].as_str().unwrap().to_owned()).collect()
}

/// Preimage of spec 4b, built by hand from the trade file (independent of `iroha_core::rd_dvp`).
fn spec_digest(t: &Trade) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"rd.iroha2.dvp.v1");
    h.update(hex::decode(&t.trade_id).unwrap());
    h.update((t.chain.len() as u16).to_be_bytes());
    h.update(t.chain.as_bytes());
    h.update(t.expiry_height.to_be_bytes());
    for l in [t.delivery_leg.as_ref().unwrap(), t.payment_leg.as_ref().unwrap()] {
        h.update((l.asset.len() as u16).to_be_bytes());
        h.update(l.asset.as_bytes());
        h.update([l.inputs.len() as u8]);
        l.inputs.iter().for_each(|x| h.update(hex::decode(x).unwrap()));
        h.update([l.outputs.len() as u8]);
        l.outputs.iter().for_each(|x| h.update(hex::decode(x).unwrap()));
    }
    h.finalize().into()
}

fn flow(award: bool) {
    let w = World::new(if award { "award" } else { "interbank" });
    let (rd, dfabi) = (asset("rd"), asset("dfabi_2026_01"));
    let (seller, buyer) = if award { ("bi", "bank-a") } else { ("bank-a", "bank-b") };
    let (cs, cb) = (w.ctx(seller), w.ctx(buyer));
    let (acct_s, acct_b) = (cs.own_account().unwrap(), cb.own_account().unwrap());

    // funds: the seller holds 10 DFABI (for bi that is UC-02: BI shields to its own address), the buyer 5000 RD
    let (mut l_dfabi, mut l_rd) = (Ledger::default(), Ledger::default());
    w.shield(&mut l_dfabi, &dfabi, seller, 10, 1);
    w.shield(&mut l_rd, &rd, buyer, 5000, 1);

    // --- BI award (UC-03) ---
    let award_file = award.then(|| {
        let bi = w.ctx("bi");
        let a = dvp::award_sign(
            &bi,
            &AwardArgs { award_id: k("award-1"), winner: buyer, instrument: "dfabi_2026_01", quantity: 4, consideration: 3000, expiry_height: 100 },
        )
        .unwrap();
        dvp::verify_award(&a, &bi.own_account().unwrap().to_string()).expect("award signature verifies");
        // the node's own digest over the same record verifies too, and any changed field breaks it
        let s = a.to_signed().unwrap();
        let key = rd_driver::chain::own_account(&bi.me).unwrap();
        s.bi_signature.verify(key.try_signatory().unwrap(), &award_digest(CHAIN, &s).unwrap()).unwrap();
        let mut bad = a.clone();
        bad.consideration = "3001".into();
        assert!(dvp::verify_award(&bad, &bi.own_account().unwrap().to_string()).is_err(), "tampered award must not verify");
        let mut bad = a.clone();
        bad.winner_party = "bank-b".into();
        bad.winner = w.ctx("bank-b").own_account().unwrap().to_string();
        assert!(dvp::verify_award(&bad, &bi.own_account().unwrap().to_string()).is_err(), "other winner must not verify");
        a
    });

    // --- propose (file round trip) ---
    let args = |kind: Option<&'static str>, award: Option<dvp::AwardFile>| ProposeArgs {
        trade_id: "auto",
        deliver_asset: "dfabi_2026_01",
        deliver_amount: 4,
        pay_asset: "rd",
        pay_amount: 3000,
        seller,
        buyer,
        expiry_height: 100,
        kind,
        award,
    };
    if award {
        assert!(dvp::propose(&cs, &args(Some("interbank"), award_file.clone())).is_err(), "interbank carries no award");
        assert!(dvp::propose(&cs, &args(Some("award"), None)).is_err(), "award trade needs an award");
        let mut wrong = award_file.clone().unwrap();
        wrong.instrument = rd.clone();
        assert!(dvp::propose(&cs, &args(None, Some(wrong))).is_err(), "award for another instrument");
    }
    let path = w.dir.join("trade.json");
    dvp::propose(&cs, &args(None, award_file)).unwrap().save(&path).unwrap();
    let mut t = Trade::load(&path).unwrap();
    assert_eq!(t.kind, if award { "award" } else { "interbank" });
    assert!(t.digest().is_err(), "no digest before both legs exist");

    // --- each party proves its own leg: the recipient is the counterparty, the envelope is in aux ---
    let notes = |c: &Ctx, a: &str, l: &Ledger| scan_notes(l, &c.me, a, CHAIN, vec![]).0;
    let (notes_s, notes_b) = (notes(&cs, &dfabi, &l_dfabi), notes(&cb, &rd, &l_rd));
    assert_eq!((notes_s.len(), notes_b.len()), (1, 1));
    let d = dvp::build_leg(&cs, &dfabi, &notes_s, &l_dfabi, buyer, 4, &format!("dvp:{}", t.trade_id)).expect("prove delivery leg");
    let p = dvp::build_leg(&cb, &rd, &notes_b, &l_rd, seller, 3000, &format!("dvp:{}", t.trade_id)).expect("prove payment leg");
    eprintln!("dvp legs prove_ms: delivery={} payment={}", d.prove_ms, p.prove_ms);
    t.delivery_leg = Some(Leg::from_zk(seller, &d.zk));
    t.payment_leg = Some(Leg::from_zk(buyer, &p.zk));
    t.save(&path).unwrap();
    let mut t = Trade::load(&path).unwrap();
    assert_eq!(t.delivery_leg.as_ref().unwrap().to_zk().unwrap(), d.zk, "leg survives the file round trip");

    // --- before signing: each side checks what it will receive (proof, binding, envelope, amount) ---
    dvp::check_incoming(&t, &cs.me).expect("seller accepts the payment leg");
    dvp::check_incoming(&t, &cb.me).expect("buyer accepts the delivery leg");
    let mut short = t.clone();
    short.pay.amount = "3001".into();
    let e = dvp::check_incoming(&short, &cs.me).unwrap_err().to_string();
    assert!(e.contains("pays me 3000"), "{e}");
    let mut wrong_asset = t.clone();
    wrong_asset.deliver.asset = rd.clone();
    assert!(dvp::check_incoming(&wrong_asset, &cb.me).is_err());

    // --- both sign through the CLI code path; only each party's own key is used ---
    assert!(t.build().is_err(), "not signed yet");
    dvp::sign(&cs, &path).unwrap();
    assert!(dvp::sign(&cs, &path).is_err(), "no double signature");
    dvp::sign(&cb, &path).unwrap();
    t = Trade::load(&path).unwrap();
    assert_eq!(t.intents.len(), 2);

    // --- the intents verify over the spec 4b tuple, computed independently ---
    let digest = t.digest().unwrap();
    assert_eq!(digest, spec_digest(&t), "driver digest is the spec 4b tuple");
    for i in &t.intents {
        t.verify_intent(i).expect("intent verifies");
    }
    let ix = t.build().expect("both legs and intents present");
    assert_eq!(ix.kind, if award { DvpKind::Award } else { DvpKind::Interbank });
    assert_eq!(ix.award.is_some(), award);
    let dvp_digest = settlement_digest(CHAIN, &ix.trade_id, ix.expiry_height, &ix.delivery, &ix.payment).unwrap();
    assert_eq!(dvp_digest, digest);
    for i in &ix.intents {
        i.signature.verify(i.signer.try_signatory().unwrap(), &dvp_digest).expect("intent in the instruction verifies");
    }
    assert_eq!(
        ix.intents.iter().map(|i| i.signer.to_string()).collect::<Vec<_>>(),
        vec![acct_s.to_string(), acct_b.to_string()]
    );

    // --- a mutated leg (or id) breaks the digest and with it both intents ---
    let mut bad = t.clone();
    let l = bad.delivery_leg.as_mut().unwrap();
    let mut o = hex::decode(&l.outputs[0]).unwrap();
    o[0] ^= 1;
    l.outputs[0] = hex::encode(o);
    assert_ne!(bad.digest().unwrap(), digest);
    assert!(bad.intents.iter().all(|i| bad.verify_intent(i).is_err()));
    assert!(bad.build().is_err());
    let mut bad = t.clone();
    let l = bad.payment_leg.as_mut().unwrap();
    l.inputs[0] = hex::encode(k("other nullifier"));
    assert_ne!(bad.digest().unwrap(), digest);
    let mut bad = t.clone();
    bad.trade_id = hex::encode(k("other trade"));
    assert_ne!(bad.digest().unwrap(), digest);
    let mut bad = t.clone();
    bad.expiry_height += 1;
    assert_ne!(bad.digest().unwrap(), digest);
    let mut bad = t.clone();
    bad.chain = "other-chain".into();
    assert_ne!(bad.digest().unwrap(), digest);

    // --- the replayed chain: both legs appear as transfers; BI audit is clean, and the signers field is what lets the
    //     other party's leg pass the sender check; scan finds the counterparty's note ---
    let signers = [acct_s.to_string(), acct_b.to_string()];
    let auth = acct_s.to_string(); // the seller submits
    l_dfabi.push(leg_event(&ix.delivery, &auth, &signers));
    l_rd.push(leg_event(&ix.payment, &auth, &signers));
    for (ledger, supply) in [(&l_dfabi, "10"), (&l_rd, "5000")] {
        let rep = audit(&ledger.events, &w.audit);
        assert_eq!(rep["summary"]["violations"], 0, "{rep:#}");
        assert_eq!(rep["summary"]["supply_reconciles"], true, "{rep:#}");
        assert_eq!(rep["summary"]["shielded_outstanding"], supply);
    }
    let mut no_signers = l_rd.events.clone();
    no_signers[1].signers.clear();
    assert!(codes(&audit(&no_signers, &w.audit), 1).contains(&"sender_mismatch".to_owned()));
    let got_dfabi = scan_notes(&l_dfabi, &cb.me, &dfabi, CHAIN, vec![]).0;
    let got_rd = scan_notes(&l_rd, &cs.me, &rd, CHAIN, vec![]).0;
    assert_eq!((got_dfabi.len(), got_dfabi[0].amount()), (1, 4), "buyer holds 4 DFABI");
    assert_eq!((got_rd.len(), got_rd[0].amount()), (1, 3000), "seller holds 3000 RD");
    assert!(scan_notes(&l_dfabi, &cs.me, &dfabi, CHAIN, notes_s).0[0].spent, "seller's DFABI input is spent");
    assert!(scan_notes(&l_rd, &cb.me, &rd, CHAIN, notes_b).0[0].spent, "buyer's RD input is spent");
    let _ = std::fs::remove_dir_all(&w.dir);
}

#[test]
fn interbank_dvp_two_party_flow() {
    flow(false);
}

#[test]
fn award_dvp_bi_delivers_dfabi() {
    flow(true);
}
