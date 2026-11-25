//! Subcommand bodies. Each returns one JSON value; `main` prints it as `result_json=<json>`.

use std::{fs, path::Path, time::Instant};

use eyre::{Result, eyre};
use iroha_data_model::{
    asset::AssetId,
    confidential::ConfidentialEncryptedPayload,
    isi::{
        InstructionBox, Mint,
        zk::{Shield, Unshield, ZkTransfer},
    },
    metadata::Metadata,
    proof::{ProofAttachment, ProofBox, VerifyingKeyId},
};
use iroha_primitives::numeric::Numeric;
use serde_json::{Value, json};

use crate::{
    audit,
    chain::{self, Net},
    envelope::{BindingCtx, Bytes32, Envelope},
    proto::{self, Address, BuiltTransfer, OutSpec},
    wallet::{self, Me, NoteRec, Parties},
};

pub struct Ctx {
    pub torii: String,
    pub chain: String,
    pub parties: Parties,
    pub me: Me,
}

impl Ctx {
    pub fn net(&self) -> Result<Net> {
        chain::connect(&self.torii, &self.chain, &self.me)
    }
    pub fn own_account(&self) -> Result<String> {
        Ok(chain::own_account(&self.me)?.to_string())
    }
}

pub fn recipient_address(c: &Ctx, to: &str, tag: Option<&str>, div: Option<&str>) -> Result<Address> {
    match (tag, div) {
        (Some(t), Some(d)) => Ok(Address { owner_tag: wallet::h32(t)?, diversifier: wallet::h32(d)? }),
        (None, None) => c.parties.address(to),
        _ => Err(eyre!("pass both --to-owner-tag and --to-diversifier, or neither")),
    }
}

pub fn attachment(proof: ProofBox, vk_name: &str) -> ProofAttachment {
    ProofAttachment::new_ref("halo2/ipa".into(), proof, VerifyingKeyId::new("halo2/ipa", vk_name))
}

// ----- keygen / address ------------------------------------------------------------------------

/// Write a party wallet dir (spec 1 layout) with fresh keys. Public halves are returned for parties.json.
pub fn keygen(dir: &Path, party: &str, audit_key: bool) -> Result<Value> {
    use iroha_crypto::{ExposedPrivateKey, KeyPair};
    use rand_core_06::{OsRng, RngCore};
    fs::create_dir_all(dir)?;
    let kp = KeyPair::random();
    let account = iroha_data_model::account::AccountId::of(kp.public_key().clone());
    let w = |name: &str, v: String| -> Result<()> {
        let p = dir.join(name);
        fs::write(&p, v)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    };
    w(
        "account.json",
        serde_json::to_string_pretty(&json!({
            "public_key": kp.public_key().to_string(),
            "private_key": ExposedPrivateKey(kp.private_key().clone()).to_string(),
        }))?,
    )?;
    let mut view_sk = [0u8; 32];
    OsRng.fill_bytes(&mut view_sk);
    let view_pk = crate::envelope::public_from_secret(&view_sk);
    w("view.json", serde_json::to_string_pretty(&json!({"public": hex::encode(view_pk), "secret": hex::encode(view_sk)}))?)?;
    let spend = proto::rand32();
    w("spend.key", hex::encode(spend))?;
    let addr = proto::address_of(&spend);
    let mut out = json!({
        "party": party,
        "account_id": account.to_string(),
        "view_pk": hex::encode(view_pk),
        "address": {"owner_tag": hex::encode(addr.owner_tag), "diversifier": hex::encode(addr.diversifier)},
    });
    if audit_key {
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        let pk = crate::envelope::public_from_secret(&sk);
        w("audit-v1.json", serde_json::to_string_pretty(&json!({"public": hex::encode(pk), "secret": hex::encode(sk)}))?)?;
        out["bi_audit"] = json!([{"version": 1, "pk": hex::encode(pk), "activation_height": 1, "retire_height": null}]);
    }
    Ok(out)
}

pub fn address(me: &Me) -> Value {
    let a = me.address();
    json!({"address": {"owner_tag": hex::encode(a.owner_tag), "diversifier": hex::encode(a.diversifier)}})
}

// ----- issue (BI: mint + shield) ----------------------------------------------------------------

pub fn issue(c: &Ctx, asset: &str, to: &str, amount: u128, reference: &str, tag: Option<&str>, div: Option<&str>) -> Result<Value> {
    let asset = c.parties.asset(asset);
    let def = chain::asset_def(&asset)?;
    let addr = recipient_address(c, to, tag, div)?;
    let rho = proto::rand32();
    let commitment = proto::commitment(&asset, amount, rho, addr.owner_tag)?;
    let note = proto::NoteOut {
        amount,
        rho,
        diversifier: addr.diversifier,
        owner_tag: addr.owner_tag,
        owner: c.parties.account_id(to)?,
        commitment,
    };
    let me_acct = c.own_account()?;
    let pt = proto::plaintext("shield", &asset, &me_acct, reference, &[], std::slice::from_ref(&note), Some(amount));
    let outs = [commitment];
    let ctx = BindingCtx { asset: &asset, inputs: &[], outputs: &outs, public_amount: amount };
    let (ver, bi_pk) = c.parties.audit_key()?;
    // Spec 3.3 says `rc` is the sender's own view key for Shield; for an issue into a bank's tag the bank is the
    // one who must learn the note, so `rc` is the bank's view key (no wire change). See README.
    let env = proto::make_envelope(&pt, &ctx, ver, bi_pk, c.parties.view_pk(to)?)?;
    let me = chain::own_account(&c.me)?;
    let net = c.net()?;
    let instrs: Vec<InstructionBox> = vec![
        Mint::asset_numeric(Numeric::new(amount, 0), AssetId::new(def.clone(), me.clone())).into(),
        Shield::new(def, me, amount, commitment, ConfidentialEncryptedPayload::default()).into(),
    ];
    let tx = chain::submit(&net, instrs, chain::envelope_metadata(&env.encode()))?;
    Ok(json!({"cmd": "issue", "asset": asset, "to": to, "amount": amount.to_string(), "commitment": hex::encode(commitment), "tx": tx}))
}

// ----- scan -------------------------------------------------------------------------------------

pub fn synced(c: &Ctx, net: &Net, asset: &str) -> Result<(crate::events::Ledger, Vec<NoteRec>, Vec<Value>, Option<(bool, String, String)>)> {
    let (ledger, root) = chain::sync(net, asset)?;
    let existing = wallet::load_notes(&c.me.notes_path());
    let (notes, anomalies) = wallet::scan_notes(&ledger, &c.me, asset, &c.chain, existing.clone());
    // notes.json holds every asset (RD and DFABI): rewrite only this asset's notes
    let mut all: Vec<NoteRec> = existing.into_iter().filter(|n| n.asset != asset).collect();
    all.extend(notes.iter().cloned());
    wallet::save_notes(&c.me.notes_path(), &all)?;
    Ok((ledger, notes, anomalies, root))
}

pub fn scan(c: &Ctx, asset: &str) -> Result<Value> {
    let asset = c.parties.asset(asset);
    let net = c.net()?;
    let (ledger, notes, anomalies, root) = synced(c, &net, &asset)?;
    let spendable: u128 = notes.iter().filter(|n| !n.spent && n.leaf_index.is_some()).map(NoteRec::amount).sum();
    let vk = json!({
        "transfer": chain::vk_registered(&net, "vk_transfer", &proto::transfer_vk()?),
        "unshield": chain::vk_registered(&net, "vk_unshield", &proto::unshield_vk()?),
    });
    Ok(json!({
        "cmd": "scan", "asset": asset, "party": c.me.party,
        "blocks_events": ledger.events.len(), "leaves": ledger.leaves.len(),
        "root_ok": root.as_ref().map(|r| r.0), "root_local": root.as_ref().map(|r| r.1.clone()), "root_node": root.as_ref().map(|r| r.2.clone()),
        "vk_registered_matches_local": vk,
        "notes": notes.len(), "spendable_notes": notes.iter().filter(|n| !n.spent && n.leaf_index.is_some()).count(),
        "spendable_amount": spendable.to_string(), "anomalies": anomalies,
    }))
}

// ----- transfer ---------------------------------------------------------------------------------

pub fn unspent(notes: &[NoteRec]) -> Vec<NoteRec> {
    notes.iter().filter(|n| !n.spent && n.leaf_index.is_some()).cloned().collect()
}

/// A `ZkTransfer` over `b`; `aux` (the envelope) goes into the proof's `OpenVerifyEnvelope.aux`.
pub fn zk_leg(asset: &str, b: &BuiltTransfer, aux: Option<&[u8]>, root: Bytes32, inputs: Vec<Bytes32>) -> Result<ZkTransfer> {
    let mut proof = b.proof.clone();
    if let Some(a) = aux {
        proto::set_aux(&mut proof, a)?;
    }
    Ok(ZkTransfer::new(chain::asset_def(asset)?, inputs, b.outputs.clone(), attachment(proof, "vk_transfer"), Some(root)))
}

fn zk_transfer(asset: &str, b: &BuiltTransfer, aux: Option<&[u8]>, root: Bytes32, inputs: Vec<Bytes32>) -> Result<InstructionBox> {
    Ok(zk_leg(asset, b, aux, root, inputs)?.into())
}

pub struct Prepared {
    pub built: BuiltTransfer,
    pub inputs: Vec<NoteRec>,
    pub prove_ms: u128,
}

pub fn prepare_transfer(c: &Ctx, asset: &str, notes: &[NoteRec], ledger: &crate::events::Ledger, to: &str, addr: Address, amount: u128) -> Result<Prepared> {
    let pool = unspent(notes);
    let idx = proto::select(&pool, NoteRec::amount, amount).ok_or_else(|| eyre!("not enough spendable notes for {amount} (max 2 inputs)"))?;
    let inputs: Vec<NoteRec> = idx.iter().map(|i| pool[*i].clone()).collect();
    let total: u128 = inputs.iter().map(NoteRec::amount).sum();
    let mut outs = vec![OutSpec { amount, addr, owner: c.parties.account_id(to)? }];
    if total > amount {
        outs.push(OutSpec { amount: total - amount, addr: c.me.address(), owner: c.own_account()? });
    }
    let ins = inputs.iter().map(NoteRec::in_note).collect::<Result<Vec<_>>>()?;
    let t = Instant::now();
    let built = proto::build_transfer(&c.chain, asset, &c.me.spend_key, &ledger.leaves, &ins, &outs)?;
    Ok(Prepared { built, inputs, prove_ms: t.elapsed().as_millis() })
}

pub fn seal_transfer(c: &Ctx, asset: &str, b: &BuiltTransfer, to: &str, reference: &str) -> Result<Envelope> {
    let pt = proto::plaintext("transfer", asset, &c.own_account()?, reference, &b.nullifiers, &b.notes, None);
    let ctx = BindingCtx { asset, inputs: &b.nullifiers, outputs: &b.outputs, public_amount: 0 };
    let (ver, bi_pk) = c.parties.audit_key()?;
    proto::make_envelope(&pt, &ctx, ver, bi_pk, c.parties.view_pk(to)?)
}

pub fn transfer(c: &Ctx, asset: &str, to: &str, amount: u128, reference: &str, tag: Option<&str>, div: Option<&str>) -> Result<Value> {
    let asset = c.parties.asset(asset);
    let addr = recipient_address(c, to, tag, div)?;
    let net = c.net()?;
    let (ledger, notes, _, root) = synced(c, &net, &asset)?;
    if root.as_ref().is_some_and(|r| !r.0) {
        return Err(eyre!("replayed leaf list does not match the node root; refusing to prove"));
    }
    let p = prepare_transfer(c, &asset, &notes, &ledger, to, addr, amount)?;
    let env = seal_transfer(c, &asset, &p.built, to, reference)?;
    let instr = zk_transfer(&asset, &p.built, Some(&env.encode()), p.built.root, p.built.nullifiers.clone())?;
    let tx = chain::submit(&net, vec![instr], Metadata::default())?;
    // mark inputs spent, remember the change note (own change is not recoverable from the chain)
    let mut all = wallet::load_notes(&c.me.notes_path());
    for n in &mut all {
        if p.inputs.iter().any(|i| i.commitment == n.commitment) {
            n.spent = true;
        }
    }
    let me_acct = c.own_account()?;
    for n in p.built.notes.iter().filter(|n| n.owner == me_acct) {
        all.push(wallet::note_rec(&asset, &c.chain, &c.me.spend_key, n, &tx));
    }
    wallet::save_notes(&c.me.notes_path(), &all)?;
    Ok(json!({
        "cmd": "transfer", "asset": asset, "to": to, "amount": amount.to_string(), "tx": tx, "prove_ms": p.prove_ms.to_string(),
        "inputs": p.built.nullifiers.iter().map(hex::encode).collect::<Vec<_>>(),
        "outputs": p.built.outputs.iter().map(hex::encode).collect::<Vec<_>>(),
        "root": hex::encode(p.built.root), "proof_bytes": p.built.proof.bytes.len(),
    }))
}

// ----- unshield ---------------------------------------------------------------------------------

pub fn unshield(c: &Ctx, asset: &str, amount: u128, to: Option<&str>, reference: &str) -> Result<Value> {
    let asset = c.parties.asset(asset);
    let net = c.net()?;
    let (ledger, notes, _, root) = synced(c, &net, &asset)?;
    if root.as_ref().is_some_and(|r| !r.0) {
        return Err(eyre!("replayed leaf list does not match the node root; refusing to prove"));
    }
    let pool = unspent(&notes);
    let idx = proto::select_exact(&pool, NoteRec::amount, amount)
        .ok_or_else(|| eyre!("unshield v2 exits whole notes: no 1-2 spendable notes sum to exactly {amount}"))?;
    let inputs: Vec<NoteRec> = idx.iter().map(|i| pool[*i].clone()).collect();
    let ins = inputs.iter().map(NoteRec::in_note).collect::<Result<Vec<_>>>()?;
    let t = Instant::now();
    let b = proto::build_unshield(&c.chain, &asset, &c.me.spend_key, &ledger.leaves, &ins)?;
    let prove_ms = t.elapsed().as_millis();
    let pt = proto::plaintext("unshield", &asset, &c.own_account()?, reference, &b.nullifiers, &[], Some(amount));
    let ctx = BindingCtx { asset: &asset, inputs: &b.nullifiers, outputs: &[], public_amount: amount };
    let (ver, bi_pk) = c.parties.audit_key()?;
    let env = proto::make_envelope(&pt, &ctx, ver, bi_pk, c.me.view_pk)?;
    let mut proof = b.proof.clone();
    proto::set_aux(&mut proof, &env.encode())?;
    let to_acct = match to {
        Some(p) => iroha_data_model::account::AccountId::parse_encoded(&c.parties.account_id(p)?)
            .map_err(|e| eyre!("account id of {p}: {e:?}"))?
            .into_account_id(),
        None => chain::own_account(&c.me)?,
    };
    let instr: InstructionBox =
        Unshield::new(chain::asset_def(&asset)?, to_acct, amount, b.nullifiers.clone(), attachment(proof, "vk_unshield"), Some(b.root)).into();
    let tx = chain::submit(&net, vec![instr], Metadata::default())?;
    let mut all = wallet::load_notes(&c.me.notes_path());
    for n in &mut all {
        if inputs.iter().any(|i| i.commitment == n.commitment) {
            n.spent = true;
        }
    }
    wallet::save_notes(&c.me.notes_path(), &all)?;
    Ok(json!({"cmd": "unshield", "asset": asset, "amount": amount.to_string(), "to": to, "tx": tx, "prove_ms": prove_ms.to_string(),
        "inputs": b.nullifiers.iter().map(hex::encode).collect::<Vec<_>>()}))
}

// ----- audit ------------------------------------------------------------------------------------

pub fn audit_cmd(c: &Ctx, assets: &[String], key_dir: &Path) -> Result<Value> {
    let keys = wallet::load_audit_keys(key_dir)?;
    let net = c.net()?;
    let mut out = vec![];
    for a in assets {
        let asset = c.parties.asset(a);
        let (ledger, root) = chain::sync(&net, &asset)?;
        let mut rep = audit::audit(&ledger.events, &keys);
        rep["asset"] = json!(asset);
        rep["root_ok"] = json!(root.map(|r| r.0));
        out.push(rep);
    }
    let violations: u64 = out.iter().map(|r| r["summary"]["violations"].as_u64().unwrap_or(0)).sum();
    Ok(json!({"cmd": "audit", "detected_violations": violations, "assets": out}))
}

// ----- negative ---------------------------------------------------------------------------------

fn case(name: &str, expect_hint: &str, must_contain: Option<&str>, r: Result<String>) -> Value {
    let (got, err) = match &r {
        Ok(tx) => ("accepted", tx.clone()),
        Err(e) => ("rejected", format!("{e:#}")),
    };
    let pass = got == "rejected" && must_contain.is_none_or(|m| err.contains(m));
    json!({"case": name, "expected": "rejected", "expected_reason": expect_hint, "got": got, "detail": err, "pass": pass})
}

/// TC-CRYP and P2 attacks. One valid proof is built and mutated, so only one proving run is needed
/// (plus one more if a spent note exists for the replay case). NOTE: on a node without P2 the envelope cases are
/// accepted and consume the base note: they run last.
pub fn negative(c: &Ctx, asset: &str, other_asset: &str, to: &str, amount: u128, tag: Option<&str>, div: Option<&str>) -> Result<Value> {
    let asset = c.parties.asset(asset);
    let other = c.parties.asset(other_asset);
    let addr = recipient_address(c, to, tag, div)?;
    let net = c.net()?;
    let (ledger, notes, _, _) = synced(c, &net, &asset)?;
    let p = prepare_transfer(c, &asset, &notes, &ledger, to, addr, amount)?;
    let b = &p.built;
    let env = seal_transfer(c, &asset, b, to, "negative")?.encode();
    let sub = |i: InstructionBox| chain::submit(&net, vec![i], Metadata::default());
    let mut cases = vec![];

    // TC-CRYP-04: same nullifier twice in one transaction
    let dup = vec![b.nullifiers[0], b.nullifiers[0]];
    cases.push(case("duplicate_nullifier", "duplicate nullifier / public input mismatch", None, zk_transfer(&asset, b, Some(&env), b.root, dup).and_then(&sub)));

    // TC-CRYP-05: replay of a spent nullifier (needs a spent note in the wallet)
    let spent: Vec<NoteRec> = notes.iter().filter(|n| n.spent && n.leaf_index.is_some()).cloned().collect();
    if let Some(sn) = spent.first() {
        let r = (|| -> Result<String> {
            let out = [OutSpec { amount: sn.amount(), addr, owner: c.parties.account_id(to)? }];
            let built = proto::build_transfer(&c.chain, &asset, &c.me.spend_key, &ledger.leaves, &[sn.in_note()?], &out)?;
            let e = seal_transfer(c, &asset, &built, to, "negative-replay")?.encode();
            sub(zk_transfer(&asset, &built, Some(&e), built.root, built.nullifiers.clone())?)
        })();
        cases.push(case("replayed_nullifier", "nullifier already spent", None, r));
    } else {
        cases.push(json!({"case": "replayed_nullifier", "skipped": "no spent note in notes.json (run a transfer first)"}));
    }

    // TC-CRYP-06: unknown root
    let bad_root = proto::rand32();
    cases.push(case("wrong_root", "stale or unknown Merkle root", None, zk_transfer(&asset, b, Some(&env), bad_root, b.nullifiers.clone()).and_then(&sub)));

    // TC-CRYP-09: tampered proof bytes
    let r = (|| -> Result<String> {
        let mut t = BuiltTransfer { nullifiers: b.nullifiers.clone(), outputs: b.outputs.clone(), notes: vec![], root: b.root, proof: b.proof.clone() };
        proto::tamper_proof(&mut t.proof)?;
        sub(zk_transfer(&asset, &t, Some(&env), b.root, b.nullifiers.clone())?)
    })();
    cases.push(case("tampered_proof", "invalid transfer proof", None, r));

    // TC-CRYP-06: proof for `asset` submitted on `other` (asset tag mismatch); envelope sealed for `other` so P2 passes
    let r = (|| -> Result<String> {
        let pt = proto::plaintext("transfer", &other, &c.own_account()?, "negative-asset", &b.nullifiers, &b.notes, None);
        let ctx = BindingCtx { asset: &other, inputs: &b.nullifiers, outputs: &b.outputs, public_amount: 0 };
        let (ver, bi_pk) = c.parties.audit_key()?;
        let e = proto::make_envelope(&pt, &ctx, ver, bi_pk, c.parties.view_pk(to)?)?.encode();
        sub(zk_transfer(&other, b, Some(&e), b.root, b.nullifiers.clone())?)
    })();
    cases.push(case("wrong_asset_tag", "asset tag mismatch", None, r));

    // P2 (TC-AUD-02): valid transfer without envelope
    cases.push(case("envelope_missing", "rd-disclosure: envelope missing", Some("rd-disclosure"), zk_transfer(&asset, b, None, b.root, b.nullifiers.clone()).and_then(&sub)));

    // P2 (TC-AUD-05 family): envelope bound to different outputs
    let r = (|| -> Result<String> {
        let mut other_outs = b.outputs.clone();
        other_outs[0] = proto::rand32();
        let pt = proto::plaintext("transfer", &asset, &c.own_account()?, "negative-binding", &b.nullifiers, &b.notes, None);
        let ctx = BindingCtx { asset: &asset, inputs: &b.nullifiers, outputs: &other_outs, public_amount: 0 };
        let (ver, bi_pk) = c.parties.audit_key()?;
        let e = proto::make_envelope(&pt, &ctx, ver, bi_pk, c.parties.view_pk(to)?)?.encode();
        sub(zk_transfer(&asset, b, Some(&e), b.root, b.nullifiers.clone())?)
    })();
    cases.push(case("binding_mismatch", "rd-disclosure: binding mismatch", Some("rd-disclosure"), r));

    let passed = cases.iter().filter(|x| x["pass"] == json!(true)).count();
    let failed = cases.iter().filter(|x| x["pass"] == json!(false)).count();
    Ok(json!({"cmd": "negative", "asset": asset, "other_asset": other, "prove_ms": p.prove_ms.to_string(), "passed": passed, "failed": failed, "cases": cases}))
}
