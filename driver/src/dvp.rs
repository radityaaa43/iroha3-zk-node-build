//! `ConfidentialDvp` driver (fork patch P3, spec 4b): a two-party, file-based flow. Each party only ever uses its own
//! keys: it proves its own leg, signs the settlement digest with its account key, and one of the two submits.
//! The digests come straight from `iroha_core::rd_dvp` (the node's own code), nothing is re-implemented here.
//!
//! `propose` -> (`leg` by each party) -> (`sign` by each party) -> `submit` by either party; all steps edit `trade.json`.

use std::{fs, path::Path, time::Instant};

use eyre::{Result, WrapErr, eyre};
use iroha_core::{
    rd_dvp::{award_digest, settlement_digest},
    zk::{ZK_BACKEND_HALO2_IPA, verify_backend},
};
use iroha_crypto::{ExposedPrivateKey, Signature};
use iroha_data_model::{
    account::AccountId,
    isi::{
        InstructionBox,
        zk::{ConfidentialDvp, DvpIntent, DvpKind, SignedAward, ZkTransfer},
    },
    metadata::Metadata,
    proof::ProofBox,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    chain,
    cmd::{self, Ctx},
    envelope::{BindingCtx, Bytes32, Envelope},
    proto::{self, NoteOut},
    wallet::{self, Me, NoteRec, h32},
};

// ----- file formats ---------------------------------------------------------------------------------

/// `trade.json`. Everything the two parties exchange: no secrets (the legs are public instruction data; amounts and
/// notes stay inside the proofs and the envelopes).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Trade {
    pub v: u32,
    /// 32 bytes hex, single use on chain.
    pub trade_id: String,
    /// `interbank` (UC-06) or `award` (UC-03).
    pub kind: String,
    /// Chain id: part of the signed digest.
    pub chain: String,
    pub expiry_height: u64,
    /// Party names of parties.json. The seller delivers DFABI and is paid in RD, the buyer the other way round.
    pub seller: String,
    pub buyer: String,
    pub deliver: Side,
    pub pay: Side,
    /// Required for `award`: the BI-signed record from `rd2 award sign`.
    pub award: Option<AwardFile>,
    /// Built by the seller (`rd2 dvp leg`).
    pub delivery_leg: Option<Leg>,
    /// Built by the buyer.
    pub payment_leg: Option<Leg>,
    pub intents: Vec<IntentRec>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Side {
    /// `AssetDefinitionId` string.
    pub asset: String,
    /// Agreed amount (decimal). Both parties only know it from this file and from the envelope of the other's leg.
    pub amount: String,
}

/// A `ZkTransfer` as stored in `trade.json`. The proof bytes already carry the BI envelope in `aux`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Leg {
    /// Party that proved it.
    pub by: String,
    pub asset: String,
    /// Nullifiers (hex).
    pub inputs: Vec<String>,
    /// Output commitments in proof order (hex).
    pub outputs: Vec<String>,
    pub root: Option<String>,
    /// Hex of `ProofBox.bytes` (`OpenVerifyEnvelope`, aux = `RdEnvelopeV1`).
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentRec {
    pub party: String,
    /// Signing account id (display form).
    pub signer: String,
    /// Hex of `Signature::payload()` over the settlement digest.
    pub signature: String,
}

/// `award.json`: a `SignedAward` in readable form (`rd2 award sign`, BI only).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AwardFile {
    pub v: u32,
    pub chain: String,
    pub award_id: String,
    pub winner_party: String,
    pub winner: String,
    pub instrument: String,
    pub quantity: String,
    pub consideration: String,
    pub expiry_height: u64,
    pub bi_signature: String,
}

pub fn account(s: &str) -> Result<AccountId> {
    Ok(AccountId::parse_encoded(s).map_err(|e| eyre!("account id {s}: {e:?}"))?.into_account_id())
}

fn private_key(me: &Me) -> Result<iroha_crypto::PrivateKey> {
    Ok(me.private_key.parse::<ExposedPrivateKey>().map_err(|e| eyre!("account.json private_key: {e:?}"))?.0)
}

fn sig(hex_sig: &str) -> Result<Signature> {
    Ok(Signature::from_bytes(&hex::decode(hex_sig).wrap_err("signature hex")?))
}

impl AwardFile {
    pub fn to_signed(&self) -> Result<SignedAward> {
        Ok(SignedAward {
            award_id: h32(&self.award_id)?,
            winner: account(&self.winner)?,
            instrument: chain::asset_def(&self.instrument)?,
            quantity: self.quantity.parse().wrap_err("quantity")?,
            consideration: self.consideration.parse().wrap_err("consideration")?,
            expiry_height: self.expiry_height,
            bi_signature: sig(&self.bi_signature)?,
        })
    }
}

impl Leg {
    pub fn from_zk(by: &str, z: &ZkTransfer) -> Self {
        Self {
            by: by.to_owned(),
            asset: z.asset.to_string(),
            inputs: z.inputs.iter().map(hex::encode).collect(),
            outputs: z.outputs.iter().map(hex::encode).collect(),
            root: z.root_hint.map(hex::encode),
            proof: hex::encode(&z.proof.proof.bytes),
        }
    }

    pub fn proof_box(&self) -> Result<ProofBox> {
        Ok(ProofBox::new("halo2/ipa".into(), hex::decode(&self.proof).wrap_err("leg proof hex")?))
    }

    pub fn to_zk(&self) -> Result<ZkTransfer> {
        Ok(ZkTransfer::new(
            chain::asset_def(&self.asset)?,
            self.inputs.iter().map(|x| h32(x)).collect::<Result<Vec<Bytes32>>>()?,
            self.outputs.iter().map(|x| h32(x)).collect::<Result<Vec<Bytes32>>>()?,
            cmd::attachment(self.proof_box()?, "vk_transfer"),
            self.root.as_deref().map(h32).transpose()?,
        ))
    }
}

impl Trade {
    pub fn load(p: &Path) -> Result<Self> {
        serde_json::from_slice(&fs::read(p).wrap_err_with(|| format!("read {}", p.display()))?)
            .wrap_err_with(|| format!("parse {}", p.display()))
    }

    pub fn save(&self, p: &Path) -> Result<()> {
        fs::write(p, serde_json::to_vec_pretty(self)?).wrap_err_with(|| format!("write {}", p.display()))
    }

    fn legs(&self) -> Result<(ZkTransfer, ZkTransfer)> {
        let d = self.delivery_leg.as_ref().ok_or_else(|| eyre!("the delivery leg (seller {}) is not built yet", self.seller))?;
        let p = self.payment_leg.as_ref().ok_or_else(|| eyre!("the payment leg (buyer {}) is not built yet", self.buyer))?;
        Ok((d.to_zk()?, p.to_zk()?))
    }

    /// The 32 bytes both parties sign (spec 4b): `iroha_core::rd_dvp::settlement_digest`.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let (d, p) = self.legs()?;
        settlement_digest(&self.chain, &h32(&self.trade_id)?, self.expiry_height, &d, &p).map_err(proto::s)
    }

    pub fn dvp_kind(&self) -> Result<DvpKind> {
        match self.kind.as_str() {
            "interbank" => Ok(DvpKind::Interbank),
            "award" => Ok(DvpKind::Award),
            k => Err(eyre!("unknown kind {k}")),
        }
    }

    /// Check one intent against the digest (what the node does).
    pub fn verify_intent(&self, i: &IntentRec) -> Result<()> {
        let digest = self.digest()?;
        let who = account(&i.signer)?;
        let key = who.try_signatory().ok_or_else(|| eyre!("{} is not a single-key account", i.signer))?;
        sig(&i.signature)?.verify(key, &digest).map_err(|_| eyre!("intent of {} does not verify over the settlement digest", i.party))
    }

    /// Assemble the instruction. Needs both legs and both intents (seller first, then buyer).
    pub fn build(&self) -> Result<ConfidentialDvp> {
        let (d, p) = self.legs()?;
        let intent = |party: &str| -> Result<DvpIntent> {
            let i = self.intents.iter().find(|i| i.party == party).ok_or_else(|| eyre!("{party} has not signed"))?;
            self.verify_intent(i)?;
            Ok(DvpIntent { signer: account(&i.signer)?, signature: sig(&i.signature)? })
        };
        let award = self.award.as_ref().map(AwardFile::to_signed).transpose()?;
        Ok(ConfidentialDvp::new(
            h32(&self.trade_id)?,
            d,
            p,
            self.expiry_height,
            [intent(&self.seller)?, intent(&self.buyer)?],
            self.dvp_kind()?,
            award,
        ))
    }
}

// ----- award sign (BI) --------------------------------------------------------------------------------

pub struct AwardArgs<'a> {
    pub award_id: Bytes32,
    pub winner: &'a str,
    pub instrument: &'a str,
    pub quantity: u128,
    pub consideration: u128,
    pub expiry_height: u64,
}

/// Sign the award record with the account key of the wallet (must be the owner of domain `rd`: `bi`).
pub fn award_sign(c: &Ctx, a: &AwardArgs<'_>) -> Result<AwardFile> {
    let mut s = SignedAward {
        award_id: a.award_id,
        winner: account(&c.parties.account_id(a.winner)?)?,
        instrument: chain::asset_def(&c.parties.asset(a.instrument))?,
        quantity: a.quantity,
        consideration: a.consideration,
        expiry_height: a.expiry_height,
        bi_signature: Signature::from_bytes(&[]),
    };
    let digest = award_digest(&c.chain, &s).map_err(proto::s)?;
    s.bi_signature = Signature::new(&private_key(&c.me)?, &digest);
    Ok(AwardFile {
        v: 1,
        chain: c.chain.clone(),
        award_id: hex::encode(s.award_id),
        winner_party: a.winner.to_owned(),
        winner: s.winner.to_string(),
        instrument: s.instrument.to_string(),
        quantity: s.quantity.to_string(),
        consideration: s.consideration.to_string(),
        expiry_height: s.expiry_height,
        bi_signature: hex::encode(s.bi_signature.payload()),
    })
}

/// Does the award signature verify under `bi_key` (the account that owns domain `rd`)?
pub fn verify_award(a: &AwardFile, bi_account: &str) -> Result<()> {
    let digest = award_digest(&a.chain, &a.to_signed()?).map_err(proto::s)?;
    let who = account(bi_account)?;
    let key = who.try_signatory().ok_or_else(|| eyre!("{bi_account} is not a single-key account"))?;
    sig(&a.bi_signature)?.verify(key, &digest).map_err(|_| eyre!("award signature does not verify"))
}

// ----- propose ------------------------------------------------------------------------------------------

pub struct ProposeArgs<'a> {
    pub trade_id: &'a str,
    pub deliver_asset: &'a str,
    pub deliver_amount: u128,
    pub pay_asset: &'a str,
    pub pay_amount: u128,
    pub seller: &'a str,
    pub buyer: &'a str,
    pub expiry_height: u64,
    /// `interbank` or `award`; `None` = `award` if `award` is given, else `interbank`.
    pub kind: Option<&'a str>,
    pub award: Option<AwardFile>,
}

pub fn propose(c: &Ctx, a: &ProposeArgs<'_>) -> Result<Trade> {
    let kind = a.kind.unwrap_or(if a.award.is_some() { "award" } else { "interbank" });
    let deliver = c.parties.asset(a.deliver_asset);
    let pay = c.parties.asset(a.pay_asset);
    if deliver == pay {
        return Err(eyre!("delivery and payment must be different assets"));
    }
    if a.seller == a.buyer {
        return Err(eyre!("seller and buyer must be different parties"));
    }
    c.parties.account_id(a.seller)?;
    c.parties.account_id(a.buyer)?;
    match (kind, &a.award) {
        ("interbank", None) => {}
        ("interbank", Some(_)) => return Err(eyre!("an interbank trade carries no award")),
        ("award", None) => return Err(eyre!("an award trade needs --award <award.json> (rd2 award sign)")),
        ("award", Some(w)) => {
            if w.chain != c.chain {
                return Err(eyre!("award was signed for chain {}, not {}", w.chain, c.chain));
            }
            if w.instrument != deliver {
                return Err(eyre!("award instrument {} is not the delivery asset {deliver}", w.instrument));
            }
            if ![a.seller, a.buyer].contains(&w.winner_party.as_str()) || ![a.seller, a.buyer].contains(&"bi") {
                return Err(eyre!("an award trade is between bi and the winner {}", w.winner_party));
            }
        }
        (k, _) => return Err(eyre!("unknown kind {k} (interbank|award)")),
    }
    let trade_id = if a.trade_id == "auto" { proto::rand32() } else { h32(a.trade_id)? };
    Ok(Trade {
        v: 1,
        trade_id: hex::encode(trade_id),
        kind: kind.to_owned(),
        chain: c.chain.clone(),
        expiry_height: a.expiry_height,
        seller: a.seller.to_owned(),
        buyer: a.buyer.to_owned(),
        deliver: Side { asset: deliver, amount: a.deliver_amount.to_string() },
        pay: Side { asset: pay, amount: a.pay_amount.to_string() },
        award: a.award.clone(),
        delivery_leg: None,
        payment_leg: None,
        intents: vec![],
    })
}

// ----- leg ---------------------------------------------------------------------------------------------

/// Which leg `party` proves: the seller the delivery, the buyer the payment. Returns (my side, counterparty).
fn role<'a>(t: &'a Trade, party: &str) -> Result<(&'a Side, &'a str, bool)> {
    if party == t.seller {
        Ok((&t.deliver, t.buyer.as_str(), true))
    } else if party == t.buyer {
        Ok((&t.pay, t.seller.as_str(), false))
    } else {
        Err(eyre!("{party} is neither the seller ({}) nor the buyer ({}) of this trade", t.seller, t.buyer))
    }
}

pub struct BuiltLeg {
    pub zk: ZkTransfer,
    /// Output notes of the leg (the counterparty's, and my change if any).
    pub notes: Vec<NoteOut>,
    pub inputs: Vec<NoteRec>,
    pub prove_ms: u128,
}

/// Prove my leg: input notes of mine, recipient output to the counterparty (+ change to me), BI/recipient envelope
/// in `aux`. No network: `ledger` is the replayed leaf list of the leg's asset.
pub fn build_leg(c: &Ctx, asset: &str, notes: &[NoteRec], ledger: &crate::events::Ledger, to: &str, amount: u128, reference: &str) -> Result<BuiltLeg> {
    let addr = c.parties.address(to)?;
    let p = cmd::prepare_transfer(c, asset, notes, ledger, to, addr, amount)?;
    let env = cmd::seal_transfer(c, asset, &p.built, to, reference)?;
    let zk = cmd::zk_leg(asset, &p.built, Some(&env.encode()), p.built.root, p.built.nullifiers.clone())?;
    Ok(BuiltLeg { zk, notes: p.built.notes, inputs: p.inputs, prove_ms: p.prove_ms })
}

pub fn leg(c: &Ctx, trade_path: &Path) -> Result<Value> {
    let mut t = Trade::load(trade_path)?;
    if t.chain != c.chain {
        return Err(eyre!("trade is for chain {}, not {}", t.chain, c.chain));
    }
    let (side, to, is_delivery) = role(&t, &c.me.party)?;
    let (side, to) = (side.clone(), to.to_owned());
    if (if is_delivery { &t.delivery_leg } else { &t.payment_leg }).is_some() {
        return Err(eyre!("my leg is already in the trade file (rebuilding would spend other notes)"));
    }
    let amount: u128 = side.amount.parse().wrap_err("amount")?;
    let net = c.net()?;
    let (ledger, notes, _, root) = cmd::synced(c, &net, &side.asset)?;
    if root.as_ref().is_some_and(|r| !r.0) {
        return Err(eyre!("replayed leaf list does not match the node root; refusing to prove"));
    }
    let b = build_leg(c, &side.asset, &notes, &ledger, &to, amount, &format!("dvp:{}", t.trade_id))?;
    // own change is not recoverable from the chain: keep it now; `scan` binds it to its leaf after the DvP commits
    let me_acct = c.own_account()?;
    let mut all = wallet::load_notes(&c.me.notes_path());
    for n in b.notes.iter().filter(|n| n.owner == me_acct) {
        all.push(wallet::note_rec(&side.asset, &c.chain, &c.me.spend_key, n, &format!("dvp-pending:{}", t.trade_id)));
    }
    wallet::save_notes(&c.me.notes_path(), &all)?;
    let l = Leg::from_zk(&c.me.party, &b.zk);
    let which = if is_delivery { "delivery" } else { "payment" };
    let out = json!({
        "cmd": "dvp leg", "trade_id": t.trade_id, "leg": which, "asset": side.asset,
        "prove_ms": b.prove_ms.to_string(), "inputs": l.inputs, "outputs": l.outputs, "proof_bytes": l.proof.len() / 2,
    });
    if is_delivery { t.delivery_leg = Some(l) } else { t.payment_leg = Some(l) }
    t.save(trade_path)?;
    Ok(out)
}

// ----- sign ---------------------------------------------------------------------------------------------

/// What a party checks before it signs: the other party's leg is for the agreed asset, its proof verifies, and its
/// envelope (encrypted to my view key) pays me exactly the agreed amount in notes I can recompute on chain.
pub fn check_incoming(t: &Trade, me: &Me) -> Result<()> {
    let (_, _, i_am_seller) = role(t, &me.party)?;
    // the seller receives the payment leg, the buyer the delivery leg
    let (leg, side, from) = if i_am_seller { (&t.payment_leg, &t.pay, &t.buyer) } else { (&t.delivery_leg, &t.deliver, &t.seller) };
    let leg = leg.as_ref().ok_or_else(|| eyre!("the leg of {from} is not built yet"))?;
    if leg.asset != side.asset || leg.by != *from {
        return Err(eyre!("the leg of {from} is for {} by {}, expected {} by {from}", leg.asset, leg.by, side.asset));
    }
    let proof = leg.proof_box()?;
    if !verify_backend(ZK_BACKEND_HALO2_IPA, &proof, Some(&proto::transfer_vk()?)) {
        return Err(eyre!("the proof of the leg of {from} does not verify"));
    }
    let aux = proto::get_aux(&proof).ok_or_else(|| eyre!("the leg of {from} has no envelope"))?;
    let env = Envelope::parse(&aux).map_err(|e| eyre!("envelope of the leg of {from}: {e}"))?;
    let (ins, outs) = (leg.inputs.iter().map(|x| h32(x)).collect::<Result<Vec<_>>>()?, leg.outputs.iter().map(|x| h32(x)).collect::<Result<Vec<_>>>()?);
    if !env.binds(&BindingCtx { asset: &leg.asset, inputs: &ins, outputs: &outs, public_amount: 0 }) {
        return Err(eyre!("the envelope of the leg of {from} is not bound to its instruction fields"));
    }
    let pt = env.open_rc(&me.view_secret).map_err(|e| eyre!("the envelope of the leg of {from} is not readable by me: {e}"))?;
    let my_tag = hex::encode(me.address().owner_tag);
    let mut got: u128 = 0;
    for (i, o) in pt.outputs.iter().enumerate().filter(|(_, o)| o.owner_tag == my_tag) {
        let (amount, rho, tag) = (o.amount.parse::<u128>()?, h32(&o.rho)?, h32(&o.owner_tag)?);
        if outs.get(i) != Some(&proto::commitment(&leg.asset, amount, rho, tag)?) {
            return Err(eyre!("output {i} of the leg of {from} does not match its envelope: the note would be unspendable"));
        }
        got += amount;
    }
    let want: u128 = side.amount.parse().wrap_err("amount")?;
    if got != want {
        return Err(eyre!("the leg of {from} pays me {got} of {}, the trade says {want}", leg.asset));
    }
    Ok(())
}

pub fn sign(c: &Ctx, trade_path: &Path) -> Result<Value> {
    let mut t = Trade::load(trade_path)?;
    if t.chain != c.chain {
        return Err(eyre!("trade is for chain {}, not {}", t.chain, c.chain));
    }
    role(&t, &c.me.party)?;
    if t.intents.iter().any(|i| i.party == c.me.party) {
        return Err(eyre!("{} has already signed this trade", c.me.party));
    }
    check_incoming(&t, &c.me)?;
    let digest = t.digest()?;
    let signer = chain::own_account(&c.me)?;
    let s = Signature::new(&private_key(&c.me)?, &digest);
    t.intents.push(IntentRec { party: c.me.party.clone(), signer: signer.to_string(), signature: hex::encode(s.payload()) });
    t.save(trade_path)?;
    Ok(json!({"cmd": "dvp sign", "trade_id": t.trade_id, "party": c.me.party, "signer": signer.to_string(), "digest": hex::encode(digest), "intents": t.intents.len()}))
}

// ----- submit -------------------------------------------------------------------------------------------

pub fn submit(c: &Ctx, trade_path: &Path) -> Result<Value> {
    let t = Trade::load(trade_path)?;
    if t.chain != c.chain {
        return Err(eyre!("trade is for chain {}, not {}", t.chain, c.chain));
    }
    role(&t, &c.me.party)?; // the transaction authority must be one of the two signers
    let dvp = t.build()?; // verifies both intents against the digest
    let t0 = Instant::now();
    let tx = chain::submit(&c.net()?, vec![InstructionBox::from(dvp)], Metadata::default())?;
    Ok(json!({"cmd": "dvp submit", "trade_id": t.trade_id, "kind": t.kind, "tx": tx, "submit_ms": t0.elapsed().as_millis().to_string()}))
}
