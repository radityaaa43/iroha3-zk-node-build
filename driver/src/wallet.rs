//! Party wallet directory, parties.json and the note store (`notes.json`).

use std::{collections::HashMap, fs, path::{Path, PathBuf}};

use eyre::{Result, WrapErr, eyre};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    envelope::{Bytes32, Envelope},
    events::Ledger,
    proto::{self, Address},
};

pub fn h32(s: &str) -> Result<Bytes32> {
    hex::decode(s.trim()).wrap_err("bad hex")?.try_into().map_err(|_| eyre!("expected 32 bytes of hex"))
}

fn read_json(p: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(p).wrap_err_with(|| format!("read {}", p.display()))?)
        .wrap_err_with(|| format!("parse {}", p.display()))
}

/// `network/public/parties.json` (spec 1).
pub struct Parties(pub Value);

impl Parties {
    pub fn load(p: &Path) -> Result<Self> {
        Ok(Self(read_json(p)?))
    }
    fn party(&self, name: &str) -> Result<&Value> {
        self.0.get(name).ok_or_else(|| eyre!("party {name} not in parties.json"))
    }
    pub fn account_id(&self, name: &str) -> Result<String> {
        Ok(self.party(name)?["account_id"].as_str().ok_or_else(|| eyre!("{name}.account_id"))?.to_owned())
    }
    pub fn view_pk(&self, name: &str) -> Result<Bytes32> {
        h32(self.party(name)?["view_pk"].as_str().ok_or_else(|| eyre!("{name}.view_pk"))?)
    }
    /// Optional `address: {owner_tag, diversifier}` (not in spec 1; written by `rd2 address`).
    pub fn address(&self, name: &str) -> Result<Address> {
        let a = self.party(name)?.get("address").ok_or_else(|| {
            eyre!("parties.json has no address for {name}: run `rd2 address` as {name} and merge it, or pass --to-owner-tag/--to-diversifier")
        })?;
        Ok(Address {
            owner_tag: h32(a["owner_tag"].as_str().unwrap_or(""))?,
            diversifier: h32(a["diversifier"].as_str().unwrap_or(""))?,
        })
    }
    /// Short name (`rd`) -> asset id string from `assets`; unknown names pass through.
    pub fn asset(&self, name: &str) -> String {
        self.0["assets"][name].as_str().unwrap_or(name).to_owned()
    }
    /// Latest audit key without retire height: (version, public key).
    pub fn audit_key(&self) -> Result<(u32, Bytes32)> {
        let arr = self.0["bi_audit"].as_array().ok_or_else(|| eyre!("bi_audit missing"))?;
        let k = arr
            .iter()
            .filter(|k| k["retire_height"].is_null())
            .max_by_key(|k| k["version"].as_u64().unwrap_or(0))
            .ok_or_else(|| eyre!("no active audit key"))?;
        Ok((k["version"].as_u64().unwrap_or(0) as u32, h32(k["pk"].as_str().unwrap_or(""))?))
    }
}

/// One party's secret files (party wallet dir layout of the spec).
pub struct Me {
    pub party: String,
    pub dir: PathBuf,
    pub public_key: String,
    pub private_key: String,
    pub view_secret: Bytes32,
    pub view_pk: Bytes32,
    pub spend_key: Bytes32,
}

impl Me {
    pub fn load(dir: &Path, party: &str) -> Result<Self> {
        let a = read_json(&dir.join("account.json"))?;
        let v = read_json(&dir.join("view.json"))?;
        let spend = fs::read_to_string(dir.join("spend.key")).wrap_err("spend.key")?;
        Ok(Self {
            party: party.to_owned(),
            dir: dir.to_owned(),
            public_key: a["public_key"].as_str().ok_or_else(|| eyre!("account.json public_key"))?.to_owned(),
            private_key: a["private_key"].as_str().ok_or_else(|| eyre!("account.json private_key"))?.to_owned(),
            view_secret: h32(v["secret"].as_str().unwrap_or(""))?,
            view_pk: h32(v["public"].as_str().unwrap_or(""))?,
            spend_key: h32(&spend)?,
        })
    }

    pub fn address(&self) -> Address {
        proto::address_of(&self.spend_key)
    }

    pub fn notes_path(&self) -> PathBuf {
        self.dir.join("notes.json")
    }
}

/// `<wallet>/audit-v1.json` style files: `{"public","secret"}`, version from the file name `audit-v<N>.json`.
pub fn load_audit_keys(dir: &Path) -> Result<HashMap<u32, Bytes32>> {
    let mut m = HashMap::new();
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_owned();
        if let Some(v) = name.strip_prefix("audit-v").and_then(|r| r.strip_suffix(".json")).and_then(|r| r.parse::<u32>().ok()) {
            m.insert(v, h32(read_json(&p)?["secret"].as_str().unwrap_or(""))?);
        }
    }
    if m.is_empty() {
        return Err(eyre!("no audit-v<N>.json in {}", dir.display()));
    }
    Ok(m)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoteRec {
    pub asset: String,
    pub commitment: String,
    pub amount: String,
    pub rho: String,
    pub diversifier: String,
    pub owner_tag: String,
    pub leaf_index: Option<usize>,
    pub spent: bool,
    pub nullifier: String,
    pub source_tx: String,
}

impl NoteRec {
    pub fn amount(&self) -> u128 {
        self.amount.parse().unwrap_or(0)
    }
    pub fn in_note(&self) -> Result<proto::InNote> {
        Ok(proto::InNote {
            amount: self.amount(),
            rho: h32(&self.rho)?,
            diversifier: h32(&self.diversifier)?,
            leaf_index: self.leaf_index.ok_or_else(|| eyre!("note {} is not on chain yet", self.commitment))?,
        })
    }
}

pub fn load_notes(p: &Path) -> Vec<NoteRec> {
    fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn save_notes(p: &Path, notes: &[NoteRec]) -> Result<()> {
    fs::write(p, serde_json::to_vec_pretty(notes)?).wrap_err("write notes.json")
}

pub fn note_rec(asset: &str, chain: &str, spend: &[u8], n: &proto::NoteOut, tx: &str) -> NoteRec {
    NoteRec {
        asset: asset.to_owned(),
        commitment: hex::encode(n.commitment),
        amount: n.amount.to_string(),
        rho: hex::encode(n.rho),
        diversifier: hex::encode(n.diversifier),
        owner_tag: hex::encode(n.owner_tag),
        leaf_index: None,
        spent: false,
        nullifier: hex::encode(proto::nullifier(chain, asset, spend, n.rho)),
        source_tx: tx.to_owned(),
    }
}

/// Rebuild the spendable-note set: keep known notes (own change is not recoverable from the chain, see
/// README), add notes found by trial-decrypting envelopes with the view secret, then bind each note to a
/// leaf and to the nullifier set. Returns (notes, anomalies).
pub fn scan_notes(ledger: &Ledger, me: &Me, asset: &str, chain: &str, existing: Vec<NoteRec>) -> (Vec<NoteRec>, Vec<Value>) {
    let addr = me.address();
    let my_tag = hex::encode(addr.owner_tag);
    let mut notes: Vec<NoteRec> = existing.into_iter().filter(|n| n.asset == asset).collect();
    let mut anomalies = vec![];
    for ev in &ledger.events {
        let Some(raw) = &ev.envelope else { continue };
        let Ok(env) = Envelope::parse(raw) else { continue };
        let Ok(p) = env.open_rc(&me.view_secret) else { continue };
        for (i, o) in p.outputs.iter().enumerate() {
            if o.owner_tag != my_tag {
                continue;
            }
            let rec = (|| -> Result<NoteRec> {
                let (amount, rho, div, tag) = (o.amount.parse::<u128>()?, h32(&o.rho)?, h32(&o.diversifier)?, h32(&o.owner_tag)?);
                let c = proto::commitment(asset, amount, rho, tag)?;
                if ev.outputs.get(i) != Some(&c) {
                    return Err(eyre!("recomputed commitment differs from on-chain output {i}"));
                }
                Ok(NoteRec {
                    asset: asset.to_owned(),
                    commitment: hex::encode(c),
                    amount: o.amount.clone(),
                    rho: o.rho.clone(),
                    diversifier: hex::encode(div),
                    owner_tag: o.owner_tag.clone(),
                    leaf_index: None,
                    spent: false,
                    nullifier: hex::encode(proto::nullifier(chain, asset, &me.spend_key, rho)),
                    source_tx: ev.tx.clone(),
                })
            })();
            match rec {
                Ok(r) => {
                    if !notes.iter().any(|n| n.commitment == r.commitment) {
                        notes.push(r);
                    }
                }
                Err(e) => anomalies.push(json!({"tx": ev.tx, "output": i, "problem": e.to_string(), "meaning": "sender gave a note that does not match the chain: unspendable, detected"})),
            }
        }
    }
    let pos: HashMap<Bytes32, usize> = ledger.leaves.iter().enumerate().map(|(i, c)| (*c, i)).collect();
    for n in &mut notes {
        n.leaf_index = h32(&n.commitment).ok().and_then(|c| pos.get(&c).copied());
        n.spent = h32(&n.nullifier).is_ok_and(|x| ledger.nullifiers.contains(&x));
    }
    (notes, anomalies)
}
