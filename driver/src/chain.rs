//! Network access: client from a party's key, block replay into a `Ledger`, root check, submit.
//! Not exercised by unit tests (needs a node); compile-checked only.

use std::{fs, num::NonZeroU64, path::Path};

use eyre::{Result, WrapErr, eyre};
use iroha::{
    client::Client,
    config::{Config, LoadPath},
};
use iroha_data_model::{
    asset::AssetDefinitionId,
    block::SignedBlock,
    isi::{
        Instruction, InstructionBox,
        zk::{ConfidentialDvp, Shield, Unshield, ZkTransfer},
    },
    metadata::Metadata,
    name::Name,
    prelude::Executable,
};
use iroha_primitives::json::Json;

use crate::{
    envelope::Bytes32,
    events::{Event, Kind, Ledger},
    proto,
    wallet::Me,
};

pub struct Net {
    pub client: Client,
    pub chain: String,
}

/// Build a client for `me`. The iroha config loader wants a TOML file: it is written next to the
/// process, loaded, and removed. `domain` is only syntax-checked by the loader (account = key).
pub fn connect(torii: &str, chain: &str, me: &Me) -> Result<Net> {
    let toml = format!(
        "chain = \"{chain}\"\ntorii_url = \"{torii}\"\n[account]\ndomain = \"rd.universal\"\npublic_key = \"{}\"\nprivate_key = \"{}\"\n[transaction]\ntime_to_live_ms = 600000\nstatus_timeout_ms = 300000\nnonce = true\n",
        me.public_key, me.private_key
    );
    let path = std::env::temp_dir().join(format!("rd2-client-{}.toml", std::process::id()));
    fs::write(&path, toml)?;
    let cfg = Config::load(LoadPath::Explicit(&path));
    let _ = fs::remove_file(&path);
    let cfg = cfg.map_err(|e| eyre!("client config: {e:?}"))?;
    Ok(Net { client: Client::new(cfg), chain: chain.to_owned() })
}

pub fn own_account(me: &Me) -> Result<iroha_data_model::account::AccountId> {
    let pk: iroha_crypto::PublicKey = me.public_key.parse().map_err(|e| eyre!("public key: {e:?}"))?;
    Ok(iroha_data_model::account::AccountId::of(pk))
}

pub fn asset_def(s: &str) -> Result<AssetDefinitionId> {
    s.parse().map_err(|e| eyre!("asset definition id {s}: {e:?}"))
}

pub fn envelope_key() -> Name {
    "rd_envelope".parse().expect("valid name")
}

fn to_event(block: u64, tx: &iroha_data_model::transaction::SignedTransaction, ins: &InstructionBox, asset: &AssetDefinitionId) -> Option<Event> {
    let base = |kind, from, inputs, outputs, public_amount, root_hint, envelope| Event {
        block,
        tx: tx.hash_as_entrypoint().to_string(),
        authority: tx.authority().to_string(),
        kind,
        asset: asset.to_string(),
        from,
        inputs,
        outputs,
        public_amount,
        root_hint,
        envelope,
        signers: vec![],
        leaf_start: 0,
    };
    let any = ins.as_any();
    if let Some(s) = any.downcast_ref::<Shield>() {
        if s.asset != *asset {
            return None;
        }
        let env = tx
            .metadata()
            .get(&envelope_key())
            .and_then(|j| j.try_into_any::<String>().ok())
            .and_then(|h| hex::decode(h).ok());
        return Some(base(Kind::Shield, Some(s.from.to_string()), vec![], vec![s.note_commitment], s.amount, None, env));
    }
    if let Some(t) = any.downcast_ref::<ZkTransfer>() {
        if t.asset != *asset {
            return None;
        }
        return Some(base(Kind::Transfer, None, t.inputs.clone(), t.outputs.clone(), 0, t.root_hint, proto::get_aux(&t.proof.proof)));
    }
    if let Some(d) = any.downcast_ref::<ConfidentialDvp>() {
        // the two legs have different assets (node rule), so at most one matches; it behaves like a ZkTransfer
        let leg = [&d.delivery, &d.payment].into_iter().find(|l| l.asset == *asset)?;
        let mut ev = base(Kind::Transfer, None, leg.inputs.clone(), leg.outputs.clone(), 0, leg.root_hint, proto::get_aux(&leg.proof.proof));
        ev.signers = d.intents.iter().map(|i| i.signer.to_string()).collect();
        return Some(ev);
    }
    if let Some(u) = any.downcast_ref::<Unshield>() {
        if u.asset != *asset {
            return None;
        }
        return Some(base(Kind::Unshield, None, u.inputs.clone(), u.outputs.clone(), u.public_amount, u.root_hint, proto::get_aux(&u.proof.proof)));
    }
    None
}

pub fn apply_block(ledger: &mut Ledger, b: &SignedBlock, asset: &AssetDefinitionId) {
    let height = b.header().height.get();
    let total = b.external_transactions().len();
    for (tx, result) in b.external_transactions().zip(b.results().take(total)) {
        if result.as_ref().is_err() {
            continue; // rejected tx: state reverted
        }
        let Executable::Instructions(instrs) = tx.instructions() else { continue };
        for ins in instrs.iter() {
            if let Some(ev) = to_event(height, tx, ins, asset) {
                ledger.push(ev);
            }
        }
    }
}

/// Replay the chain from block 1 to the current tip (blocks over the WebSocket stream).
pub fn fetch_ledger(net: &Net, asset: &AssetDefinitionId) -> Result<Ledger> {
    let tip = net.client.get_status().wrap_err("status")?.blocks;
    fetch_ledger_to(net, asset, tip)
}

/// Replay blocks 1..=`tip`.
pub fn fetch_ledger_to(net: &Net, asset: &AssetDefinitionId, tip: u64) -> Result<Ledger> {
    let mut ledger = Ledger::default();
    if tip == 0 {
        return Ok(ledger);
    }
    let it = net.client.listen_for_blocks(NonZeroU64::new(1).expect("1"))?;
    for b in it {
        let b = b?;
        apply_block(&mut ledger, &b, asset);
        if b.header().height.get() >= tip {
            break;
        }
    }
    Ok(ledger)
}

/// Compare the replayed leaf list with the node's latest root (`/v1/zk/roots`). `Ok(None)` if there are no leaves.
pub fn check_root(net: &Net, asset: &str, ledger: &Ledger) -> Result<Option<(bool, String, String)>> {
    if ledger.leaves.is_empty() {
        return Ok(None);
    }
    let mine = hex::encode(proto::leaf_root(&ledger.leaves)?);
    let v = net.client.get_zk_roots_json(asset, 1)?;
    let v: serde_json::Value = serde_json::from_slice(&norito::json::to_vec(&v)?)?;
    let node = v["latest"].as_str().unwrap_or("").to_owned();
    Ok(Some((mine == node, mine, node)))
}

/// Replay and verify the root; retry a few times because a block may land between the two reads.
pub fn sync(net: &Net, asset: &str) -> Result<(Ledger, Option<(bool, String, String)>)> {
    let def = asset_def(asset)?;
    let mut last = None;
    for _ in 0..3 {
        let l = fetch_ledger(net, &def)?;
        let r = check_root(net, asset, &l)?;
        if r.as_ref().is_none_or(|x| x.0) {
            return Ok((l, r));
        }
        last = Some((l, r));
    }
    Ok(last.expect("loop ran"))
}

/// Does the registered VK record contain the hash of our locally generated VK? Lenient text check.
pub fn vk_registered(net: &Net, name: &str, local: &iroha_data_model::proof::VerifyingKeyBox) -> Option<bool> {
    let v = net.client.get_zk_vk_json("halo2/ipa", name).ok()?;
    let text = String::from_utf8(norito::json::to_vec(&v).ok()?).ok()?;
    let h = hex::encode(iroha_core::zk::hash_vk(local));
    Some(text.contains(&h))
}

/// Submit and wait for commit or rejection. Returns the tx hash or the node's error text.
pub fn submit(net: &Net, instrs: Vec<InstructionBox>, md: Metadata) -> Result<String> {
    net.client.submit_all_blocking_with_metadata(instrs, md).map(|h| h.to_string())
}

pub fn envelope_metadata(env_bytes: &[u8]) -> Metadata {
    let mut md = Metadata::default();
    md.insert(envelope_key(), Json::new(hex::encode(env_bytes)));
    md
}

pub fn root_of(ledger: &Ledger) -> Result<Bytes32> {
    proto::leaf_root(&ledger.leaves)
}

pub fn ensure_dir(p: &Path) -> Result<()> {
    fs::create_dir_all(p).wrap_err("create dir")
}
