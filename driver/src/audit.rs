//! BI audit (spec 3.7): decrypt every envelope, recompute output commitments, check conservation.
//! Pure over `events::Event`; the node is never asked to do anything.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::{
    envelope::{Bytes32, Envelope},
    events::{Event, Kind},
    proto,
};

/// Audit secret keys by key version.
pub type AuditKeys = HashMap<u32, Bytes32>;

struct Pool {
    /// account -> unspent notes (amount, commitment hex) as far as the envelopes show
    notes: HashMap<String, Vec<(u128, String)>>,
}

impl Pool {
    /// Remove `n` notes of `owner` whose amounts sum to `need`.
    fn take(&mut self, owner: &str, n: usize, need: u128) -> bool {
        let Some(v) = self.notes.get_mut(owner) else { return false };
        let idx = match n {
            1 => v.iter().position(|(a, _)| *a == need).map(|i| vec![i]),
            2 => (0..v.len()).find_map(|i| (i + 1..v.len()).find(|&j| v[i].0 + v[j].0 == need).map(|j| vec![i, j])),
            _ => None,
        };
        let Some(mut idx) = idx else { return false };
        idx.sort_unstable_by(|a, b| b.cmp(a));
        for i in idx {
            v.remove(i);
        }
        true
    }
}

fn viol(v: &mut Vec<Value>, code: &str, detail: impl Into<String>) {
    v.push(json!({"code": code, "detail": detail.into()}));
}

/// Check one event; returns the violations found. Updates the note pools and supply counters.
fn check(ev: &Event, keys: &AuditKeys, pool: &mut Pool, issued: &mut u128, unshielded: &mut u128) -> Vec<Value> {
    let mut v = vec![];
    let Some(raw) = &ev.envelope else {
        viol(&mut v, "envelope_missing", "no envelope in the carrier");
        return v;
    };
    let env = match Envelope::parse(raw) {
        Ok(e) => e,
        Err(e) => {
            viol(&mut v, "envelope_malformed", e.to_string());
            return v;
        }
    };
    if !env.binds(&ev.binding_ctx()) {
        viol(&mut v, "binding_mismatch", "binding or asset does not match the instruction");
    }
    let Some(sk) = keys.get(&env.key_version) else {
        viol(&mut v, "no_audit_key_for_version", format!("key_version {}", env.key_version));
        return v;
    };
    let p = match env.open_bi(sk) {
        Ok(p) => p,
        Err(e) => {
            viol(&mut v, "decrypt_failed", e.to_string());
            return v;
        }
    };
    if p.asset != ev.asset {
        viol(&mut v, "asset_mismatch", format!("plaintext {} vs instruction {}", p.asset, ev.asset));
    }
    if p.kind != ev.kind.as_str() {
        viol(&mut v, "kind_mismatch", format!("plaintext {} vs instruction {}", p.kind, ev.kind.as_str()));
    }
    // A ConfidentialDvp leg may be sent by the other signer, not the transaction authority.
    let sender = if ev.signers.contains(&p.sender) { p.sender.clone() } else { ev.authority.clone() };
    if p.sender != sender {
        viol(&mut v, "sender_mismatch", format!("plaintext {} vs signer {}", p.sender, ev.authority));
    }
    if let Some(from) = &ev.from {
        if *from != ev.authority {
            viol(&mut v, "shield_from_not_signer", format!("from {from} vs signer {}", ev.authority));
        }
    }
    let pin: Vec<&str> = p.inputs.iter().map(|i| i.nullifier.as_str()).collect();
    let cin: Vec<String> = ev.inputs.iter().map(hex::encode).collect();
    if pin != cin.iter().map(String::as_str).collect::<Vec<_>>() {
        viol(&mut v, "nullifier_mismatch", "plaintext nullifiers differ from instruction inputs");
    }
    match (ev.kind, &p.public_amount) {
        (Kind::Transfer, None) => {}
        (Kind::Transfer, Some(a)) => viol(&mut v, "public_amount_mismatch", format!("transfer carries {a}")),
        (_, Some(a)) if a.parse::<u128>().ok() == Some(ev.public_amount) => {}
        (_, a) => viol(&mut v, "public_amount_mismatch", format!("plaintext {a:?} vs instruction {}", ev.public_amount)),
    }
    if p.outputs.len() != ev.outputs.len() {
        viol(&mut v, "output_count_mismatch", format!("plaintext {} vs instruction {}", p.outputs.len(), ev.outputs.len()));
        return v;
    }
    let mut sum_out: u128 = 0;
    let mut outs: Vec<(String, u128, String)> = vec![];
    let mut outs_ok = true;
    for (i, o) in p.outputs.iter().enumerate() {
        let parsed = (|| -> Option<(u128, Bytes32, Bytes32)> {
            Some((
                o.amount.parse().ok()?,
                hex::decode(&o.rho).ok()?.try_into().ok()?,
                hex::decode(&o.owner_tag).ok()?.try_into().ok()?,
            ))
        })();
        let Some((amount, rho, tag)) = parsed else {
            viol(&mut v, "output_unparsable", format!("output {i}"));
            outs_ok = false;
            continue;
        };
        match proto::commitment(&ev.asset, amount, rho, tag) {
            Ok(c) if c == ev.outputs[i] => {}
            Ok(c) => {
                viol(&mut v, "commitment_mismatch", format!("output {i}: recomputed {} on-chain {}", hex::encode(c), hex::encode(ev.outputs[i])));
                outs_ok = false;
            }
            Err(e) => {
                viol(&mut v, "commitment_error", format!("output {i}: {e}"));
                outs_ok = false;
            }
        }
        sum_out = sum_out.saturating_add(amount);
        outs.push((o.owner.clone(), amount, hex::encode(ev.outputs[i])));
    }
    // Conservation (3.7). Inputs are matched to the sender's earlier outputs by amount (BI cannot derive nullifiers).
    match ev.kind {
        Kind::Shield => {
            *issued = issued.saturating_add(ev.public_amount);
            if sum_out != ev.public_amount {
                viol(&mut v, "shield_amount_mismatch", format!("burned {} but note commits {}", ev.public_amount, sum_out));
            }
        }
        Kind::Transfer | Kind::Unshield => {
            let need = sum_out.saturating_add(ev.public_amount);
            if !pool.take(&sender, ev.inputs.len(), need) {
                viol(
                    &mut v,
                    "conservation_unmatched_inputs",
                    format!("no {} earlier note(s) of {} sum to {need}", ev.inputs.len(), sender),
                );
            }
            if ev.kind == Kind::Unshield {
                *unshielded = unshielded.saturating_add(ev.public_amount);
            }
        }
    }
    if outs_ok || ev.kind == Kind::Shield {
        for (owner, amount, c) in outs {
            pool.notes.entry(owner).or_default().push((amount, c));
        }
    }
    v
}

/// Audit all events in chain order. Output: machine-readable report with detected violations.
pub fn audit(events: &[Event], keys: &AuditKeys) -> Value {
    let mut pool = Pool { notes: HashMap::new() };
    let (mut issued, mut unshielded) = (0u128, 0u128);
    let mut rows = vec![];
    let mut n_viol = 0usize;
    for ev in events {
        let vs = check(ev, keys, &mut pool, &mut issued, &mut unshielded);
        n_viol += vs.len();
        rows.push(json!({
            "block": ev.block, "tx": ev.tx, "kind": ev.kind.as_str(), "asset": ev.asset,
            "signer": ev.authority, "ok": vs.is_empty(), "violations": vs,
        }));
    }
    let outstanding = issued.saturating_sub(unshielded);
    let mut balances = serde_json::Map::new();
    let mut pooled: u128 = 0;
    for (k, v) in &pool.notes {
        let t: u128 = v.iter().map(|(a, _)| *a).sum();
        pooled += t;
        balances.insert(k.clone(), json!(t.to_string()));
    }
    let supply_ok = pooled == outstanding;
    json!({
        "events": rows,
        "summary": {
            "events": events.len(),
            "events_with_violations": rows.iter().filter(|r| r["ok"] == json!(false)).count(),
            "violations": n_viol,
            "issued": issued.to_string(),
            "unshielded": unshielded.to_string(),
            "shielded_outstanding": outstanding.to_string(),
            "envelope_pool_total": pooled.to_string(),
            "supply_reconciles": supply_ok,
            "balances_by_account": balances,
        },
    })
}
