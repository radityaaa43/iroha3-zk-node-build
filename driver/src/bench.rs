//! `rd2 bench`: closed-loop RD transfer load for the performance ladder (KPID benchmarks/spec/scenario.md).
//!
//! One process per sending bank, in that bank's wallet. `stages` lists the concurrency of each step; every step
//! lasts `stage_secs`, after `warmup_secs` at the first step's concurrency. All senders get the same `start_at`
//! (unix seconds), so their steps line up and the merged records give the network-wide rate.
//!
//! Confidential mode: worker `w` owns one note and spends it in a chain (`amount` to the next recipient, the change
//! back to itself), so workers never race for inputs. A block-stream thread keeps the leaf list current; a worker
//! proves against the latest snapshot (the node accepts any of its last `root_history_cap` roots) and waits until
//! its change note has a leaf before the next transfer. `--public` sends a transparent RD transfer instead (the
//! privacy-off baseline on the same network).
//!
//! Every attempt is one JSON line in `out`: the merger in KPID (platforms/iroha2/bench/) buckets them by step.

use std::{
    fs::OpenOptions,
    io::Write,
    num::NonZeroU64,
    path::Path,
    sync::{Arc, Mutex, RwLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eyre::{Result, eyre};
use iroha::client::Client;
use iroha_data_model::{
    asset::AssetId,
    isi::{InstructionBox, Mint, Transfer},
    metadata::Metadata,
};
use iroha_primitives::numeric::Numeric;
use serde_json::{Value, json};

use crate::{
    chain,
    cmd::{self, Ctx},
    dvp,
    envelope::Bytes32,
    events::Ledger,
    proto::{self, OutSpec},
    wallet::{self, NoteRec},
};

pub struct BenchArgs<'a> {
    pub asset: &'a str,
    pub to: &'a [String],
    pub stages: &'a [usize],
    pub stage_secs: u64,
    pub warmup_secs: u64,
    pub start_at: u64,
    pub out: &'a Path,
    pub public: bool,
    pub amount: u128,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Step at `t_ms`: `Some(-1)` warm-up, `Some(i)` step i, `None` before the start or after the last step.
fn step_at(a: &BenchArgs, t_ms: u64) -> Option<i64> {
    let start = a.start_at * 1000;
    if t_ms < start {
        return None;
    }
    let t = t_ms - start;
    let warm = a.warmup_secs * 1000;
    if t < warm {
        return Some(-1);
    }
    let i = (t - warm) / (a.stage_secs * 1000);
    (i < a.stages.len() as u64).then_some(i as i64)
}

fn concurrency(a: &BenchArgs, step: i64) -> usize {
    a.stages[step.max(0) as usize]
}

struct Sink(Mutex<std::fs::File>);

impl Sink {
    fn put(&self, v: &Value) {
        if let Ok(mut f) = self.0.lock() {
            let _ = writeln!(f, "{v}");
        }
    }
}

/// Follow the chain from `from` on and append every block's leaves for `asset` (runs until the process exits).
fn follow(client: Client, ledger: Arc<RwLock<Ledger>>, asset: String, from: u64) {
    thread::spawn(move || {
        let Ok(def) = chain::asset_def(&asset) else { return };
        let mut next = from;
        loop {
            match client.listen_for_blocks(NonZeroU64::new(next).expect("height >= 1")) {
                Ok(it) => {
                    for b in it {
                        let Ok(b) = b else { break };
                        next = b.header().height.get() + 1;
                        if let Ok(mut l) = ledger.write() {
                            chain::apply_block(&mut l, &b, &def);
                        }
                    }
                }
                Err(e) => eprintln!("block stream: {e:#}"),
            }
            thread::sleep(Duration::from_millis(500));
        }
    });
}

fn leaf_of(ledger: &RwLock<Ledger>, c: &Bytes32) -> Option<usize> {
    ledger.read().ok()?.leaves.iter().position(|l| l == c)
}

pub fn bench(c: &Ctx, a: &BenchArgs) -> Result<Value> {
    if a.stages.is_empty() || a.to.is_empty() {
        return Err(eyre!("--stages and --to must not be empty"));
    }
    let asset = c.parties.asset(a.asset);
    let net = c.net()?;
    let me_acct = c.own_account()?;
    let max_c = *a.stages.iter().max().expect("non-empty");
    let sink = Sink(Mutex::new(OpenOptions::new().create(true).append(true).open(a.out)?));

    // Confidential: one note per worker, and a ledger kept current by the block stream.
    let mut notes: Vec<NoteRec> = vec![];
    let ledger = Arc::new(RwLock::new(Ledger::default()));
    if !a.public {
        let tip = net.client.get_status().map_err(|e| eyre!("status: {e:#}"))?.blocks;
        let l = chain::fetch_ledger_to(&net, &chain::asset_def(&asset)?, tip)?;
        let (mine, _) = wallet::scan_notes(&l, &c.me, &asset, &c.chain, wallet::load_notes(&c.me.notes_path()));
        notes = cmd::unspent(&mine);
        notes.sort_by(|x, y| y.amount().cmp(&x.amount()));
        if notes.len() < max_c {
            return Err(eyre!("{} spendable notes, need one per worker ({max_c}); issue more first", notes.len()));
        }
        notes.truncate(max_c);
        *ledger.write().map_err(|_| eyre!("lock"))? = l;
        follow(net.client.clone(), ledger.clone(), asset.clone(), tip + 1);
    }

    let start_at = if a.start_at == 0 { now_ms() / 1000 + 5 } else { a.start_at };
    let a = BenchArgs { start_at, ..*a };
    let end_ms = (start_at + a.warmup_secs + a.stage_secs * a.stages.len() as u64) * 1000;
    let def = chain::asset_def(&asset)?;
    let me_id = chain::own_account(&c.me)?;
    let recipients = a.to.iter().map(|t| Ok((t.clone(), c.parties.account_id(t)?))).collect::<Result<Vec<_>>>()?;

    let finals: Vec<Option<NoteRec>> = thread::scope(|s| {
        let hs: Vec<_> = (0..max_c).map(|w| (w, notes.get(w).cloned())).map(|(w, note)| {
            let (client, a, sink, ledger, recipients, asset, def, me_acct, me_id) =
                (net.client.clone(), &a, &sink, &ledger, &recipients, &asset, &def, &me_acct, &me_id);
            s.spawn(move || -> Option<NoteRec> {
                let mut note = note;
                let mut k = w;
                loop {
                    let now = now_ms();
                    if now >= end_ms {
                        return note;
                    }
                    let Some(step) = step_at(a, now) else {
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    };
                    if w >= concurrency(a, step) {
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    let (to, to_acct) = &recipients[k % recipients.len()];
                    k += 1;
                    let mut rec = json!({"party": c.me.party, "worker": w, "step": step, "to": to, "public": a.public});
                    let res: Result<(String, u64, Option<NoteRec>)> = (|| {
                        if a.public {
                            let to_id = dvp::account(to_acct)?;
                            let ins: InstructionBox =
                                Transfer::asset_numeric(AssetId::new(def.clone(), me_id.clone()), Numeric::new(a.amount, 0), to_id).into();
                            let t0 = now_ms();
                            rec["submit_ms"] = json!(t0);
                            let h = client.submit_all_blocking_with_metadata(vec![ins], Metadata::default()).map_err(|e| eyre!("{e:#}"))?;
                            return Ok((h.to_string(), 0, None));
                        }
                        let n = note.as_ref().ok_or_else(|| eyre!("no note"))?;
                        if n.amount() <= a.amount {
                            return Err(eyre!("note exhausted"));
                        }
                        let leaves = ledger.read().map_err(|_| eyre!("lock"))?.leaves.clone();
                        let outs = vec![
                            OutSpec { amount: a.amount, addr: c.parties.address(to)?, owner: to_acct.clone() },
                            OutSpec { amount: n.amount() - a.amount, addr: c.me.address(), owner: me_acct.clone() },
                        ];
                        let t = Instant::now();
                        let b = proto::build_transfer(&c.chain, asset, &c.me.spend_key, &leaves, &[n.in_note()?], &outs)?;
                        let prove_ms = t.elapsed().as_millis() as u64;
                        let env = cmd::seal_transfer(c, asset, &b, to, "bench")?;
                        let ins: InstructionBox = cmd::zk_leg(asset, &b, Some(&env.encode()), b.root, b.nullifiers.clone())?.into();
                        let t0 = now_ms();
                        rec["submit_ms"] = json!(t0);
                        let h = client.submit_all_blocking_with_metadata(vec![ins], Metadata::default()).map_err(|e| eyre!("{e:#}"))?;
                        let h = h.to_string();
                        let change = b.notes.iter().find(|o| o.owner == *me_acct).ok_or_else(|| eyre!("no change note"))?;
                        Ok((h.clone(), prove_ms, Some(wallet::note_rec(asset, &c.chain, &c.me.spend_key, change, &h))))
                    })();
                    let done = now_ms();
                    rec["done_ms"] = json!(done);
                    match res {
                        Ok((tx, prove_ms, change)) => {
                            rec["ok"] = json!(true);
                            rec["tx"] = json!(tx);
                            rec["prove_ms"] = json!(prove_ms);
                            sink.put(&rec);
                            if let Some(mut ch) = change {
                                // next input: the change note, once the block stream has its leaf
                                let cm = wallet::h32(&ch.commitment).unwrap_or_default();
                                let deadline = Instant::now() + Duration::from_secs(60);
                                while ch.leaf_index.is_none() && Instant::now() < deadline {
                                    ch.leaf_index = leaf_of(ledger, &cm);
                                    if ch.leaf_index.is_none() {
                                        thread::sleep(Duration::from_millis(50));
                                    }
                                }
                                if ch.leaf_index.is_none() {
                                    sink.put(&json!({"party": c.me.party, "worker": w, "stop": "change note has no leaf after 60 s"}));
                                    return None;
                                }
                                note = Some(ch);
                            }
                        }
                        Err(e) => {
                            let msg = format!("{e:#}");
                            rec["ok"] = json!(false);
                            rec["err"] = json!(msg);
                            sink.put(&rec);
                            // a spent or exhausted note cannot be retried; anything else (timeout, transient) can
                            if msg.contains("duplicate nullifier") || msg.contains("note exhausted") || msg.contains("no note") {
                                sink.put(&json!({"party": c.me.party, "worker": w, "stop": msg}));
                                return note;
                            }
                            thread::sleep(Duration::from_millis(200));
                        }
                    }
                }
            })
        }).collect();
        hs.into_iter().map(|h| h.join().ok().flatten()).collect()
    });

    // keep each chain's last change note: it is not recoverable from the chain (TC-REC-01)
    if !a.public {
        let mut all = wallet::load_notes(&c.me.notes_path());
        for n in &mut all {
            if notes.iter().any(|u| u.commitment == n.commitment) && !finals.iter().flatten().any(|f| f.commitment == n.commitment) {
                n.spent = true;
            }
        }
        for f in finals.iter().flatten() {
            if !all.iter().any(|n| n.commitment == f.commitment) {
                all.push(f.clone());
            }
        }
        wallet::save_notes(&c.me.notes_path(), &all)?;
    }

    Ok(json!({
        "cmd": "bench", "asset": asset, "party": c.me.party, "public": a.public, "stages": a.stages,
        "stage_secs": a.stage_secs, "warmup_secs": a.warmup_secs, "start_at": start_at, "out": a.out,
    }))
}

/// BI: mint a public (transparent) balance of `asset` to a party, for the `--public` baseline.
pub fn mint_public(c: &Ctx, asset: &str, to: &str, amount: u128) -> Result<Value> {
    let asset = c.parties.asset(asset);
    let to_id = dvp::account(&c.parties.account_id(to)?)?;
    let ins: InstructionBox = Mint::asset_numeric(Numeric::new(amount, 0), AssetId::new(chain::asset_def(&asset)?, to_id)).into();
    let tx = chain::submit(&c.net()?, vec![ins], Metadata::default())?;
    Ok(json!({"cmd": "mint-public", "asset": asset, "to": to, "amount": amount.to_string(), "tx": tx}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_line_up_on_start_at() {
        let to = vec!["bank-b".to_owned()];
        let a = BenchArgs {
            asset: "rd", to: &to, stages: &[1, 2, 4], stage_secs: 10, warmup_secs: 5, start_at: 100,
            out: Path::new("/dev/null"), public: false, amount: 1,
        };
        assert_eq!(step_at(&a, 99_999), None);
        assert_eq!(step_at(&a, 100_000), Some(-1));
        assert_eq!(concurrency(&a, -1), 1);
        assert_eq!(step_at(&a, 105_000), Some(0));
        assert_eq!(step_at(&a, 124_999), Some(1));
        assert_eq!(concurrency(&a, 2), 4);
        assert_eq!(step_at(&a, 135_000), None);
    }
}

/// What `bench_open` sends: transparent RD `Transfer`, or a `Log` (TRACE, not printed at the default level), the
/// lightest transaction the node accepts: the ledger-only ceiling (benchmarks scenario `ledger`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OpenKind {
    Public,
    Log,
}

/// Open loop (benchmarks/spec/scenario.md): each step submits at a fixed rate (`rates[i]` tx/s from this sender)
/// without waiting for commit. A block-stream thread records when each transaction is committed or rejected; a
/// transaction not committed 60 s after submit counts as an error. Same record format as `bench`.
pub fn bench_open(c: &Ctx, a: &BenchArgs, rates: &[f64], kind: OpenKind) -> Result<Value> {
    use std::{collections::HashMap, sync::mpsc};
    if rates.is_empty() || rates.iter().any(|r| *r <= 0.0) {
        return Err(eyre!("--rates must be positive"));
    }
    let asset = c.parties.asset(a.asset);
    let net = c.net()?;
    let def = chain::asset_def(&asset)?;
    let me_id = chain::own_account(&c.me)?;
    let recipients = a.to.iter().map(|t| Ok((t.clone(), dvp::account(&c.parties.account_id(t)?)?))).collect::<Result<Vec<_>>>()?;
    let sink = Sink(Mutex::new(OpenOptions::new().create(true).append(true).open(a.out)?));
    let start_at = if a.start_at == 0 { now_ms() / 1000 + 5 } else { a.start_at };
    let steps = vec![0usize; rates.len()];
    let a = BenchArgs { start_at, stages: &steps, ..*a };
    let end_ms = (start_at + a.warmup_secs + a.stage_secs * rates.len() as u64) * 1000;
    let deadline_ms = end_ms + 60_000;

    // hash -> (seen_ms, ok, rejection reason)
    let seen: Arc<Mutex<HashMap<String, (u64, bool, Option<String>)>>> = Arc::default();
    let tip = net.client.get_status().map_err(|e| eyre!("status: {e:#}"))?.blocks;
    {
        let (client, seen) = (net.client.clone(), seen.clone());
        thread::spawn(move || {
            let mut next = tip + 1;
            while now_ms() < deadline_ms + 5_000 {
                if let Ok(it) = client.listen_for_blocks(NonZeroU64::new(next).expect("height >= 1")) {
                    for b in it {
                        let Ok(b) = b else { break };
                        let t = now_ms();
                        next = b.header().height.get() + 1;
                        let total = b.external_transactions().len();
                        if let Ok(mut m) = seen.lock() {
                            for (tx, r) in b.external_transactions().zip(b.results().take(total)) {
                                let err = r.as_ref().err().map(|e| format!("{e:?}").chars().take(160).collect::<String>());
                                m.insert(tx.hash().to_string(), (t, err.is_none(), err));
                            }
                        }
                        if t > deadline_ms + 5_000 {
                            return;
                        }
                    }
                }
                thread::sleep(Duration::from_millis(500));
            }
        });
    }

    // pending submissions: (hash, step, submit_ms, to)
    let pending: Mutex<Vec<(String, i64, u64, String)>> = Mutex::default();
    let amount = a.amount;
    let (jobs_tx, jobs_rx) = mpsc::channel::<(i64, usize)>();
    let jobs_rx = Mutex::new(jobs_rx);
    thread::scope(|s| {
        for _ in 0..64 {
            let (client, jobs_rx, pending, sink, recipients, def, me_id) =
                (net.client.clone(), &jobs_rx, &pending, &sink, &recipients, &def, &me_id);
            s.spawn(move || loop {
                let Ok((step, k)) = jobs_rx.lock().map_err(|_| ()).and_then(|r| r.recv().map_err(|_| ())) else { return };
                let (to, to_id) = &recipients[k % recipients.len()];
                let ins: InstructionBox = match kind {
                    OpenKind::Public => Transfer::asset_numeric(AssetId::new(def.clone(), me_id.clone()), Numeric::new(amount, 0), to_id.clone()).into(),
                    OpenKind::Log => iroha_data_model::isi::Log::new(iroha_data_model::Level::TRACE, format!("rd-bench {k}")).into(),
                };
                let t0 = now_ms();
                match client.submit_all_with_metadata(vec![ins], Metadata::default()) {
                    Ok(h) => {
                        if let Ok(mut p) = pending.lock() {
                            p.push((h.to_string(), step, t0, to.clone()));
                        }
                    }
                    Err(e) => sink.put(&json!({"party": c.me.party, "step": step, "to": to, "submit_ms": t0, "done_ms": now_ms(),
                        "ok": false, "err": format!("submit: {e:#}").chars().take(200).collect::<String>(), "open": true})),
                }
            });
        }
        // dispatcher: fixed arrival rate per step
        let mut k = 0usize;
        let mut next = (start_at * 1000) as f64;
        loop {
            let now = now_ms();
            if now >= end_ms {
                break;
            }
            let Some(step) = step_at(&a, now) else {
                thread::sleep(Duration::from_millis(20));
                next = now_ms() as f64;
                continue;
            };
            if (now as f64) < next {
                thread::sleep(Duration::from_micros(((next - now as f64) * 1000.0).min(50_000.0) as u64));
                continue;
            }
            let _ = jobs_tx.send((step, k));
            k += 1;
            next += 1000.0 / rates[step.max(0) as usize];
        }
        drop(jobs_tx);
    });

    // wait for commits up to 60 s after the last submit, then write one record per submission
    let all = pending.into_inner().unwrap_or_default();
    while now_ms() < deadline_ms {
        let done = seen.lock().map(|m| all.iter().all(|(h, ..)| m.contains_key(h))).unwrap_or(false);
        if done {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    let m = seen.lock().map(|m| m.clone()).unwrap_or_default();
    let (mut ok, mut bad) = (0u64, 0u64);
    for (h, step, t0, to) in &all {
        let mut rec = json!({"party": c.me.party, "step": step, "to": to, "submit_ms": t0, "tx": h, "open": true});
        match m.get(h) {
            Some((t, true, _)) if t.saturating_sub(*t0) <= 60_000 => {
                rec["ok"] = json!(true);
                rec["done_ms"] = json!(t);
                ok += 1;
            }
            Some((t, okk, err)) => {
                rec["ok"] = json!(false);
                rec["done_ms"] = json!(t);
                rec["err"] = json!(if *okk { "committed more than 60 s after submit".to_owned() } else { format!("rejected: {}", err.clone().unwrap_or_default()) });
                bad += 1;
            }
            None => {
                rec["ok"] = json!(false);
                rec["done_ms"] = json!(deadline_ms);
                rec["err"] = json!("not committed within 60 s");
                bad += 1;
            }
        }
        sink.put(&rec);
    }
    Ok(json!({
        "cmd": "bench", "open": true, "kind": if kind == OpenKind::Log { "log" } else { "public" }, "party": c.me.party,
        "rates": rates, "stage_secs": a.stage_secs, "warmup_secs": a.warmup_secs, "start_at": start_at,
        "submitted": all.len(), "committed": ok, "failed": bad, "out": a.out,
    }))
}
