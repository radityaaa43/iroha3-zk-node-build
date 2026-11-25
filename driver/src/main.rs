use std::{fs, path::{Path, PathBuf}};

use clap::{Parser, Subcommand};
use rd_driver::{
    cmd::{self, Ctx},
    dvp::{self, AwardArgs, AwardFile, ProposeArgs},
    wallet::{Me, Parties},
};
use serde_json::Value;

/// RD/DFABI confidential wallet, BI audit and negative-test driver for Iroha 2.
/// Every command prints one line `result_json=<json>` on success.
#[derive(Parser)]
#[command(name = "rd2")]
struct Cli {
    /// Torii base URL (e.g. http://127.0.0.1:8080)
    #[arg(long, global = true, default_value = "http://127.0.0.1:8080")]
    torii: String,
    /// Chain id (network/public/chain_id)
    #[arg(long, global = true, default_value = "")]
    chain: String,
    /// network/public/parties.json
    #[arg(long, global = true, default_value = "parties.json")]
    parties: PathBuf,
    /// Party wallet dir (account.json, view.json, spend.key, notes.json; BI: audit-v1.json)
    #[arg(long, global = true, default_value = ".")]
    wallet: PathBuf,
    /// This party's name in parties.json (bi, bank-a, ...)
    #[arg(long, global = true, default_value = "")]
    party: String,
    #[command(subcommand)]
    cmd: Sub,
}

#[derive(Subcommand)]
enum Sub {
    /// Create a party wallet dir with fresh keys (tests). Prints the public halves for parties.json.
    Keygen {
        #[arg(long)]
        audit_key: bool,
    },
    /// Print this wallet's public receive address (merge into parties.json as "address").
    Address,
    /// BI: Mint to BI, then Shield to a party's address, envelope in tx metadata.
    Issue {
        #[arg(long)]
        asset: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value = "issue")]
        reference: String,
        #[arg(long)]
        to_owner_tag: Option<String>,
        #[arg(long)]
        to_diversifier: Option<String>,
    },
    /// Rebuild the leaf list from blocks, check the root, trial-decrypt envelopes, store notes.json.
    Scan {
        #[arg(long)]
        asset: String,
    },
    /// Private transfer (1-2 input notes, recipient + change output).
    Transfer {
        #[arg(long)]
        asset: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value = "transfer")]
        reference: String,
        #[arg(long)]
        to_owner_tag: Option<String>,
        #[arg(long)]
        to_diversifier: Option<String>,
    },
    /// Exit whole notes to a public balance (amount must equal the sum of 1-2 notes).
    Unshield {
        #[arg(long)]
        asset: String,
        #[arg(long)]
        amount: u128,
        /// Party to credit (default: self)
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value = "unshield")]
        reference: String,
    },
    /// BI: decrypt every envelope, recompute commitments, check conservation, print violations.
    Audit {
        /// Asset names or ids (repeatable)
        #[arg(long, required = true)]
        asset: Vec<String>,
        /// Dir with audit-v<N>.json (default: --wallet)
        #[arg(long)]
        audit_dir: Option<PathBuf>,
    },
    /// Two-party confidential DvP (fork patch P3): propose, each party `leg` and `sign`, one `submit`.
    Dvp {
        #[command(subcommand)]
        cmd: DvpCmd,
    },
    /// BI: sign the award record of a UC-03 trade.
    Award {
        #[command(subcommand)]
        cmd: AwardCmd,
    },
    /// Closed-loop RD transfer load for the 2.6 ladder: one JSON line per attempt in --out (src/bench.rs).
    Bench {
        #[arg(long)]
        asset: String,
        /// Recipients, comma-separated, used round robin
        #[arg(long, value_delimiter = ',', required = true)]
        to: Vec<String>,
        /// Concurrency of each step, comma-separated
        #[arg(long, value_delimiter = ',', default_value = "1,2,4,8")]
        stages: Vec<usize>,
        #[arg(long, default_value_t = 120)]
        stage_secs: u64,
        #[arg(long, default_value_t = 60)]
        warmup_secs: u64,
        /// Unix seconds when the warm-up starts (same value on every sender); 0 = in 5 s
        #[arg(long, default_value_t = 0)]
        start_at: u64,
        #[arg(long)]
        out: PathBuf,
        /// Transparent transfer instead of ZkTransfer (privacy-off baseline)
        #[arg(long)]
        public: bool,
        /// Open loop: tx/s per step from this sender, comma-separated (then --stages is ignored; needs --public or --log)
        #[arg(long, value_delimiter = ',')]
        rates: Vec<f64>,
        /// Open loop with a `Log` instruction (ledger-only ceiling, benchmarks scenario `ledger`)
        #[arg(long)]
        log: bool,
        #[arg(long, default_value_t = 1)]
        amount: u128,
    },
    /// BI: mint a public (transparent) balance to a party, for `bench --public`.
    MintPublic {
        #[arg(long)]
        asset: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },
    /// Submit the attacks the node can reject; print expected vs got.
    Negative {
        #[arg(long)]
        asset: String,
        /// A second asset for the wrong-asset-tag case
        #[arg(long)]
        other_asset: String,
        #[arg(long)]
        to: String,
        #[arg(long, default_value_t = 1)]
        amount: u128,
        #[arg(long)]
        to_owner_tag: Option<String>,
        #[arg(long)]
        to_diversifier: Option<String>,
    },
}

#[derive(Subcommand)]
enum DvpCmd {
    /// Write a new trade file (no keys, no network).
    Propose {
        /// 32 bytes hex, or `auto`
        #[arg(long)]
        trade_id: String,
        #[arg(long)]
        deliver_asset: String,
        #[arg(long)]
        deliver_amount: u128,
        #[arg(long)]
        pay_asset: String,
        #[arg(long)]
        pay_amount: u128,
        /// Delivers the DFABI, receives the RD
        #[arg(long)]
        seller: String,
        /// Pays the RD, receives the DFABI
        #[arg(long)]
        buyer: String,
        #[arg(long)]
        expiry_height: u64,
        /// interbank | award (default: award if --award is given, else interbank)
        #[arg(long)]
        kind: Option<String>,
        /// award.json from `rd2 award sign`
        #[arg(long)]
        award: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Prove my leg (seller: delivery, buyer: payment) and write it into the trade file.
    Leg {
        #[arg(long)]
        trade: PathBuf,
    },
    /// Check the other leg, then sign the settlement digest with my account key and add my intent.
    Sign {
        #[arg(long)]
        trade: PathBuf,
    },
    /// Submit the ConfidentialDvp (both legs and both intents present), wait for the result.
    Submit {
        #[arg(long)]
        trade: PathBuf,
    },
}

#[derive(Subcommand)]
enum AwardCmd {
    /// Sign an award record with the BI account key.
    Sign {
        /// 32 bytes hex, or `auto`
        #[arg(long)]
        award_id: String,
        #[arg(long)]
        winner: String,
        #[arg(long)]
        instrument: String,
        #[arg(long)]
        quantity: u128,
        #[arg(long)]
        consideration: u128,
        #[arg(long)]
        expiry_height: u64,
        #[arg(long)]
        out: PathBuf,
    },
}

fn write_json<T: serde::Serialize>(p: &Path, v: &T) -> eyre::Result<()> {
    Ok(fs::write(p, serde_json::to_vec_pretty(v)?)?)
}

fn id32(s: &str) -> eyre::Result<[u8; 32]> {
    if s == "auto" { Ok(rd_driver::proto::rand32()) } else { rd_driver::wallet::h32(s) }
}

fn run(cli: Cli) -> eyre::Result<Value> {
    let party = cli.party.clone();
    if let Sub::Keygen { audit_key } = &cli.cmd {
        return cmd::keygen(&cli.wallet, &party, *audit_key);
    }
    let me = Me::load(&cli.wallet, &party)?;
    if let Sub::Address = &cli.cmd {
        return Ok(cmd::address(&me));
    }
    let c = Ctx { torii: cli.torii, chain: cli.chain, parties: Parties::load(&cli.parties)?, me };
    if c.chain.is_empty() {
        return Err(eyre::eyre!("--chain is required"));
    }
    match cli.cmd {
        Sub::Issue { asset, to, amount, reference, to_owner_tag, to_diversifier } => {
            cmd::issue(&c, &asset, &to, amount, &reference, to_owner_tag.as_deref(), to_diversifier.as_deref())
        }
        Sub::Scan { asset } => cmd::scan(&c, &asset),
        Sub::Transfer { asset, to, amount, reference, to_owner_tag, to_diversifier } => {
            cmd::transfer(&c, &asset, &to, amount, &reference, to_owner_tag.as_deref(), to_diversifier.as_deref())
        }
        Sub::Unshield { asset, amount, to, reference } => cmd::unshield(&c, &asset, amount, to.as_deref(), &reference),
        Sub::Audit { asset, audit_dir } => {
            let dir = audit_dir.unwrap_or_else(|| cli.wallet.clone());
            cmd::audit_cmd(&c, &asset, &dir)
        }
        Sub::Bench { asset, to, stages, stage_secs, warmup_secs, start_at, out, public, amount, rates, log } => {
            let args = rd_driver::bench::BenchArgs { asset: &asset, to: &to, stages: &stages, stage_secs, warmup_secs, start_at, out: &out, public, amount };
            if rates.is_empty() {
                rd_driver::bench::bench(&c, &args)
            } else if log || public {
                let kind = if log { rd_driver::bench::OpenKind::Log } else { rd_driver::bench::OpenKind::Public };
                rd_driver::bench::bench_open(&c, &args, &rates, kind)
            } else {
                Err(eyre::eyre!("--rates (open loop) needs --public or --log; confidential transfers stay closed loop"))
            }
        }
        Sub::MintPublic { asset, to, amount } => rd_driver::bench::mint_public(&c, &asset, &to, amount),
        Sub::Negative { asset, other_asset, to, amount, to_owner_tag, to_diversifier } => {
            cmd::negative(&c, &asset, &other_asset, &to, amount, to_owner_tag.as_deref(), to_diversifier.as_deref())
        }
        Sub::Dvp { cmd } => match cmd {
            DvpCmd::Propose { trade_id, deliver_asset, deliver_amount, pay_asset, pay_amount, seller, buyer, expiry_height, kind, award, out } => {
                let award = award.map(|p| -> eyre::Result<AwardFile> { Ok(serde_json::from_slice(&fs::read(p)?)?) }).transpose()?;
                let t = dvp::propose(
                    &c,
                    &ProposeArgs {
                        trade_id: &trade_id,
                        deliver_asset: &deliver_asset,
                        deliver_amount,
                        pay_asset: &pay_asset,
                        pay_amount,
                        seller: &seller,
                        buyer: &buyer,
                        expiry_height,
                        kind: kind.as_deref(),
                        award,
                    },
                )?;
                t.save(&out)?;
                Ok(serde_json::json!({"cmd": "dvp propose", "trade_id": t.trade_id, "kind": t.kind, "out": out}))
            }
            DvpCmd::Leg { trade } => dvp::leg(&c, &trade),
            DvpCmd::Sign { trade } => dvp::sign(&c, &trade),
            DvpCmd::Submit { trade } => dvp::submit(&c, &trade),
        },
        Sub::Award { cmd: AwardCmd::Sign { award_id, winner, instrument, quantity, consideration, expiry_height, out } } => {
            let a = dvp::award_sign(
                &c,
                &AwardArgs { award_id: id32(&award_id)?, winner: &winner, instrument: &instrument, quantity, consideration, expiry_height },
            )?;
            write_json(&out, &a)?;
            Ok(serde_json::json!({"cmd": "award sign", "award_id": a.award_id, "winner": a.winner_party, "out": out}))
        }
        Sub::Keygen { .. } | Sub::Address => unreachable!(),
    }
}

fn main() {
    match run(Cli::parse()) {
        Ok(v) => println!("result_json={v}"),
        Err(e) => {
            println!("result_json={}", serde_json::json!({"error": format!("{e:#}")}));
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}
