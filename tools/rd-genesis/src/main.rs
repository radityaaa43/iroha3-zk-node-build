//! rd-genesis: the extra genesis instructions of genesis v2 (docs/spec-g2-g5.md sections 1, 2 and 4).
//!
//!   rd-genesis <input.json>   (output: one JSON object on stdout)
//!
//! input : {"discriminant": 753, "genesis_public_key": "ed0120..",
//!          "parties": {"bi": {"public_key": "ed0120..", "view_secret": "<hex32>"}, "bank-a": {..}, ..},
//!          "audit_secret": "<hex32>"}
//! output: {"genesis_account": "..", "parties": <network/public/parties.json>, "instructions": [..]}
//!         Each instruction is in the genesis.json form (JSON object, or a base64 Norito string for the
//!         ones without a JSON form: RegisterVerifyingKey, RegisterZkAsset). `generate.sh` appends them as one
//!         transaction and drops kagami's grants to its hard-coded client account.
//! Secrets stay in the shell; this tool only turns view/audit secrets into their X25519 public keys.

use std::{collections::BTreeMap, str::FromStr};

use iroha_core::zk::confidential_v2;
use iroha_crypto::PublicKey;
use iroha_data_model::{
    account::address::ChainDiscriminantGuard,
    isi::{
        verifying_keys::RegisterVerifyingKey,
        zk::{RegisterZkAsset, ZkAssetMode},
    },
    prelude::*,
    proof::{VerifyingKeyId, VerifyingKeyRecord},
};
use iroha_genesis::{genesis_instructions_json::instruction_value, init_instruction_registry};
use iroha_primitives::{json::Json, numeric::NumericSpec};
use serde_json::{Value, json};

type Res<T> = Result<T, String>;

const PARTIES: [&str; 4] = ["bi", "bank-a", "bank-b", "bank-c"];
const VK_BACKEND: &str = "halo2/ipa";
// Versions as kagami's own NPoS bootstrap registers them (localnet.rs: transfer 1, unshield 2).
const VK_TRANSFER: (&str, u32) = ("vk_transfer", 1);
const VK_UNSHIELD: (&str, u32) = ("vk_unshield", 2);
const DOMAIN: &str = "rd.universal";

fn x25519_pub(secret_hex: &str) -> Res<String> {
    let secret: [u8; 32] = hex::decode(secret_hex)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "x25519 secret must be 32 bytes".to_owned())?;
    Ok(hex::encode(x25519_dalek::x25519(
        secret,
        x25519_dalek::X25519_BASEPOINT_BYTES,
    )))
}

fn name(s: &str) -> Res<Name> {
    s.parse::<Name>().map_err(|e| format!("name {s}: {e}"))
}

fn md(entries: &[(&str, Value)]) -> Res<Metadata> {
    let mut m = Metadata::default();
    for (k, v) in entries {
        m.insert(name(k)?, Json::from_str(&v.to_string()).map_err(|e| e.to_string())?);
    }
    Ok(m)
}

fn ins(i: impl Into<InstructionBox>, out: &mut Vec<Value>) -> Res<()> {
    let text = norito::json::to_json(&instruction_value(&i.into())).map_err(|e| e.to_string())?;
    out.push(serde_json::from_str(&text).map_err(|e| e.to_string())?);
    Ok(())
}

fn run(input: &Value) -> Res<Value> {
    init_instruction_registry();
    let disc = input["discriminant"].as_u64().ok_or("discriminant")?;
    let _guard = ChainDiscriminantGuard::enter(u16::try_from(disc).map_err(|e| e.to_string())?);
    let key = |s: &str| PublicKey::from_str(s).map_err(|e| format!("public key {s}: {e}"));
    let genesis = AccountId::new(key(input["genesis_public_key"].as_str().ok_or("genesis_public_key")?)?);

    let mut account: BTreeMap<&str, AccountId> = BTreeMap::new();
    let mut view: BTreeMap<&str, String> = BTreeMap::new();
    for p in PARTIES {
        let e = &input["parties"][p];
        account.insert(p, AccountId::new(key(e["public_key"].as_str().ok_or(p)?)?));
        view.insert(p, x25519_pub(e["view_secret"].as_str().ok_or(p)?)?);
    }
    let bi = account["bi"].clone();
    let audit = json!([{"version": 1, "pk": x25519_pub(input["audit_secret"].as_str().ok_or("audit_secret")?)?,
                        "activation_height": 1, "retire_height": null}]);

    let domain: DomainId = DomainId::parse_fully_qualified(DOMAIN).map_err(|e| e.to_string())?;
    let rd = AssetDefinitionId::new(domain.clone(), name("rd")?);
    let dfabi = AssetDefinitionId::new(domain.clone(), name("dfabi_2026_01")?);
    let eligible: Vec<String> = PARTIES.iter().map(|p| account[p].to_string()).collect();
    let disclosure = ("rd_disclosure", json!("required"));
    let auditor = ("rd_auditor", json!(bi.to_string()));
    let instrument = json!({"isin": "SYN-DFABI-2026-01", "series": "DFABI-2026-01", "nominal": "1000000",
        "currency": "IDR", "maturity": "2027-12-31", "cap_units": "10000", "issuer": "BI"});

    let mut out = Vec::new();
    // Party accounts: view public key in metadata; bi also carries the audit keys.
    for p in PARTIES {
        let mut entries = vec![("rd_view_pk", json!(view[p]))];
        if p == "bi" {
            entries.push(("rd_audit_keys", audit.clone()));
        }
        ins(Register::account(Account::new(account[p].clone()).with_metadata(md(&entries)?)), &mut out)?;
    }
    // Domain `rd`, owner bi (after the accounts: the transfer needs bi to exist) (Register makes the genesis account the owner, then hand it over).
    ins(Register::domain(Domain::new(domain.clone())), &mut out)?;
    ins(Transfer::domain(genesis.clone(), domain.clone(), bi.clone()), &mut out)?;
    // Grants to bi only, direct (not via a role): .work/reports/s1-genesis-needs.md (P1 rules 5 and 7).
    for perm in ["CanManageVerifyingKeys", "CanSetParameters", "CanUpgradeExecutor"] {
        ins(
            Grant::account_permission(Permission::new(perm.into(), Json::new(())), bi.clone()),
            &mut out,
        )?;
    }
    // Verifying keys must exist before RegisterZkAsset (world.rs RegisterZkAsset::execute).
    let vk = |(n, v): (&str, u32), unshield: bool| -> Res<(VerifyingKeyId, VerifyingKeyRecord)> {
        let rec = if unshield {
            confidential_v2::confidential_unshield_v2_vk_record(n, v)
        } else {
            confidential_v2::confidential_transfer_v2_vk_record(n, v)
        }?;
        Ok((VerifyingKeyId::new(VK_BACKEND, n), rec))
    };
    let (t_id, t_rec) = vk(VK_TRANSFER, false)?;
    let (u_id, u_rec) = vk(VK_UNSHIELD, true)?;
    ins(RegisterVerifyingKey { id: t_id.clone(), record: t_rec }, &mut out)?;
    ins(RegisterVerifyingKey { id: u_id.clone(), record: u_rec }, &mut out)?;
    // The two assets: definition, ZK registration (Hybrid, shield and unshield allowed), then owner bi.
    for (id, nm, extra) in [
        (&rd, "rd", vec![]),
        (
            &dfabi,
            "dfabi_2026_01",
            vec![("rd_instrument", instrument), ("rd_eligible", json!(eligible))],
        ),
    ] {
        let mut entries = vec![disclosure.clone(), auditor.clone()];
        entries.extend(extra);
        ins(
            Register::asset_definition(
                AssetDefinition::new(id.clone(), NumericSpec::integer())
                    .with_name(nm.to_owned())
                    .with_metadata(md(&entries)?),
            ),
            &mut out,
        )?;
        ins(
            RegisterZkAsset::new(
                id.clone(),
                ZkAssetMode::Hybrid,
                true,
                true,
                Some(t_id.clone()),
                Some(u_id.clone()),
                None,
            ),
            &mut out,
        )?;
        ins(Transfer::asset_definition(genesis.clone(), id.clone(), bi.clone()), &mut out)?;
    }

    let mut parties = serde_json::Map::new();
    for p in PARTIES {
        parties.insert(p.into(), json!({"account_id": account[p].to_string(), "view_pk": view[p]}));
    }
    parties.insert("bi_audit".into(), audit);
    parties.insert("assets".into(), json!({"rd": rd.to_string(), "dfabi_2026_01": dfabi.to_string()}));
    Ok(json!({"genesis_account": genesis.to_string(), "parties": parties, "instructions": out}))
}

fn main() {
    let result = std::env::args()
        .nth(1)
        .ok_or_else(|| "usage: rd-genesis <input.json>".to_owned())
        .and_then(|p| std::fs::read_to_string(p).map_err(|e| e.to_string()))
        .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()))
        .and_then(|v| run(&v));
    match result {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("rd-genesis: {e}");
            std::process::exit(2);
        }
    }
}
