//! Deterministic envelope v1 vectors for stream S1 (node parser). File: tests/vectors/envelope_v1.json.
//! Regenerate: `cargo test --release -p rd_driver --test envelope_vectors -- --ignored write_vectors`.

use rd_driver::envelope::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/envelope_v1.json");

fn h32(tag: &str) -> Bytes32 {
    Sha256::digest(format!("rd.iroha2.vector.{tag}").as_bytes()).into()
}
fn h24(tag: &str) -> [u8; 24] {
    h32(tag)[..24].try_into().unwrap()
}
fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

struct Case {
    name: &'static str,
    kind: &'static str,
    asset: &'static str,
    inputs: Vec<Bytes32>,
    outputs: Vec<Bytes32>,
    public_amount: u128,
    carrier: &'static str,
    key_version: u32,
}

impl Case {
    /// Binding public amount: ZkTransfer binds 0.
    fn bound_amount(&self) -> u128 {
        if self.kind == "transfer" { 0 } else { self.public_amount }
    }
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "shield",
            kind: "shield",
            asset: "rd#rd",
            inputs: vec![],
            outputs: vec![h32("shield.commitment")],
            public_amount: 1000,
            carrier: "transaction metadata key rd_envelope (hex)",
            key_version: 1,
        },
        Case {
            name: "transfer_one_input_two_outputs",
            kind: "transfer",
            asset: "rd#rd",
            inputs: vec![h32("transfer.nullifier0")],
            outputs: vec![h32("transfer.out0"), h32("transfer.out1")],
            public_amount: 0,
            carrier: "OpenVerifyEnvelope.aux of ZkTransfer.proof",
            key_version: 1,
        },
        Case {
            name: "unshield_no_change",
            kind: "unshield",
            asset: "rd#rd",
            inputs: vec![h32("unshield.nullifier0"), h32("unshield.nullifier1")],
            outputs: vec![],
            public_amount: 250,
            carrier: "OpenVerifyEnvelope.aux of Unshield.proof",
            key_version: 1,
        },
        Case {
            name: "transfer_key_version_9",
            kind: "transfer",
            asset: "dfabi_2026_01#rd",
            inputs: vec![h32("kv9.nullifier0")],
            outputs: vec![h32("kv9.out0")],
            public_amount: 0,
            carrier: "OpenVerifyEnvelope.aux of ZkTransfer.proof",
            key_version: 9,
        },
    ]
}

struct Built {
    env: Envelope,
    wire: Vec<u8>,
    pt: Plaintext,
    bi_sk: Bytes32,
    rc_sk: Bytes32,
    params: SealParams,
}

fn build(c: &Case) -> Built {
    let bi_sk = h32("bi.audit.v1.secret");
    let rc_sk = h32("receiver.view.secret");
    let outs_json: Vec<OutputNote> = c
        .outputs
        .iter()
        .enumerate()
        .map(|(i, _)| OutputNote {
            amount: format!("{}", 100 + i as u32),
            rho: hx(&h32(&format!("{}.rho{i}", c.name))),
            diversifier: hx(&h32(&format!("{}.div{i}", c.name))),
            owner_tag: hx(&h32(&format!("{}.tag{i}", c.name))),
            owner: if i == 0 { "bank-b".into() } else { "bank-a".into() },
        })
        .collect();
    let pt = Plaintext {
        v: 1,
        kind: c.kind.into(),
        asset: c.asset.into(),
        sender: "bank-a".into(),
        reference: format!("vector-{}", c.name),
        inputs: c.inputs.iter().map(|n| InputRef { nullifier: hx(n) }).collect(),
        outputs: outs_json,
        public_amount: if c.kind == "transfer" { None } else { Some(c.public_amount.to_string()) },
    };
    let params = SealParams {
        key_version: c.key_version,
        bi_pk: public_from_secret(&bi_sk),
        rc_pk: public_from_secret(&rc_sk),
        eph_bi: h32(&format!("{}.eph.bi", c.name)),
        eph_rc: h32(&format!("{}.eph.rc", c.name)),
        nonce_bi: h24(&format!("{}.nonce.bi", c.name)),
        nonce_rc: h24(&format!("{}.nonce.rc", c.name)),
    };
    let ctx = BindingCtx {
        asset: c.asset,
        inputs: &c.inputs,
        outputs: &c.outputs,
        public_amount: c.bound_amount(),
    };
    let env = seal(&pt, &ctx, &params).unwrap();
    let wire = env.encode();
    Built { env, wire, pt, bi_sk, rc_sk, params }
}

fn ctx_json(c: &Case) -> Value {
    json!({
        "asset": c.asset,
        "inputs": c.inputs.iter().map(|b| hx(b)).collect::<Vec<_>>(),
        "outputs": c.outputs.iter().map(|b| hx(b)).collect::<Vec<_>>(),
        "public_amount": c.bound_amount().to_string(),
    })
}

fn vectors() -> Value {
    let all = cases();
    let mut cs = vec![];
    for c in &all {
        let b = build(c);
        let ctx = BindingCtx {
            asset: c.asset,
            inputs: &c.inputs,
            outputs: &c.outputs,
            public_amount: c.bound_amount(),
        };
        assert!(Envelope::parse(&b.wire).unwrap().binds(&ctx));
        assert_eq!(b.env.open_bi(&b.bi_sk).unwrap(), b.pt);
        assert_eq!(b.env.open_rc(&b.rc_sk).unwrap(), b.pt);
        cs.push(json!({
            "name": c.name,
            "kind": c.kind,
            "carrier": c.carrier,
            "key_version": c.key_version,
            "instruction": ctx_json(c),
            "plaintext": String::from_utf8(b.pt.to_bytes()).unwrap(),
            "bi_audit_secret": hx(&b.bi_sk),
            "bi_audit_pk": hx(&b.params.bi_pk),
            "receiver_view_secret": hx(&b.rc_sk),
            "receiver_view_pk": hx(&b.params.rc_pk),
            "eph_bi_secret": hx(&b.params.eph_bi),
            "eph_rc_secret": hx(&b.params.eph_rc),
            "nonce_bi": hx(&b.params.nonce_bi),
            "nonce_rc": hx(&b.params.nonce_rc),
            "e_bi": hx(&b.env.e_bi),
            "e_rc": hx(&b.env.e_rc),
            "ct_bi": hx(&b.env.ct_bi),
            "ct_rc": hx(&b.env.ct_rc),
            "binding": hx(&b.env.binding),
            "envelope_hex": hx(&b.wire),
            "expect": "parse_ok, binding_ok",
        }));
    }
    // Negative cases derived from the transfer case.
    let c = &all[1];
    let b = build(c);
    let ctx_ok = BindingCtx { asset: c.asset, inputs: &c.inputs, outputs: &c.outputs, public_amount: 0 };
    let mut neg = vec![];
    let mut push = |name: &str, desc: &str, wire: Vec<u8>, instr: Value, expect: &str| {
        neg.push(json!({"name": name, "description": desc, "instruction": instr, "envelope_hex": hx(&wire), "expect": expect}));
    };
    let mut trailing = b.wire.clone();
    trailing.push(0);
    push("trailing_byte", "one extra byte after binding", trailing, ctx_json(c), "parse_error");
    push("truncated", "last byte missing", b.wire[..b.wire.len() - 1].to_vec(), ctx_json(c), "parse_error");
    let mut magic = b.wire.clone();
    magic[3] = b'2';
    push("bad_magic", "RDE2", magic, ctx_json(c), "parse_error");
    let mut short = b.env.clone();
    short.ct_rc.truncate(16);
    let short = short.with_binding(&ctx_ok).unwrap();
    push("short_ciphertext", "ct_rc is 16 bytes (tag only)", short.encode(), ctx_json(c), "parse_error");
    let mut flip = b.env.clone();
    flip.binding[0] ^= 1;
    push("binding_bit_flip", "first binding byte flipped", flip.encode(), ctx_json(c), "binding_mismatch");
    let mut ct = b.env.clone();
    ct.ct_bi[0] ^= 1;
    push("ct_bi_bit_flip_binding_not_updated", "bit flip in ct_bi, old binding", ct.encode(), ctx_json(c), "binding_mismatch");
    let ct2 = ct.clone().with_binding(&ctx_ok).unwrap();
    push(
        "ct_bi_bit_flip_binding_updated",
        "bit flip in ct_bi with the binding recomputed: structurally valid, the node accepts, only BI audit (AEAD failure) detects it (TC-AUD-03 partial)",
        ct2.encode(),
        ctx_json(c),
        "parse_ok, binding_ok",
    );
    let mut instr = ctx_json(c);
    instr["asset"] = json!("dfabi_2026_01#rd");
    push("asset_mismatch", "envelope asset differs from the instruction asset", b.wire.clone(), instr, "asset_mismatch");
    let mut instr = ctx_json(c);
    instr["outputs"] = json!([hx(&h32("transfer.out0")), hx(&h32("other"))]);
    push("outputs_differ", "an instruction output differs from the bound outputs", b.wire.clone(), instr, "binding_mismatch");
    let mut instr = ctx_json(c);
    instr["inputs"] = json!([]);
    push("inputs_differ", "instruction has no nullifier", b.wire.clone(), instr, "binding_mismatch");
    json!({
        "spec": "platforms/iroha2/docs/spec-g2-g5.md section 3 (envelope v1)",
        "note": "Synthetic. Commitments, nullifiers and note fields are arbitrary 32-byte values; asset and account strings are opaque labels. key_version is checked against bi.rd_audit_keys by the node, not by these vectors. All keys are test keys.",
        "encoding": "hex lowercase without 0x",
        "cases": cs,
        "negative": neg,
    })
}

#[test]
fn vectors_match_file() {
    let want = vectors();
    let got: Value = serde_json::from_str(&std::fs::read_to_string(PATH).expect("vector file")).unwrap();
    assert_eq!(got, want, "tests/vectors/envelope_v1.json is stale: regenerate with --ignored write_vectors");
}

#[test]
#[ignore]
fn write_vectors() {
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors()).unwrap() + "\n").unwrap();
}
