//! Note model and prover glue over `iroha_core::zk::confidential_v2` (research g2 Q2-Q4).

use eyre::{Result, eyre};
use iroha_core::zk::confidential_v2 as cv2;
use iroha_data_model::{
    ChainId,
    proof::{ProofBox, VerifyingKeyBox},
    zk::OpenVerifyEnvelope,
};
use rand_core_06::{OsRng, RngCore};

use crate::envelope::{self, BindingCtx, Bytes32, Envelope, Plaintext, SealParams};

pub fn s(e: String) -> eyre::Report {
    eyre!(e)
}

pub fn rand32() -> Bytes32 {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

/// Public receive address: what a sender needs to create a note for this party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub owner_tag: Bytes32,
    pub diversifier: Bytes32,
}

/// The party's single address: default diversifier (spec gap, see README: parties.json carries it).
pub fn address_of(spend_key: &[u8]) -> Address {
    let diversifier = cv2::default_confidential_diversifier_v2();
    let owner_tag = cv2::derive_confidential_owner_tag_v2_with_diversifier(spend_key, diversifier)
        .expect("default diversifier is canonical");
    Address { owner_tag, diversifier }
}

pub fn commitment(asset: &str, amount: u128, rho: Bytes32, owner_tag: Bytes32) -> Result<Bytes32> {
    cv2::derive_confidential_note_v2(asset, amount, rho, owner_tag).map_err(s)
}

pub fn nullifier(chain: &str, asset: &str, spend_key: &[u8], rho: Bytes32) -> Bytes32 {
    cv2::derive_confidential_nullifier_v2(chain, asset, spend_key, rho)
}

pub fn leaf_root(leaves: &[Bytes32]) -> Result<Bytes32> {
    cv2::compute_confidential_root_v2(leaves).map_err(s)
}

#[derive(Clone, Debug)]
pub struct InNote {
    pub amount: u128,
    pub rho: Bytes32,
    pub diversifier: Bytes32,
    pub leaf_index: usize,
}

#[derive(Clone, Debug)]
pub struct OutSpec {
    pub amount: u128,
    pub addr: Address,
    /// Account the output belongs to (envelope `owner`).
    pub owner: String,
}

/// An output note with everything the wallet and the envelope need.
#[derive(Clone, Debug)]
pub struct NoteOut {
    pub amount: u128,
    pub rho: Bytes32,
    pub diversifier: Bytes32,
    pub owner_tag: Bytes32,
    pub owner: String,
    pub commitment: Bytes32,
}

pub struct BuiltTransfer {
    pub nullifiers: Vec<Bytes32>,
    /// Output commitments in proof order (= ZkTransfer.outputs order).
    pub outputs: Vec<Bytes32>,
    pub notes: Vec<NoteOut>,
    pub root: Bytes32,
    pub proof: ProofBox,
}

pub fn transfer_vk() -> Result<VerifyingKeyBox> {
    cv2::confidential_transfer_v2_vk_box().map_err(s)
}

pub fn unshield_vk() -> Result<VerifyingKeyBox> {
    cv2::confidential_unshield_v2_vk_box().map_err(s)
}

pub fn build_transfer(
    chain: &str,
    asset: &str,
    spend_key: &[u8],
    leaves: &[Bytes32],
    ins: &[InNote],
    outs: &[OutSpec],
) -> Result<BuiltTransfer> {
    let root = leaf_root(leaves)?;
    let vk = transfer_vk()?;
    let mut notes = vec![];
    for o in outs {
        let rho = rand32();
        notes.push(NoteOut {
            amount: o.amount,
            rho,
            diversifier: o.addr.diversifier,
            owner_tag: o.addr.owner_tag,
            owner: o.owner.clone(),
            commitment: commitment(asset, o.amount, rho, o.addr.owner_tag)?,
        });
    }
    let p = cv2::build_confidential_transfer_proof_v2(
        &ChainId::from(chain),
        asset,
        spend_key,
        leaves,
        &ins.iter()
            .map(|i| cv2::ConfidentialTransferInputV2 {
                amount: i.amount,
                rho: i.rho,
                diversifier: i.diversifier,
                leaf_index: i.leaf_index,
            })
            .collect::<Vec<_>>(),
        &notes
            .iter()
            .map(|n| cv2::ConfidentialTransferOutputV2 { amount: n.amount, rho: n.rho, owner_tag: n.owner_tag })
            .collect::<Vec<_>>(),
        root,
        cv2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        &vk,
    )
    .map_err(s)?;
    if p.output_commitments != notes.iter().map(|n| n.commitment).collect::<Vec<_>>() {
        return Err(eyre!("prover output commitments differ from the wallet's own recomputation"));
    }
    Ok(BuiltTransfer { nullifiers: p.nullifiers, outputs: p.output_commitments, notes, root: p.root, proof: p.proof })
}

pub struct BuiltUnshield {
    pub nullifiers: Vec<Bytes32>,
    pub root: Bytes32,
    pub public_amount: u128,
    pub proof: ProofBox,
}

/// Unshield v2 exits whole notes (no change output, research Q4): `public_amount = sum(inputs)`.
pub fn build_unshield(chain: &str, asset: &str, spend_key: &[u8], leaves: &[Bytes32], ins: &[InNote]) -> Result<BuiltUnshield> {
    let root = leaf_root(leaves)?;
    let vk = unshield_vk()?;
    let public_amount: u128 = ins.iter().map(|i| i.amount).sum();
    let p = cv2::build_confidential_unshield_proof_v2(
        &ChainId::from(chain),
        asset,
        spend_key,
        leaves,
        &ins.iter()
            .map(|i| cv2::ConfidentialUnshieldInputV2 {
                amount: i.amount,
                rho: i.rho,
                diversifier: i.diversifier,
                leaf_index: i.leaf_index,
            })
            .collect::<Vec<_>>(),
        public_amount,
        root,
        cv2::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID,
        &vk,
    )
    .map_err(s)?;
    Ok(BuiltUnshield { nullifiers: p.nullifiers, root: p.root, public_amount, proof: p.proof })
}

/// Pick 1 or 2 notes covering `amount`: the smallest single note, else the cheapest pair.
pub fn select<T>(notes: &[T], amt: impl Fn(&T) -> u128, amount: u128) -> Option<Vec<usize>> {
    let mut best: Option<(u128, Vec<usize>)> = None;
    for i in 0..notes.len() {
        let a = amt(&notes[i]);
        if a >= amount && best.as_ref().is_none_or(|(b, v)| v.len() == 2 || a < *b) {
            best = Some((a, vec![i]));
        }
    }
    if best.is_some() {
        return best.map(|b| b.1);
    }
    for i in 0..notes.len() {
        for j in i + 1..notes.len() {
            let t = amt(&notes[i]) + amt(&notes[j]);
            if t >= amount && best.as_ref().is_none_or(|(b, _)| t < *b) {
                best = Some((t, vec![i, j]));
            }
        }
    }
    best.map(|b| b.1)
}

/// Pick 1 or 2 notes whose sum equals `amount` exactly (unshield has no change).
pub fn select_exact<T>(notes: &[T], amt: impl Fn(&T) -> u128, amount: u128) -> Option<Vec<usize>> {
    for i in 0..notes.len() {
        if amt(&notes[i]) == amount {
            return Some(vec![i]);
        }
    }
    for i in 0..notes.len() {
        for j in i + 1..notes.len() {
            if amt(&notes[i]) + amt(&notes[j]) == amount {
                return Some(vec![i, j]);
            }
        }
    }
    None
}

// ----- proof attachment <-> envelope aux --------------------------------------------------------

/// Put the `RdEnvelopeV1` bytes into `OpenVerifyEnvelope.aux` of the proof (spec 3.5).
pub fn set_aux(proof: &mut ProofBox, aux: &[u8]) -> Result<()> {
    let mut env: OpenVerifyEnvelope =
        norito::decode_from_bytes(&proof.bytes).map_err(|e| eyre!("decode OpenVerifyEnvelope: {e}"))?;
    env.aux = aux.to_vec();
    proof.bytes = norito::to_bytes(&env).map_err(|e| eyre!("encode OpenVerifyEnvelope: {e}"))?;
    Ok(())
}

/// `aux` of the proof's `OpenVerifyEnvelope`; `None` if the proof does not decode or aux is empty.
pub fn get_aux(proof: &ProofBox) -> Option<Vec<u8>> {
    let env: OpenVerifyEnvelope = norito::decode_from_bytes(&proof.bytes).ok()?;
    (!env.aux.is_empty()).then_some(env.aux)
}

/// Flip one bit in the middle of the inner proof bytes (negative tests).
pub fn tamper_proof(proof: &mut ProofBox) -> Result<()> {
    let mut env: OpenVerifyEnvelope =
        norito::decode_from_bytes(&proof.bytes).map_err(|e| eyre!("decode OpenVerifyEnvelope: {e}"))?;
    let m = env.proof_bytes.len() / 2;
    env.proof_bytes[m] ^= 1;
    proof.bytes = norito::to_bytes(&env).map_err(|e| eyre!("encode OpenVerifyEnvelope: {e}"))?;
    Ok(())
}

// ----- envelope construction --------------------------------------------------------------------

pub fn plaintext(
    kind: &str,
    asset: &str,
    sender: &str,
    reference: &str,
    nullifiers: &[Bytes32],
    notes: &[NoteOut],
    public_amount: Option<u128>,
) -> Plaintext {
    Plaintext {
        v: 1,
        kind: kind.into(),
        asset: asset.into(),
        sender: sender.into(),
        reference: reference.into(),
        inputs: nullifiers.iter().map(|n| envelope::InputRef { nullifier: hex::encode(n) }).collect(),
        outputs: notes
            .iter()
            .map(|n| envelope::OutputNote {
                amount: n.amount.to_string(),
                rho: hex::encode(n.rho),
                diversifier: hex::encode(n.diversifier),
                owner_tag: hex::encode(n.owner_tag),
                owner: n.owner.clone(),
            })
            .collect(),
        public_amount: public_amount.map(|a| a.to_string()),
    }
}

pub fn make_envelope(
    pt: &Plaintext,
    ctx: &BindingCtx<'_>,
    key_version: u32,
    bi_pk: Bytes32,
    rc_pk: Bytes32,
) -> Result<Envelope> {
    envelope::seal(pt, ctx, &SealParams::random(key_version, bi_pk, rc_pk)).map_err(|e| eyre!("{e}"))
}
