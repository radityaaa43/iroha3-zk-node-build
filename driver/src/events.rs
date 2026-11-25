//! Chain-independent view of the confidential instructions of one asset, plus the leaf list replay.
//! `chain.rs` fills it from blocks; `scan` and `audit` consume it (and are unit-tested without a node).

use std::collections::HashSet;

use crate::envelope::{BindingCtx, Bytes32};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Shield,
    Transfer,
    Unshield,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shield => "shield",
            Self::Transfer => "transfer",
            Self::Unshield => "unshield",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub block: u64,
    pub tx: String,
    /// Signing account (display form).
    pub authority: String,
    pub kind: Kind,
    pub asset: String,
    /// Shield: the debited account.
    pub from: Option<String>,
    /// ZkTransfer/Unshield: nullifiers as submitted.
    pub inputs: Vec<Bytes32>,
    /// Shield: `[note_commitment]`; ZkTransfer: outputs in proof order; Unshield: change outputs.
    pub outputs: Vec<Bytes32>,
    /// Shield amount / Unshield public amount / 0.
    pub public_amount: u128,
    pub root_hint: Option<Bytes32>,
    /// Raw `RdEnvelopeV1` bytes if the carrier held something.
    pub envelope: Option<Vec<u8>>,
    /// ConfidentialDvp legs: the two intent signers (display form). Either may be the sender of its leg; the
    /// transaction authority is only one of them. Empty for every other instruction.
    pub signers: Vec<String>,
    /// Index of the first leaf this instruction appended (set by `Ledger::push`).
    pub leaf_start: usize,
}

impl Event {
    pub fn binding_ctx(&self) -> BindingCtx<'_> {
        BindingCtx {
            asset: &self.asset,
            inputs: &self.inputs,
            outputs: &self.outputs,
            public_amount: self.public_amount,
        }
    }

    /// Leaf index of `outputs[i]`. The node appends ZkTransfer/Unshield outputs sorted.
    pub fn leaf_index_of(&self, i: usize) -> usize {
        match self.kind {
            Kind::Shield => self.leaf_start,
            _ => {
                let mut sorted = self.outputs.clone();
                sorted.sort_unstable();
                self.leaf_start + sorted.iter().position(|c| *c == self.outputs[i]).expect("own output")
            }
        }
    }
}

#[derive(Default, Debug)]
pub struct Ledger {
    pub leaves: Vec<Bytes32>,
    pub events: Vec<Event>,
    pub nullifiers: HashSet<Bytes32>,
}

impl Ledger {
    /// Apply an event the node executed successfully (same append rule as the node, W:8306, 8527-8538, 8809-8812).
    pub fn push(&mut self, mut ev: Event) {
        ev.leaf_start = self.leaves.len();
        match ev.kind {
            Kind::Shield => self.leaves.extend_from_slice(&ev.outputs),
            _ => {
                let mut s = ev.outputs.clone();
                s.sort_unstable();
                self.leaves.extend(s);
            }
        }
        self.nullifiers.extend(ev.inputs.iter().copied());
        self.events.push(ev);
    }
}
