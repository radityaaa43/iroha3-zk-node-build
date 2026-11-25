# rd2: RD/DFABI confidential driver (Iroha 2)

Rust CLI and library (`rd_driver`, binary `rd2`) for the Iroha 2 track: party wallets, BI issuance, private
transfer and unshield with real Halo2 v2 proofs, BI audit, and negative tests. Contract: `spec-g2-g5.md` (envelope v1, parties, asset ids) in the platform repo.


## Build and test

The crate is a member of the upstream workspace as `crates/rd_driver` (`ci/prepare-src.sh` copies `driver/` in). It is
never built on a developer host: the `ci` workflow runs `cargo test --release -p rd_driver -p rd_genesis` on every push
(release mode, proving is impractical in debug). Regenerate the vectors in CI-like conditions with
`cargo test --release -p rd_driver --test envelope_vectors -- --ignored write_vectors`.

Tests:

| Test | What it proves |
|---|---|
| `src/envelope.rs` unit tests | round trip, layout lengths, binding mismatch, wrong key, tamper, malformed input |
| `tests/envelope_vectors.rs` | `tests/vectors/envelope_v1.json` is what the code produces (S1 tests the node parser against it). Regenerate with the command above |
| `tests/offline_prover.rs` | no node: issue 250 to A, A sends 100 to B with change, B unshields 100. Real proofs, envelope in `OpenVerifyEnvelope.aux` (proof still verifies), recipient scan, BI audit clean, and BI detects a lying envelope, a missing envelope and a forged signer |
| `tests/offline_dvp.rs` | no node: the two-party `dvp` flow through trade.json for UC-06 (interbank) and UC-03 (award, BI delivers DFABI it shielded to itself). Real proofs for both legs, intents verify over the spec 4b tuple (hand-built preimage), a mutated leg, id, expiry or chain breaks the digest, award signature verifies and a changed field breaks it, BI audit of both legs is clean |
| `tests/wallet_cli.rs` | keygen writes a loadable wallet, `parties.json` parsing (audit key choice, address, asset names), note selection |

## Commands

Global flags: `--torii <url> --chain <id> --parties <parties.json> --wallet <dir> --party <name>`.
Every command prints one line `result_json=<json>`; on failure `result_json={"error":...}` and exit code 1.

| Command | Who | What |
|---|---|---|
| `keygen [--audit-key]` | tests | writes a wallet dir (spec 1 layout) and prints the public halves (`account_id`, `view_pk`, `address`, `bi_audit`) for `parties.json` |
| `address` | any | prints the party's receive address `{owner_tag, diversifier}` |
| `issue --asset rd --to bank-a --amount N` | BI | one tx: `Mint` to BI, `Shield` to the bank's address, envelope in tx metadata `rd_envelope` |
| `scan --asset rd` | any | replays blocks from 1 to the tip into the leaf list, checks the root against `/v1/zk/roots`, trial-decrypts envelopes with the view secret, writes `<wallet>/notes.json`; reports anomalies (a note that does not match the chain) and whether the registered VKs match the locally generated ones |
| `transfer --asset rd --to bank-b --amount N` | bank | scans, selects 1-2 notes, proves, builds `ZkTransfer` (recipient output, then change), envelope in `aux`, submits, waits |
| `unshield --asset rd --amount N [--to party]` | bank | exits whole notes (v2 has no change output, so `N` must equal the sum of 1-2 notes) |
| `audit --asset rd [--asset dfabi_2026_01]` | BI | decrypts every envelope with `audit-v<N>.json`, recomputes commitments, checks conservation and supply, prints detected violations |
| `dvp propose --trade-id <hex32\|auto> --deliver-asset dfabi_2026_01 --deliver-amount Q --pay-asset rd --pay-amount P --seller <party> --buyer <party> --expiry-height H [--kind interbank\|award] [--award award.json] --out trade.json` | either | writes the trade file; no keys, no node. `seller` delivers the DFABI and is paid in RD |
| `dvp leg --trade trade.json` | seller, then or before buyer | scans, proves my leg (seller: delivery in `deliver-asset`, buyer: payment in `pay-asset`) with the counterparty as recipient and the BI envelope in `aux`, writes it into the trade file; my change note goes into `notes.json` at once |
| `dvp sign --trade trade.json` | seller and buyer, each | needs both legs. Checks the other party's leg (proof verifies, envelope binds, decrypts for me, pays me exactly the agreed amount in recomputable notes), then signs the spec 4b digest with my account key and appends the intent |
| `dvp submit --trade trade.json` | seller or buyer | needs both intents; verifies them, submits one `ConfidentialDvp` (my account is the transaction authority), waits, prints the tx hash or the node's `rd-dvp:` error |
| `award sign --award-id <hex32\|auto> --winner <party> --instrument dfabi_2026_01 --quantity Q --consideration P --expiry-height H --out award.json` | BI | signs the UC-03 award record with the `bi` account key (the node wants the owner of domain `rd`) |
| `negative --asset rd --other-asset dfabi_2026_01 --to bank-b` | bank | submits the attacks below and prints `expected` vs `got` per case |
| `bench --asset rd --to bank-b,bank-c [--stages 1,2,4,8] [--stage-secs 120] [--warmup-secs 60] [--start-at <unix s>] --out bench.jsonl [--public] [--amount 1]` | bank | closed-loop transfer load (2.6 ladder): one worker per note, each spends its own chain (amount to the next recipient, change to itself); a block-stream thread keeps the leaf list current. One JSON line per attempt (`step`, `submit_ms`, `done_ms`, `prove_ms`, `ok`, `err`). `--public` sends a transparent `Transfer` instead. Needs one unspent note per worker; keeps each chain's last change note in `notes.json` |
| `mint-public --asset rd --to <party> --amount N` | BI | public (transparent) balance for `bench --public` |

`negative` builds one valid proof and mutates it, so it needs one unspent note (and one spent note for the replay case):

| Case | Mutation | Node must |
|---|---|---|
| `duplicate_nullifier` (TC-CRYP-04) | `inputs = [n, n]` | reject |
| `replayed_nullifier` (TC-CRYP-05) | fresh proof over an already spent note | reject (nullifier seen) |
| `wrong_root` (TC-CRYP-06) | random `root_hint` | reject (unknown root) |
| `tampered_proof` (TC-CRYP-09) | one bit flipped in the proof | reject |
| `wrong_asset_tag` (TC-CRYP-06) | proof for asset A submitted as asset B | reject |
| `envelope_missing` (TC-AUD-02) | empty `aux` | reject `rd-disclosure:` (P2) |
| `binding_mismatch` (TC-AUD-05 family) | envelope bound to other outputs | reject `rd-disclosure:` (P2) |

On a node without P2 the last two are accepted (and consume the note), so they run last. TC-CRYP-01 and -03 (inflated
output, wrong owner) need the unchecked builder from the upstream patch in the research note and are not in the driver.

## DvP flows (fork patch P3, spec 4b)

Each party only ever uses its own keys; the only thing exchanged is `trade.json` (legs are public instruction data, amounts
stay in proofs and envelopes). One DvP per trade id; an expired or failed DvP leaves everything untouched (nothing is locked:
a party that spends its input note elsewhere makes the DvP fail).

`trade.json` (`v: 1`): `trade_id`, `kind`, `chain`, `expiry_height`, `seller`, `buyer`, `deliver {asset, amount}`, `pay {asset, amount}`,
`award` (award.json content or null), `delivery_leg` and `payment_leg` (`{by, asset, inputs[], outputs[], root, proof}`, `proof` = hex of the
`OpenVerifyEnvelope` bytes, envelope inside), `intents[]` (`{party, signer, signature}`; signature over the 32 digest bytes).
`award.json`: `{v, chain, award_id, winner_party, winner, instrument, quantity, consideration, expiry_height, bi_signature}`.

**UC-02 first** (DFABI to the BI treasury), as BI: `rd2 issue --asset dfabi_2026_01 --to bi --amount N`. Needs `bi` `address` and `view_pk` in
`parties.json` (`rd2 address`). Banks need RD notes (`issue --asset rd --to bank-x`).

**UC-03 award (BI delivers DFABI to the winner, the winner pays RD to BI)**, winner `bank-a`:
1. BI: `award sign --award-id auto --winner bank-a --instrument dfabi_2026_01 --quantity Q --consideration P --expiry-height H --out award.json`
2. BI: `dvp propose --trade-id auto --deliver-asset dfabi_2026_01 --deliver-amount Q --pay-asset rd --pay-amount P --seller bi --buyer bank-a --expiry-height H --award award.json --out trade.json`; send `trade.json` to bank-a.
3. BI and bank-a, either order: `dvp leg --trade trade.json` (pass the file along between the two).
4. BI and bank-a: `dvp sign --trade trade.json` (each checks the other leg first).
5. Either: `dvp submit --trade trade.json`. Then both `scan` both assets; BI `audit --asset rd --asset dfabi_2026_01`.

**UC-06 interbank (bank-a delivers DFABI to bank-b, bank-b pays RD to bank-a)**: step 2 with `--seller bank-a --buyer bank-b` and no `--award`
(`--kind interbank` is the default), then steps 3 to 5. `expiry-height` must be at or above the block height at submit time.

Rules the node applies (all errors start with `rd-dvp:`): expiry, unused trade id, the two assets differ and both carry `rd_disclosure = "required"`,
two different registered signers one of whom submits, both intents verify, `award`: BI signs the award, the BI account is a signer, the winner is a signer,
instrument is the delivery asset, award not expired or reused. Each leg then runs the stock `ZkTransfer` path (P2 envelope and proof checks).

## Files

- Wallet dir (spec 1): `account.json`, `view.json`, `spend.key`, BI also `audit-v1.json` (`{"public","secret"}`), and
  `notes.json` written by the driver: array of `{asset, commitment, amount, rho, diversifier, owner_tag, leaf_index, spent, nullifier, source_tx}`.
- `parties.json` (spec 1) plus an optional per-party `"address": {"owner_tag","diversifier"}` (see gaps).
- Envelope vectors: `tests/vectors/envelope_v1.json`.

## Enforced on chain vs detected by BI

| Property | Node (stock) | Node + P2 | BI `audit` |
|---|---|---|---|
| Proof valid, amounts conserved in the circuit, nullifier unspent, root known, asset and chain tag | yes | yes | no |
| Envelope present, parses, asset matches, key version active, binding matches the instruction | no | yes (fail closed) | re-checks binding |
| Envelope decrypts for BI, plaintext is consistent (kind, asset, signer, nullifiers, public amount) | no | no | yes |
| Output commitments equal `derive_confidential_note_v2` of the plaintext (wrong amount, rho or owner tag) | no | no | yes |
| Conservation: inputs equal outputs plus public amount, Shield amount equals the committed amount | circuit only (no range checks, Shield unchecked) | same | yes (inputs matched by amount to the sender's earlier outputs, BI cannot derive nullifiers) |
| Supply: shielded outstanding equals the sum of unspent notes seen in envelopes | no | no | yes |

## Gaps and decisions (for the lead)

1. **Recipient address.** Spec 1 publishes only `view_pk` per party. A sender needs the recipient's `owner_tag` and
   `diversifier`, which depend on the recipient's spend key. The driver uses one address per party (default
   diversifier) and reads it from `parties.json` `"address"` (or `--to-owner-tag/--to-diversifier`). `rd2 address` and
   `rd2 keygen` print it. `network/generate.sh` should add it to `parties.json`. One fixed address per party links all of a party's incoming notes by tag.
2. **Shield `rc` key.** Spec 3.3 says the Shield envelope's `rc` is the sender's own view key. For `issue` into a bank's
   address the bank must learn the note, so `rc` is the bank's view key. No wire or binding change.
3. **Own change is not recoverable from the chain.** The transfer envelope is encrypted to BI and the recipient only.
   The sender keeps its change note in `notes.json`; losing that file loses the change note (a third ciphertext would fix it, a wire change).
4. The leaf list is replayed from the blocks WebSocket stream (`/v1/confidential/notes` omits the envelope and, per research, Unshield change).
5. The VK used for proving is regenerated locally (deterministic); `scan` reports whether it matches the registered one. Not yet confirmed against a live node.
6. Unshield v2 only: whole-note exits, no change.
7. DvP: `kind` and `award` are not inside the signed tuple (node patch gap, planned v2 tuple); amounts of the legs are hidden, so each party relies on `sign`'s check of the other leg's envelope (the sender could still lie to BI in the envelope it encrypts to BI: `audit` detects that). `dvp leg` writes my change note to `notes.json` before the DvP commits, `scan` binds it to its leaf afterwards (a failed DvP leaves a harmless unbound note). `scan` and `audit` replay `ConfidentialDvp` legs as transfers; BI audit accepts either signer as the sender of a leg. `notes.json` now keeps notes of all assets (a scan of one asset used to drop the other's).
8. Client config: the loader needs an account domain; `rd.universal` is written and is only syntax-checked.
