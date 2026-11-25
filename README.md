# iroha3-zk-node-build

Builds and tests the Iroha 3 node image of the RD/DFABI exploration on **GitHub-hosted runners** (this repo is public
for the 4 vCPU / 16 GB runner; it holds no keys, configs or cluster data). The network, deployment and findings live in
the private KPID repo, track `platforms/iroha` (ADR 0005: Iroha 3 blueprint v1.0, permissioned, one lane).

| Path | What |
|---|---|
| `ci/prepare-src.sh` | upstream `hyperledger-iroha/iroha` @ `fbe677b9` + build fix + `image/Cargo.lock` + `fork/patches/*` + our crates |
| `fork/patches/` | P1 authority rules, P2 fail-closed BI disclosure envelope, P1b `vk_unshield` lock, P3 `ConfidentialDvp` |
| `driver/` | `rd2`: confidential wallet, BI audit, DvP, negative tests, bench |
| `tools/rd-genesis/` | genesis v2 instructions |
| `image/build.sh` | node image: `iroha3d iroha3 kagami rd2 rd-genesis`, features `build-i3`, profile `deploy` (release + LTO) |

Workflows: `ci` (every push: lockfile check, `rd_driver`/`rd_genesis` tests, `iroha_core` `rd_` tests), `build-image`
(push to `main` or manual: `ghcr.io/radityaaa43/iroha3-zk-node:fbe677b9-<commit>`, digest in the job summary).

Forked from `radityaaa43/iroha2-rd-node-build` @ `6a53038` (same pin, patches and driver; only the build line and
profile differ). The protocol domain separators keep their `rd.iroha2.*` names on purpose: they are part of the
envelope v1 and DvP v1 formats and the committed test vectors; renaming them is a protocol version change.
Spec references point to `platforms/iroha2/docs/` in KPID, where the protocol was designed.

Synthetic test data only. Not production software.
