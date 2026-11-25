#!/usr/bin/env bash
# Prepare the Iroha 3 source tree this repo builds: upstream at the pin, our build fix, our lockfile, the fork
# patches in order, and our crates as workspace members. Used by image/build.sh and by the CI test job.
#   ci/prepare-src.sh <dir>     (<dir> must not exist, or must be an existing checkout of the pin)
set -euo pipefail
IROHA_COMMIT=fbe677b98ed309808074ec5a0a8a16de2a0c2286
here=$(cd "$(dirname "$0")/.." && pwd)
SRC=${1:?usage: prepare-src.sh <dir>}

if [[ ! -d $SRC/.git ]]; then
  git init -q "$SRC"
  git -C "$SRC" fetch -q --depth 1 https://github.com/hyperledger-iroha/iroha "$IROHA_COMMIT"
  git -C "$SRC" -c advice.detachedHead=false checkout -q FETCH_HEAD
fi
[[ $(git -C "$SRC" rev-parse HEAD) == "$IROHA_COMMIT" ]] || { echo "source at $SRC is not $IROHA_COMMIT" >&2; exit 1; }
git -C "$SRC" checkout -q -- .
git -C "$SRC" clean -qfd -e target

# Upstream gitignores Cargo.lock and every halo2_gadgets release <= 0.4 is yanked: drop that optional dependency
# (its only user, feature zk-halo2-ipa-poseidon, is a documented no-op) and build with our committed lockfile.
core="$SRC/crates/iroha_core/Cargo.toml"
sed -i -e 's|^zk-halo2-ipa-poseidon = \["zk-halo2-ipa", "dep:halo2_gadgets"\]|zk-halo2-ipa-poseidon = ["zk-halo2-ipa"]|' \
  -e '/^halo2_gadgets = { version = "0.3.1", optional = true }$/d' "$core"
[[ $(git -C "$SRC" diff --numstat -- crates/iroha_core/Cargo.toml) == $'1\t2\tcrates/iroha_core/Cargo.toml' ]] ||
  { echo "iroha_core/Cargo.toml patch did not apply as expected" >&2; exit 1; }
cp "$here/image/Cargo.lock" "$SRC/Cargo.lock"

# Fork layer: patches in lexical order, each checked before it is applied.
shopt -s nullglob
for p in "$here"/fork/patches/[0-9][0-9][0-9][0-9]-*.patch; do
  git -C "$SRC" apply --check "$p" || { echo "fork patch does not apply: $p" >&2; exit 1; }
  git -C "$SRC" apply "$p"
  echo "applied $(basename "$p")"
done
shopt -u nullglob

# Our crates join the workspace (members = "crates/*").
rm -rf "$SRC/crates/rd_driver" "$SRC/crates/rd_genesis"
cp -a "$here/driver" "$SRC/crates/rd_driver"
cp -a "$here/tools/rd-genesis" "$SRC/crates/rd_genesis"
# The norito build script runs a Python sync check against upstream bindings; not ours to maintain here.
echo "export NORITO_SKIP_BINDINGS_SYNC=1" >"$SRC/.rd-env"
echo "prepared $SRC"
