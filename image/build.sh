#!/usr/bin/env bash
# Build the Iroha 3 RD/DFABI node image: upstream fbe677b9 + fork patches + rd2/rd-genesis (ci/prepare-src.sh).
# Runs on GitHub-hosted runners (.github/workflows/build-image.yml); never on the operator host.
#   image/build.sh <image-tag>        Env: SRC (source dir, default: temp), CARGO_BUILD_JOBS (default 2)
#
# Why this commit: blueprint v1.0 (Iroha 3) needs the native ZK ISIs RegisterZkAsset/Shield/ZkTransfer/Unshield and
# the confidential_v2 circuit; upstream main @ fbe677b9 has them and the Iroha 3 build line (KPID ADR 0005). Later
# upstream branches (master, optimizations) dropped confidential_v2; 071e281e dropped Shield/ZkTransfer/Unshield.
# Why build-i3: iroha3d / iroha3 are the Iroha 3 line (upstream default features). The network runs it permissioned
# with nexus off and DA/RBC on; that is node config, not a build switch.
# Why PROFILE=deploy: upstream Dockerfile default (release + lto = true + strip, Cargo.toml [profile.deploy]).
set -euo pipefail
RUST_IMAGE=rust:1.93.1-slim-bookworm # = rust-toolchain.toml channel at the pin
TAG=${1:?usage: build.sh <image-tag>}
here=$(cd "$(dirname "$0")/.." && pwd)
if [[ -z ${SRC:-} ]]; then SRC=$(mktemp -d)/iroha; trap 'rm -rf "$(dirname "$SRC")"' EXIT; fi
"$here/ci/prepare-src.sh" "$SRC"
mkdir -p "$SRC/dist" # the upstream Dockerfile COPYs dist/ (prebuilt binaries, unused here)

# kagami and our crates are not default workspace members: select the packages explicitly.
pkgs="-p irohad -p iroha_cli -p iroha_kagami -p rd_driver -p rd_genesis"
dockerfile=$(mktemp)
sed -e "s|^FROM rust:slim-bookworm AS builder|FROM $RUST_IMAGE AS builder|" \
  -e "s|set -- cargo \${CARGOFLAGS} build --profile|set -- cargo \${CARGOFLAGS} build $pkgs --profile|" \
  -e "s|^ARG IROHA_GIT_COMMIT_HASH=\"\"|ARG IROHA_GIT_COMMIT_HASH=\"\"\nENV NORITO_SKIP_BINDINGS_SYNC=1|" \
  "$SRC/Dockerfile" >"$dockerfile"
grep -q "^FROM $RUST_IMAGE AS builder" "$dockerfile" && grep -qF "build $pkgs --profile" "$dockerfile" &&
  grep -q '^ENV NORITO_SKIP_BINDINGS_SYNC=1' "$dockerfile" ||
  { echo "upstream Dockerfile builder lines changed; update build.sh" >&2; exit 1; }

DOCKER_BUILDKIT=1 docker build -f "$dockerfile" \
  --build-arg PROFILE=deploy \
  --build-arg CARGOFLAGS=--locked \
  --build-arg FEATURES=irohad/build-i3,iroha_cli/build-i3 \
  --build-arg BINARIES="iroha3d iroha3 kagami rd2 rd-genesis" \
  --build-arg CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
  --build-arg CONFIG_PROFILE=single \
  --build-arg IROHA_GIT_COMMIT_HASH=fbe677b98ed309808074ec5a0a8a16de2a0c2286 \
  --label org.opencontainers.image.source=https://github.com/radityaaa43/iroha3-zk-node-build \
  --label org.opencontainers.image.revision="$(git -C "$here" rev-parse HEAD 2>/dev/null || echo unknown)" \
  -t "$TAG" "$SRC"
rm -f "$dockerfile"

docker run --rm --entrypoint iroha3d "$TAG" --version
docker run --rm --entrypoint kagami "$TAG" --help >/dev/null
docker run --rm --entrypoint iroha3 "$TAG" --help >/dev/null
docker run --rm --entrypoint rd2 "$TAG" --help >/dev/null
echo "built $TAG"
