#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

if [[ -f scripts/check-vectors.mjs ]]; then
  node scripts/check-vectors.mjs
fi

pnpm format:check
pnpm typecheck
pnpm test
pnpm build

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc --all-features

if rg -n "(from[[:space:]]+|import\\()[\"'](node:|fs([/\"'])|net([/\"'])|tls([/\"'])|child_process([/\"'])|dgram([/\"'])|worker_threads([/\"']))" typescript/src; then
  echo "native Node dependency found in browser-safe TypeScript core" >&2
  exit 1
fi

git diff --check
