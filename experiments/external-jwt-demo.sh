#!/usr/bin/env bash
# External JWT experiment for the demo-2 branch of millionsouls/keystone.
#
# Runs, from the repository root:
#   1. the demo test, which verifies JWTs from a mock identity provider and
#      prints which tokens are accepted and which are rejected;
#   2. the token exchange tests, which cover the OAuth2 token exchange
#      endpoint (the external JWT cases and the existing Keystone token cases).
#
# Usage:
#   git clone -b demo-2 https://github.com/millionsouls/keystone.git
#   cd keystone
#   ./experiments/external-jwt-demo.sh
#
# Needs: Rust (cargo) and protoc (macOS: brew install protobuf,
# Debian/Ubuntu: apt install protobuf-compiler). The first build takes a few
# minutes.

set -euo pipefail

# The script lives in <repo>/experiments, so run from the repo root.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

EXPECTED_TOKEN_EXCHANGE_TESTS=15

for tool in cargo; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: '$tool' not found. Install Rust from https://rustup.rs" >&2
    exit 1
  }
done
if [ -z "${PROTOC:-}" ] && ! command -v protoc >/dev/null 2>&1; then
  echo "error: 'protoc' not found. macOS: brew install protobuf; Debian/Ubuntu: apt install protobuf-compiler" >&2
  exit 1
fi

echo "== 1/2 Demo: verifying external JWTs against a mock identity provider"
echo
cargo test -p openstack-keystone --lib demo_external_jwt_verification -- --nocapture

echo
echo "== 2/2 Token exchange tests"
echo
out=$(cargo test -p openstack-keystone --lib api::v4::oauth2::token::token_exchange::tests 2>&1) || {
  echo "$out"
  echo "FAIL: token exchange tests failed" >&2
  exit 1
}
echo "$out" | grep -E '^test |^test result'

passed=$(echo "$out" | sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' | tail -1)
echo
if [ "${passed:-0}" -eq "$EXPECTED_TOKEN_EXCHANGE_TESTS" ]; then
  echo "OK: demo passed and all $passed token exchange tests passed."
else
  echo "FAIL: expected $EXPECTED_TOKEN_EXCHANGE_TESTS token exchange tests to pass, got ${passed:-0}." >&2
  exit 1
fi
