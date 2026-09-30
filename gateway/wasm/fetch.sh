#!/usr/bin/env bash
# Fetch the Coraza proxy-wasm plugin (with OWASP CRS bundled) from its pinned
# OCI image and place it at gateway/wasm/coraza.wasm. The binary is not committed.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="ghcr.io/corazawaf/coraza-proxy-wasm@sha256:d66f944831428ea27039207fa4019bea55f9ea0a876d7b0dc8cc7c9e385fa4b1"
EXPECT_SHA256="f36e710529167482df820b790981230092da098d26d21aebb16f1d9c8c4e26d5"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
docker pull -q "$IMAGE" >/dev/null
docker save "$IMAGE" -o "$tmp/img.tar"
tar -xf "$tmp/img.tar" -C "$tmp"
layer="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[0]["Layers"][0])' "$tmp/manifest.json")"
tar -xf "$tmp/$layer" -C "$tmp" plugin.wasm
got="$(sha256sum "$tmp/plugin.wasm" | cut -d" " -f1)"
if [ "$got" != "$EXPECT_SHA256" ]; then
  echo "sha256 mismatch: got $got, expected $EXPECT_SHA256" >&2
  exit 1
fi
mv "$tmp/plugin.wasm" coraza.wasm
echo "coraza.wasm ok ($got)"
