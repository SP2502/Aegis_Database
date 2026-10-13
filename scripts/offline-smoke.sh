#!/usr/bin/env bash
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go run -buildvcs=false ./cmd/aegis-keygen -out "$work/keys"
go run -buildvcs=false ./cmd/aegis-builder -sources fixtures/sources.json -fixtures fixtures -repository fixture/AEGIS-Intelligence -key-file "$work/keys/signing.seed" -out "$work/release" -created-at 2026-10-12T06:00:00Z
go run -buildvcs=false ./cmd/aegis-verify -repository fixture/AEGIS-Intelligence -dir "$work/release" -public-key-file "$work/keys/verification.pub"
# Verify tampering is rejected by the actual executable, not just unit tests.
printf 'corruption' >> "$work/release/aegis-rules.bin.gz"
if go run -buildvcs=false ./cmd/aegis-verify -repository fixture/AEGIS-Intelligence -dir "$work/release" -public-key-file "$work/keys/verification.pub"; then
  echo 'ERROR: tampered release accepted' >&2
  exit 1
fi
echo 'Offline smoke passed; tampered release rejected.'
