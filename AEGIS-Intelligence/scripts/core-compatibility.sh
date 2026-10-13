#!/usr/bin/env bash
set -euo pipefail
core=$(cd "${1:?path to existing AEGIS Core required}" && pwd)
cloud=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp examples/core_contract_test.go.txt "$work/core_contract_test.go"
cd "$work"
go mod init aegis-contract-check
go mod edit -go=1.26.0 -require=aegis@v0.0.0 -require=aegis-intelligence@v0.0.0
go mod edit "-replace=aegis=$core" "-replace=aegis-intelligence=$cloud"
go mod tidy
go test -v ./...
