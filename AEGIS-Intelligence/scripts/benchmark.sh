#!/usr/bin/env bash
set -euo pipefail
mkdir -p bin docs/validation
go build -trimpath -buildvcs=false -o bin/aegis-bench ./cmd/aegis-bench
: > docs/validation/benchmarks.jsonl
for n in 10000 100000 1000000; do
  for index in sorted trie; do
    bin/aegis-bench -n "$n" -index "$index" | tee -a docs/validation/benchmarks.jsonl
  done
done
