# Reproducible performance report

Measured on Linux amd64, Go 1.27.2, AMD EPYC 9V74 virtual CPU. These are single
runs on a shared container; concurrent validation affected some phase timings.
Repeat on target devices before setting budgets. Bytes below are decimal.

## Sorted binary index

| Domains | Raw bytes | Gzip bytes | Verify/decompress/load (ms) | Retained heap (bytes) | Exact (ns) | Child (ns) | Peak pipeline RSS (bytes) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | 400,165 | 50,168 | 1.77 | 435,088 | 216.04 | 309.71 | 10,014,720 |
| 100,000 | 4,000,165 | 459,506 | 22.14 | 4,059,496 | 361.69 | 406.53 | 27,701,248 |
| 1,000,000 | 40,000,165 | 4,562,859 | 199.12 | 40,069,224 | 303.22 | 369.98 | 269,086,720 |

## Sorted versus reversed-label map trie

| Domains | Index | Index startup (ms) | Retained client heap (bytes) | Exact (ns) | Child (ns) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 10,000 | sorted | 1.03 | 435,088 | 216.04 | 309.71 |
| 10,000 | trie | 2.15 | 877,032 | 109.75 | 101.69 |
| 100,000 | sorted | 11.22 | 4,059,496 | 361.69 | 406.53 |
| 100,000 | trie | 23.62 | 10,324,856 | 80.97 | 145.36 |
| 1,000,000 | sorted | 107.24 | 40,069,224 | 303.22 | 369.98 |
| 1,000,000 | trie | 462.79 | 91,761,936 | 103.29 | 110.51 |

The trie is an experimental in-memory index using the same sorted wire dataset
before building maps. These are not independently serialized formats: gzip bytes
are identical by construction. Its faster lookups cost retained objects/heap and
startup time. The allocation-delta `resident_index_bytes` field excludes some
previously allocated strings; compare total post-GC `client_retained_heap_bytes`.
The shipped sorted index holds one byte buffer, with no per-domain maps.

Names are host-NNNNNNN.group-NNN.example; every second rule includes subdomains.
Each case executes 100,000 lookups cycling through 10,000 prebuilt query names.
Query normalization is excluded and separately measured. This cache-friendly
query set is not uniformly random over a million domains. Real lists have
different name lengths and compression entropy.

Raw JSON includes input parsing, normalization, deduplication, compilation, gzip
build and streaming parse/normalize times. Heap peak is sampled every 1 ms and
can miss transient peaks. Linux VmHWM measures process peak RSS across the whole
pipeline. Retained heap differs from RSS. Startup temporarily holds compressed
and raw buffers; steady filtering retains only the immutable raw index.

## Supplementary compression comparison

Separate Python processes used the same 1m-domain raw file. This measures Python
zlib versus python-zstandard, not equivalent Go implementations. RSS includes
input/output, decoded data and interpreter. Python/zstd is not a production
dependency.

| Codec | Level | Compressed bytes | Compress (ms) | Decompress (ms) | Peak RSS (bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| gzip | 9 | 4,536,069 | 4194.06 | 60.69 | 138,473,472 |
| zstd | 3 | 1,822,599 | 70.61 | 34.88 | 91,578,368 |

Zstd is a worthwhile future optimization on these synthetic names. Format 1
ships gzip from the Go standard library with a tested bounded verifier. Adding
Zstd requires reviewed encoding/schema negotiation, a bounded-window decoder and
target-device measurements. Different Python/Go timings do not establish a
production Zstd speedup.

## Reproduce

```bash
bash scripts/benchmark.sh
bin/aegis-bench -n 1000000 -index sorted -raw-out /tmp/aegis-benchmark.bin
python3 scripts/compression-benchmark.py --raw /tmp/aegis-benchmark.bin --codec gzip
python3 scripts/compression-benchmark.py --raw /tmp/aegis-benchmark.bin --codec zstd
```

The optional Zstd comparison requires Python zstandard. Raw evidence is in
docs/validation/benchmarks.jsonl, compression.jsonl and compression-input.json.

## Actual four-source build

The final code processed downloaded upstream snapshots with production source
contracts and thresholds, using a disposable local signing key. This was a
verified local build, not a GitHub release or a test of the direct Go HTTP path.

| Measurement | Result |
| --- | ---: |
| Accepted input records | 4,077,708 |
| Rejected input records | 1,149 |
| Cross-source duplicate domain memberships merged | 32,576 |
| Unique domains | 4,045,132 |
| Compressed artifact | 37,489,578 bytes |
| Immutable raw index | 113,837,113 bytes |
| Total builder wall time | 25.98 seconds |
| Peak builder process RSS | 1,119,535,104 bytes |

This fits a standard public Ubuntu runner's documented 16 GB memory budget.
The dataset alone retains about 108.6 MiB on a client, before the Go runtime,
DNS cache, policy state and temporary update buffers. That is a concrete memory
cost, not a negligible-RAM claim. Category-specific distributions or delta
updates are potential later optimizations; they are not implemented here.
The gzip file is about 35.8 MiB. Mobile-device startup and update memory
need measurement before Android qualification. Full source/resource/hash evidence
is retained in docs/validation/real-source-*.
