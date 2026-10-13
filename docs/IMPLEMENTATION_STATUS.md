# Implementation status

## Completed code

- Reviewed source registry with identity/format/license contracts, required flags,
  category/scope definitions, byte limits and quality thresholds.
- HTTPS downloader with validated public-IP dialing, cancellation, timeouts,
  bounded retries/backoff and sequential streaming to disk.
- Domain and hosts adapters; unchanged Core normalization; shared vectors;
  global merging with independent exact/suffix category masks.
- Deterministic binary compiler/strict reader; gzip and bounded exact-size
  decompression; source provenance and compressed/raw hashes.
- Exact-byte Ed25519 signing, local private-key generation, offline verifier,
  key/compatibility/repository checks and replay protection.
- Single-writer reference updater: pinned signature/asset downloads, durable
  high-water state, staged generations, immutable snapshots, offline recovery,
  timeouts/backoff and randomized 24–30 hour scheduling.
- Tests/race/fuzz targets; actual-Core contract harness; offline smoke and
  publication-script mocks; reproducible 10k/100k/1m comparisons.
- SHA-pinned test/monthly workflows, concurrency/branch/repository gates,
  previous-release comparison, no-change preservation, draft-first publication.
- Setup, format, source/license, security/rotation, distribution/retention,
  performance and Core integration documentation.

## Validation boundaries

All unit tests are offline. Real upstream files were downloaded through the
environment's required HTTPS proxy, then processed from disk with production
thresholds and headers. This validates real parsing, normalization, merging,
compilation, signing and offline verification. Direct DNS/Internet access for
the production Go downloader was unavailable here; its behavior is tested using
local TLS servers and injected transports. The GitHub runner network path still
needs the first real workflow run.

The supplied Phase 2 Core was actually imported for normalization and exact/suffix
policy parity tests. Its backend was not edited; category-policy, DNS and status
API integration is documented but not implemented. No production key or remote
repository identity was invented.

Shell publication tests use fake gh, not GitHub. **No actual repository, secrets,
variables, published release or monthly schedule was activated.** Enable GitHub
release immutability before the first production publication.

## Known limits

- Full snapshots, no category shards or delta updates. The tested full dataset
  is approximately 37.5 MB gzip / 113.8 MB raw; mobile qualification is needed.
- Sorted lookups are slower than the experimental map trie on the measured
  cache-friendly synthetic query set, but retain less heap and start faster.
- Gzip ships in production. Supplementary Zstd results warrant further work;
  no Zstd client decoder is provided.
- Bridge must protect the updater directory and enforce single-process ownership.
  Windows replacement/durability/ACL behavior is not qualified by Linux tests.
  Local historical generations remain until reviewed manual pruning.
- Quality gates cannot prove accuracy or detect all false positives/same-count
  poisoning. Upstream licensing discrepancy is recorded and notices retained;
  future source lineage/license changes require review.
- First installation needs an app-supplied floor to resist replay of an old
  authentic release. Existing durable version floors are enforced.
- Free-service terms and scheduling can change. Monitor failed/disabled runs;
  no fake keepalive commits or paid infrastructure are required.

README contains activation steps; docs/validation contains raw local evidence.
