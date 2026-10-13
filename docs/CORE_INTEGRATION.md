# Integration with the supplied AEGIS Phase 2 backend

The supplied Core was inspected. `core/domain/domain.go` is reused unchanged as
`pkg/domain/domain.go`, with the same `x/net` and `x/text` versions. Its actual
`core/policy` accepts only `custom`/`explicit` categories and `user`/`example`
sources, and caps compiled policy rules at 100,000. Therefore **do not expand
this dataset into millions of policy.Rule values** or claim this ZIP is already
wired into the existing DNS service. Core integration is a separate reviewed
backend change; no OS networking or backend files were modified here.

## Portable packages

Use this repository as a version-pinned module after publishing its source, or
vendor the four portable `pkg` packages with their dependencies into the backend.
The temporary module name `aegis-intelligence` is intentionally local: before
publishing a consumable Go module, change `go.mod` and imports together to your
actual `github.com/OWNER/AEGIS-Intelligence` module path. Do not invent a remote
module identity before the repository exists. Local `replace` works immediately.

- `dataset.Reader`: validated immutable dataset, category-mask lookups.
- `release`: exact-byte signatures, manifest contract, bounded artifact verifier.
- `updater.Store`: single-writer generation transactions, offline recovery and
  atomic in-memory snapshots.
- `updater.Client`: unauthenticated latest check, version-pinned signature/asset,
  timeout/backoff, no-change handling, rollback checks.

## Integration order

1. Embed the repository identity, trusted public-key map, client semantic version
   and optional minimum first-install dataset version in the backend binary.
   A public key downloaded from GitHub is not a trust anchor.
2. Put updater state under the backend's already protected canonical data path;
   acquire its OS-held single-writer lock. On startup call `Store.LoadOffline()`.
   Report missing/corrupt data explicitly; do not falsely report coverage.
3. Run `Client.Update(ctx)` in a background maintenance task with a total deadline
   (for example 10 minutes), independent of DNS request handling. Schedule the
   next attempt with `NextCheck`: 24–30 hours, including per-client random jitter.
   Failed checks can use increasing backoff capped at 24 hours. No update should
   block the DNS request thread.
4. Normalize the DNS host once using the existing Core function, then call
   `snapshot.Dataset.LookupNormalized(host.Value)` on the immutable snapshot.
   Intersect the returned category mask with independently enabled user settings.
   The dataset provides classifications; Core still owns the allow/block policy.
5. Preserve existing explicit custom-block precedence over category blocks and
   allows. The Phase 2 policy evaluator may return a user allow; a dataset category
   block must still be considered at the category-block rank before deciding.
   Integrate this in the central evaluator, with tests for managed rules, custom
   blocks, disabled categories, allows, exact/suffix overlaps and SafeSearch.
   Never blindly call the dataset only after an unconditional user allow return.
6. Activate only after both durable pointer transaction and complete verification.
   Retain the old snapshot until concurrent DNS users release it. Linux/POSIX
   behavior is tested; qualify Windows replacement/ACL/crash behavior in Bridge.
7. Add fields to the existing authenticated backend status API: dataset version,
   created_at/age, count, last update attempt, last success, update error code,
   currently enabled category mask and recovery status. Return metadata only;
   never include queried domains or browsing history in update/status reports.
8. For Android, wait for Wi-Fi/unmetered access unless the user authorizes a
   metered download; account for battery/storage constraints. Monthly full
   datasets currently measure roughly 37.5 MB compressed on the tested lists.
   The reference client exposes Update, but does not implement Android scheduling.

## Compatibility verification

Run from this project directory:

```bash
bash scripts/core-compatibility.sh /absolute/path/to/aegis
```

This builds a temporary Go module using the **actual** supplied Core and this
reader, compares normalization outputs and verifies exact/subdomain matching
against the actual Core policy evaluator. It does not change the backend or
claim dataset category-policy integration. Shared JSON domain vectors are also
part of offline unit tests. Update the shared contract whenever normalization
changes; a version mismatch must stop activation.

The reference updater knows a fixed local client version `0.1.0`; production
must provide the actual application's supported contract/version. It does not
make AEGIS 0.1.0 a published application release.

## Rotation integration

The client trust map supports multiple explicit key IDs. For planned rotation,
release a client trusting the new key first, retain the old key during overlap,
then set CI's optional `AEGIS_PREVIOUS_PUBLIC_KEY` to the old public key while
`AEGIS_PUBLIC_KEY` and `AEGIS_SIGNING_SEED` name the new key. The builder's
`-previous-public-key-file` provides the same option locally. The publisher
always verifies against the current public key. Follow the stopped-workflow
sequence in SECURITY.md; do not substitute unsigned key discovery or relax
rollback/signature checks.
