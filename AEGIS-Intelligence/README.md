# AEGIS Cloud Intelligence

A working Go dataset compiler and signed-update foundation for a **public**
`AEGIS-Intelligence` repository. Monthly builds run on a standard GitHub Ubuntu
runner and publish compressed datasets as public GitHub Release assets. No
continuously running server, database, paid API or custom domain is required.

Ordinary filtering stays local. This repository does not modify OS networking,
implement a frontend, or upload browsing history.

## Included

- Four approved Block List Project domain-only sources: adult, gambling, malware,
  phishing. Required-source, malformed-rate, duplicate-rate and change gates.
- Allowlisted HTTPS downloader, bounded retries/timeouts/body sizes, sequential
  source processing, streaming adapters for domain and hosts formats.
- Exact AEGIS Phase 2 IDNA normalization; category and scope-preserving merging.
- Deterministic version 1 sorted binary index, gzip, SHA-256, exact-bytes detached
  Ed25519 signatures, offline verifier and reference update store.
- Test and monthly workflows; draft-first publication; offline and Core contract
  tests; 10k/100k/1m sorted-versus-trie benchmarks.

See [implementation status](docs/IMPLEMENTATION_STATUS.md),
[measured performance](docs/PERFORMANCE.md) and [Core integration](docs/CORE_INTEGRATION.md).

## Requirements

Go **1.26 or newer**, Bash, Python 3 for scripts, and `gh` for publishing. Ubuntu
standard GitHub runners supply Bash, Python and `gh`; setup-go installs the Go
latest patch of the validated Go 1.27 minor series. go.mod retains the compatible
Go 1.26 minimum. Only `golang.org/x/net/idna` and its `x/text` dependency are
used, matching the existing Core. Network access is needed to obtain dependencies
unless they are already cached; tests themselves never fetch upstream lists.

## Run locally

From the extracted `AEGIS-Intelligence` directory:

```bash
go test ./...
go vet ./...
go test -race ./...
bash scripts/offline-smoke.sh
bash scripts/benchmark.sh
```

The smoke script uses disposable signing keys, fixture lists and temporary
artifacts. It verifies a valid release and checks that a tampered artifact fails.
Do not embed its disposable key in production clients.

To generate your production key locally, outside CI:

```bash
go run -buildvcs=false ./cmd/aegis-keygen -out keys
```

This refuses to overwrite an existing directory, writes `keys/signing.seed` with
mode 0600, writes `keys/verification.pub`, and prints **only** the public key ID.
Keep an encrypted offline backup of the private seed. Never paste it into a chat,
commit it, print it in a workflow or use shell tracing with secrets.

Build and verify a live-source release locally:

```bash
go run -buildvcs=false ./cmd/aegis-builder \
  -repository YOUR_GITHUB_USERNAME/AEGIS-Intelligence \
  -key-file keys/signing.seed -out out/release
go run -buildvcs=false ./cmd/aegis-verify \
  -repository YOUR_GITHUB_USERNAME/AEGIS-Intelligence \
  -public-key-file keys/verification.pub -dir out/release
```

The output directory must be new. For later builds, provide `-previous PATH`
containing the prior `manifest.json` and `manifest.sig`; its signature is checked.
An unchanged compiled dataset produces `NO_CHANGE` and no output directory.
All enabled source failures stop the release. Never treat a reduced fixture
registry as a production baseline.

## Activate the free monthly workflow

1. Create a **public** GitHub repository named `AEGIS-Intelligence`. Use `main` as
   its default branch. Copy this project's files, **including `.github`**, into
   the repository root and push them. Do not include `keys`, `out`, or `bin`.
2. Locally run the key-generation command above. In GitHub **Settings → Secrets
   and variables → Actions → Secrets**, create `AEGIS_SIGNING_SEED` using the
   contents of `keys/signing.seed`. Use the GitHub UI's secret field; do not put
   the value in a command line or repository file.
3. In the **Variables** tab, create `AEGIS_PUBLIC_KEY` using
   `keys/verification.pub`, and `AEGIS_RELEASE_REPOSITORY` with the exact value
   `YOUR_GITHUB_USERNAME/AEGIS-Intelligence`. These values are public. Embed the
   same verification key and repository identity in AEGIS clients.
4. Under **Settings → Actions → General**, enable Actions and allow the pinned
   `actions/checkout` and `actions/setup-go` actions. Organization restrictions
   must allow this job's `contents: write` permission. The workflow uses the
   built-in `GITHUB_TOKEN`; no personal access token is needed. No Actions
   cache or uploaded workflow artifact storage is used.
5. Under **Settings → General → Releases**, enable **release immutability**
   before the first publication. Protect `main` with reviewed changes to workflows, registry and dependencies.
   Publication is restricted to `main`, the configured repository, and a
   non-fork repository. Keep `main` as the default branch; other names require
   coordinated edits to both workflow and publish script.
6. In **Actions → Monthly signed dataset → Run workflow**, select `main` and run
   it once. Inspect the run summary, quality gates and published release. A
   successful first run should contain `aegis-rules.bin.gz`, `manifest.json`,
   `manifest.sig` and the two source notice files. Download and verify the
   release using the public key before enabling updates in clients.
7. The schedule is **03:37 UTC on the first of every month** (09:07 IST).
   GitHub may delay or drop scheduled jobs. Public-repository schedules may be
   disabled after 60 days without repository activity; check the Actions page
   and re-enable the workflow if necessary. This implementation deliberately
   does not generate empty commits to simulate activity.

The code and workflows are delivered; **no GitHub repository, production secret,
published release or enabled monthly schedule was configured by this task**.
Only a real successful repository run establishes deployment operation.

## Costs and distribution

As checked on 2026-10-12, GitHub documents standard hosted runners in public
repositories as free, and Release downloads without a total bandwidth quota.
This design does not require a credit card or paid subscription. Service terms,
anti-abuse policies, availability and limits can change; this is not a perpetual
hosting guarantee. See [distribution](docs/DISTRIBUTION.md) for official links.
Do not switch this workflow to a private repository or a paid larger runner and
assume the same cost model.

## Repository map

| Path | Purpose |
| --- | --- |
| `cmd/aegis-builder`, `aegis-keygen`, `aegis-verify` | Build, generate keys, verify |
| `cmd/aegis-bench`, `internal/benchindex` | Reproducible measurements and alternative trie |
| `internal/sources`, `fetcher`, `parser`, `validation`, `pipeline` | Build pipeline |
| `pkg/domain`, `dataset`, `release`, `updater` | Portable client compatibility packages |
| `config`, `fixtures`, `examples` | Reviewed registry, offline inputs, Core contract harness |
| `scripts`, `.github/workflows` | Tests, release publication and monthly automation |
| `docs` | Format, sources, security, integration, performance and status |

`config/categories.json` documents format 1's fixed category table. The Go table
is authoritative; changing the JSON alone does not redefine the wire format.
