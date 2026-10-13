# GitHub distribution and operations

Current official documentation, checked 2026-10-12:

- Standard GitHub-hosted runners in public repositories are free:
  https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- Releases have no total storage/bandwidth quota stated; each asset must be under
  2 GiB: https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases
- Schedules may be delayed/dropped and public-repository schedules can be disabled
  after 60 days of inactivity:
  https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule

These conditions permit this foundation without a credit card or paid cloud
subscription. They are third-party terms, not an SLA or a permanent entitlement.
GitHub acceptable-use/anti-abuse rules and future pricing changes still apply.
GitHub is a release distributor here, not a DNS service or browsing-data server.

Clients request `https://github.com/OWNER/AEGIS-Intelligence/releases/latest/download/manifest.json`
without an account or token. They read a constrained version locator from these
untrusted bytes, fetch `manifest.sig` from that **versioned** tag, then verify
before following the artifact URL. A latest-pointer race yields either a coherent
older published release or a verification failure that is retried later, never
a mismatched activated dataset. The signature is deliberately not fetched from
an independently mutable latest pointer.

The publication script validates locally, refuses existing versions/tags,
creates a draft, uploads the three data assets and two license notices,
downloads the three assets again, compares bytes and runs the verifier. Only
then does it publish the draft and mark it latest. Failures retain the previous
published latest release and may leave an unpublished draft for inspection.
Do not edit a failed draft's assets and manually make it latest without rerunning
full verification. Use a new version after review; do not reuse existing tags.

The built-in GITHUB_TOKEN has contents-write only in the publication job; the PR
workflow has contents-read and no secrets. Official checkout/setup-go actions are
pinned to v4.2.2/v5.5.0 commit SHAs verified against GitHub tag references in this
task. Review updates to those SHAs and dependencies as ordinary code changes.
The runner is standard `ubuntu-24.04`; jobs are limited to 30 minutes, with a
20-minute builder context timeout and serialized publication concurrency.

## Retention

No automatic deletion is implemented. Keep every supported format/key generation
available and at least 12 months of releases when possible. Before deleting any
older release, verify supported-client requirements and offline fallback use.
An inactive client can update directly to the latest compatible dataset; there
are no required delta chains. Do not delete versions merely to save unused
quota, and do not overwrite assets under a retained version.

## Monthly operation

Use the exact README setup steps. Check workflow notifications and the run
summary after each monthly build. A successful no-change run preserves the
existing dataset/version/date. Its age means the dataset's release age, not the
date of the most recent upstream validation; no-change validation appears only
in the Actions summary. The workflow does not pretend to be continuously running
or guaranteed to execute on time.

If the current repository contains unrelated releases, move datasets into their
own repository: `/releases/latest` must identify an AEGIS dataset release.
The workflow only publishes from `main` in `AEGIS_RELEASE_REPOSITORY`; forks and
other branches cannot obtain a publication through this workflow. Manual CLI
publication additionally checks the branch and configured key.

No real GitHub create/upload/publish operation was performed in this task.
Publication-script tests use a fake gh executable and local files. Repository
secrets/variables/Actions settings and first real release must be configured by
the owner; this code does not claim those external steps are completed.
