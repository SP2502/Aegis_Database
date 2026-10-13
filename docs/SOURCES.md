# Approved sources and review

Verified on 2026-10-12 against the project's current published documentation and
actual generated list headers. All four URLs were downloaded successfully for a
real-data build in this task. The publication host is explicitly allowlisted.

| ID | Category | Approved domain-only URL | Minimum unique records |
| --- | --- | --- | ---: |
| blp-adult | adult | https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt | 100,000 |
| blp-gambling | gambling | https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt | 10,000 |
| blp-malware | malware | https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt | 100,000 |
| blp-phishing | phishing | https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt | 50,000 |

Documentation: https://blocklistproject.github.io/Lists/
Repository: https://github.com/blocklistproject/Lists
Repository license: https://github.com/blocklistproject/Lists/blob/main/LICENSE

Upstream documents `-nl.txt` as plain domains and the original `.txt` as hosts
entries. Neither format explicitly grants suffix semantics; the approved
sources therefore use **exact** matching. This preserves literal hosts-style
semantics and avoids silently widening rules to all subdomains. The format and
reader support reviewed subdomain-inclusive sources later.

The repository LICENSE and README identify Unlicense. Generated headers identify
MIT. The registry records **both** and requires the observed MIT header. The
original Unlicense and a conservative MIT/attribution notice accompany releases.
See `BLOCKLISTPROJECT-NOTICE.txt`. Both declarations are permissive, but changes
to declarations or upstream aggregation require review. No independently added
GPL/attribution/share-alike lists are enabled by this implementation.

Only reviewed Block List Project paths on the configured approved hosts pass
registry validation. A source owner cannot use the config to fetch an unrelated
repository just by keeping the same hostname. Additional source providers need
a code review updating this allowlist, license review, adapter tests and minimum
counts. Source IDs are restricted to safe lowercase identifiers and never used
as shell code. In production downloads, temp filenames are generated locally.

## Quality gates

- Every enabled source must succeed; all initial sources are required.
- Header title, declared format and declared license must match.
- Each source has a byte cap, minimum unique count, malformed rate ≤1%, and
  duplicate rate ≤50%. Overlong lines fail the whole source.
- Global unique count must be ≥200,000. A >35% change in either global count or
  per-source unique count compared with the trusted previous manifest stops
  publication. This is a conservative review threshold, not an accuracy claim.
- Added/removed sources and changes to URL, scope, category or license stop
  publication against an existing baseline; such migrations need a reviewed
  change to the baseline-validation logic, not a runtime bypass switch.
- The critical-domain list is a **publication stop list**, never an allow policy.
  It tests both exact and ancestor suffix matches. No records are silently
  removed or whitelisted. The list is intentionally small and cannot detect all
  false positives. Review additions using the same policy precedence as Core.

Unexpected changes require inspection of upstream diffs and a reviewed PR to
registry thresholds or validation logic. Keep the prior release available.
Do not lower thresholds automatically or publish a partial successful subset.

For a false positive, record the source and version without user browsing
history, verify the disputed rule, report it upstream and publish a reviewed
newer dataset. User/managed policy precedence must be enforced in Core rather
than adding hidden unconditional exceptions to this dataset compiler.

Real source bodies are processed sequentially from disk. Only the normalized
union and a per-current-source uniqueness map are retained. No remote content
is executed. Raw source SHA-256 and counts remain in signed build metadata;
provenance identifies the source snapshots but is not a per-domain membership
trace. Retain private build snapshots externally when detailed audits require
them; no mandatory paid archive service is required.
