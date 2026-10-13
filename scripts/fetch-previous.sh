#!/usr/bin/env bash
set -euo pipefail
: "${GITHUB_REPOSITORY:?repository required}"
: "${GH_TOKEN:?repository token required}"
[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || exit 1
mkdir -p previous
if gh api "repos/$GITHUB_REPOSITORY/releases/latest" > previous/release.json 2> previous/api-error.txt; then
  tag=$(python3 -c 'import json; print(json.load(open("previous/release.json"))["tag_name"])')
  [[ "$tag" =~ ^rules-[0-9]{14}$ ]] || { echo 'Unexpected latest release tag; review required' >&2; exit 1; }
  gh release download "$tag" --repo "$GITHUB_REPOSITORY" --dir previous --pattern manifest.json --pattern manifest.sig
  [[ $(stat -c %s previous/manifest.json) -le 1048576 && $(stat -c %s previous/manifest.sig) -eq 64 ]] || exit 1
  printf 'previous=previous\n' >> "$GITHUB_OUTPUT"
else
  # Only an explicit GitHub 404 is bootstrap. Auth, rate limit and transient
  # failures MUST NOT silently turn into a first-release build.
  if python3 - <<'PY'
import json
try:
    data=json.load(open('previous/release.json'))
    assert data.get('message') == 'Not Found'
    assert 'HTTP 404' in open('previous/api-error.txt').read()
except Exception:
    raise SystemExit(1)
PY
  then
    printf 'previous=\n' >> "$GITHUB_OUTPUT"
  else
    echo 'Could not establish previous release; build stopped' >&2
    exit 1
  fi
fi
