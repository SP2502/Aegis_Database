#!/usr/bin/env bash
# Called only on the protected default branch after tests and signed validation.
set -euo pipefail
: "${GITHUB_REPOSITORY:?repository required}"
: "${GITHUB_SHA:?source commit required}"
: "${GH_TOKEN:?repository token required}"
: "${AEGIS_PUBLIC_KEY:?trusted public verification key required}"
[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] || exit 1
[[ "${GITHUB_REF:-}" == 'refs/heads/main' ]] || { echo 'Publication requires main' >&2; exit 1; }
dir=out/release
bin/aegis-verify -dir "$dir" -repository "$GITHUB_REPOSITORY"
tag=$(python3 -c 'import json; print(json.load(open("out/release/manifest.json"))["release_tag"])')
[[ "$tag" =~ ^rules-[0-9]{14}$ ]] || exit 1
# HTTP listing must succeed; distinguish an existing version from network errors.
exists=$(gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100" --jq ".[] | select(.tag_name == \"$tag\") | .tag_name")
[[ -z "$exists" ]] || { echo 'Version already exists; never overwrite assets' >&2; exit 1; }
if gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$tag" > "$dir/tag-check.json" 2> "$dir/tag-error.txt"; then
  echo 'Tag already exists; review required' >&2; exit 1
else
  python3 - <<'PY'
import json
assert json.load(open('out/release/tag-check.json')).get('message') == 'Not Found'
assert 'HTTP 404' in open('out/release/tag-error.txt').read()
PY
fi
# Keep failed drafts for inspection; never expose them as latest.
gh release create "$tag" --repo "$GITHUB_REPOSITORY" --target "$GITHUB_SHA" --draft --title "AEGIS Intelligence $tag" --notes 'Signed local-filtering dataset. Source provenance and hashes are in manifest.json.'
gh release upload "$tag" --repo "$GITHUB_REPOSITORY" "$dir/aegis-rules.bin.gz" "$dir/manifest.json" "$dir/manifest.sig" docs/BLOCKLISTPROJECT-LICENSE.txt docs/BLOCKLISTPROJECT-NOTICE.txt
check=$(mktemp -d)
trap 'rm -rf "$check"' EXIT
gh release download "$tag" --repo "$GITHUB_REPOSITORY" --dir "$check" --pattern aegis-rules.bin.gz --pattern manifest.json --pattern manifest.sig
cmp "$dir/manifest.json" "$check/manifest.json"
cmp "$dir/manifest.sig" "$check/manifest.sig"
cmp "$dir/aegis-rules.bin.gz" "$check/aegis-rules.bin.gz"
bin/aegis-verify -dir "$check" -repository "$GITHUB_REPOSITORY"
gh release edit "$tag" --repo "$GITHUB_REPOSITORY" --draft=false --latest
printf 'Published verified release %s\n' "$tag"
