# AEGIS Intelligence repository rules
- Domain normalization is extracted unchanged from AEGIS Phase 2. Update both implementations and shared vectors together.
- Never change OS networking, UI or the existing AEGIS backend in this repository.
- No source URLs outside the reviewed registry, no unsigned publication, no secrets in logs.
- Preserve exact and suffix category masks separately; never collapse parent/subdomain rules.
- Fail closed on quality gates. Review threshold changes in a pull request.
- Run gofmt, go vet ./..., go test ./..., go test -race ./..., offline smoke and benchmark commands before delivery.
- Record actual external deployment status accurately; local mocks do not prove GitHub publication.
