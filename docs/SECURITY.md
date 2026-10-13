# Security model

## Trust and threat boundaries

Sources are untrusted data, never executable code. HTTPS, allowlisted hosts and
reviewed URL paths restrict download destinations. Production HTTP clients ignore
environment proxies, validate resolved public IPs and dial validated addresses
without a second DNS resolution. Source redirects remain on the original host;
release redirects are restricted to GitHub and its documented asset hosts.
Connections, TLS handshake, response headers, overall requests, body sizes,
retry counts and build duration are bounded. TLS certificate verification stays
enabled. Source content is parsed as domain/hosts records, not shell or Adblock
cosmetic instructions. Local TLS transports are injected only inside tests.

One required-source failure, suspicious count change, excessive malformed input,
critical-domain hit, corrupt binary, signature failure or invalid signing key
stops publication. SHA-256 establishes integrity, not origin: only a signature
under the client's pinned Ed25519 key establishes release authenticity.

The client verifies exact manifest bytes, pinned key identity, schema/category/
normalization/format compatibility, repository/version asset URL, monotonic
version, signed sizes and hard local caps before activation. Gzip is limited to
one member and the declared raw size. Rollback state advances with the active
pointer; offline recovery may use the previous dataset without lowering that
high-water mark. Same-version changed hashes are rejected. Initial installation
has no persisted floor unless the application supplies one; pin a minimum
acceptable dataset version in a shipped client when first-install replay matters.
A signed old release is otherwise still authentic, even when no longer fresh.

## Secret handling and CI

`aegis-keygen` writes a base64 32-byte seed to a new private directory with mode
0600 and prints no private material. This is a Linux/POSIX file-permission
boundary; on Windows protect the key directory using an ACL. The production
seed belongs only in the `AEGIS_SIGNING_SEED` Actions secret and an encrypted
offline backup. The public key belongs in clients and `AEGIS_PUBLIC_KEY`.
`.gitignore` excludes keys and private seeds. It is not a substitute for checking
what is staged. Never enable shell tracing or print secret environment values.

PR tests have read-only contents and no signing secrets. Publication is a
schedule/manual-only workflow, restricted to the configured non-fork repository
and `main`. Tests run before the signing step. Official actions are SHA pinned;
checkout does not persist token credentials. Only the release job has
contents-write; no personal access token, cloud key or extra paid service exists.
Anyone who can alter trusted main-branch code can still arrange secret theft or
malicious signed datasets. Branch restrictions alone cannot protect against a
malicious authorized maintainer. Protect main and require review of workflow,
registry, dependencies and signing code.

Enable **Settings → General → Releases → Enable release immutability** before the
first production publication. The scripts already refuse overwrites; GitHub's
setting adds server-side asset/tag protection after publication. It applies to
future releases. See:
https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes

## Compromise and key rotation

A stolen signing seed can produce authentic-looking malicious category rules,
false positives, missing blocks or a signed future version that freezes clients'
update floor. Bounds still prevent executable payloads and unlimited allocation,
but cannot distinguish a malicious valid signature from the legitimate signer.
A compromised source can also poison list contents while staying under count
gates. These gates reduce accidents; they do not prove classification accuracy.

1. Stop the workflow, revoke repository access and replace the signing secret.
   Audit recent main-branch changes and release manifests. Keep evidence; do not
   silently overwrite compromised releases under their existing tags.
2. Generate a replacement key offline. Ship an authenticated application update
   embedding the new key and revoking the compromised key. Never trust a new
   key merely because the compromised key signed it.
3. For planned rotation, first ship clients trusting both keys. Set
   `AEGIS_PREVIOUS_PUBLIC_KEY` to the old public key, set `AEGIS_PUBLIC_KEY` to
   the new public key, and replace `AEGIS_SIGNING_SEED` with the new seed while
   the workflow is stopped. Re-enable and run it once after the three values
   agree. The builder accepts the explicit prior key for baseline verification
   but requires the current public key to match its signing seed. Publication
   independently verifies against the current public key.
4. Keep the prior key in supported clients while older releases need it. Remove
   the previous CI public-key variable after the latest baseline is signed by
   the new key. The client keyring is explicit; no remote unsigned key discovery
   is used. A key change causes a newer release even if compiled rules match.
5. If a malicious version advanced the durable floor, recovery needs a reviewed
   application migration of that floor/key generation, not disabling rollback
   checks in the ordinary updater. Keep filtering with the previous verified
   dataset while recovery is prepared.

## Reference updater limits

`pkg/updater.Store` assumes one trusted backend process owns its protected state
directory. Its mutex serializes that instance, not competing processes. The
Bridge must use its existing OS-held lock/service ownership and secure ACLs.
POSIX directory fsync is performed; Windows atomic-replace/crash durability is
not qualified here and needs Bridge-specific implementation/testing. A local
administrator able to delete rollback state or replace application binaries is
outside this dataset signature boundary. No anti-uninstall claim is made.

Snapshot data and trusted keys must be immutable to concurrent readers. Retain
only current/previous generations after a reviewed platform-safe pruning policy;
this reference store does not automatically delete old versions. Update failures
never replace a valid snapshot. A corrupt current snapshot may use the prior
verified one and explicitly reports `UsingPrevious`; it will still reject older
network releases. No data travels from DNS lookups to GitHub. Public update
requests expose an ordinary network address/timing to GitHub but include no
history, domain queries, stable tracking identifier or account token.
