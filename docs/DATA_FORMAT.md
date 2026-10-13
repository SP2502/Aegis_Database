# Dataset format 1 and normalization contract 1

All integers are little endian. No executable instructions, URLs or source names
are stored in domain records. One domain string is stored once.

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | ASCII `AEGISDB` followed by NUL |
| 8 | 2 | Format version, 1 |
| 10 | 2 | Normalization contract, 1 |
| 12 | 4 | Unique domain count |
| 16 | 4 | Category JSON byte length |
| 20 | 4 | Domain blob byte length |
| 24 | 32 | SHA-256 of all bytes following the header |
| 56 | 8 | Reserved; must be zero |
| 64 | variable | Canonical category JSON |
| following | 10 × count | Sorted fixed-width records |
| following | blob length | Concatenated canonical ASCII domain strings |

Each record contains `offset:u32`, `length:u16`, `exact_mask:u16`,
`subdomain_mask:u16`. Offset is relative to the blob. Records are lexicographically
sorted by **forward domain string**. Offsets must be contiguous and nonoverlapping.
The reader rejects invalid lengths, unsupported flags, ordering errors, unknown
versions, incompatible category bytes, reserved values, corrupt payload hashes,
trailing bytes and out-of-range arithmetic before serving lookups.

Canonical category JSON is:

```json
[{"id":"adult","bit":1},{"id":"gambling","bit":2},{"id":"malware","bit":4},{"id":"phishing","bit":8}]
```

Masks are independent. For `exact_mask=adult`, `subdomain_mask=malware`, the base
name matches both categories and children match malware only. Ancestors' suffix
masks are also unioned. Label boundaries prevent `notexample.com` from matching
`example.com`. Never remove a child rule just because a parent exists.

`pkg/domain/domain.go` is extracted unchanged from the supplied AEGIS Phase 2
Core; dependency versions match that Core. It uses IDNA Lookup, lowercase ASCII,
one optional root dot, label limits of 63 bytes and host limit of 253 bytes.
It distinguishes IP literals from DNS domains. Public blocklist admission is
stricter: single-label names and IPs are excluded. See shared vectors in
`fixtures/domain_vectors.json`, and `scripts/core-compatibility.sh`.

## Manifest and signature

`manifest.sig` is exactly 64 **raw** Ed25519 signature bytes over the exact
`manifest.json` bytes, including whitespace and the final newline. Do not
reserialize JSON before verification. The trust key comes from the application,
not from a manifest or download. `signing_key_id` is the first 16 lowercase hex
characters of SHA-256(public-key-bytes); the full trusted public key is required.

The manifest binds the gzip hash, raw dataset hash, both file sizes, counts,
category definitions, compatibility versions and the repository's versioned
public asset URL. Source provenance includes URL, license, downloaded hash,
size, accepted/rejected/duplicate/unique counts, category and scope. Source
records stay out of the hot-path index.

Versions are UTC timestamps `YYYYMMDDHHMMSS` encoded as a JSON integer. They fit
within JavaScript's exact integer range. Tags are `rules-<version>`; second
resolution allows reviewed manual releases in the same month without changing
an existing monthly tag. Creation time must match the version. Existing tags
and assets are never overwritten by these scripts.

Gzip headers are deterministic (no timestamp/name); compression uses Go's best
compression. Determinism means identical inputs, timestamp and key produce the
same release **with the same toolchain/compressor**. The raw binary is independent
of release time; cross-Go-version gzip byte identity is not promised.

Hard local bounds: manifest 1 MiB, compressed artifact 128 MiB, raw dataset
512 MiB, count 10 million, source 128 MiB, source line 4 KiB. The verifier checks
signed size limits against local caps and uses bounded reads. It accepts one gzip
member and no trailing bytes. Startup validates the whole dataset before use;
lookup uses binary search on the full name and successive label suffixes.

The reader retains one raw byte buffer. `Open` transfers immutable ownership of
its input by contract; never mutate that slice afterwards. `LookupNormalized`
expects canonical input and avoids repeated normalization in the DNS path.

`fixtures/format1.bin` and `fixtures/matching_vectors.json` provide a fixed wire
fixture for readers implemented in other languages. It is unsigned test data,
not a production update. Go tests validate the expected category masks.
