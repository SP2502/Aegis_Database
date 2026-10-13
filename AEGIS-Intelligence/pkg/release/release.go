// Package release defines the exact-bytes signed manifest and offline verifier.
package release

import (
	"aegis-intelligence/pkg/dataset"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const ArtifactName = "aegis-rules.bin.gz"
const MaxManifestSize = 1 << 20
const MaxCompressedSize = 128 << 20
const ClientVersion = "0.1.0"

type SourceSummary struct {
	ID           string `json:"id"`
	URL          string `json:"url"`
	License      string `json:"license"`
	Category     string `json:"category"`
	Semantics    string `json:"semantics"`
	SHA256       string `json:"sha256"`
	DownloadSize int64  `json:"download_size"`
	Accepted     int    `json:"accepted"`
	Rejected     int    `json:"rejected"`
	Duplicates   int    `json:"duplicates"`
	Unique       int    `json:"unique"`
}
type Manifest struct {
	SchemaVersion        int                `json:"schema_version"`
	DatasetVersion       uint64             `json:"dataset_version"`
	CreatedAt            string             `json:"created_at"`
	MinimumClientVersion string             `json:"minimum_client_version"`
	FormatVersion        int                `json:"format_version"`
	NormalizationVersion int                `json:"normalization_version"`
	CategoryDefinitions  []dataset.Category `json:"category_definitions"`
	DomainCount          int                `json:"domain_count"`
	CompressedSize       int64              `json:"compressed_size"`
	UncompressedSize     int64              `json:"uncompressed_size"`
	ArtifactSHA256       string             `json:"artifact_sha256"`
	DatasetSHA256        string             `json:"dataset_sha256"`
	ArtifactName         string             `json:"artifact_name"`
	ArtifactURL          string             `json:"artifact_url"`
	ReleaseTag           string             `json:"release_tag"`
	SigningKeyID         string             `json:"signing_key_id"`
	BuildCommit          string             `json:"build_commit"`
	SourceSummary        []SourceSummary    `json:"source_summary"`
}

var repoRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func ValidRepository(r string) bool { return repoRE.MatchString(r) && !strings.Contains(r, "..") }
func Tag(v uint64) string           { return "rules-" + strconv.FormatUint(v, 10) }
func AssetURL(repo, tag, name string) string {
	return "https://github.com/" + repo + "/releases/download/" + tag + "/" + name
}
func Hash(b []byte) string               { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func KeyID(pub ed25519.PublicKey) string { return Hash(pub)[:16] }
func Seed(encoded string) (ed25519.PrivateKey, error) {
	b, e := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if e != nil || len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key must be a base64 Ed25519 32-byte seed")
	}
	return ed25519.NewKeyFromSeed(b), nil
}
func Public(encoded string) (ed25519.PublicKey, error) {
	b, e := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if e != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key")
	}
	return ed25519.PublicKey(b), nil
}
func Encode(m Manifest) ([]byte, error) {
	b, e := json.MarshalIndent(m, "", "  ")
	return append(b, '\n'), e
}
func Parse(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > MaxManifestSize {
		return m, fmt.Errorf("manifest too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&m); e != nil {
		return m, e
	}
	if d.Decode(new(any)) != io.EOF {
		return m, fmt.Errorf("trailing manifest bytes")
	}
	return m, nil
}
func Sign(b []byte, k ed25519.PrivateKey) []byte { return ed25519.Sign(k, b) }
func semver(v string) ([3]int, error) {
	var n [3]int
	p := strings.Split(v, ".")
	if len(p) != 3 {
		return n, fmt.Errorf("invalid client version")
	}
	for i, s := range p {
		if len(s) == 0 || len(s) > 6 || len(s) > 1 && s[0] == '0' {
			return n, fmt.Errorf("invalid client version")
		}
		x, e := strconv.Atoi(s)
		if e != nil || x < 0 {
			return n, fmt.Errorf("invalid client version")
		}
		n[i] = x
	}
	return n, nil
}
func compatible(min, client string) bool {
	a, e := semver(min)
	if e != nil {
		return false
	}
	b, e := semver(client)
	if e != nil {
		return false
	}
	for i := range a {
		if b[i] != a[i] {
			return b[i] > a[i]
		}
	}
	return true
}
func VerifyManifest(b, sig []byte, keys map[string]ed25519.PublicKey, repo, client string, floor uint64) (Manifest, error) {
	m, e := Parse(b)
	if e != nil {
		return m, e
	}
	pub, ok := keys[m.SigningKeyID]
	if !ok || len(pub) != 32 || KeyID(pub) != m.SigningKeyID || !ed25519.Verify(pub, b, sig) {
		return m, fmt.Errorf("untrusted manifest signature")
	}
	if !ValidRepository(repo) || m.SchemaVersion != 1 || m.FormatVersion != dataset.FormatVersion || m.NormalizationVersion != dataset.NormalizationVersion || !compatible(m.MinimumClientVersion, client) || m.DatasetVersion <= floor || m.DatasetVersion < 20200101000000 || m.DatasetVersion > 99991231235959 || m.ReleaseTag != Tag(m.DatasetVersion) || m.ArtifactName != ArtifactName || m.ArtifactURL != AssetURL(repo, m.ReleaseTag, ArtifactName) || m.DomainCount < 1 || m.DomainCount > dataset.MaxEntries || m.CompressedSize <= 0 || m.CompressedSize > MaxCompressedSize || m.UncompressedSize < dataset.HeaderSize || m.UncompressedSize > dataset.MaxFileSize {
		return m, fmt.Errorf("incompatible manifest, sizes, URL or replayed version")
	}
	t, e := time.Parse(time.RFC3339, m.CreatedAt)
	if e != nil || t.UTC().Format("20060102150405") != strconv.FormatUint(m.DatasetVersion, 10) {
		return m, fmt.Errorf("invalid version timestamp")
	}
	cats, _ := json.Marshal(m.CategoryDefinitions)
	want, _ := json.Marshal(dataset.Categories)
	if !bytes.Equal(cats, want) {
		return m, fmt.Errorf("incompatible categories")
	}
	for _, h := range []string{m.ArtifactSHA256, m.DatasetSHA256} {
		v, e := hex.DecodeString(h)
		if e != nil || len(v) != 32 || h != strings.ToLower(h) {
			return m, fmt.Errorf("invalid hash")
		}
	}
	if len(m.SourceSummary) == 0 || len(m.SourceSummary) > 32 {
		return m, fmt.Errorf("missing provenance")
	}
	ids := map[string]bool{}
	for _, s := range m.SourceSummary {
		if s.ID == "" || ids[s.ID] || s.Unique < 1 || s.Accepted < s.Unique || s.Duplicates != s.Accepted-s.Unique || s.Rejected < 0 || s.DownloadSize <= 0 {
			return m, fmt.Errorf("invalid source provenance")
		}
		ids[s.ID] = true
	}
	return m, nil
}
func Compress(raw []byte) ([]byte, error) {
	var b bytes.Buffer
	w, e := gzip.NewWriterLevel(&b, gzip.BestCompression)
	if e != nil {
		return nil, e
	}
	if _, e = w.Write(raw); e != nil {
		return nil, e
	}
	if e = w.Close(); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func VerifyArtifact(m Manifest, in io.Reader) (*dataset.Reader, []byte, error) {
	// Signed expected sizes still have hard local caps: a compromised key cannot
	// instruct the client to allocate unbounded memory.
	if m.CompressedSize <= 0 || m.CompressedSize > MaxCompressedSize || m.UncompressedSize < dataset.HeaderSize || m.UncompressedSize > dataset.MaxFileSize {
		return nil, nil, fmt.Errorf("invalid artifact limits")
	}
	compressed, e := io.ReadAll(io.LimitReader(in, m.CompressedSize+1))
	if e != nil {
		return nil, nil, e
	}
	return VerifyArtifactBytes(m, compressed)
}

// VerifyArtifactBytes avoids copying a caller-owned compressed buffer. Treat it
// as immutable for the duration of verification; raw bytes are independently owned.
func VerifyArtifactBytes(m Manifest, compressed []byte) (*dataset.Reader, []byte, error) {
	if m.CompressedSize <= 0 || m.CompressedSize > MaxCompressedSize || m.UncompressedSize < dataset.HeaderSize || m.UncompressedSize > dataset.MaxFileSize {
		return nil, nil, fmt.Errorf("invalid artifact limits")
	}
	if int64(len(compressed)) != m.CompressedSize || Hash(compressed) != m.ArtifactSHA256 {
		return nil, nil, fmt.Errorf("artifact size or hash mismatch")
	}
	br := bytes.NewReader(compressed)
	z, e := gzip.NewReader(br)
	if e != nil {
		return nil, nil, e
	}
	z.Multistream(false)
	raw := make([]byte, int(m.UncompressedSize))
	if _, e = io.ReadFull(z, raw); e != nil {
		z.Close()
		return nil, nil, e
	}
	var extra [1]byte
	n, tailErr := z.Read(extra[:])
	ce := z.Close()
	if n != 0 || tailErr != io.EOF || ce != nil || br.Len() != 0 || Hash(raw) != m.DatasetSHA256 {
		return nil, nil, fmt.Errorf("decompression size, trailing member or hash mismatch")
	}
	r, e := dataset.Open(raw)
	if e != nil {
		return nil, nil, e
	}
	if r.Count() != m.DomainCount {
		return nil, nil, fmt.Errorf("entry count mismatch")
	}
	return r, raw, nil
}
