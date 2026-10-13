package release

import (
	"aegis-intelligence/pkg/dataset"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func bundle(t *testing.T) (Manifest, []byte, []byte, []byte, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	raw, e := dataset.Compile([]dataset.Entry{{Domain: "blocked.test", Exact: 1}})
	if e != nil {
		t.Fatal(e)
	}
	gz, e := Compress(raw)
	if e != nil {
		t.Fatal(e)
	}
	m := Manifest{SchemaVersion: 1, DatasetVersion: 20261012060000, CreatedAt: "2026-10-12T06:00:00Z", MinimumClientVersion: ClientVersion, FormatVersion: 1, NormalizationVersion: 1, CategoryDefinitions: dataset.Categories, DomainCount: 1, CompressedSize: int64(len(gz)), UncompressedSize: int64(len(raw)), ArtifactSHA256: Hash(gz), DatasetSHA256: Hash(raw), ArtifactName: ArtifactName, ArtifactURL: AssetURL("owner/repo", Tag(20261012060000), ArtifactName), ReleaseTag: Tag(20261012060000), SigningKeyID: KeyID(pub), SourceSummary: []SourceSummary{{ID: "fixture", Unique: 1, Accepted: 1, DownloadSize: 10}}}
	b, _ := Encode(m)
	return m, b, Sign(b, key), gz, map[string]ed25519.PublicKey{KeyID(pub): pub}
}
func TestSignatureAndReplay(t *testing.T) {
	m, b, sig, gz, keys := bundle(t)
	v, e := VerifyManifest(b, sig, keys, "owner/repo", ClientVersion, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = VerifyArtifact(v, bytes.NewReader(gz)); e != nil {
		t.Fatal(e)
	}
	bad := bytes.Clone(b)
	bad[len(b)-2] ^= 1
	if _, e = VerifyManifest(bad, sig, keys, "owner/repo", ClientVersion, 0); e == nil {
		t.Fatal("tampered manifest")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, e = VerifyManifest(b, sig, map[string]ed25519.PublicKey{m.SigningKeyID: pub}, "owner/repo", ClientVersion, 0); e == nil {
		t.Fatal("wrong key")
	}
	if _, e = VerifyManifest(b, sig, keys, "owner/repo", ClientVersion, m.DatasetVersion); e == nil {
		t.Fatal("replay")
	}
	if _, e = VerifyManifest(b, sig, keys, "other/repo", ClientVersion, 0); e == nil {
		t.Fatal("wrong repository")
	}
	if _, e = VerifyManifest(b, sig, keys, "owner/repo", "0.0.1", 0); e == nil {
		t.Fatal("old client")
	}
}
func TestArtifactCorruptionAndBomb(t *testing.T) {
	m, _, _, gz, _ := bundle(t)
	bad := bytes.Clone(gz)
	bad[len(bad)/2] ^= 1
	if _, _, e := VerifyArtifact(m, bytes.NewReader(bad)); e == nil {
		t.Fatal("tamper")
	}
	m.UncompressedSize--
	if _, _, e := VerifyArtifact(m, bytes.NewReader(gz)); e == nil {
		t.Fatal("decompression cap")
	}
	m.UncompressedSize++
	joined := append(bytes.Clone(gz), gz...)
	m.CompressedSize = int64(len(joined))
	m.ArtifactSHA256 = Hash(joined)
	if _, _, e := VerifyArtifact(m, bytes.NewReader(joined)); e == nil {
		t.Fatal("gzip multi-member accepted")
	}
	bomb, _ := Compress(bytes.Repeat([]byte("x"), 1<<20))
	m.CompressedSize = int64(len(bomb))
	m.UncompressedSize = 100
	m.ArtifactSHA256 = Hash(bomb)
	if _, _, e := VerifyArtifact(m, bytes.NewReader(bomb)); e == nil {
		t.Fatal("bomb")
	}
}
func FuzzManifest(f *testing.F) {
	f.Add([]byte(`{"schema_version":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = Parse(b)
	})
}
