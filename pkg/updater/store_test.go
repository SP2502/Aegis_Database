package updater

import (
	"aegis-intelligence/pkg/dataset"
	"aegis-intelligence/pkg/release"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func makeBundle(t *testing.T, key ed25519.PrivateKey, v uint64) ([]byte, []byte, []byte) {
	t.Helper()
	raw, _ := dataset.Compile([]dataset.Entry{{Domain: "blocked.test", Exact: 1}})
	gz, _ := release.Compress(raw)
	stamp, _ := time.Parse("20060102150405", strconv.FormatUint(v, 10))
	m := release.Manifest{SchemaVersion: 1, DatasetVersion: v, CreatedAt: stamp.Format(time.RFC3339), MinimumClientVersion: release.ClientVersion, FormatVersion: 1, NormalizationVersion: 1, CategoryDefinitions: dataset.Categories, DomainCount: 1, CompressedSize: int64(len(gz)), UncompressedSize: int64(len(raw)), ArtifactSHA256: release.Hash(gz), DatasetSHA256: release.Hash(raw), ArtifactName: release.ArtifactName, ArtifactURL: release.AssetURL("owner/repo", release.Tag(v), release.ArtifactName), ReleaseTag: release.Tag(v), SigningKeyID: release.KeyID(key.Public().(ed25519.PublicKey)), SourceSummary: []release.SourceSummary{{ID: "fixture", Accepted: 1, Unique: 1, DownloadSize: 10}}}
	b, _ := release.Encode(m)
	return b, release.Sign(b, key), gz
}
func TestAtomicOfflineAndRollback(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := Store{Dir: t.TempDir(), Repository: "owner/repo", Keys: map[string]ed25519.PublicKey{release.KeyID(pub): pub}}
	b, sig, gz := makeBundle(t, key, 20261012060000)
	if e := s.Activate(b, sig, gz); e != nil {
		t.Fatal(e)
	}
	if e := s.Activate(b, sig, gz); e == nil {
		t.Fatal("replay")
	}
	b2, sig2, gz2 := makeBundle(t, key, 20261013060000)
	bad := bytes.Clone(gz2)
	bad[0] ^= 1
	if e := s.Activate(b2, sig2, bad); e == nil {
		t.Fatal("tampered update")
	}
	if v, _ := s.HighestVersion(); v != 20261012060000 {
		t.Fatal("state changed on failure")
	}
	if e := s.Activate(b2, sig2, gz2); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(generation(s.Dir, 20261013060000), release.ArtifactName), []byte("corrupt"), 0600)
	if e := s.LoadOffline(); e != nil {
		t.Fatal(e)
	}
	if !s.Snapshot().UsingPrevious || s.Snapshot().Manifest.DatasetVersion != 20261012060000 {
		t.Fatal("offline fallback")
	}
	if v, _ := s.HighestVersion(); v != 20261013060000 {
		t.Fatal("highwater downgraded")
	}
	if e := s.Activate(b, sig, gz); e == nil {
		t.Fatal("rollback after recovery")
	}
	mask, _ := s.Snapshot().Dataset.Lookup("blocked.test")
	if mask != 1 {
		t.Fatal("offline filtering")
	}
}

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestClientUsesPinnedSignatureAndNoArtifactOnNoChange(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	b, sig, gz := makeBundle(t, key, 20261012060000)
	s := &Store{Dir: t.TempDir(), Repository: "owner/repo", Keys: map[string]ed25519.PublicKey{release.KeyID(pub): pub}}
	artifacts := 0
	h := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		var data []byte
		switch {
		case strings.HasSuffix(r.URL.Path, "manifest.json"):
			data = b
		case strings.HasSuffix(r.URL.Path, "manifest.sig"):
			if !strings.Contains(r.URL.Path, "rules-20261012060000") {
				t.Fatal("mutable signature locator")
			}
			data = sig
		case strings.HasSuffix(r.URL.Path, release.ArtifactName):
			data = gz
			artifacts++
		default:
			return nil, fmt.Errorf("unexpected request")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data))}, nil
	})}
	c := Client{Store: s, HTTP: h, Backoff: time.Millisecond}
	if changed, e := c.Update(context.Background()); e != nil || !changed {
		t.Fatal(changed, e)
	}
	if changed, e := c.Update(context.Background()); e != nil || changed || artifacts != 1 {
		t.Fatal(changed, e, artifacts)
	}
	for i := 0; i < 20; i++ {
		now := time.Now()
		next, e := NextCheck(now)
		if e != nil || next.Before(now.Add(24*time.Hour)) || !next.Before(now.Add(30*time.Hour)) {
			t.Fatal("jitter bounds")
		}
	}
}
