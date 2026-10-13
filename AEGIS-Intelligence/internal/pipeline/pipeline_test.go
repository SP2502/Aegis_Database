package pipeline

import (
	"aegis-intelligence/internal/sources"
	"aegis-intelligence/pkg/release"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineSignedPipeline(t *testing.T) {
	reg, e := sources.Read("../../fixtures/sources.json")
	if e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	o := Options{Registry: reg, Out: filepath.Join(t.TempDir(), "release"), FixtureDir: "../../fixtures", Repository: "owner/repo", CreatedAt: time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC), Key: key, TrustedKeys: map[string]ed25519.PublicKey{release.KeyID(pub): pub}}
	res, e := Build(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	if res.Manifest.DomainCount != 6 {
		t.Fatalf("count %d", res.Manifest.DomainCount)
	}
	b, _ := os.ReadFile(filepath.Join(o.Out, "manifest.json"))
	sig, _ := os.ReadFile(filepath.Join(o.Out, "manifest.sig"))
	gz, _ := os.ReadFile(filepath.Join(o.Out, release.ArtifactName))
	m, e := release.VerifyManifest(b, sig, o.TrustedKeys, o.Repository, release.ClientVersion, 0)
	if e != nil {
		t.Fatal(e)
	}
	r, _, e := release.VerifyArtifact(m, bytes.NewReader(gz))
	if e != nil {
		t.Fatal(e)
	}
	if mask, _ := r.Lookup("shared.test"); mask != 7 {
		t.Fatal("category union", mask)
	}
	o.Out = filepath.Join(t.TempDir(), "second")
	res, e = Build(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	b2, _ := os.ReadFile(filepath.Join(o.Out, "manifest.json"))
	gz2, _ := os.ReadFile(filepath.Join(o.Out, release.ArtifactName))
	if !bytes.Equal(b, b2) || !bytes.Equal(gz, gz2) {
		t.Fatal("nondeterministic release")
	}
	o.PreviousManifest = b
	o.PreviousSignature = sig
	o.CreatedAt = o.CreatedAt.Add(time.Hour)
	o.Out = filepath.Join(t.TempDir(), "unchanged")
	res, e = Build(context.Background(), o)
	if e != nil || !res.NoChange {
		t.Fatal("no change", e)
	}
	if _, e = os.Stat(o.Out); !os.IsNotExist(e) {
		t.Fatal("unchanged release written")
	}
	o.Registry.Sources[0].MinRecords = 100
	if _, e = Build(context.Background(), o); e == nil {
		t.Fatal("incomplete source accepted")
	}
	o.Registry = reg
	o.PreviousManifest = nil
	o.PreviousSignature = nil
	o.Registry.CriticalDomains = []string{"shared.test"}
	if _, e = Build(context.Background(), o); e == nil {
		t.Fatal("critical domain accepted")
	}
}

func TestPlannedKeyRotation(t *testing.T) {
	reg, e := sources.Read("../../fixtures/sources.json")
	if e != nil {
		t.Fatal(e)
	}
	oldPub, oldKey, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	o := Options{Registry: reg, FixtureDir: "../../fixtures", Repository: "owner/repo", Out: filepath.Join(dir, "old"), CreatedAt: time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC), Key: oldKey, TrustedKeys: map[string]ed25519.PublicKey{release.KeyID(oldPub): oldPub}}
	if _, e = Build(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	o.PreviousManifest, _ = os.ReadFile(filepath.Join(o.Out, "manifest.json"))
	o.PreviousSignature, _ = os.ReadFile(filepath.Join(o.Out, "manifest.sig"))
	o.Out = filepath.Join(dir, "new")
	o.CreatedAt = o.CreatedAt.Add(time.Hour)
	o.Key = newKey
	result, e := Build(context.Background(), o)
	if e != nil || result.NoChange {
		t.Fatal("rotation must publish", e)
	}
	b, _ := os.ReadFile(filepath.Join(o.Out, "manifest.json"))
	sig, _ := os.ReadFile(filepath.Join(o.Out, "manifest.sig"))
	if _, e = release.VerifyManifest(b, sig, o.TrustedKeys, o.Repository, release.ClientVersion, 0); e == nil {
		t.Fatal("new key trusted without client update")
	}
	if _, e = release.VerifyManifest(b, sig, map[string]ed25519.PublicKey{release.KeyID(newPub): newPub}, o.Repository, release.ClientVersion, 0); e != nil {
		t.Fatal(e)
	}
}
