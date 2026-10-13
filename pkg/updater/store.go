// Package updater is a reference single-writer integration for the Go Bridge.
// The caller must own a protected state directory and serialize all processes.
package updater

import (
	"aegis-intelligence/pkg/dataset"
	"aegis-intelligence/pkg/release"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
)

type State struct {
	HighestVersion  uint64 `json:"highest_version"`
	PreviousVersion uint64 `json:"previous_version"`
}
type Snapshot struct {
	Dataset       *dataset.Reader
	Manifest      release.Manifest
	UsingPrevious bool
}
type Store struct {
	Dir        string
	Repository string
	Keys       map[string]ed25519.PublicKey
	mu         sync.Mutex
	active     atomic.Pointer[Snapshot]
}

func (s *Store) Snapshot() *Snapshot { return s.active.Load() }
func (s *Store) state() (State, error) {
	b, e := readBounded(filepath.Join(s.Dir, "CURRENT.json"), 4096)
	if os.IsNotExist(e) {
		return State{}, nil
	}
	if e != nil {
		return State{}, e
	}
	var st State
	if e = json.Unmarshal(b, &st); e != nil {
		return st, e
	}
	if st.HighestVersion == 0 || st.PreviousVersion >= st.HighestVersion {
		return st, fmt.Errorf("invalid durable rollback state")
	}
	return st, nil
}
func (s *Store) HighestVersion() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.state()
	return st.HighestVersion, e
}
func generation(dir string, v uint64) string { return filepath.Join(dir, strconv.FormatUint(v, 10)) }
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func writeSync(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	return f.Close()
}
func (s *Store) Activate(manifest, sig, artifact []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.state()
	if e != nil {
		return e
	}
	m, e := release.VerifyManifest(manifest, sig, s.Keys, s.Repository, release.ClientVersion, st.HighestVersion)
	if e != nil {
		return e
	}
	r, _, e := release.VerifyArtifactBytes(m, artifact)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(s.Dir, 0700); e != nil {
		return e
	}
	tmp, e := os.MkdirTemp(s.Dir, ".generation-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	for _, f := range []struct {
		name string
		b    []byte
	}{{"manifest.json", manifest}, {"manifest.sig", sig}, {release.ArtifactName, artifact}} {
		if e = writeSync(filepath.Join(tmp, f.name), f.b); e != nil {
			return e
		}
	}
	if e = syncDir(tmp); e != nil {
		return e
	}
	target := generation(s.Dir, m.DatasetVersion)
	if _, e = os.Stat(target); e == nil {
		// Recover only an identical fully verified generation left by a crash before
		// the pointer transaction. Never overwrite different bytes at the same version.
		for _, f := range []struct {
			name string
			b    []byte
		}{{"manifest.json", manifest}, {"manifest.sig", sig}, {release.ArtifactName, artifact}} {
			b, e := os.ReadFile(filepath.Join(target, f.name))
			if e != nil || !bytes.Equal(b, f.b) {
				return fmt.Errorf("generation version collision")
			}
		}
	} else if !os.IsNotExist(e) {
		return e
	} else if e = os.Rename(tmp, target); e != nil {
		return e
	}
	if e = syncDir(s.Dir); e != nil {
		return e
	}
	next := State{m.DatasetVersion, st.HighestVersion}
	b, _ := json.Marshal(next)
	pointer, e := os.CreateTemp(s.Dir, ".CURRENT-*")
	if e != nil {
		return e
	}
	name := pointer.Name()
	defer os.Remove(name)
	if _, e = pointer.Write(b); e != nil {
		pointer.Close()
		return e
	}
	if e = pointer.Sync(); e != nil {
		pointer.Close()
		return e
	}
	if e = pointer.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, filepath.Join(s.Dir, "CURRENT.json")); e != nil {
		return e
	}
	// The high-water mark and active generation change in one pointer transaction.
	// A post-rename fsync error must be reported, though disk state may be advanced.
	if e = syncDir(s.Dir); e != nil {
		return e
	}
	s.active.Store(&Snapshot{Dataset: r, Manifest: m})
	return nil
}
func (s *Store) load(v uint64) (*Snapshot, error) {
	dir := generation(s.Dir, v)
	manifest, e := readBounded(filepath.Join(dir, "manifest.json"), release.MaxManifestSize)
	if e != nil {
		return nil, e
	}
	sig, e := readBounded(filepath.Join(dir, "manifest.sig"), 64)
	if e != nil {
		return nil, e
	}
	m, e := release.VerifyManifest(manifest, sig, s.Keys, s.Repository, release.ClientVersion, 0)
	if e != nil || m.DatasetVersion != v {
		return nil, fmt.Errorf("stored manifest invalid")
	}
	f, e := os.Open(filepath.Join(dir, release.ArtifactName))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	r, _, e := release.VerifyArtifact(m, f)
	if e != nil {
		return nil, e
	}
	return &Snapshot{Dataset: r, Manifest: m}, nil
}

// LoadOffline explicitly exposes recovery use; the durable high-water mark stays
// unchanged when falling back, so an older network release cannot be reinstalled.
func (s *Store) LoadOffline() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.state()
	if e != nil {
		return e
	}
	if st.HighestVersion == 0 {
		return fmt.Errorf("no installed dataset")
	}
	snap, e := s.load(st.HighestVersion)
	if e != nil && st.PreviousVersion > 0 {
		snap, e = s.load(st.PreviousVersion)
		if e == nil {
			snap.UsingPrevious = true
		}
	}
	if e != nil {
		return e
	}
	s.active.Store(snap)
	return nil
}
