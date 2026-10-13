package pipeline

import (
	"aegis-intelligence/internal/fetcher"
	"aegis-intelligence/internal/parser"
	"aegis-intelligence/internal/sources"
	"aegis-intelligence/internal/validation"
	"aegis-intelligence/pkg/dataset"
	"aegis-intelligence/pkg/release"
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	Registry          sources.Registry
	Out               string
	FixtureDir        string
	Repository        string
	Commit            string
	CreatedAt         time.Time
	Key               ed25519.PrivateKey
	TrustedKeys       map[string]ed25519.PublicKey
	PreviousManifest  []byte
	PreviousSignature []byte
}
type Result struct {
	Manifest release.Manifest
	NoChange bool
}

func Build(ctx context.Context, o Options) (Result, error) {
	var result Result
	if e := o.Registry.Validate(); e != nil {
		return result, e
	}
	if !release.ValidRepository(o.Repository) || len(o.Key) != 64 {
		return result, fmt.Errorf("repository and signing key required")
	}
	if o.CreatedAt.IsZero() {
		return result, fmt.Errorf("creation time required")
	}
	version, e := strconv.ParseUint(o.CreatedAt.UTC().Format("20060102150405"), 10, 64)
	if e != nil {
		return result, e
	}
	var prev release.Manifest
	if len(o.PreviousManifest) > 0 {
		prev, e = release.VerifyManifest(o.PreviousManifest, o.PreviousSignature, o.TrustedKeys, o.Repository, release.ClientVersion, 0)
		if e != nil {
			return result, fmt.Errorf("previous release: %w", e)
		}
	} else if len(o.PreviousSignature) > 0 {
		return result, fmt.Errorf("signature without previous manifest")
	}
	pub := o.Key.Public().(ed25519.PublicKey)
	tag := release.Tag(version)
	m := release.Manifest{SchemaVersion: 1, DatasetVersion: version, CreatedAt: o.CreatedAt.UTC().Format(time.RFC3339), MinimumClientVersion: release.ClientVersion, FormatVersion: dataset.FormatVersion, NormalizationVersion: dataset.NormalizationVersion, CategoryDefinitions: dataset.Categories, ArtifactName: release.ArtifactName, ArtifactURL: release.AssetURL(o.Repository, tag, release.ArtifactName), ReleaseTag: tag, SigningKeyID: release.KeyID(pub), BuildCommit: o.Commit}
	temp, e := os.MkdirTemp("", "aegis-sources-*")
	if e != nil {
		return result, e
	}
	defer os.RemoveAll(temp)
	client := fetcher.New(o.Registry.AllowedHosts)
	unified := map[string]dataset.Entry{}
	// One source at a time: bounded concurrency of one, no duplicate source bodies
	// retained in memory. Required and enabled optional failures both stop release.
	for _, s := range o.Registry.Sources {
		if !s.Enabled {
			continue
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		var path, hash string
		var size int64
		if o.FixtureDir != "" {
			path = filepath.Join(o.FixtureDir, s.ID+".txt")
			f, e := os.Open(path)
			if e != nil {
				return result, e
			}
			b, e := io.ReadAll(io.LimitReader(f, s.MaxBytes+1))
			f.Close()
			if e != nil || len(b) == 0 || int64(len(b)) > s.MaxBytes {
				return result, fmt.Errorf("fixture bounds")
			}
			hash = release.Hash(b)
			size = int64(len(b))
		} else {
			d, e := client.Fetch(ctx, s.URL, s.MaxBytes, temp)
			if e != nil {
				return result, fmt.Errorf("%s: %w", s.ID, e)
			}
			path = d.Path
			hash = d.SHA256
			size = d.Size
		}
		f, e := os.Open(path)
		if e != nil {
			return result, e
		}
		header := make([]byte, 4096)
		n, e := f.Read(header)
		if e != nil && e != io.EOF {
			f.Close()
			return result, e
		}
		if !headerLine(header[:n], s.Header) || !headerLine(header[:n], s.LicenseHeader) || !headerLine(header[:n], "# Format: "+s.Format) {
			f.Close()
			return result, fmt.Errorf("%s: source identity, format or license header changed", s.ID)
		}
		if _, e = f.Seek(0, 0); e != nil {
			f.Close()
			return result, e
		}
		seen := map[string]struct{}{}
		st, e := parser.Parse(f, s.Format, func(h string) bool {
			_, dup := seen[h]
			seen[h] = struct{}{}
			dataset.Merge(unified, h, sources.Mask(s.Category), s.Semantics == "subdomains")
			return dup
		})
		f.Close()
		if o.FixtureDir == "" {
			os.Remove(path)
		}
		if e != nil {
			return result, e
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if e = validation.Source(s, st); e != nil {
			return result, e
		}
		m.SourceSummary = append(m.SourceSummary, release.SourceSummary{ID: s.ID, URL: s.URL, License: s.License, Category: s.Category, Semantics: s.Semantics, SHA256: hash, DownloadSize: size, Accepted: st.Accepted, Rejected: st.Rejected, Duplicates: st.Duplicates, Unique: st.Unique})
	}
	entries := dataset.Sorted(unified)
	unified = nil
	raw, e := dataset.Compile(entries)
	if e != nil {
		return result, e
	}
	again, e := dataset.Compile(entries)
	if e != nil || !bytes.Equal(raw, again) {
		return result, fmt.Errorf("nondeterministic compiler")
	}
	again = nil
	entries = nil
	reader, e := dataset.Open(raw)
	if e != nil {
		return result, e
	}
	m.DomainCount = reader.Count()
	m.UncompressedSize = int64(len(raw))
	m.DatasetSHA256 = release.Hash(raw)
	if e = validation.Dataset(o.Registry, reader, m, prev); e != nil {
		return result, e
	}
	// Compare content and rule semantics, not volatile source comments/timestamps.
	if prev.DatasetVersion > 0 && prev.DatasetSHA256 == m.DatasetSHA256 && prev.SigningKeyID == m.SigningKeyID {
		return Result{prev, true}, nil
	}
	artifact, e := release.Compress(raw)
	if e != nil {
		return result, e
	}
	m.CompressedSize = int64(len(artifact))
	m.ArtifactSHA256 = release.Hash(artifact)
	manifest, e := release.Encode(m)
	if e != nil {
		return result, e
	}
	sig := release.Sign(manifest, o.Key)
	keys := map[string]ed25519.PublicKey{m.SigningKeyID: pub}
	verified, e := release.VerifyManifest(manifest, sig, keys, o.Repository, release.ClientVersion, prev.DatasetVersion)
	if e != nil {
		return result, e
	}
	if _, _, e = release.VerifyArtifactBytes(verified, artifact); e != nil {
		return result, e
	}
	// Stage then rename a fresh output directory; refuse accidental overwrites.
	if _, e = os.Stat(o.Out); !os.IsNotExist(e) {
		return result, fmt.Errorf("output directory already exists or cannot be accessed")
	}
	parent := filepath.Dir(o.Out)
	if e = os.MkdirAll(parent, 0755); e != nil {
		return result, e
	}
	stage, e := os.MkdirTemp(parent, ".release-*")
	if e != nil {
		return result, e
	}
	defer os.RemoveAll(stage)
	for _, f := range []struct {
		name string
		data []byte
	}{{release.ArtifactName, artifact}, {"manifest.json", manifest}, {"manifest.sig", sig}} {
		if e = os.WriteFile(filepath.Join(stage, f.name), f.data, 0644); e != nil {
			return result, e
		}
	}
	if e = os.Rename(stage, o.Out); e != nil {
		return result, e
	}
	return Result{m, false}, nil
}

func headerLine(b []byte, want string) bool {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}
