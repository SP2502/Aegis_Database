package main

import (
	"aegis-intelligence/internal/pipeline"
	"aegis-intelligence/internal/sources"
	"aegis-intelligence/pkg/release"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "Build stopped:", e)
		os.Exit(1)
	}
}
func run() error {
	config := flag.String("sources", "config/sources.json", "reviewed registry")
	out := flag.String("out", "out/release", "fresh output directory")
	fixtures := flag.String("fixtures", "", "offline fixture directory")
	repo := flag.String("repository", os.Getenv("GITHUB_REPOSITORY"), "owner/repository")
	previous := flag.String("previous", "", "directory with previous signed manifest")
	keyFile := flag.String("key-file", "", "local signing seed file (CI uses AEGIS_SIGNING_SEED)")
	publicFile := flag.String("public-key-file", "", "current trusted public key (CI uses AEGIS_PUBLIC_KEY)")
	previousPublicFile := flag.String("previous-public-key-file", "", "optional previous trust key during planned rotation")
	created := flag.String("created-at", "", "RFC3339 reproducible build timestamp")
	flag.Parse()
	reg, e := sources.Read(*config)
	if e != nil {
		return e
	}
	encoded := os.Getenv("AEGIS_SIGNING_SEED")
	if *keyFile != "" {
		b, e := os.ReadFile(*keyFile)
		if e != nil {
			return e
		}
		encoded = string(b)
	}
	key, e := release.Seed(encoded)
	if e != nil {
		return e
	}
	pub := key.Public().(ed25519.PublicKey)
	keys := map[string]ed25519.PublicKey{release.KeyID(pub): pub}
	trust := os.Getenv("AEGIS_PUBLIC_KEY")
	if *publicFile != "" {
		b, e := os.ReadFile(*publicFile)
		if e != nil {
			return e
		}
		trust = string(b)
	}
	if trust != "" {
		p, e := release.Public(trust)
		if e != nil {
			return e
		}
		if !bytes.Equal(p, pub) {
			return fmt.Errorf("configured public key does not match signing seed")
		}
		keys[release.KeyID(p)] = p
	}
	previousTrust := os.Getenv("AEGIS_PREVIOUS_PUBLIC_KEY")
	if *previousPublicFile != "" {
		b, e := os.ReadFile(*previousPublicFile)
		if e != nil {
			return e
		}
		previousTrust = string(b)
	}
	if previousTrust != "" {
		p, e := release.Public(previousTrust)
		if e != nil {
			return e
		}
		keys[release.KeyID(p)] = p
	}
	now := time.Now().UTC().Truncate(time.Second)
	if *created != "" {
		now, e = time.Parse(time.RFC3339, *created)
		if e != nil {
			return e
		}
	}
	o := pipeline.Options{Registry: reg, Out: *out, FixtureDir: *fixtures, Repository: *repo, Key: key, TrustedKeys: keys, CreatedAt: now, Commit: os.Getenv("GITHUB_SHA")}
	if *previous != "" {
		o.PreviousManifest, e = os.ReadFile(filepath.Join(*previous, "manifest.json"))
		if e != nil {
			return e
		}
		o.PreviousSignature, e = os.ReadFile(filepath.Join(*previous, "manifest.sig"))
		if e != nil {
			return e
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 20*time.Minute)
	defer timeout()
	result, e := pipeline.Build(ctx, o)
	if e != nil {
		return e
	}
	if result.NoChange {
		fmt.Println("NO_CHANGE: existing signed dataset retained")
		if p := os.Getenv("GITHUB_OUTPUT"); p != "" {
			return appendOutput(p, "changed=false\n")
		}
		return nil
	}
	b, _ := json.Marshal(result.Manifest)
	fmt.Println(string(b))
	if p := os.Getenv("GITHUB_OUTPUT"); p != "" {
		if e = appendOutput(p, "changed=true\ntag="+result.Manifest.ReleaseTag+"\n"); e != nil {
			return e
		}
	}
	return nil
}
func appendOutput(path, content string) error {
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = f.WriteString(content)
	return e
}
