package main

import (
	"aegis-intelligence/pkg/release"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "Verification failed:", e)
		os.Exit(1)
	}
}
func run() error {
	dir := flag.String("dir", "out/release", "release directory")
	repo := flag.String("repository", os.Getenv("GITHUB_REPOSITORY"), "trusted owner/repository")
	keyFile := flag.String("public-key-file", "", "trusted base64 public key file")
	floor := flag.Uint64("floor", 0, "highest accepted version")
	flag.Parse()
	pubString := os.Getenv("AEGIS_PUBLIC_KEY")
	if *keyFile != "" {
		b, e := os.ReadFile(*keyFile)
		if e != nil {
			return e
		}
		pubString = string(b)
	}
	pub, e := release.Public(pubString)
	if e != nil {
		return e
	}
	b, e := os.ReadFile(filepath.Join(*dir, "manifest.json"))
	if e != nil {
		return e
	}
	sig, e := os.ReadFile(filepath.Join(*dir, "manifest.sig"))
	if e != nil {
		return e
	}
	m, e := release.VerifyManifest(b, sig, map[string]ed25519.PublicKey{release.KeyID(pub): pub}, *repo, release.ClientVersion, *floor)
	if e != nil {
		return e
	}
	f, e := os.Open(filepath.Join(*dir, release.ArtifactName))
	if e != nil {
		return e
	}
	defer f.Close()
	r, _, e := release.VerifyArtifact(m, f)
	if e != nil {
		return e
	}
	fmt.Printf("Verified %s: %d domains, %d bytes resident\n", m.ReleaseTag, r.Count(), r.Bytes())
	return nil
}
