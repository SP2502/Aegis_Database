package main

import (
	"aegis-intelligence/pkg/release"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	dir := flag.String("out", "keys", "new private output directory")
	flag.Parse()
	if e := run(*dir); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(dir string) error {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		return fmt.Errorf("refuse existing/inaccessible key directory: %w", e)
	}
	if e = os.WriteFile(filepath.Join(dir, "signing.seed"), []byte(base64.StdEncoding.EncodeToString(key.Seed())+"\n"), 0600); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "verification.pub"), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0644); e != nil {
		return e
	}
	fmt.Printf("Created key files. Public key ID: %s\n", release.KeyID(pub))
	return nil
}
