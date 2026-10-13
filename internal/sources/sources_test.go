package sources

import (
	"os"
	"testing"
)

func TestRegistry(t *testing.T) {
	b, e := os.ReadFile("../../config/sources.json")
	if e != nil {
		t.Fatal(e)
	}
	r, e := Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Sources) != 4 {
		t.Fatal("sources")
	}
	r.Sources[0].URL = "https://raw.githubusercontent.com/evil/repo/main/list.txt"
	r.AllowedHosts = append(r.AllowedHosts, "raw.githubusercontent.com")
	if r.Validate() == nil {
		t.Fatal("arbitrary source")
	}
	r, _ = Decode(b)
	r.Sources[0].License = "GPL-3.0"
	if r.Validate() == nil {
		t.Fatal("unreviewed license")
	}
}
