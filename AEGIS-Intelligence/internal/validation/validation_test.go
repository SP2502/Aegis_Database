package validation

import (
	"aegis-intelligence/internal/parser"
	"aegis-intelligence/internal/sources"
	"aegis-intelligence/pkg/dataset"
	"aegis-intelligence/pkg/release"
	"testing"
)

func TestSourceGates(t *testing.T) {
	s := sources.Source{ID: "fixture", MinRecords: 10, MaxMalformed: .01, MaxDuplicates: .5}
	for _, st := range []parser.Stats{{Accepted: 5, Unique: 5}, {Accepted: 100, Unique: 100, Rejected: 2}, {Accepted: 100, Unique: 20, Duplicates: 80}} {
		if Source(s, st) == nil {
			t.Fatal("gate accepted", st)
		}
	}
	if e := Source(s, parser.Stats{Accepted: 100, Unique: 90, Duplicates: 10}); e != nil {
		t.Fatal(e)
	}
}
func TestChangesAndCriticalDomains(t *testing.T) {
	raw, _ := dataset.Compile([]dataset.Entry{{Domain: "github.com", Subdomains: 4}})
	r, _ := dataset.Open(raw)
	reg := sources.Registry{MinimumDomains: 1, MaxCountChange: .35, CriticalDomains: []string{"api.github.com"}}
	if Dataset(reg, r, release.Manifest{}, release.Manifest{}) == nil {
		t.Fatal("critical suffix")
	}
	reg.CriticalDomains = nil
	if Dataset(reg, r, release.Manifest{DatasetVersion: 2, DomainCount: 1}, release.Manifest{DatasetVersion: 1, DomainCount: 100}) == nil {
		t.Fatal("count drift")
	}
}
