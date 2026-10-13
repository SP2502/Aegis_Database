package validation

import (
	"aegis-intelligence/internal/parser"
	"aegis-intelligence/internal/sources"
	"aegis-intelligence/pkg/dataset"
	"aegis-intelligence/pkg/release"
	"fmt"
	"math"
)

func Source(s sources.Source, st parser.Stats) error {
	if st.Unique < s.MinRecords || st.Accepted == 0 {
		return fmt.Errorf("%s: record floor violated", s.ID)
	}
	if float64(st.Rejected)/float64(st.Accepted+st.Rejected) > s.MaxMalformed {
		return fmt.Errorf("%s: malformed rate exceeded", s.ID)
	}
	if float64(st.Duplicates)/float64(st.Accepted) > s.MaxDuplicates {
		return fmt.Errorf("%s: duplicate rate exceeded", s.ID)
	}
	return nil
}
func change(old, new int, limit float64) bool {
	return old > 0 && math.Abs(float64(new-old))/float64(old) > limit
}
func Dataset(reg sources.Registry, r *dataset.Reader, current, previous release.Manifest) error {
	if r.Count() < reg.MinimumDomains {
		return fmt.Errorf("global entry floor violated")
	}
	for _, h := range reg.CriticalDomains {
		mask, e := r.Lookup(h)
		if e != nil {
			return fmt.Errorf("invalid critical domain configuration")
		}
		if mask != 0 {
			return fmt.Errorf("critical domain matches dataset; review required")
		}
	}
	if previous.DatasetVersion > 0 {
		if current.DatasetVersion <= previous.DatasetVersion {
			return fmt.Errorf("release version did not increase")
		}
		if change(previous.DomainCount, current.DomainCount, reg.MaxCountChange) {
			return fmt.Errorf("unexpected global count change")
		}
		old := map[string]release.SourceSummary{}
		for _, s := range previous.SourceSummary {
			old[s.ID] = s
		}
		for _, s := range current.SourceSummary {
			p, ok := old[s.ID]
			if !ok {
				return fmt.Errorf("new source requires reviewed baseline")
			}
			if p.Category != s.Category || p.Semantics != s.Semantics || p.URL != s.URL || p.License != s.License || change(p.Unique, s.Unique, reg.MaxCountChange) {
				return fmt.Errorf("source contract or count changed: %s", s.ID)
			}
			delete(old, s.ID)
		}
		if len(old) != 0 {
			return fmt.Errorf("source removed; review required")
		}
	}
	return nil
}
