package sources

import (
	"aegis-intelligence/pkg/dataset"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
)

type Source struct {
	ID            string  `json:"id"`
	URL           string  `json:"url"`
	License       string  `json:"license"`
	Category      string  `json:"category"`
	Format        string  `json:"format"`
	Enabled       bool    `json:"enabled"`
	Required      bool    `json:"required"`
	MaxBytes      int64   `json:"max_download_bytes"`
	MinRecords    int     `json:"minimum_records"`
	MaxMalformed  float64 `json:"max_malformed_rate"`
	MaxDuplicates float64 `json:"max_duplicate_rate"`
	Semantics     string  `json:"semantics"`
	Header        string  `json:"required_header"`
	LicenseHeader string  `json:"required_license_header"`
}
type Registry struct {
	SchemaVersion   int      `json:"schema_version"`
	AllowedHosts    []string `json:"allowed_hosts"`
	Sources         []Source `json:"sources"`
	MinimumDomains  int      `json:"minimum_domains"`
	MaxCountChange  float64  `json:"max_count_change"`
	CriticalDomains []string `json:"critical_domains"`
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func Mask(id string) uint16 {
	for _, c := range dataset.Categories {
		if c.ID == id {
			return c.Bit
		}
	}
	return 0
}
func Read(path string) (Registry, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Registry{}, e
	}
	return Decode(b)
}
func Decode(b []byte) (Registry, error) {
	var r Registry
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&r); e != nil {
		return r, e
	}
	if d.Decode(new(any)) != io.EOF {
		return r, fmt.Errorf("trailing configuration")
	}
	return r, r.Validate()
}
func (r Registry) Validate() error {
	if r.SchemaVersion != 1 || r.MinimumDomains < 1 || r.MaxCountChange <= 0 || r.MaxCountChange > 1 || len(r.Sources) == 0 || len(r.Sources) > 32 {
		return fmt.Errorf("invalid registry bounds")
	}
	hosts := map[string]bool{}
	for _, h := range r.AllowedHosts {
		if h != "blocklistproject.github.io" && h != "raw.githubusercontent.com" {
			return fmt.Errorf("host has not been reviewed")
		}
		hosts[h] = true
	}
	ids := map[string]bool{}
	required := 0
	for _, s := range r.Sources {
		if !idPattern.MatchString(s.ID) || ids[s.ID] {
			return fmt.Errorf("invalid source id")
		}
		ids[s.ID] = true
		u, e := url.Parse(s.URL)
		if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" || !hosts[u.Hostname()] {
			return fmt.Errorf("unapproved source URL")
		}
		// Host allowance alone cannot authorize unrelated repositories or paths.
		if u.Hostname() == "blocklistproject.github.io" {
			if !regexp.MustCompile(`^/Lists/alt-version/(porn|gambling|malware|phishing)-nl\.txt$`).MatchString(u.Path) {
				return fmt.Errorf("unreviewed source path")
			}
		} else if !regexp.MustCompile(`^/blocklistproject/Lists/(main|master)/((alt-version/(porn|gambling|malware|phishing)-nl)|(porn|gambling|malware|phishing))\.txt$`).MatchString(u.Path) {
			return fmt.Errorf("unreviewed source path")
		}
		if s.License != "Unlicense (repository); MIT (generated header)" || s.Header == "" || s.LicenseHeader == "" || Mask(s.Category) == 0 || (s.Format != "domains" && s.Format != "hosts") || (s.Semantics != "exact" && s.Semantics != "subdomains") || s.MaxBytes <= 0 || s.MaxBytes > 128<<20 || s.MinRecords < 1 || s.MaxMalformed < 0 || s.MaxMalformed > 0.1 || s.MaxDuplicates < 0 || s.MaxDuplicates > 0.99 {
			return fmt.Errorf("invalid source contract: %s", s.ID)
		}
		if s.Required && !s.Enabled {
			return fmt.Errorf("required source disabled")
		}
		if s.Required {
			required++
		}
	}
	if required == 0 {
		return fmt.Errorf("no required sources")
	}
	return nil
}
