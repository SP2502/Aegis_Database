package parser

import (
	"aegis-intelligence/pkg/domain"
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

type Stats struct {
	Accepted   int `json:"accepted"`
	Rejected   int `json:"rejected"`
	Duplicates int `json:"duplicates"`
	Unique     int `json:"unique"`
}

// Parse streams one line at a time (4 KiB maximum). emit returns true for a
// duplicate within this source. Memory for deduplication is owned by caller.
func Parse(r io.Reader, format string, emit func(string) bool) (Stats, error) {
	var st Stats
	if format != "domains" && format != "hosts" {
		return st, fmt.Errorf("unsupported source adapter")
	}
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 1024), 4096)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if format == "hosts" {
			if len(fields) < 2 {
				st.Rejected++
				continue
			}
			a, e := netip.ParseAddr(fields[0])
			if e != nil || !(a.IsUnspecified() || a.IsLoopback()) {
				st.Rejected++
				continue
			}
			fields = fields[1:]
		} else if len(fields) != 1 {
			st.Rejected++
			continue
		}
		for _, v := range fields {
			h, e := domain.Normalize(v)
			// Public source admission is deliberately stricter than Core host syntax:
			// no IPs or single-label names (which can block an entire TLD).
			if e != nil || h.Kind != domain.Name || !strings.Contains(h.Value, ".") || h.Value == "localhost.localdomain" {
				st.Rejected++
				continue
			}
			st.Accepted++
			if emit(h.Value) {
				st.Duplicates++
			} else {
				st.Unique++
			}
		}
	}
	return st, scan.Err()
}
