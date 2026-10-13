// Package domain validates host names and keeps IP literals distinct from DNS names.
package domain

import (
	"fmt"
	"golang.org/x/net/idna"
	"net/netip"
	"strings"
)

type Kind string

const (
	Name Kind = "DOMAIN"
	IP   Kind = "IP"
)

type Host struct {
	Value string
	Kind  Kind
}

func Normalize(input string) (Host, error) {
	if input == "" || len(input) > 1024 || input != strings.TrimSpace(input) {
		return Host{}, fmt.Errorf("empty host or surrounding whitespace")
	}
	if a, err := netip.ParseAddr(input); err == nil {
		if a.Zone() != "" {
			return Host{}, fmt.Errorf("scoped IP literals are unsupported")
		}
		return Host{a.Unmap().String(), IP}, nil
	}
	// One root dot is permitted; URLs, ports, brackets and scoped IPs are not domains.
	if strings.HasSuffix(input, ".") {
		input = input[:len(input)-1]
	} else if strings.HasSuffix(input, "。") || strings.HasSuffix(input, "．") || strings.HasSuffix(input, "｡") {
		input = input[:len(input)-3]
	}
	ascii, err := idna.Lookup.ToASCII(input)
	if err != nil {
		return Host{}, fmt.Errorf("invalid IDNA host: %w", err)
	}
	ascii = strings.ToLower(ascii)
	if a, e := netip.ParseAddr(ascii); e == nil {
		return Host{a.Unmap().String(), IP}, nil
	}
	if len(ascii) == 0 || len(ascii) > 253 {
		return Host{}, fmt.Errorf("invalid host length")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Host{}, fmt.Errorf("invalid label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return Host{}, fmt.Errorf("invalid host character")
			}
		}
	}
	return Host{ascii, Name}, nil
}

// NormalizeDNS accepts the DNS root and ASCII service labels used by SRV/TXT.
// Host rules still use strict Normalize. Escaped arbitrary-octet labels are unsupported.
func NormalizeDNS(input string) (Host, error) {
	if input == "." {
		return Host{".", Name}, nil
	}
	if !strings.Contains(input, "_") {
		return Normalize(input)
	}
	if input != strings.TrimSpace(input) || len(input) > 254 {
		return Host{}, fmt.Errorf("invalid DNS query name")
	}
	labels := strings.Split(strings.TrimSuffix(input, "."), ".")
	for i, label := range labels {
		if strings.HasPrefix(label, "_") {
			if len(label) > 63 || len(label) < 2 {
				return Host{}, fmt.Errorf("invalid service label")
			}
			for _, c := range label[1:] {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
					return Host{}, fmt.Errorf("invalid service label")
				}
			}
			labels[i] = strings.ToLower(label)
		} else {
			h, e := Normalize(label)
			if e != nil || h.Kind != Name {
				return Host{}, fmt.Errorf("invalid DNS label")
			}
			labels[i] = h.Value
		}
	}
	name := strings.Join(labels, ".")
	if len(name) > 253 {
		return Host{}, fmt.Errorf("invalid DNS name length")
	}
	return Host{name, Name}, nil
}
