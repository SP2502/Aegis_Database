// Package dataset implements the portable AEGIS sorted binary index (format 1).
package dataset

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"

	"aegis-intelligence/pkg/domain"
)

const FormatVersion = 1
const NormalizationVersion = 1
const HeaderSize = 64
const RecordSize = 10
const MaxFileSize = 512 << 20
const MaxEntries = 10_000_000

var magic = [8]byte{'A', 'E', 'G', 'I', 'S', 'D', 'B', 0}
var order = binary.LittleEndian

type Category struct {
	ID  string `json:"id"`
	Bit uint16 `json:"bit"`
}

var Categories = []Category{{"adult", 1}, {"gambling", 2}, {"malware", 4}, {"phishing", 8}}

const KnownMask uint16 = 15

type Entry struct {
	Domain     string
	Exact      uint16
	Subdomains uint16
}

// Merge stores a domain once, retaining independent semantics for each category.
func Merge(m map[string]Entry, host string, mask uint16, suffix bool) bool {
	e, exists := m[host]
	e.Domain = host
	if suffix {
		e.Subdomains |= mask
	} else {
		e.Exact |= mask
	}
	m[host] = e
	return exists
}
func Sorted(m map[string]Entry) []Entry {
	entries := make([]Entry, 0, len(m))
	for _, e := range m {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Domain < entries[j].Domain })
	return entries
}
func validASCII(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			n := i - start
			if n == 0 || n > 63 || s[start] == '-' || s[i-1] == '-' {
				return false
			}
			start = i + 1
			continue
		}
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	if s[0] >= '0' && s[0] <= '9' && s[len(s)-1] >= '0' && s[len(s)-1] <= '9' {
		if _, e := netip.ParseAddr(s); e == nil {
			return false
		}
	}
	if strings.Contains(s, "xn--") {
		h, e := domain.Normalize(s)
		if e != nil || h.Kind != domain.Name || h.Value != s {
			return false
		}
	}
	return true
}
func Compile(entries []Entry) ([]byte, error) {
	if len(entries) == 0 || len(entries) > MaxEntries {
		return nil, fmt.Errorf("entry count out of bounds")
	}
	cats, _ := json.Marshal(Categories)
	var size uint64
	prev := ""
	for _, e := range entries {
		h, err := domain.Normalize(e.Domain)
		if err != nil || h.Kind != domain.Name || h.Value != e.Domain || e.Domain <= prev || e.Exact|e.Subdomains == 0 || (e.Exact|e.Subdomains)&^KnownMask != 0 {
			return nil, fmt.Errorf("invalid or unordered entry")
		}
		prev = e.Domain
		size += uint64(len(e.Domain))
	}
	total := uint64(HeaderSize+len(cats)) + uint64(len(entries))*RecordSize + size
	if total > MaxFileSize {
		return nil, fmt.Errorf("dataset too large")
	}
	b := make([]byte, int(total))
	copy(b, magic[:])
	order.PutUint16(b[8:10], FormatVersion)
	order.PutUint16(b[10:12], NormalizationVersion)
	order.PutUint32(b[12:16], uint32(len(entries)))
	order.PutUint32(b[16:20], uint32(len(cats)))
	order.PutUint32(b[20:24], uint32(size))
	copy(b[HeaderSize:], cats)
	base := HeaderSize + len(cats)
	blob := base + len(entries)*RecordSize
	off := 0
	for i, e := range entries {
		r := b[base+i*RecordSize:]
		order.PutUint32(r[:4], uint32(off))
		order.PutUint16(r[4:6], uint16(len(e.Domain)))
		order.PutUint16(r[6:8], e.Exact)
		order.PutUint16(r[8:10], e.Subdomains)
		copy(b[blob+off:], e.Domain)
		off += len(e.Domain)
	}
	sum := sha256.Sum256(b[HeaderSize:])
	copy(b[24:56], sum[:])
	return b, nil
}

// Reader owns a single compact byte buffer, with no per-domain maps or strings.
// Bytes passed to Open must never be modified afterwards.
type Reader struct {
	data    []byte
	records int
	blob    int
	count   int
}

func Open(b []byte) (*Reader, error) {
	if len(b) < HeaderSize || len(b) > MaxFileSize || !bytes.Equal(b[:8], magic[:]) || order.Uint16(b[8:10]) != FormatVersion || order.Uint16(b[10:12]) != NormalizationVersion || !bytes.Equal(b[56:64], make([]byte, 8)) {
		return nil, fmt.Errorf("incompatible header")
	}
	count := uint64(order.Uint32(b[12:16]))
	catlen := uint64(order.Uint32(b[16:20]))
	bloblen := uint64(order.Uint32(b[20:24]))
	if count == 0 || count > MaxEntries || catlen > 4096 || uint64(HeaderSize)+catlen+count*RecordSize+bloblen != uint64(len(b)) {
		return nil, fmt.Errorf("invalid dataset bounds")
	}
	sum := sha256.Sum256(b[HeaderSize:])
	if !bytes.Equal(sum[:], b[24:56]) {
		return nil, fmt.Errorf("payload hash mismatch")
	}
	cats, _ := json.Marshal(Categories)
	if !bytes.Equal(b[HeaderSize:HeaderSize+int(catlen)], cats) {
		return nil, fmt.Errorf("incompatible categories")
	}
	r := &Reader{b, HeaderSize + int(catlen), HeaderSize + int(catlen) + int(count)*RecordSize, int(count)}
	off := uint64(0)
	var prev []byte
	for i := 0; i < r.count; i++ {
		rec := r.record(i)
		n := uint64(order.Uint16(rec[4:6]))
		if uint64(order.Uint32(rec[:4])) != off || n == 0 || n > 253 || off+n > bloblen {
			return nil, fmt.Errorf("invalid entry bounds")
		}
		host := b[r.blob+int(off) : r.blob+int(off+n)]
		mask := order.Uint16(rec[6:8]) | order.Uint16(rec[8:10])
		if !validASCII(string(host)) || mask == 0 || mask&^KnownMask != 0 || i > 0 && bytes.Compare(prev, host) >= 0 {
			return nil, fmt.Errorf("invalid record")
		}
		prev = host
		off += n
	}
	if off != bloblen {
		return nil, fmt.Errorf("unused bytes")
	}
	return r, nil
}

// Load limits bytes before allocation, then validates all records before use.
func Load(in io.Reader, max int64) (*Reader, error) {
	if max <= 0 || max > MaxFileSize {
		return nil, fmt.Errorf("invalid size limit")
	}
	b, e := io.ReadAll(io.LimitReader(in, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("size limit exceeded")
	}
	return Open(b)
}
func (r *Reader) Count() int { return r.count }
func (r *Reader) Bytes() int { return len(r.data) }
func (r *Reader) record(i int) []byte {
	return r.data[r.records+i*RecordSize : r.records+(i+1)*RecordSize]
}
func (r *Reader) name(i int) []byte {
	rec := r.record(i)
	o := int(order.Uint32(rec[:4]))
	n := int(order.Uint16(rec[4:6]))
	return r.data[r.blob+o : r.blob+o+n]
}
func (r *Reader) find(s string) int {
	return sort.Search(r.count, func(i int) bool { return string(r.name(i)) >= s })
}

// LookupNormalized accepts a canonical AEGIS host. Core can normalize once and use
// this method in the DNS hot path. Returns matching category union, never policy.
func (r *Reader) LookupNormalized(s string) uint16 {
	var mask uint16
	full := true
	for {
		i := r.find(s)
		if i < r.count && string(r.name(i)) == s {
			rec := r.record(i)
			mask |= order.Uint16(rec[8:10])
			if full {
				mask |= order.Uint16(rec[6:8])
			}
		}
		dot := strings.IndexByte(s, '.')
		if dot < 0 {
			break
		}
		s = s[dot+1:]
		full = false
	}
	return mask
}
func (r *Reader) Lookup(s string) (uint16, error) {
	h, e := domain.Normalize(s)
	if e != nil {
		return 0, e
	}
	if h.Kind != domain.Name {
		return 0, nil
	}
	return r.LookupNormalized(h.Value), nil
}
