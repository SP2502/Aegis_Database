package dataset

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
)

func testEntries() []Entry {
	return []Entry{{"exact.test", 1, 0}, {"mixed.test", 2, 4}, {"parent.test", 0, 1}, {"sub.parent.test", 8, 0}}
}
func TestRoundTripSemantics(t *testing.T) {
	b, e := Compile(testEntries())
	if e != nil {
		t.Fatal(e)
	}
	r, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		host string
		mask uint16
	}{{"EXACT.test.", 1}, {"sub.exact.test", 0}, {"mixed.test", 6}, {"sub.mixed.test", 4}, {"sub.parent.test", 9}, {"x.sub.parent.test", 1}, {"notparent.test", 0}, {"127.0.0.1", 0}} {
		got, e := r.Lookup(c.host)
		if e != nil || got != c.mask {
			t.Fatalf("%s: %d %v", c.host, got, e)
		}
	}
	b2, _ := Compile(testEntries())
	if !bytes.Equal(b, b2) {
		t.Fatal("nondeterministic")
	}
	if _, e = Load(bytes.NewReader(b), int64(len(b)-1)); e == nil {
		t.Fatal("limit ignored")
	}
}
func TestMerge(t *testing.T) {
	m := map[string]Entry{}
	Merge(m, "a.test", 1, false)
	Merge(m, "a.test", 2, true)
	Merge(m, "a.test", 4, false)
	e := m["a.test"]
	if len(m) != 1 || e.Exact != 5 || e.Subdomains != 2 {
		t.Fatal(m)
	}
}
func TestCorruption(t *testing.T) {
	b, _ := Compile(testEntries())
	for _, i := range []int{0, 8, 10, 12, 16, 20, 24, 56, len(b) - 1} {
		bad := bytes.Clone(b)
		bad[i] ^= 255
		if _, e := Open(bad); e == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
	for _, n := range []int{0, 1, 63, len(b) - 1} {
		if _, e := Open(b[:n]); e == nil {
			t.Fatal("truncation")
		}
	}
	bad := bytes.Clone(b)
	catlen := int(order.Uint32(b[16:20]))
	order.PutUint32(bad[HeaderSize+catlen:HeaderSize+catlen+4], 0xffffffff)
	sum := sha256.Sum256(bad[HeaderSize:])
	copy(bad[24:56], sum[:])
	if _, e := Open(bad); e == nil {
		t.Fatal("valid hash bypassed bounds")
	}
}
func FuzzOpen(f *testing.F) {
	b, _ := Compile(testEntries())
	f.Add(b)
	f.Add([]byte("AEGISDB"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		r, e := Open(b)
		if e == nil {
			_, _ = r.Lookup("x.parent.test")
		}
	})
}

func TestCanonicalReaderValidation(t *testing.T) {
	b, _ := Compile([]Entry{{Domain: "bad.test", Exact: 1}})
	// Replace the domain with an IPv4 address, adjust declared bounds and retain a
	// valid payload hash. Parser validation must still reject compiler-incompatible data.
	catlen := int(order.Uint32(b[16:20]))
	base := HeaderSize + catlen
	blob := base + RecordSize
	bad := append(bytes.Clone(b[:blob]), []byte("1.2.3.4")...)
	order.PutUint16(bad[base+4:base+6], 7)
	order.PutUint32(bad[20:24], 7)
	sum := sha256.Sum256(bad[HeaderSize:])
	copy(bad[24:56], sum[:])
	if _, e := Open(bad); e == nil {
		t.Fatal("IP dataset record accepted")
	}
}

func TestPublishedWireFixture(t *testing.T) {
	b, e := os.ReadFile("../../fixtures/format1.bin")
	if e != nil {
		t.Fatal(e)
	}
	r, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	vectors, e := os.ReadFile("../../fixtures/matching_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Query string
		Mask  uint16
	}
	if e = json.Unmarshal(vectors, &cases); e != nil {
		t.Fatal(e)
	}
	for _, v := range cases {
		got, e := r.Lookup(v.Query)
		if e != nil || got != v.Mask {
			t.Fatal("wire contract", v.Query, got, e)
		}
	}
}
