package parser

import (
	"strings"
	"testing"
)

func TestAdapters(t *testing.T) {
	for _, tc := range []struct {
		format, in                     string
		accepted, rejected, duplicates int
	}{{"domains", "# hello\n\n EXAMPLE.com. \nexample.com # inline\nbücher.example\nx..com\nhttps://bad.test\n127.0.0.1\ncom\n||bad.test^\n", 3, 5, 1}, {"hosts", "0.0.0.0 one.test two.test\n127.0.0.1 TWO.test # hi\n:: blocked.test\n1.2.3.4 nope.test\n", 4, 1, 1}} {
		seen := map[string]bool{}
		st, e := Parse(strings.NewReader(tc.in), tc.format, func(s string) bool { v := seen[s]; seen[s] = true; return v })
		if e != nil || st.Accepted != tc.accepted || st.Rejected != tc.rejected || st.Duplicates != tc.duplicates {
			t.Fatalf("%s: %+v %v", tc.format, st, e)
		}
	}
}
func TestOversizeLine(t *testing.T) {
	if _, e := Parse(strings.NewReader(strings.Repeat("x", 5000)), "domains", func(string) bool { return false }); e == nil {
		t.Fatal("oversized line accepted")
	}
	if _, e := Parse(strings.NewReader("x"), "adblock", func(string) bool { return false }); e == nil {
		t.Fatal("adapter accepted")
	}
}
func FuzzParse(f *testing.F) {
	f.Add("0.0.0.0 x.test\n# comment")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 100000 {
			return
		}
		_, _ = Parse(strings.NewReader(s), "domains", func(string) bool { return false })
		_, _ = Parse(strings.NewReader(s), "hosts", func(string) bool { return false })
	})
}
