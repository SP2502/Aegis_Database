package domain

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct {
		in, want string
		kind     Kind
	}{{"EXAMPLE.Com.", "example.com", Name}, {"bücher.example", "xn--bcher-kva.example", Name}, {"2001:db8::1", "2001:db8::1", IP}, {"::ffff:192.0.2.1", "192.0.2.1", IP}, {"192.0.2.1", "192.0.2.1", IP}, {"sub.example.com", "sub.example.com", Name}}
	for _, c := range cases {
		h, e := Normalize(c.in)
		if e != nil || h.Value != c.want || h.Kind != c.kind {
			t.Errorf("%s => %+v %v", c.in, h, e)
		}
	}
	for _, v := range []string{"", " example.com", "https://example.com", "example.com:53", "x..com", "-x.com", "x-.com", "a_b.com", "example.com..", "[::1]", "fe80::1%eth0"} {
		if _, e := Normalize(v); e == nil {
			t.Errorf("accepted %q", v)
		}
	}
}
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"example.com", "bücher.de", "a..b", "::1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		h, e := Normalize(s)
		if e == nil {
			h2, e := Normalize(h.Value)
			if e != nil || h != h2 {
				t.Fatal("normalization not idempotent")
			}
		}
	})
}
