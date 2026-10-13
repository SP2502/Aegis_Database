package fetcher

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func localClient(t *testing.T, handler http.HandlerFunc) (*Client, string) {
	t.Helper()
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	c := New([]string{u.Hostname()})
	c.http = s.Client()
	c.http.Timeout = time.Second
	c.Backoff = time.Millisecond
	return c, s.URL
}

// Production URL validation rejects test-server ports. Tests invoke once after
// installing the local TLS transport; production Fetch restrictions are separate.
func TestResponseValidation(t *testing.T) {
	for _, tc := range []struct {
		name, typ, body string
		status          int
		max             int64
		ok              bool
	}{{"valid", "text/plain", "x.test\n", 200, 100, true}, {"html", "text/html", "<html>", 200, 100, false}, {"oversized", "text/plain", strings.Repeat("x", 101), 200, 100, false}, {"empty", "text/plain", "", 200, 100, false}, {"status", "text/plain", "bad", 404, 100, false}} {
		t.Run(tc.name, func(t *testing.T) {
			c, u := localClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.typ)
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			d, _, e := c.once(context.Background(), u, tc.max, t.TempDir())
			if (e == nil) != tc.ok {
				t.Fatalf("%v", e)
			}
			if e == nil {
				b, _ := os.ReadFile(d.Path)
				if int64(len(b)) != d.Size || d.SHA256 == "" {
					t.Fatal("metadata")
				}
			}
		})
	}
}
func TestPolicy(t *testing.T) {
	c := New([]string{"blocklistproject.github.io"})
	for _, u := range []string{"http://blocklistproject.github.io/x", "https://evil.test/x", "https://user@blocklistproject.github.io/x", "https://blocklistproject.github.io:443/x"} {
		if _, e := c.Fetch(context.Background(), u, 100, t.TempDir()); e == nil {
			t.Fatal("accepted", u)
		}
	}
	req, _ := http.NewRequest("GET", "https://evil.test/x", nil)
	via, _ := http.NewRequest("GET", "https://blocklistproject.github.io/x", nil)
	if e := c.http.CheckRedirect(req, []*http.Request{via}); e == nil {
		t.Fatal("cross host redirect")
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "169.254.169.254", "100.64.1.1"} {
		if publicIP(netip.MustParseAddr(ip)) {
			t.Fatal("private", ip)
		}
	}
	if !publicIP(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRetriesAndCancellation(t *testing.T) {
	c := New([]string{"blocklistproject.github.io"})
	c.Backoff = time.Millisecond
	var calls atomic.Int32
	c.http.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, fmt.Errorf("network unavailable")
	})
	if _, e := c.Fetch(context.Background(), "https://blocklistproject.github.io/x", 100, t.TempDir()); e == nil || calls.Load() != 3 {
		t.Fatal("retry limit", calls.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls.Store(0)
	if _, e := c.Fetch(ctx, "https://blocklistproject.github.io/x", 100, t.TempDir()); e == nil || calls.Load() != 0 {
		t.Fatal("cancellation")
	}
}
