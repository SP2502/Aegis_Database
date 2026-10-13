package updater

import (
	"aegis-intelligence/pkg/release"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"
)

func readBounded(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return readLimit(f, max)
}
func readLimit(r io.Reader, max int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("response size exceeded")
	}
	return b, nil
}

// NewHTTPClient permits GitHub release redirects to its two documented asset
// hosts; the repository/version URL is additionally pinned by the signed manifest.
func NewHTTPClient() *http.Client {
	hosts := map[string]bool{"github.com": true, "release-assets.githubusercontent.com": true, "objects.githubusercontent.com": true}
	check := func(u *url.URL) error {
		if u.Scheme != "https" || u.User != nil || u.Port() != "" || !hosts[u.Hostname()] {
			return fmt.Errorf("unapproved release URL")
		}
		return nil
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, DisableCompression: true, MaxIdleConnsPerHost: 2}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil || !hosts[host] || port != "443" {
			return nil, fmt.Errorf("unapproved connection")
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
				return nil, fmt.Errorf("nonpublic release address")
			}
		}
		for _, ip := range ips {
			c, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return c, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, fmt.Errorf("release connection failed")
	}
	return &http.Client{Transport: tr, Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return check(req.URL)
	}}
}

type Client struct {
	Store   *Store
	HTTP    *http.Client
	Backoff time.Duration
}

func (c *Client) get(ctx context.Context, raw string, max int64) ([]byte, error) {
	h := c.HTTP
	if h == nil {
		h = NewHTTPClient()
	}
	delay := c.Backoff
	if delay <= 0 {
		delay = time.Second
	}
	var last error
	for i := 0; i < 3; i++ {
		req, e := http.NewRequestWithContext(ctx, "GET", raw, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Accept-Encoding", "identity")
		resp, e := h.Do(req)
		retry := true
		if e == nil {
			if resp.StatusCode == 200 && resp.Header.Get("Content-Encoding") == "" && resp.ContentLength <= max {
				b, e := readLimit(resp.Body, max)
				resp.Body.Close()
				if e == nil {
					return b, nil
				}
				last = e
			} else {
				retry = resp.StatusCode == 429 || resp.StatusCode >= 500
				last = fmt.Errorf("release HTTP status/size/encoding rejected: %d", resp.StatusCode)
				resp.Body.Close()
			}
		} else {
			last = e
		}
		if !retry {
			return nil, last
		}
		if i < 2 {
			t := time.NewTimer(delay * time.Duration(1<<i))
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}
	}
	return nil, last
}
func (c *Client) Update(ctx context.Context) (bool, error) {
	if c.Store == nil || !release.ValidRepository(c.Store.Repository) {
		return false, fmt.Errorf("store/repository required")
	}
	repo := c.Store.Repository
	latest := "https://github.com/" + repo + "/releases/latest/download/manifest.json"
	b, e := c.get(ctx, latest, release.MaxManifestSize)
	if e != nil {
		return false, e
	}
	// Untrusted bytes only select a constrained numeric tag. Trust is established
	// before following the signed artifact URL or interpreting its size/count.
	hint, e := release.Parse(b)
	if e != nil || hint.DatasetVersion < 20200101000000 || hint.DatasetVersion > 99991231235959 || hint.ReleaseTag != release.Tag(hint.DatasetVersion) {
		return false, fmt.Errorf("invalid manifest locator")
	}
	sig, e := c.get(ctx, release.AssetURL(repo, hint.ReleaseTag, "manifest.sig"), 64)
	if e != nil {
		return false, e
	}
	m, e := release.VerifyManifest(b, sig, c.Store.Keys, repo, release.ClientVersion, 0)
	if e != nil {
		return false, e
	}
	floor, e := c.Store.HighestVersion()
	if e != nil {
		return false, e
	}
	if m.DatasetVersion < floor {
		return false, fmt.Errorf("rollback rejected")
	}
	if m.DatasetVersion == floor {
		snap := c.Store.Snapshot()
		if snap == nil {
			return false, fmt.Errorf("load offline state first")
		}
		if snap.UsingPrevious {
			return false, fmt.Errorf("active generation corrupt; newer release required")
		}
		if snap.Manifest.DatasetSHA256 != m.DatasetSHA256 || snap.Manifest.ArtifactSHA256 != m.ArtifactSHA256 {
			return false, fmt.Errorf("mutable release rejected")
		}
		return false, nil
	}
	artifact, e := c.get(ctx, m.ArtifactURL, m.CompressedSize)
	if e != nil {
		return false, e
	}
	if e = c.Store.Activate(b, sig, artifact); e != nil {
		return false, e
	}
	return true, nil
}

// NextCheck is 24 hours plus uniform bounded jitter; injected now enables tests.
// Schedule updates independently of DNS queries and honor metered-network policy.
func NextCheck(now time.Time) (time.Time, error) {
	var b [8]byte
	if _, e := rand.Read(b[:]); e != nil {
		return time.Time{}, e
	}
	j := time.Duration(binary.LittleEndian.Uint64(b[:]) % uint64(6*time.Hour))
	return now.Add(24*time.Hour + j), nil
}
