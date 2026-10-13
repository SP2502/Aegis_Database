// Package fetcher provides bounded, allowlisted HTTPS downloads to disk.
package fetcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"
)

type Client struct {
	http     *http.Client
	hosts    map[string]bool
	Backoff  time.Duration
	Attempts int
}

func New(hosts []string) *Client {
	allowed := map[string]bool{}
	for _, h := range hosts {
		allowed[h] = true
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, DisableCompression: true, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
	// Ignore environment proxies. Resolve and validate every IP, then dial the
	// validated address directly so a DNS rebinding cannot reach a private host.
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		h, p, e := net.SplitHostPort(address)
		if e != nil || !allowed[h] || p != "443" {
			return nil, fmt.Errorf("unapproved connection")
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			if !publicIP(ip) {
				return nil, fmt.Errorf("nonpublic source address")
			}
		}
		for _, ip := range ips {
			c, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), p))
			if e == nil {
				return c, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, fmt.Errorf("source connection failed")
	}
	c := &Client{hosts: allowed, Backoff: time.Second, Attempts: 3}
	c.http = &http.Client{Transport: tr, Timeout: 90 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("redirect rejected")
		}
		return c.check(req.URL)
	}}
	return c
}
func publicIP(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}
func (c *Client) check(u *url.URL) error {
	if u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" || !c.hosts[u.Hostname()] {
		return fmt.Errorf("unapproved HTTPS host")
	}
	return nil
}

type Download struct {
	Path   string
	SHA256 string
	Size   int64
}

func (c *Client) Fetch(ctx context.Context, raw string, max int64, dir string) (Download, error) {
	u, e := url.Parse(raw)
	if e != nil {
		return Download{}, e
	}
	if e = c.check(u); e != nil {
		return Download{}, e
	}
	if max <= 0 || max > 512<<20 || c.Attempts < 1 || c.Attempts > 5 {
		return Download{}, fmt.Errorf("invalid download limits")
	}
	var last error
	for attempt := 0; attempt < c.Attempts; attempt++ {
		if ctx.Err() != nil {
			return Download{}, ctx.Err()
		}
		d, retry, e := c.once(ctx, raw, max, dir)
		if e == nil {
			return d, nil
		}
		last = e
		if !retry {
			break
		}
		if attempt+1 < c.Attempts {
			timer := time.NewTimer(c.Backoff * time.Duration(1<<attempt))
			select {
			case <-ctx.Done():
				timer.Stop()
				return Download{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return Download{}, fmt.Errorf("download failed: %w", last)
}
func (c *Client) once(ctx context.Context, raw string, max int64, dir string) (Download, bool, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if e != nil {
		return Download{}, false, e
	}
	req.Header.Set("User-Agent", "AEGIS-Intelligence/1")
	req.Header.Set("Accept-Encoding", "identity")
	resp, e := c.http.Do(req)
	if e != nil {
		return Download{}, true, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Download{}, resp.StatusCode == 429 || resp.StatusCode >= 500, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	typ, _, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e != nil || (typ != "text/plain" && typ != "application/octet-stream") || resp.Header.Get("Content-Encoding") != "" || resp.ContentLength > max {
		return Download{}, false, fmt.Errorf("unexpected type, encoding or size")
	}
	f, e := os.CreateTemp(dir, "source-*")
	if e != nil {
		return Download{}, false, e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, max+1))
	if e != nil {
		return Download{}, true, e
	}
	if n == 0 || n > max {
		return Download{}, false, fmt.Errorf("empty or oversized response")
	}
	if e = f.Close(); e != nil {
		return Download{}, false, e
	}
	ok = true
	return Download{f.Name(), hex.EncodeToString(h.Sum(nil)), n}, false, nil
}
