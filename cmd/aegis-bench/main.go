package main

import (
	"aegis-intelligence/internal/benchindex"
	"aegis-intelligence/internal/parser"
	"aegis-intelligence/pkg/dataset"
	"aegis-intelligence/pkg/domain"
	"aegis-intelligence/pkg/release"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var sink uint16

func host(i int) string               { return fmt.Sprintf("host-%07d.group-%03d.example", i, i%100) }
func elapsed(start time.Time) float64 { return float64(time.Since(start).Nanoseconds()) / 1e6 }
func memory() uint64                  { var m runtime.MemStats; runtime.ReadMemStats(&m); return m.HeapAlloc }
func main() {
	n := flag.Int("n", 10000, "synthetic unique domains")
	mode := flag.String("index", "sorted", "sorted or trie")
	save := flag.String("raw-out", "", "optional raw binary benchmark artifact")
	flag.Parse()
	if *n < 1 || *n > 1000000 || (*mode != "sorted" && *mode != "trie") {
		panic("invalid benchmark options")
	}
	runtime.GC()
	base := memory()
	var peak atomic.Uint64
	peak.Store(base)
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				v := memory()
				for old := peak.Load(); v > old && !peak.CompareAndSwap(old, v); old = peak.Load() {
				}
			}
		}
	}()
	r := map[string]any{"domains": *n, "index": *mode, "go": runtime.Version(), "arch": runtime.GOARCH, "os": runtime.GOOS}
	// Streaming line parsing baseline, without normalization or deduplication.
	generate := func() io.Reader {
		pr, pw := io.Pipe()
		go func() {
			w := bufio.NewWriter(pw)
			for i := 0; i < *n; i++ {
				fmt.Fprintln(w, host(i))
			}
			w.Flush()
			pw.Close()
		}()
		return pr
	}
	start := time.Now()
	scan := bufio.NewScanner(generate())
	for scan.Scan() {
		if len(strings.Fields(scan.Text())) != 1 {
			panic("synthetic record")
		}
	}
	if e := scan.Err(); e != nil {
		panic(e)
	}
	r["input_parse_ms"] = elapsed(start)
	start = time.Now()
	for i := 0; i < *n; i++ {
		if _, e := domain.Normalize(host(i)); e != nil {
			panic(e)
		}
	}
	r["normalization_ms"] = elapsed(start)
	m := make(map[string]dataset.Entry, *n)
	start = time.Now()
	for i := 0; i < *n; i++ {
		dataset.Merge(m, host(i), 1, i%2 == 0)
	}
	r["deduplication_ms"] = elapsed(start)
	// End-to-end parser with normalization; includes synthetic input generation.
	start = time.Now()
	count := 0
	st, e := parser.Parse(generate(), "domains", func(string) bool { count++; return false })
	if e != nil || st.Accepted != *n || count != *n {
		panic("parser benchmark")
	}
	r["parse_normalize_stream_ms"] = elapsed(start)
	entries := dataset.Sorted(m)
	m = nil
	start = time.Now()
	raw, e := dataset.Compile(entries)
	if e != nil {
		panic(e)
	}
	r["compilation_ms"] = elapsed(start)
	r["uncompressed_bytes"] = len(raw)
	start = time.Now()
	gz, e := release.Compress(raw)
	if e != nil {
		panic(e)
	}
	r["gzip_build_ms"] = elapsed(start)
	r["compressed_bytes"] = len(gz)
	manifest := release.Manifest{DomainCount: *n, CompressedSize: int64(len(gz)), UncompressedSize: int64(len(raw)), ArtifactSHA256: release.Hash(gz), DatasetSHA256: release.Hash(raw)}
	start = time.Now()
	reader, _, e := release.VerifyArtifactBytes(manifest, gz)
	if e != nil {
		panic(e)
	}
	r["verify_decompress_load_ms"] = elapsed(start)
	if *save != "" {
		if e = os.WriteFile(*save, raw, 0600); e != nil {
			panic(e)
		}
	}
	reader = nil
	gz = nil
	runtime.GC()
	residentBase := memory()
	var lookup func(string) uint16
	start = time.Now()
	if *mode == "sorted" {
		reader, e = dataset.Open(raw)
		if e != nil {
			panic(e)
		}
		lookup = reader.LookupNormalized
		r["resident_index_bytes"] = len(raw)
	} else {
		trie := benchindex.Build(entries)
		lookup = trie.Lookup
		r["resident_index_bytes"] = int(memory() - residentBase)
	}
	r["client_index_load_ms"] = elapsed(start)
	queries := make([]string, 10000)
	subs := make([]string, len(queries))
	for i := range queries {
		queries[i] = host(i % *n)
		subs[i] = "child." + queries[i]
	}
	start = time.Now()
	for round := 0; round < 10; round++ {
		for _, q := range queries {
			sink ^= lookup(q)
		}
	}
	r["exact_lookup_ns"] = float64(time.Since(start).Nanoseconds()) / 100000
	start = time.Now()
	for round := 0; round < 10; round++ {
		for _, q := range subs {
			sink ^= lookup(q)
		}
	}
	r["subdomain_lookup_ns"] = float64(time.Since(start).Nanoseconds()) / 100000
	// Retained heap measured with the representation rooted and temporary compile
	// objects dropped. Go heap and process RSS are different measurements.
	raw = nil
	entries = nil
	queries = nil
	subs = nil
	runtime.GC()
	runtime.KeepAlive(lookup)
	r["client_retained_heap_bytes"] = int64(memory()) - int64(base)
	r["peak_sampled_heap_bytes"] = peak.Load()
	r["heap_sample_interval_ms"] = 1
	close(done)
	// Linux VmHWM is process peak RSS, including Go runtime and all pipeline phases.
	if b, e := os.ReadFile("/proc/self/status"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "VmHWM:") {
				p := strings.Fields(line)
				kb, _ := strconv.ParseUint(p[1], 10, 64)
				r["process_peak_rss_bytes"] = kb * 1024
			}
		}
	}
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}
