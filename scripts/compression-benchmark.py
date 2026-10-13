#!/usr/bin/env python3
"""Optional supplementary codec comparison; not a production dependency.

Run each codec in a separate process. Python zstandard is needed only for the
optional zstd run. Go gzip measurements remain in benchmarks.jsonl.
"""
import argparse,json,platform,resource,time,gzip
p=argparse.ArgumentParser();p.add_argument('--raw',required=True);p.add_argument('--codec',choices=['gzip','zstd'],required=True);a=p.parse_args()
raw=open(a.raw,'rb').read();level=9 if a.codec=='gzip' else 3
start=time.perf_counter()
if a.codec=='gzip':
 compressed=gzip.compress(raw,compresslevel=level,mtime=0)
else:
 import zstandard
 compressed=zstandard.ZstdCompressor(level=level).compress(raw)
compression_ms=(time.perf_counter()-start)*1000
start=time.perf_counter()
if a.codec=='gzip':decoded=gzip.decompress(compressed)
else:decoded=zstandard.ZstdDecompressor().decompress(compressed,max_output_size=len(raw))
decompression_ms=(time.perf_counter()-start)*1000
assert decoded==raw
print(json.dumps(dict(codec=a.codec,level=level,raw_bytes=len(raw),compressed_bytes=len(compressed),compression_ms=compression_ms,decompression_ms=decompression_ms,process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,python=platform.python_version(),implementation='Python zlib' if a.codec=='gzip' else 'python-zstandard '+zstandard.__version__)))
