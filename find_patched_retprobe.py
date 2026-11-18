#!/usr/bin/env python3
"""Map functions modified by patches listed in patch-info.txt onto kretprobe_functions.txt."""
import re
import os
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
import sys
from collections import defaultdict

BASE = "/home/gowtham-23345/SOURCES/kcare"
REPO = "/home/gowtham-23345/SOURCES/linux-stable-rc"
HASH_RE = re.compile(r"\b([0-9a-f]{12,40})\b")
IDENT_CALL_RE = re.compile(r"([A-Za-z_]\w*)\s*\(")
SYSCALL_RE = re.compile(r"^(COMPAT_)?SYSCALL_DEFINE\d\s*\(\s*(\w+)")

# kretprobe symbols (strip "kretprobe:" and compiler suffixes -> base name)
probe_syms = {}
for line in open(f"{BASE}/kretprobe_functions.txt"):
    line = line.strip()
    if not line.startswith("kretprobe:"):
        continue
    sym = line[len("kretprobe:"):]
    probe_syms[sym] = sym
base_map = defaultdict(list)
for sym in probe_syms:
    base_map[re.sub(r"\.(isra|constprop|part|cold|llvm)\.\d+.*$", "", sym)].append(sym)

# parse patch-info.txt entries
entries = []
cur = {}
for line in open(f"{BASE}/patch-info.txt", errors="replace"):
    line = line.rstrip("\n")
    if line.startswith("kpatch-name:"):
        if cur:
            entries.append(cur)
        cur = {"name": line.split(": ", 1)[1]}
    elif line.startswith("kpatch-cve:") and cur:
        cur["cve"] = line.split(": ", 1)[1]
    elif line.startswith("kpatch-patch-url:") and cur:
        cur["url"] = line.split(": ", 1)[1]
if cur:
    entries.append(cur)


def candidates(name):
    """Return kernel symbol names a source-level function name may map to."""
    return base_map.get(name, [])


def syscall_syms(m):
    compat, n = m.group(1), m.group(2)
    if compat:
        return [f"__ia32_compat_sys_{n}", f"__x64_compat_sys_{n}", f"__do_compat_sys_{n}"]
    return [f"__x64_sys_{n}", f"__ia32_sys_{n}", f"__do_sys_{n}", f"__se_sys_{n}"]


def fetch_patch(h):
    """Fallback: download the commit as a patch from kernel.org trees (disk cached)."""
    cpath = f"/tmp/patchcache/{h}.patch"
    if os.path.exists(cpath):
        return open(cpath, errors="replace").read()
    os.makedirs("/tmp/patchcache", exist_ok=True)
    for tree in ("torvalds/linux.git", "stable/linux.git"):
        url = f"https://git.kernel.org/pub/scm/linux/kernel/git/{tree}/patch/?id={h}"
        for attempt in range(6):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
                with urllib.request.urlopen(req, timeout=40) as r:
                    data = r.read().decode("utf-8", "replace")
                open(cpath, "w").write(data)
                return data
            except urllib.error.HTTPError as ex:
                if ex.code == 404:
                    break
                time.sleep(3 * (attempt + 1))
            except Exception:
                time.sleep(3)
    return None


def functions_for_commit(h):
    try:
        out = subprocess.run(
            ["git", "-C", REPO, "show", "--format=", "-U0", h],
            capture_output=True, text=True, errors="replace", check=True,
        ).stdout
    except subprocess.CalledProcessError:
        out = fetch_patch(h)
        if out is None:
            return None
    names = set()
    for line in out.splitlines():
        ctx = None
        if line.startswith("@@"):
            parts = line.split("@@")
            ctx = parts[2].strip() if len(parts) > 2 else ""
        elif line[:1] in "+-" and line[1:2].isalpha() or line[:2] in ("+_", "-_"):
            if not line.startswith(("+++", "---")):
                ctx = line[1:]
        if not ctx:
            continue
        m = SYSCALL_RE.match(ctx)
        if m:
            names.update(syscall_syms(m))
            continue
        for ident in IDENT_CALL_RE.findall(ctx)[:1]:
            names.add(ident)
    return names


hashes = sorted({HASH_RE.search(e.get("url", "")).group(1) for e in entries if HASH_RE.search(e.get("url", ""))})
with ThreadPoolExecutor(3) as ex:
    cache = dict(zip(hashes, ex.map(functions_for_commit, hashes)))
result = defaultdict(set)  # symbol -> set of (cve, patch name, hash)
missing = []
no_hash = []
for e in entries:
    url = e.get("url", "")
    m = HASH_RE.search(url)
    if not m:
        no_hash.append(e)
        continue
    h = m.group(1)
    funcs = cache[h]
    if funcs is None:
        missing.append((e, h))
        continue
    for f in funcs:
        for sym in candidates(f):
            result[sym].add((e.get("cve", "-"), e["name"], h))

with open(f"{BASE}/returnprobe_functions.txt", "w") as out:
    out.write("# kretprobe_functions.txt symbols that are modified by patches in patch-info.txt\n")
    out.write("# format: kretprobe:<function>\\t<CVE>\\t<patch name>\\t<commit>\n")
    for sym in sorted(result):
        for cve, name, h in sorted(result[sym]):
            out.write(f"kretprobe:{sym}\t{cve}\t{name}\t{h}\n")

print(f"entries={len(entries)} commits={len(cache)} matched_symbols={len(result)}")
print(f"commit not in local repo: {len(missing)}; entries without commit hash in url: {len(no_hash)}")
for e, h in missing[:20]:
    print("  missing", h, e["name"], file=sys.stderr)
for e in no_hash[:20]:
    print("  nohash", e.get("url"), file=sys.stderr)
