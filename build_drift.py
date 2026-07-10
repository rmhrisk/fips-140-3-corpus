#!/usr/bin/env python3
"""Component-drift join: for modules that name a well-known upstream component,
count CVEs DISCLOSED IN THAT COMPONENT (CPE-based, NVD) since the module's initial
validation date. This is a DRIFT / pressure indicator — how much the upstream has
moved since the certified snapshot — NOT a claim the module is vulnerable (the
certified version may or may not be affected; fixes may be backported). Real data,
cited to NVD. Resume-safe cache. Throwaway harness."""
import json, glob, os, re, time, urllib.request, urllib.parse

# component identity by module-name keyword -> (label, NVD CPE product match)
COMPONENTS = [
    ("openssl",   "OpenSSL",       "cpe:2.3:a:openssl:openssl"),
    ("gnutls",    "GnuTLS",        "cpe:2.3:a:gnu:gnutls"),
    ("libgcrypt", "libgcrypt",     "cpe:2.3:a:gnupg:libgcrypt"),
    ("kernel cry","Linux kernel",  "cpe:2.3:o:linux:linux_kernel"),
    ("kernel cro","Linux kernel",  "cpe:2.3:o:linux:linux_kernel"),
    ("crypto api","Linux kernel",  "cpe:2.3:o:linux:linux_kernel"),
    ("\bnss\b",   "NSS",           "cpe:2.3:a:mozilla:nss"),
    ("wolfssl",   "wolfSSL",       "cpe:2.3:a:wolfssl:wolfssl"),
]
QUARTERS = [(y,q) for y in (2023,2024,2025,2026) for q in (1,2,3,4) if not (y==2026 and q>3)]
def qbounds(y,q):
    m0=(q-1)*3+1; m1=m0+3
    end = f"{y}-{m1:02d}-01" if m1<=12 else f"{y+1}-01-01"
    return f"{y}-{m0:02d}-01T00:00:00.000", f"{end}T00:00:00.000"

# Optional NVD API key: only used for LIVE fetches (cache misses). It raises the
# NVD rate limit but changes nothing about the cached results, so committed caches
# still reproduce byte-for-byte with no key set.
_NVD_KEY = os.environ.get("NVD_API_KEY", "").strip()

def nvd_count(cpe,s,e):
    url="https://services.nvd.nist.gov/rest/json/cves/2.0?"+urllib.parse.urlencode(
        {"virtualMatchString":cpe,"pubStartDate":s,"pubEndDate":e,"resultsPerPage":1})
    req=urllib.request.Request(url, headers={"apiKey":_NVD_KEY} if _NVD_KEY else {})
    for a in range(5):
        try:
            with urllib.request.urlopen(req,timeout=40) as r:
                return json.load(r).get("totalResults",0)
        except Exception as ex:
            if a<4: time.sleep(12); continue
            raise
    return 0

CACHE="drift_cache.json"
cache=json.load(open(CACHE)) if os.path.exists(CACHE) else {}
def q_count(label,cpe):
    if label in cache: return cache[label]
    tl={}
    for (y,q) in QUARTERS:
        s,e=qbounds(y,q)
        tl[f"{y}Q{q}"]=nvd_count(cpe,s,e)
        print(f"  {label} {y}Q{q}: {tl[f'{y}Q{q}']}",flush=True); time.sleep(7)
    cache[label]=tl; json.dump(cache,open(CACHE,"w")); return tl

# 1. identify component modules GENERICALLY (full-record scan; one entry per
#    module x strong CPE-mapped component — so U-Boot/BoringSSL/etc. are picked up).
from analyze_corpus import parse_date
from components import extract_components
mods=[]
for p in sorted(glob.glob("corpus140_3/records/*.json")):
    r=json.load(open(p)); c=r.get("certificate") or {}
    vh=c.get("validationHistory") or []
    vd=sorted(d for d in (parse_date(v.get("date")) for v in vh) if d)
    if not vd: continue
    strong=[cc for cc in extract_components(r) if cc["where"]=="name/version" and cc["cpe"]]
    if not strong: continue
    n_upd=sum(1 for v in vh if (v.get('type','')).lower().startswith('update'))
    for cc in strong:
        mods.append({"cert":r.get("certNumber"),"module":(c.get("moduleName") or ""),
                     "vendor":(c.get("vendor") or {}).get("name"),
                     "component":cc["name"],"cpe":cc["cpe"],"kind":cc["kind"],
                     "version":cc["version"],"version_mappable":cc["version_upstream_mappable"],
                     "validation":vd[0],"last":vd[-1],"n_updates":n_upd})
print(f"module x component drift entries: {len(mods)} across {len({m['cert'] for m in mods})} modules",flush=True)

# 2. fetch quarterly CVE timelines per distinct component
comps={(m['component'],m['cpe']) for m in mods}
for lbl,cpe in comps: q_count(lbl,cpe)

# 3. per module: CVEs in component published AFTER its initial validation quarter
def cves_since(label,ym):
    y,mo=ym; q0=(mo-1)//3+1; tl=cache[label]; tot=0
    for (yy,qq) in QUARTERS:
        if (yy,qq)>=(y,q0): tot+=tl.get(f"{yy}Q{qq}",0)
    return tot
for m in mods:
    m["cves_in_component_since_cert"]=cves_since(m["component"],m["validation"])
    m["months_since_cert"]=(2026-m["validation"][0])*12+(7-m["validation"][1])
mods.sort(key=lambda x:-x["cves_in_component_since_cert"])
json.dump(mods,open("drift.json","w"),indent=1)
print("\n=== COMPONENT DRIFT (CVEs disclosed in upstream since module cert) ===",flush=True)
print(f"{'cert':>5} {'component':<13} {'cert':>8} {'upd':>3} {'CVEs since':>10}  module",flush=True)
for m in mods:
    print(f"{m['cert']:>5} {m['component']:<13} {m['validation'][0]}-{m['validation'][1]:02d} {m['n_updates']:>3} "
          f"{m['cves_in_component_since_cert']:>10}  {m['module'][:40]}",flush=True)
print("DRIFTDONE",flush=True)
