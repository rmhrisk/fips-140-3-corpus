#!/usr/bin/env python3
"""Version-EXACT CVE join: for modules that name a component AND expose a clean
X.Y.Z library version, count how many CVEs list THAT version in their affected
CPE range (NVD virtualMatchString with the version → NVD does the range
intersection), published after the cert date, excluding Rejected/Disputed.

This converts 'N CVEs in <component> since cert' (component pressure, upper bound)
into 'M CVEs whose affected range includes the certified version' (precise). Still
an upper bound on real exposure because distros back-port fixes without bumping the
version string — noted. Real data, cited to NVD. Throwaway harness."""
import json, glob, os, re, time, urllib.request, urllib.parse
from analyze_corpus import parse_date, months_between

COMP = [("openssl","OpenSSL","cpe:2.3:a:openssl:openssl"),
        ("libgcrypt","libgcrypt","cpe:2.3:a:gnupg:libgcrypt"),
        ("gnutls","GnuTLS","cpe:2.3:a:gnu:gnutls"),
        (r"\bnss\b","NSS","cpe:2.3:a:mozilla:nss")]

def clean_ver(sw):
    for s in sw:
        m = re.search(r"\b(\d+\.\d+\.\d+)\b", s or "")
        if m: return m.group(1)
    return None

def nvd_all(cpe_ver):
    """All CVEs whose affected CPE range includes cpe_ver → [(id, published, status)]."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(
        {"virtualMatchString": cpe_ver, "resultsPerPage": 2000})
    for a in range(5):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                d = json.load(r)
            out = []
            for v in d.get("vulnerabilities", []):
                cve = v["cve"]
                out.append((cve["id"], cve.get("published", ""), cve.get("vulnStatus", "")))
            return out
        except Exception:
            if a < 4: time.sleep(12); continue
            raise
    return []

# collect modules with a clean version
mods = []
for p in sorted(glob.glob("corpus140_3/records/*.json")):
    r = json.load(open(p)); c = r.get("certificate") or {}; nm = c.get("moduleName") or ""
    comp = next(((lbl, cpe) for kw, lbl, cpe in COMP if re.search(kw, nm, re.I)), None)
    if not comp: continue
    sw = [x.get("raw","") if isinstance(x, dict) else x for x in (c.get("softwareVersions") or [])]
    ver = clean_ver(sw)
    vh = c.get("validationHistory") or []
    vd = sorted(d for d in (parse_date(v.get("date")) for v in vh) if d)
    mods.append({"cert": r.get("certNumber"), "module": nm, "component": comp[0], "cpe": comp[1],
                 "version": ver, "validation": vd[0] if vd else None,
                 "n_updates": sum(1 for v in vh if (v.get('type','')).lower().startswith('update'))})
withver = [m for m in mods if m["version"] and m["validation"]]
print(f"component modules {len(mods)}; with clean version+date {len(withver)}", flush=True)

# fetch per distinct (cpe, version)
cache = json.load(open("ve_cache.json")) if os.path.exists("ve_cache.json") else {}
def cves_for(cpe, ver):
    key = f"{cpe}:{ver}"
    if key not in cache:
        cache[key] = nvd_all(f"{cpe}:{ver}")
        json.dump(cache, open("ve_cache.json","w")); print(f"  fetched {key}: {len(cache[key])} CVEs", flush=True); time.sleep(7)
    return cache[key]

drift = {m["cert"]: m["cves_in_component_since_cert"] for m in json.load(open("drift.json"))} if os.path.exists("drift.json") else {}
for m in withver:
    all_cves = cves_for(m["cpe"], m["version"])
    y, mo = m["validation"]
    hits = [(cid, pub) for (cid, pub, st) in all_cves
            if st.lower() not in ("rejected", "disputed") and parse_date(pub) and parse_date(pub) >= (y, mo)]
    m["version_exact_cves"] = len(hits)
    m["component_drift"] = drift.get(m["cert"])
    m["sample_cves"] = sorted({cid for cid, _ in hits})[:6]
withver.sort(key=lambda x: -x["version_exact_cves"])
json.dump(withver, open("version_exact.json","w"), indent=1)
print("\n=== VERSION-EXACT (CVEs whose affected range includes the certified version, since cert) ===", flush=True)
print(f"{'cert':>5} {'component':<10} {'ver':<8} {'cert':>8} {'drift':>6} {'exact':>6}  module", flush=True)
for m in withver:
    print(f"{m['cert']:>5} {m['component']:<10} {m['version']:<8} {m['validation'][0]}-{m['validation'][1]:02d} "
          f"{str(m['component_drift']):>6} {m['version_exact_cves']:>6}  {m['module'][:34]}", flush=True)
print("VEDONE", flush=True)
