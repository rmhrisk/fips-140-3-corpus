#!/usr/bin/env python3
"""Build the FIPS 140-3 software-library fingerprint dataset (Track A: deterministic).

For every software-involving module in the corpus, extract everything the public
record reliably reveals for *probabilistic identification* of the shipped library:

  - the artifact filenames named in the Security Policy (libcrypto.so.3, fips.so,
    bc-fips-2.0.0.jar, bcm.o, ...)
  - the module/software versions from the certificate
  - the tested operating environment(s)
  - the known upstream crypto component (OpenSSL, NSS, wolfSSL, ...) and CPE
  - any integrity digest the Security Policy prints in its own text

Track B (build_swlib_merge.py) folds in web-fished *published artifact hashes*.

Pure Python standard library. Reproducible from the committed corpus snapshot:
    python3 build_swlib.py            # -> fips_swlib.trackA.json
Inputs (all committed): corpus140_3/records/*.json, sp_text/*.txt,
corpus_analysis.json, version_exact.json
"""
import json
import glob
import re
import os
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
REC = os.path.join(HERE, "corpus140_3", "records")
SPT = os.path.join(HERE, "sp_text")
OUT = os.path.join(HERE, "fips_swlib.trackA.json")

# --- artifact filename extraction -------------------------------------------
# crypto shared objects / libraries / archives named in Security-Policy text.
ART_RE = re.compile(
    r"("
    r"lib[A-Za-z0-9_+-]{2,}\.so(?:\.[0-9]+)*"                        # libcrypto.so.3
    r"|[A-Za-z][A-Za-z0-9_+-]{1,}\.(?:so|dll|dylib|ko|sys)(?:\.[0-9]+)*"
    r"|[A-Za-z][A-Za-z0-9_+-]*(?:[.-][0-9][A-Za-z0-9._+-]*)?\.jar"   # bc-fips-2.0.0.jar
    r"|[A-Za-z][A-Za-z0-9_+-]{2,}\.(?:a|o)(?![A-Za-z0-9.])"          # bcm.o, fipscanister.o
    r"|[A-Za-z][A-Za-z0-9_+-]{2,}\.exe"
    r")"
)
STOP = {"n.a", "e.g", "i.e", "etc.a"}


def _base(tok):
    return re.split(r"[.\-]", tok, maxsplit=1)[0].lower()


def artifacts(text):
    c = collections.Counter()
    for m in ART_RE.finditer(text):
        tok = m.group(1)
        base = _base(tok)
        if tok.lower() in STOP or base.isdigit() or len(base) < 3:
            continue
        c[tok] += 1
    return [{"file": k, "mentions": n, "source": "security-policy"} for k, n in c.most_common()]


# --- integrity digests the SP prints in its own text ------------------------
# We only keep a hex digest when the text immediately preceding it *names* what
# it is. That both classifies the digest and rejects incidental hex (ACVP ids,
# certificate thumbprints, key material, generic test vectors).
HEX_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")  # SHA-256 only; the useful case
_S = r"sha[-‐ ]?2?[-‐ ]?2?56"  # SHA-256 / SHA256 / SHA2-256 / SHA2 256
DIGEST_KINDS = [
    # (pattern matched against the ~90 chars before the hash, kind)
    (re.compile(r"module\s+" + _S + r"\s+hmac", re.I), "module-integrity-hmac"),
    (re.compile(r"(expected|below)\s+" + _S + r"\s+digest", re.I), "selftest-expected-digest"),
    (re.compile(r"boringssl[-/]?fips", re.I), "published-download-sha256"),
    (re.compile(r"hash\s+(should\s+be|values?\s+for\s+this\s+file|sum)", re.I), "published-file-sha256"),
]


def integrity_digests(text):
    seen = {}
    for m in HEX_RE.finditer(text):
        h = m.group(1).lower()
        pre = re.sub(r"\s+", " ", text[max(0, m.start() - 90):m.start()])
        kind = next((k for pat, k in DIGEST_KINDS if pat.search(pre)), None)
        if kind is None:
            continue  # unlabeled hex -> not a trustworthy module digest, drop
        if h not in seen:
            seen[h] = {"digest": h, "bits": 256, "kind": kind,
                       "label": pre[-42:].strip(), "source": "security-policy"}
    return list(seen.values())


# --- known-component join ----------------------------------------------------
def load_components():
    ve = {r["cert"]: r for r in json.load(open(os.path.join(HERE, "version_exact.json")))}
    ca_recs = json.load(open(os.path.join(HERE, "corpus_analysis.json")))["records"]
    ca = {r["cert"]: (r.get("components") or []) for r in ca_recs}
    return ve, ca


VE, CA = load_components()


def pick_component(cert):
    """(name, cpe, version, kind, all_names) — best crypto-lib component for a cert."""
    all_names = [c.get("name") for c in CA.get(cert, []) if isinstance(c, dict)]
    vj = VE.get(cert)
    if vj:
        return vj.get("component"), vj.get("cpe"), vj.get("version"), "crypto-lib", all_names
    libs = [c for c in CA.get(cert, []) if c.get("kind") == "crypto-lib"]
    if libs:
        c = libs[0]
        return c.get("name"), c.get("cpe"), c.get("version"), c.get("kind"), all_names
    return None, None, None, None, all_names


# --- identity-confidence heuristic (Track A only; Track B refines) ----------
def confidence(row):
    score, reasons = 0.0, []
    if row["component"]:
        score += 0.40; reasons.append("known-upstream-component")
    if row["module_software_versions"] or row["component_version"]:
        score += 0.20; reasons.append("version-pinned")
    if row["fingerprints"]["filenames"]:
        score += 0.25; reasons.append("filename-in-SP")
    digs = row["fingerprints"]["declared_digests"]
    if any(d["kind"] in ("published-download-sha256", "published-file-sha256") for d in digs):
        score += 0.20; reasons.append("sp-published-hash")
    elif digs:
        score += 0.15; reasons.append("declared-integrity-digest")
    return round(min(score, 1.0), 2), reasons


def build():
    rows = []
    for f in glob.glob(os.path.join(REC, "*.json")):
        d = json.load(open(f))
        c = d["certificate"]
        mt = c.get("moduleType") or ""
        if "Software" not in mt:
            continue
        cert = d["certNumber"]
        sp_path = os.path.join(SPT, f"{cert}.txt")
        text = open(sp_path, encoding="utf-8", errors="ignore").read() if os.path.exists(sp_path) else ""
        name, cpe, cver, kind, allc = pick_component(cert)
        row = {
            "cert": cert,
            "module_name": c.get("moduleName", ""),
            "vendor": (c.get("vendor") or {}).get("name", ""),
            "module_type": mt,
            "overall_level": c.get("overallLevel"),
            "status": c.get("status"),
            "sunset": c.get("sunsetDate"),
            "component": name,
            "cpe": cpe,
            "component_version": cver,
            "component_kind": kind,
            "all_components": allc,
            "module_software_versions": c.get("softwareVersions") or [],
            "tested_configurations": c.get("testedConfigurations") or [],
            "security_policy_url": (d.get("source") or {}).get("securityPolicyUrl"),
            "fingerprints": {
                "filenames": artifacts(text),
                "declared_digests": integrity_digests(text),
                "published_artifacts": [],  # filled by Track B
            },
        }
        conf, reasons = confidence(row)
        row["identity_confidence"] = conf
        row["identity_evidence"] = reasons
        row["provenance"] = {"trackA": "deterministic-corpus"}
        rows.append(row)

    rows.sort(key=lambda r: r["cert"])
    doc = {
        "dataset": "fips-140-3-software-library-fingerprints",
        "track": "A (deterministic corpus extraction)",
        "reference": "2026-07",
        "n": len(rows),
        "rows": rows,
    }
    json.dump(doc, open(OUT, "w"), indent=1)
    return rows


if __name__ == "__main__":
    rows = build()
    with_comp = sum(1 for r in rows if r["component"])
    with_file = sum(1 for r in rows if r["fingerprints"]["filenames"])
    with_dig = sum(1 for r in rows if r["fingerprints"]["declared_digests"])
    print(f"software modules:        {len(rows)}")
    print(f"  with known component:  {with_comp}")
    print(f"  with SP filename(s):   {with_file}")
    print(f"  with integrity digest: {with_dig}")
    print(f"  confidence >= 0.6:     {sum(1 for r in rows if r['identity_confidence'] >= 0.6)}")
    print(f"wrote {os.path.relpath(OUT, HERE)}")
