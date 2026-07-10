#!/usr/bin/env python3
"""Analyze a corpus of extracted FIPS 140-3 records for lifecycle, exposure, and
document-quality patterns. Emits corpus_analysis.json (+ prints a summary).

Signals mined:
  - lifecycle timing: SP first-revision -> initial validation (submission span),
    SP authoring span, initial validation -> sunset (exposure window)
  - re-validation cadence: #updates and intervals from certificate.validationHistory
  - device exposure: normalized physical/logical interfaces, algorithm families,
    post-quantum adoption, module type/level/embodiment distributions
  - document quality: typed-clean %, value-fill %, section completeness -> A-F grade
"""
from __future__ import annotations
import json, os, re, sys, glob, statistics as st
from collections import Counter, defaultdict

from verify_tables import verify
from security_policy import required_sections, section_present
from components import extract_components
from motifs import match_motifs, MOTIF_INFO

# component-CVE-pressure per cert (from build_drift.py; kernel excluded — whole-kernel
# volume is not crypto-specific and would dominate the signal)
_DRIFT = {}
try:  # multiple (module x component) entries per cert now — keep the MAX pressure
    for _m in json.load(open("drift.json")):
        if _m.get("component") != "Linux kernel":
            _c = _m.get("cves_in_component_since_cert") or 0
            _DRIFT[_m["cert"]] = max(_DRIFT.get(_m["cert"], 0), _c)
except FileNotFoundError:
    pass  # warned about below, once, when version_exact.json is also absent
_VE = set()
try:  # version-EXACT count (tighter evidence) overrides component drift where available
    for _m in json.load(open("version_exact.json")):
        _DRIFT[_m["cert"]] = _m.get("version_exact_cves"); _VE.add(_m["cert"])
except FileNotFoundError:
    # The CVE-drift signal feeds review-priority; run `make all` (which builds
    # drift.json / version_exact.json first) rather than analyze_corpus.py alone.
    print("WARNING: drift.json / version_exact.json not found; review-priority will "
          "omit the CVE-drift signal. Build via `make all`.", file=sys.stderr)

_MONTHS = {m: i for i, m in enumerate(
    ["january","february","march","april","may","june","july","august",
     "september","october","november","december"], 1)}

def parse_date(s):
    """Return (year, month) with a PLAUSIBLE year, else None. Handles '6/6/2024',
    'October 18, 2021', '2021-10-18', and a bare year ONLY when the whole cell is
    one (so build/version numbers like 'build 2048' or '2.08' are not misread)."""
    if not s: return None
    s = str(s).strip()
    ok = lambda y: 1995 <= y <= 2035
    m = re.search(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b", s)
    if m and ok(int(m.group(3))): return (int(m.group(3)), int(m.group(1)))
    m = re.search(r"\b(\d{4})-(\d{1,2})-(\d{1,2})(?!\d)", s)  # ISO, incl. '...T..' timestamps
    if m and ok(int(m.group(1))): return (int(m.group(1)), int(m.group(2)))
    m = re.search(r"\b([A-Za-z]{3,9})\.?\s+\d{0,2},?\s*(\d{4})\b", s)
    if m and m.group(1).lower() in _MONTHS and ok(int(m.group(2))):
        return (int(m.group(2)), _MONTHS[m.group(1).lower()])
    m = re.fullmatch(r"\s*([A-Za-z]{3,9}\.?\s+)?(\d{4})\s*", s)  # bare year / "Oct 2021"
    if m and ok(int(m.group(2))): return (int(m.group(2)), 6)
    return None

REF = (2026, 7)   # analysis reference date (fixed for reproducibility)

def months_between(a, b):
    if not a or not b: return None
    return (b[0]-a[0])*12 + (b[1]-a[1])

_IFACE_MAP = [
    ("USB", r"\busb\b|ftdi"), ("PCIe", r"pci[- ]?e|pcie"), ("Serial/UART", r"uart|serial|rs-?232"),
    ("Network/Ethernet", r"ethernet|rj-?45|network|\blan\b"), ("SMBus/I2C", r"smbus|i2c|i²c"),
    ("SPI", r"\bspi\b"), ("JTAG", r"jtag"), ("GPIO", r"gpio"), ("Console", r"console"),
    ("Wireless", r"wifi|wi-fi|bluetooth|802\.11|nfc|radio"),
]
_PQC = r"ml-kem|ml-dsa|slh-dsa|\blms\b|\bxmss\b|hss|kyber|dilithium|sphincs|falcon|hqc|frodo|bike|mceliece"

# PQC families in NIST terms — NOT interchangeable: LMS/XMSS are stateful hash-based
# signatures (SP 800-208, long approved); ML-KEM/ML-DSA/SLH-DSA are the new FIPS
# 203/204/205 standards. Reporting a single "PQC %" hides that distinction.
# Crucially, the *approved* standards use the ML-KEM / ML-DSA / SLH-DSA names only.
# Kyber / Dilithium / SPHINCS+ are the pre-standardization names; a module naming
# those is discussing a pre-standard or non-approved function, NOT approved FIPS
# 203/204/205 use, so they are bucketed separately and never counted as adoption.
_PQC_KINDS = [
    ("stateful hash-sig (SP800-208: LMS/XMSS)", r"\blms\b|\bxmss\b|\bhss\b"),
    ("ML-KEM (FIPS 203)", r"ml-kem"),
    ("ML-DSA (FIPS 204)", r"ml-dsa"),
    ("SLH-DSA (FIPS 205)", r"slh-dsa"),
    ("pre-standard PQC name (Kyber/Dilithium/SPHINCS+)", r"kyber|dilithium|sphincs"),
    ("other PQC candidate", r"falcon|hqc|frodo|bike|mceliece"),
]

def _algo_names(cert, sp):
    return [(a.get("name") or "").strip() for a in cert.get("approvedAlgorithms", [])] + \
           [(a.get("name") or "").strip() for a in sp.get("approvedAlgorithmsDetailed", [])]

def norm_algo(name):
    """Normalize an ACVP-style name to a stable token: 'RSA SigVer (FIPS186-4)'->'RSA
    SigVer', 'AES-XTS Testing Revision 2.0'->'AES-XTS', 'KAS-ECC-SSC Sp800-56Ar3'->'KAS-ECC-SSC'."""
    n = re.sub(r"\s*\(.*?\)", "", name)
    n = re.sub(r"\s+Testing Revision.*$", "", n, flags=re.I)
    n = re.sub(r"\s+S[pP]\s?800-\S+.*$", "", n)
    n = re.sub(r"\s+FIPS\s?186-\d+.*$", "", n, flags=re.I)
    return re.sub(r"\s{2,}", " ", n).strip()

def specific_algos(cert, sp):
    """Module-level set of normalized approved-algorithm tokens (deduped — the raw
    list repeats an algorithm across key sizes / ACVP certs)."""
    return {norm_algo(n) for n in _algo_names(cert, sp) if n and len(n) < 60}

_LEGACY = {"SHA-1": r"^sha-1$", "HMAC-SHA-1": r"^hmac-sha-1$",
           "Triple-DES": r"tdes|triple-des|3des", "AES-ECB": r"^aes-ecb$"}
_MODERN = {"SHA-3/SHAKE": r"^sha3|^shake", "AES-GCM (AEAD)": r"^aes-gcm",
           "SP800-56 KAS": r"^kas-", "PBKDF": r"^pbkdf", "modern KDF": r"kbkdf|hkdf|kdf"}

def modernization(algos_norm):
    low = [a.lower() for a in algos_norm]
    match = lambda pats: sorted(k for k,rx in pats.items() if any(re.search(rx,a) for a in low))
    return match(_LEGACY), match(_MODERN)

def pqc_breakdown(cert, sp):
    names = _algo_names(cert, sp); blob = " ".join(names).lower()
    kinds = [label for label, rx in _PQC_KINDS if re.search(rx, blob)]
    specific = sorted({m.upper() for n in names
                       for m in re.findall(r"ml-kem-\d+|ml-dsa-\d+|slh-dsa[\w-]*|lms|xmss|hss|kyber|dilithium", n, re.I)})
    return kinds, specific

def revision_dates(sp):
    """All SP revision dates — from the parsed revisionHistory AND by scanning
    tables (many SPs put revision history in a table the inline parser misses).
    The date column is found by content (most date-parseable cells)."""
    dates = []
    for x in sp.get("revisionHistory") or []:
        d = parse_date(x.get("date"))
        if d: dates.append(d)
    for t in sp.get("tables", []):
        rows = t.get("rows", [])
        if len(rows) < 2: continue
        hdr = " ".join(rows[0]).lower()
        if not any(w in hdr for w in ("revision", "change", "history", "modification",
                                      "record of change", "change log", "version date")):
            continue
        ncols = t.get("nCols", 0)
        best_n, best_i = 0, None
        for i in range(ncols):
            cnt = sum(1 for r in rows[1:] if i < len(r) and parse_date(r[i]))
            if cnt > best_n: best_n, best_i = cnt, i
        if best_i is not None and best_n >= 2:
            for r in rows[1:]:
                d = parse_date(r[best_i]) if best_i < len(r) else None
                if d: dates.append(d)
    return sorted(set(dates))

def iface_categories(sp):
    blob = " ".join(
        (p.get("physicalPort") or "") + " " + (p.get("logicalInterface") or "") + " " +
        (p.get("dataThatPasses") or "") + " " + str(p.get("extraColumns") or "")
        for p in sp.get("portsAndInterfaces", [])).lower()
    return {name for name, rx in _IFACE_MAP if re.search(rx, blob)}

def algo_families(cert, sp):
    # case-insensitive on the raw blob (do NOT .upper() the patterns — that turned
    # \b into \B and dropped every LMS module from the PQC family count).
    blob = " ".join(_algo_names(cert, sp))
    fams = set()
    for fam, rx in [("AES",r"AES"),("SHA-2",r"SHA-?2|SHA-?256|SHA-?384|SHA-?512"),
                    ("SHA-3",r"SHA-?3|SHAKE"),("RSA",r"\bRSA\b"),("ECDSA",r"ECDSA"),
                    ("EdDSA",r"ED(DSA|25519)"),("ECDH/KAS",r"ECDH|\bKAS\b"),("HMAC",r"HMAC"),
                    ("DRBG",r"DRBG"),("KDF/KBKDF",r"KDF|KBKDF|HKDF"),("Triple-DES",r"TDES|TRIPLE"),
                    ("PQC",_PQC)]:
        if re.search(rx, blob, re.I): fams.add(fam)
    return fams, bool(re.search(_PQC, blob, re.I))

def classify_device(cert, sp):
    """Coarse device taxonomy: HSM / Chip-SE / PCI-Adapter / Network Appliance /
    Software-Library / Firmware / Other Hardware. Inferred from name+vendor+type+embodiment."""
    name = (cert.get("moduleName") or "").lower()
    vendor = ((cert.get("vendor") or {}).get("name") or "").lower()
    typ = cert.get("moduleType") or ""
    emb = (cert.get("embodiment") or "").lower()
    blob = name + " | " + vendor
    def has(*ws): return any(w in blob for w in ws)
    if has("hsm", "hardware security module", "luna", "nshield", "payshield", "cloudhsm",
           "key management module", "keyper", "vectera"):
        return "HSM"
    if has("secure element", "smartmx", "javacard", "java card", "applet", "smart card",
           "se050", "se05", "p71", " tpm", "trusted platform", "secure enclave", "nxp") \
       or (emb == "single chip" and typ == "Hardware"):
        return "Chip / Secure Element"
    if typ == "Software" or has("openssl", "boringssl", "gnutls", "libgcrypt", "corecrypto",
           "provider", "cryptographic library", "crypto module", "cryptographic module for",
           " sdk", "nss", "strongswan", "bouncy castle", "kernel crypto", "libica"):
        return "Software / Library"
    if typ == "Firmware":
        return "Firmware"
    if has("switch", "router", "gateway", "firewall", "appliance", "photonic",
           "access point", "controller", "data center", "load balancer", " server"):
        return "Network Appliance"
    if has("pcie", "pci-e", "pci card", "adapter", " nic", "accelerator card", "add-in"):
        return "PCI / Adapter Card"
    return "Other Hardware"

# ---- operational archetypes + ordinal review-priority model -------------------
# Archetype = HOW a module exists operationally (attack path), refining device_class.
# Reachability is weighted BY archetype: a network interface on a software library is
# host-mediated (low), on an appliance it is the mgmt/data plane (high). Impact is an
# EXPERT PRIOR per archetype (documented, not corpus-derived). Review priority =
# Likelihood + Impact as ordinal ranks (a rank SUM, banded into tiers), explicit rules, no magic weights.
def archetype(cert, sp, device_class):
    nm = (cert.get("moduleName") or "").lower(); v = ((cert.get("vendor") or {}).get("name") or "").lower()
    def hn(*w): return any(x in nm for x in w)          # module-name only
    def hb(*w): return any(x in nm+" | "+v for x in w)  # name or vendor
    # kernel first, then EXPLICIT crypto-library components (these must beat vendor
    # keywords like "CloudLinux"/"VMware" that would otherwise mislabel an OpenSSL
    # provider as a cloud appliance).
    if hn("kernel cry","kernel cro","crypto api","libkcapi","kernel module","kernel crypto"): return "OS/kernel crypto"
    if hn("openssl","gnutls","libgcrypt","fips provider"," provider","cryptographic library","corecrypto","boringssl","wolfssl"): return "Software crypto library"
    if hn("u-boot","uboot","bootloader","boot module","secure boot"): return "Firmware/boot"
    if device_class=="HSM" or hb("hsm","accelerat"): return "HSM/accelerator"
    if device_class=="Chip / Secure Element" or hn("secure element"," tpm","secure enclave","smartmx","se050","crypto engine"): return "Secure element/SoC"
    if hn("ssd","storage","data-at-rest","self-encrypting"," drive"): return "Storage/data-at-rest"
    if hn("virtual","cloud appliance","hypervisor") or (hn("vmware") and "provider" not in nm): return "Cloud/virtual appliance"
    if device_class=="Network Appliance" or hn("switch","router","firewall","gateway","access point"," ap-","session border","sbc","photonic"): return "Network appliance"
    if device_class=="Software / Library" or hn("crypto module","nss","bouncy","cryptographic module"): return "Software crypto library"
    return "Other"

_REMOTE = {"Network/Ethernet","Wireless","Console"}
# network-PROTOCOL service signal: does the SP name a service that would put this
# crypto on a reachable path (TLS/SSH/IPsec/VPN/web/admin/API), vs pure crypto ops?
_NETSVC = re.compile(r"\b(tls|ssl|https|\bssh\b|ike|ipsec|vpn|snmp|syslog|web ui|admin|rest api|management interface|dtls|802\.1x|radius|eap)\b", re.I)
def network_service_signal(sp):
    names = " ".join(s.get("name","") for s in sp.get("services",[]))
    return sorted({m.group(0).lower() for m in _NETSVC.finditer(names)})

def reachability(arch, ifaces, net_svc):
    # net_svc (a consuming network service is named) is stronger evidence than a bare
    # interface; a software library's reach depends on whether a service consumes it.
    net = bool(_REMOTE & set(ifaces)); svc = bool(net_svc)
    if arch in ("Network appliance","Cloud/virtual appliance"): return "high" if (net or svc) else "medium"
    if arch == "Software crypto library": return "medium" if svc else "low"
    if arch in ("OS/kernel crypto","HSM/accelerator"): return "medium" if (net or svc) else "low"
    if arch in ("Secure element/SoC","Firmware/boot","Storage/data-at-rest"): return "low"
    return "medium" if (net or svc) else "low"

def reach_confidence(net_svc, ifaces):
    if net_svc: return "high"                       # a consuming network service is named
    if _REMOTE & set(ifaces): return "medium"       # interface listed, no service evidence
    return "low"

_IMPACT = {"HSM/accelerator":"High","Secure element/SoC":"High","OS/kernel crypto":"High",
           "Network appliance":"High","Storage/data-at-rest":"High","Firmware/boot":"High",
           "Cloud/virtual appliance":"High","Software crypto library":"Medium","Other":"Medium"}
_ORD = {"low":0,"medium":1,"high":2,"Low":0,"Medium":1,"High":2}
def likelihood(reach, never_updated, months_stale, cve_pressure):
    # reachability + staleness are heuristics; measured upstream CVE drift is real
    # evidence, so heavy drift (>=25 CVEs since cert) weighs an extra point.
    s = (_ORD[reach] + (1 if never_updated else 0) + (1 if (months_stale or 0)>=18 else 0)
         + (1 if (cve_pressure or 0)>=10 else 0) + (1 if (cve_pressure or 0)>=25 else 0))
    return "High" if s>=4 else "Medium" if s>=2 else "Low"
def review_priority(lk, imp):
    t = _ORD[lk] + _ORD[imp]
    return "Critical" if t>=4 else "High" if t==3 else "Medium" if t==2 else "Low"

def grade(clean, fill, sec_frac):
    score = 0.45*clean + 0.35*fill + 0.20*(sec_frac*100)
    return ("A" if score>=85 else "B" if score>=72 else "C" if score>=58 else
            "D" if score>=45 else "F"), round(score,1)

def analyze_record(path):
    r = json.load(open(path))
    c = r.get("certificate") or {}; sp = r.get("securityPolicy") or {}
    std = c.get("standard") or sp.get("standard") or "FIPS 140-3"
    vh = c.get("validationHistory") or []
    vdates = sorted([d for d in (parse_date(v.get("date")) for v in vh) if d])
    initial = vdates[0] if vdates else None
    updates = [v for v in vh if (v.get("type","")).lower().startswith("update")]
    rdates = revision_dates(sp)
    sunset = parse_date(c.get("sunsetDate"))
    # recert intervals (months between consecutive validations)
    intervals = [months_between(vdates[i], vdates[i+1]) for i in range(len(vdates)-1)] if len(vdates)>1 else []
    # quality
    v = verify(r); vf, vt = v["valueFill"]
    clean = 100*v["classes"].get("typed-clean",0)/max(1,v["tables"])
    fill = 100*vf/max(1,vt)
    req = required_sections(std)
    titles = [s.get("title","") for s in sp.get("sections",[])]
    sec_present = sum(1 for s in req if section_present(titles,s,std))
    sec_frac = sec_present/max(1,len(req))
    g, gscore = grade(clean, fill, sec_frac)
    # Assurance type. The CMVP caveat is AUTHORITATIVE — an interim validation says so
    # in its caveat text ("Interim validation. ..."). Duration alone is unreliable: an
    # interim certificate can follow a path to a full five-year active window, so a
    # ~5-yr sunset does NOT mean "Full". Fall back to the duration signal only when the
    # caveat text is absent (e.g. metadata that did not carry it).
    _cav = (c.get("caveat") or "").lower()
    _win = months_between(initial, sunset) if (initial and sunset) else None
    if "interim validation" in _cav:
        assurance = "Interim (2-yr)"
    elif _win is not None and 54 <= _win <= 66:
        assurance = "Full (5-yr)"
    elif _win is not None and 18 <= _win <= 30 and initial and initial >= (2024, 6):
        assurance = "Interim (2-yr)"
    else:
        assurance = "Other/unclear"
    ifaces = iface_categories(sp)
    dclass = classify_device(c, sp)
    arch = archetype(c, sp, dclass)
    # GENERIC component identification (full-record scan; replaces the old hardcoded
    # shortlist). Strong = the module ships it (name/version field); a CPE enables the
    # NVD drift join; version_upstream_mappable gates version-exact.
    components = extract_components(r)
    strong_comps = [k for k in components if k["where"] == "name/version" and k["cpe"]]
    cve_pressure = _DRIFT.get(r.get("certNumber"))
    net_svc = network_service_signal(sp)
    motifs = match_motifs(r, components, ifaces, net_svc, arch)  # vuln-manifestation patterns
    reach = reachability(arch, sorted(ifaces), net_svc)
    mo_stale = months_between(vdates[-1], REF) if vdates else None
    never_upd = len(updates) == 0
    lk = likelihood(reach, never_upd, mo_stale, cve_pressure)
    imp = _IMPACT.get(arch, "Medium")
    prio = review_priority(lk, imp)
    # per-signal evidence confidence (offensive-triage honesty)
    named_comp = bool(strong_comps) or r.get("certNumber") in _DRIFT
    exact_ver = r.get("certNumber") in _VE
    # a named network service is a SERVICE-PATH SIGNAL, NOT confirmed reachability —
    # deployment reachability is genuinely unknown from CMVP/SP alone (kept separate
    # so 'service named' is never mistaken for 'confirmed remotely reachable').
    conf = {
        "component": "high" if named_comp else "n/a",                 # explicitly named in title
        "interface": "high" if (_REMOTE & ifaces) else "low",         # listed in SP ports
        "service_path_signal": reach_confidence(net_svc, ifaces),     # SP names TLS/SSH/etc.?
        "deployment_reachability": ("likely" if (net_svc and arch in ("Network appliance","Cloud/virtual appliance"))
                                    else "unknown"),                  # needs product/service-path evidence
        "version_cve": "high" if exact_ver else ("medium" if named_comp else "n/a"),
        "drift": "high" if cve_pressure is not None else "n/a",       # measured NVD data
        "patch_lineage": "opaque",                                    # not derivable from CMVP
    }
    # explicit claim levels — what the tool KNOWS vs INFERS (L5 never reached from public data)
    lv = []
    if never_upd or (mo_stale or 0)>=18: lv.append("L1")             # certificate drift
    if cve_pressure is not None: lv.append("L2")                     # component pressure
    if exact_ver and (cve_pressure or 0)>0: lv.append("L3")         # version-intersecting pressure
    if net_svc: lv.append("L4")                                      # service-path hypothesis
    claim_levels = lv
    claim_level = max(lv) if lv else "L0"
    # three-part badge decomposition (shown instead of one opaque number)
    drift_badge = ("High" if (never_upd and ((mo_stale or 0)>=18 or (cve_pressure or 0)>=10))
                   else "Medium" if (never_upd or (mo_stale or 0)>=18 or (cve_pressure or 0)>=1) else "Low")
    plaus_badge = {"high":"High","medium":"Medium","low":"Low"}[reach]
    evidence = {
        "CMVP cert": "complete",
        "Security Policy": "complete" if (sp.get("sections") and sp.get("services")) else "partial",
        "component version": "exact" if exact_ver else ("component-only" if named_comp else "not captured"),
        "consuming service": "named" if net_svc else "none/unknown",
        "CVE drift": "measured" if cve_pressure is not None else "n/a",
        "vendor advisory": "not collected",
        "patch lineage": "unknown",
    }
    drivers, reducers = [], []
    if never_upd: drivers.append("no CMVP validation update")
    if (mo_stale or 0)>=18: drivers.append(f"{mo_stale} months since last validation")
    if net_svc: drivers.append(f"names consuming service: {'/'.join(net_svc[:3])}")
    if imp=="High": drivers.append(f"high-impact archetype ({arch})")
    if cve_pressure: drivers.append(f"{cve_pressure} CVEs in named component/version since cert")
    if not never_upd: reducers.append(f"{len(updates)} CMVP validation update(s)")
    if reach=="low": reducers.append("no service-level reachability evidence")
    if not exact_ver: reducers.append("no confirmed exact-version CVE applicability")
    if assurance == "Interim (2-yr)": drivers.append("interim assurance (lighter CMVP review)")
    fams, pqc = algo_families(c, sp)
    algos = specific_algos(c, sp)
    legacy, modern = modernization(algos)
    pqc_kinds, pqc_specific = pqc_breakdown(c, sp)
    labs = sorted({(v.get("lab") or "").strip() for v in (c.get("validationHistory") or []) if v.get("lab")})
    return {
        "cert": r.get("certNumber"), "std": std,
        # full pdfplumber SP extraction (tables/services/etc.) vs metadata+text only.
        # Extraction-dependent metrics (TCB motifs, doc quality, review-priority) are
        # scoped to the full-extraction subset; lifecycle/archetype/algorithms/drift
        # are metadata-derivable and use the whole corpus.
        "full_extraction": (r.get("extraction") or {}).get("level") != "metadata+text",
        "vendor": (c.get("vendor") or {}).get("name"),
        "module": c.get("moduleName"),
        "level": c.get("overallLevel"), "type": c.get("moduleType"),
        "device_class": dclass, "archetype": arch, "assurance": assurance,
        "reachability": reach, "cve_pressure": cve_pressure, "net_services": net_svc,
        "likelihood": lk, "impact": imp, "review_priority": prio, "confidence": conf,
        "drift_badge": drift_badge, "plausibility_badge": plaus_badge,
        "claim_level": claim_level, "claim_levels": claim_levels,
        "components": components, "motifs": motifs,
        "evidence": evidence, "drivers": drivers, "reducers": reducers,
        "embodiment": c.get("embodiment"), "status": c.get("status"),
        "entropy": bool(c.get("entropy")),
        "n_algos": len(c.get("approvedAlgorithms",[])) or len(sp.get("approvedAlgorithmsDetailed",[])),
        "n_services": len(sp.get("services",[])), "n_ssps": len(sp.get("sensitiveSecurityParameters",[])),
        "families": sorted(fams), "pqc": pqc,
        "algos": sorted(algos), "n_distinct_algos": len(algos),
        "legacy": legacy, "modern": modern,
        "pqc_kinds": pqc_kinds, "pqc_specific": pqc_specific,
        "labs": labs,
        "interfaces": sorted(ifaces), "n_interfaces": len(ifaces),
        # timeline
        "sp_first": rdates[0] if rdates else None, "sp_last": rdates[-1] if rdates else None,
        "sp_revisions": len(rdates),
        "sp_authoring_months": months_between(rdates[0], rdates[-1]) if len(rdates)>1 else None,
        "initial_validation": initial,
        "submission_months": months_between(rdates[0], initial) if (rdates and initial) else None,
        "n_updates": len(updates), "n_validations": len(vdates),
        "recert_intervals": intervals,
        "sunset": sunset,
        "last_validation": vdates[-1] if vdates else None,
        "exposure_window_months": months_between(initial, sunset) if (initial and sunset) else None,
        "cert_age_months": months_between(initial, REF),
        "months_since_last_validation": months_between(vdates[-1], REF) if vdates else None,
        "still_active": (sunset is None or months_between(REF, sunset) is not None and months_between(REF, sunset) >= 0),
        "exposure_remaining_months": months_between(REF, sunset) if sunset else None,
        # quality
        "clean": round(clean,1), "fill": round(fill,1),
        "sections_present": f"{sec_present}/{len(req)}", "grade": g, "grade_score": gscore,
        "pages": sp.get("pageCount"),
    }

def summarize(rows):
    def nums(key): return [r[key] for r in rows if isinstance(r.get(key),(int,float))]
    def med(xs): return round(st.median(xs),1) if xs else None
    def mean(xs): return round(st.mean(xs),1) if xs else None
    # Modules with full pdfplumber SP extraction. Metrics that depend on the SP
    # structure (interfaces, TCB motifs, document quality, and the reachability that
    # drives review-priority) are computed over this subset; lifecycle, archetype,
    # algorithm and drift metrics use the whole corpus.
    frows = [r for r in rows if r.get("full_extraction")]
    out = {"n": len(rows), "n_full_extraction": len(frows)}
    out["lifecycle"] = {
        "submission_months (SP first->initial validation)": {"n":len(nums("submission_months")),"median":med(nums("submission_months")),"mean":mean(nums("submission_months")),"max":max(nums("submission_months")or[0])},
        "sp_authoring_months": {"n":len(nums("sp_authoring_months")),"median":med(nums("sp_authoring_months")),"mean":mean(nums("sp_authoring_months"))},
        "exposure_window_months (validation->sunset)": {"n":len(nums("exposure_window_months")),"median":med(nums("exposure_window_months")),"mean":mean(nums("exposure_window_months"))},
    }
    out["assurance"] = {
        "type_dist": dict(Counter(r["assurance"] for r in rows).most_common()),
        "interim_pct": round(100*sum(1 for r in rows if r["assurance"]=="Interim (2-yr)")/max(1,len(rows)),1),
        "interim_certs": [r["cert"] for r in rows if r["assurance"]=="Interim (2-yr)"],
    }
    all_int = [x for r in rows for x in r.get("recert_intervals",[])]
    out["recertification"] = {
        "modules_with_updates": sum(1 for r in rows if r["n_updates"]>0),
        "pct_with_updates": round(100*sum(1 for r in rows if r["n_updates"]>0)/max(1,len(rows)),1),
        "avg_updates_per_module": mean(nums("n_updates")),
        "recert_interval_months_median": med(all_int), "recert_interval_months_mean": mean(all_int),
        "update_count_dist": dict(Counter(r["n_updates"] for r in rows)),
    }
    out["exposure"] = {
        "interface_freq": dict(Counter(i for r in frows for i in r["interfaces"]).most_common()),
        "algo_family_freq": dict(Counter(f for r in rows for f in r["families"]).most_common()),
        "pqc_adoption_pct": round(100*sum(1 for r in rows if r["pqc"])/max(1,len(rows)),1),
        "level_dist": dict(Counter(r["level"] for r in rows)),
        "type_dist": dict(Counter(r["type"] for r in rows)),
        "embodiment_dist": dict(Counter(r["embodiment"] for r in rows).most_common()),
        "median_algos": med(nums("n_algos")), "median_services": med(nums("n_services")),
        "device_class_dist": dict(Counter(r["device_class"] for r in rows).most_common()),
    }
    N = max(1, len(rows))
    # operational archetypes + ordinal review-priority (Likelihood + Impact, a rank sum)
    archs = [a for a,_ in Counter(r["archetype"] for r in rows).most_common()]
    out["archetypes"] = {
        "dist": dict(Counter(r["archetype"] for r in rows).most_common()),
        "by_archetype": {a: {
            "n": sum(1 for r in rows if r["archetype"]==a),
            "impact_prior": _IMPACT.get(a,"Medium"),
            "pct_never_updated": round(100*sum(1 for r in rows if r["archetype"]==a and r["n_updates"]==0)/max(1,sum(1 for r in rows if r["archetype"]==a)),0),
            "median_months_stale": med([r["months_since_last_validation"] for r in rows
                                        if r["archetype"]==a and r["months_since_last_validation"] is not None]),
            "reachability_mix": dict(Counter(r["reachability"] for r in frows if r["archetype"]==a)),
        } for a in archs},
    }
    prio_rank = {"Critical":3,"High":2,"Medium":1,"Low":0}
    def reason(r):
        bits=[r["archetype"]]
        rc=r["confidence"]["service_path_signal"]; dr=r["confidence"]["deployment_reachability"]
        if r["net_services"]: bits.append(f"names service {'/'.join(r['net_services'][:3])} (service-path signal {rc}, deployment reachability {dr})")
        else: bits.append(f"reach={r['reachability']} (deployment reachability {dr})")
        if r["n_updates"]==0: bits.append("no CMVP validation update")
        if (r["months_since_last_validation"] or 0)>=18: bits.append(f"{r['months_since_last_validation']}mo stale")
        if r["cve_pressure"]: bits.append(f"{r['cve_pressure']} CVEs in named component/version since cert")
        return "; ".join(bits)
    top = sorted(frows, key=lambda r:(-prio_rank[r["review_priority"]], -(r["cve_pressure"] or 0), -(r["months_since_last_validation"] or 0)))
    out["review_priority"] = {
        "dist": dict(Counter(r["review_priority"] for r in frows).most_common()),
        "model": "Review priority combines two ordinal ranks by ADDING their positions (a rank sum, not a product), then bands the sum into Critical/High/Medium/Low. Likelihood is an additive point score over archetype-weighted reachability (service-conditional), no-CMVP-validation-update, >=18mo staleness, and measured upstream CVE drift (scored at both >=10 and >=25, so drift weighs most). Impact is an expert prior per archetype. Every input is explicit and evidence-graded. These are attack-path REVIEW-ORDER CANDIDATES requiring confirmation, NOT confirmed vulnerabilities or a severity score.",
        "top": [{"cert":r["cert"],"module":(r["module"] or "")[:44],"archetype":r["archetype"],
                 "priority":r["review_priority"],"likelihood":r["likelihood"],"impact":r["impact"],
                 "reachability":r["reachability"],"net_services":r["net_services"],"cve_pressure":r["cve_pressure"],
                 "never_updated":r["n_updates"]==0,"months_stale":r["months_since_last_validation"],
                 "confidence":r["confidence"],"reason":reason(r)}
                for r in top if r["review_priority"] in ("Critical","High")][:16],
    }
    # SPECIFIC algorithms — module-level presence (a module counts once per algo)
    algo_ct = Counter(a for r in rows for a in r["algos"])
    out["algorithms"] = {
        "distinct_algorithms_in_corpus": len(algo_ct),
        "median_distinct_per_module": med(nums("n_distinct_algos")),
        "top_specific": {a: c for a, c in algo_ct.most_common(35)},
        # modernization posture (share of modules)
        "legacy_present_pct": {k: round(100*sum(1 for r in rows if k in r["legacy"])/N,1)
                               for k in _LEGACY},
        "modern_present_pct": {k: round(100*sum(1 for r in rows if k in r["modern"])/N,1)
                               for k in _MODERN},
        "modules_with_any_legacy_pct": round(100*sum(1 for r in rows if r["legacy"])/N,1),
        "modules_with_sha3_pct": round(100*sum(1 for r in rows if "SHA-3/SHAKE" in r["modern"])/N,1),
    }
    # PQC — by NIST family + specific algorithms, WITH cert numbers (audit trail)
    pqc_rows = [r for r in rows if r["pqc"]]
    out["pqc"] = {
        "modules_with_pqc": len(pqc_rows),
        "pct": round(100*len(pqc_rows)/N,1),
        "by_kind_pct": {k: round(100*sum(1 for r in rows if k in r["pqc_kinds"])/N,1)
                        for k,_ in _PQC_KINDS},
        "specific_algo_freq": dict(Counter(a for r in pqc_rows for a in r["pqc_specific"]).most_common()),
        "modern_lattice_modules": [r["cert"] for r in rows if any(
            k.startswith(("ML-KEM","ML-DSA","SLH-DSA")) for k in r["pqc_kinds"])],
        "certs": {r["cert"]: r["pqc_specific"] for r in pqc_rows},
    }
    # lab concentration (market structure)
    lab_ct = Counter(l for r in rows for l in r["labs"])
    out["labs"] = {"distinct_labs": len(lab_ct), "top": dict(lab_ct.most_common(10))}
    # GENERIC component identification summary (full-record scan, not a hardcoded list)
    strong_ct = Counter(); ref_ct = Counter(); kind_ct = Counter()
    for r in rows:
        for cc in r.get("components", []):
            (strong_ct if cc["where"]=="name/version" else ref_ct)[cc["name"]] += 1
            if cc["where"]=="name/version": kind_ct[cc["kind"]] += 1
    out["components"] = {
        "note": "Generic full-record component identification (module name + software/firmware versions + SP body/tables) against a CPE-mapped catalog. 'strong' = the module ships/names it in a name/version field; 'referenced' = mentioned in the SP body.",
        "modules_with_strong_component": sum(1 for r in rows if any(cc["where"]=="name/version" for cc in r.get("components",[]))),
        "strong_freq": dict(strong_ct.most_common()),
        "referenced_freq": dict(ref_ct.most_common()),
        "by_kind": dict(kind_ct.most_common()),
        # non-crypto-library components (bootloaders/firmware/OS/utility) the old shortlist missed
        "non_lib_named_modules": {cc["name"]: [r["cert"] for r in rows for cc2 in r.get("components",[])
                                               if cc2["name"]==cc["name"] and cc2["where"]=="name/version"]
                                  for r in rows for cc in r.get("components",[])
                                  if cc["where"]=="name/version" and cc["kind"] in ("bootloader","firmware","os-kernel","utility")},
    }
    # vulnerability-manifestation MOTIFS — architectural patterns where a known vuln
    # class matters. A match = the pattern is present, NOT that the module is vulnerable.
    motif_ct = Counter(mo for r in frows for mo in r.get("motifs", []))
    out["motifs"] = {
        "note": ("A motif is an architectural pattern where a known vulnerability CLASS would matter, "
                 "matched from public signals (identified components, interfaces, services, archetype, SP keywords). "
                 "A match means the corpus reveals the pattern — NOT that the module is vulnerable."),
        "freq": dict(motif_ct.most_common()),
        "catalog": {name: {"description": info[0], "external_anchor": info[1], "can_cannot": info[2],
                           "n_modules": motif_ct.get(name, 0),
                           "modules": [r["cert"] for r in rows if name in r.get("motifs", [])][:20]}
                    for name, info in MOTIF_INFO.items()},
    }
    # throughput predictors — COMPLEXITY proxies for review burden. NOTE: this corpus
    # is survivorship-biased (validated modules only) and carries NO pipeline-timing
    # data, so these are candidate PREDICTORS/HYPOTHESES, not measured time drivers.
    def cx(rows_sub):
        return {"n": len(rows_sub),
                "median_algos": med([r["n_algos"] for r in rows_sub]),
                "median_services": med([r["n_services"] for r in rows_sub]),
                "median_ssps": med([r["n_ssps"] for r in rows_sub]),
                "median_interfaces": med([r["n_interfaces"] for r in rows_sub])}
    out["throughput_predictors"] = {
        "note": ("Complexity proxies for REVIEW BURDEN — candidate predictors of validation effort. "
                 "The corpus is survivorship-biased (validated modules only) and has NO pipeline-timing "
                 "data (no IUT/Cost-Recovery/Pending-Review durations, no comment cycles), so these are "
                 "HYPOTHESES, not measured time drivers."),
        "by_archetype": {a: cx([r for r in rows if r["archetype"]==a]) for a in archs},
        "by_level": {lvl: cx([r for r in rows if r["level"]==lvl]) for lvl in sorted({r["level"] for r in rows if r["level"]})},
        "by_type": {t: cx([r for r in rows if r["type"]==t]) for t in sorted({r["type"] for r in rows if r["type"]})},
        "pqc_present_n": sum(1 for r in rows if r["pqc"]),
        "not_determinable_without_MIP_snapshots": [
            "days in IUT / lab pipeline", "days in Cost Recovery", "days in Pending Review",
            "number of CMVP comment cycles", "which party (vendor/lab/CMVP) drove a delay",
            "which evidence class (entropy/algorithm/physical/SSP/OE/SP-quality) caused rework",
            "how long abandoned or still-pending modules have waited (not in a validated-cert corpus at all)"],
    }
    # corpus coverage / confidence block
    certs = [r["cert"] for r in rows if isinstance(r["cert"], int)]
    out["coverage"] = {
        "reference_date": "2026-07",
        "sweep_range": f"cert #{min(certs)}–#{max(certs)} (near-census of FIPS 140-3 in this window)" if certs else "n/a",
        "fips_140_3_modules": len(rows),
        "cert_number_span": f"#{min(certs)}–#{max(certs)}" if certs else "n/a",
        "status_dist": dict(Counter((r["status"] or "Active") for r in rows).most_common()),
        "with_sp_revision_dates": sum(1 for r in rows if r["sp_first"]),
        "with_validation_dates": sum(1 for r in rows if r["initial_validation"]),
        "fields_from_cert_page": "level, type, embodiment, vendor, standard, status, validationHistory (dates/lab), sunset, approvedAlgorithms",
        "fields_from_security_policy": "sections, revisionHistory, ports/interfaces, services, SSPs, approvedAlgorithmsDetailed, tables",
        "dedup_rule": "one record per certificate number; cross-cert rebrand/re-validation chains NOT yet merged",
    }
    # per-device-class cross-tabs: quality, exposure window, re-cert rate, PQC
    classes = [c for c,_ in Counter(r["device_class"] for r in rows).most_common()]
    out["by_device_class"] = {c: {
        "n": sum(1 for r in rows if r["device_class"]==c),
        "grade": mean([r["grade_score"] for r in rows if r["device_class"]==c]),
        "exposure_window_mo": med([r["exposure_window_months"] for r in rows if r["device_class"]==c and r["exposure_window_months"]]),
        "pct_re_validated": round(100*sum(1 for r in rows if r["device_class"]==c and r["n_updates"]>0)/max(1,sum(1 for r in rows if r["device_class"]==c)),0),
        "pqc_pct": round(100*sum(1 for r in rows if r["device_class"]==c and r["pqc"])/max(1,sum(1 for r in rows if r["device_class"]==c)),0),
        "median_algos": med([r["n_algos"] for r in rows if r["device_class"]==c]),
    } for c in classes}
    out["quality"] = {
        "grade_dist": dict(Counter(r["grade"] for r in frows)),
        "mean_clean": mean(nums("clean")), "mean_fill": mean(nums("fill")),
        "mean_grade_score": mean(nums("grade_score")),
        "by_level": {lvl: mean([r["grade_score"] for r in frows if r["level"]==lvl])
                     for lvl in sorted({r["level"] for r in frows if r["level"]})},
        "by_type": {t: mean([r["grade_score"] for r in frows if r["type"]==t])
                    for t in sorted({r["type"] for r in rows if r["type"]})},
    }
    # vuln-exposure lens: an active module whose last validation is old and which
    # exposes a remote/networked surface is where an un-recertified CVE would bite.
    REMOTE = {"Network/Ethernet", "USB", "Wireless", "Console"}
    active = [r for r in rows if r["still_active"]]
    stale_active = [r for r in active if (r["months_since_last_validation"] or 0) >= 18
                    and REMOTE & set(r["interfaces"])]
    out["vuln_exposure"] = {
        "pct_still_active": round(100*len(active)/max(1,len(rows)),1),
        "months_since_last_validation": {"median":med(nums("months_since_last_validation")),"max":max(nums("months_since_last_validation")or[0])},
        "exposure_remaining_months_median": med(nums("exposure_remaining_months")),
        "stale_active_remote_count": len(stale_active),
        "stale_active_examples": [{"cert":r["cert"],"module":(r["module"] or "")[:40],
                                   "since_last_validation_mo":r["months_since_last_validation"],
                                   "interfaces":r["interfaces"],"never_updated":r["n_updates"]==0}
                                  for r in sorted(stale_active,key=lambda x:-(x["months_since_last_validation"] or 0))[:8]],
    }
    # vendors with multiple certs (re-fips-140 signal across cert numbers)
    byv = defaultdict(list)
    for r in rows: byv[r["vendor"]].append(r["cert"])
    out["vendors_multi_cert"] = {v: len(cs) for v,cs in sorted(byv.items(), key=lambda x:-len(x[1])) if len(cs)>1}
    return out

def main():
    paths = sorted(glob.glob(sys.argv[1] if len(sys.argv)>1 else "corpus140_3/records/*.json"))
    rows = []
    for p in paths:
        try: rows.append(analyze_record(p))
        except Exception as e: print(f"FAIL {p}: {e}", file=sys.stderr)
    rows = [r for r in rows if r["std"]=="FIPS 140-3"]
    summary = summarize(rows)
    json.dump({"summary":summary,"records":rows}, open("corpus_analysis.json","w"), indent=1)
    print(json.dumps(summary, indent=1))
    print(f"\nanalyzed {len(rows)} FIPS 140-3 records -> corpus_analysis.json")

if __name__ == "__main__":
    main()
