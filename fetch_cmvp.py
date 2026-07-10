#!/usr/bin/env python3
"""Fetch FIPS 140-3 module records from the public CMVP site so the corpus can be
broadened beyond the provided sample.

For each certificate number it parses the CMVP detail page (server-rendered HTML)
into the same `certificate` schema the analysis uses, downloads the Security Policy
PDF, and extracts its per-page text with `pdftotext`. It writes:

    corpus140_3/records/<cert>.json   (certificate metadata + SP page text)
    sp_text/<cert>.txt                (form-feed separated page text)

These records carry `extraction.level = "metadata+text"`: full certificate metadata
and the verbatim Security-Policy text, but NOT the pdfplumber table reconstruction
that the originally-provided records have. The corpus-level analysis (archetype,
lifecycle, drift, review-priority) runs on the metadata; the extraction-dependent
views (typed SP tables, document-quality grade) are lighter for these modules and
are reported as such.

Standard library only, except it shells out to `pdftotext` (poppler) for the SP
text, matching how the committed sp_text/ was produced.

Usage:
    python fetch_cmvp.py 4651 4652 4653          # specific certs
    python fetch_cmvp.py --range 4650 5159        # every cert in a range
    python fetch_cmvp.py --range 4650 5159 --only-140-3   # skip non-140-3 hits
"""
import sys, os, re, json, html, time, subprocess, hashlib, urllib.request, urllib.error

BASE = "https://csrc.nist.gov/projects/cryptographic-module-validation-program"
CERT_URL = BASE + "/certificate/{n}"
SP_URL = "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp{n}.pdf"
UA = {"User-Agent": "fips-140-3-corpus/1.0 (+https://github.com/rmhrisk/fips-140-3-corpus)"}
RECORDS = "corpus140_3/records"
SPTEXT = "sp_text"


def _get(url, binary=False, tries=4):
    for a in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=45) as r:
                data = r.read()
                return data if binary else data.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if a == tries - 1:
                raise
            time.sleep(5)
        except Exception:
            if a == tries - 1:
                raise
            time.sleep(5)
    return None


def _clean(s):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", s or ""))).strip()


def _field(h, label):
    """Value of a `<span>label</span></div> <div class='col-md-9'[id]>value</div>` row.
    The label may be wrapped in a <span> or bare; the value div may carry an id."""
    m = re.search(re.escape(label) + r"\s*(?:</span>)?\s*</div>\s*<div[^>]*\bcol-md-9\b[^>]*>(.*?)</div>",
                  h, re.S)
    return _clean(m.group(1)) if m else None


def _rows(h, heading):
    """Rows of the first <table> after a section heading, as lists of cell text."""
    m = re.search(re.escape(heading) + r".*?<table.*?>(.*?)</table>", h, re.S)
    if not m:
        return []
    return [[_clean(c) for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", tr, re.S)]
            for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", m.group(1), re.S)]


def _vendor(h):
    m = re.search(r">Vendor</h4>.*?<div class=\"panel-body\">(.*?)</div>", h, re.S)
    if not m:
        return {}
    block = m.group(1)
    name_m = re.search(r"<a[^>]*>(.*?)</a>", block, re.S)
    name = _clean(name_m.group(1)) if name_m else _clean(re.split(r"<span|<br", block)[0])
    lines = []
    for x in re.findall(r"<span[^>]*>(.*?)</span>", block, re.S):
        x = _clean(x)
        if not x or re.search(r"@|Phone:|Fax:|E-?mail", x, re.I):
            break  # address block ends where contact details begin
        lines.append(x)
    return {"name": name, "addressLines": lines} if name else {}


def _algorithms(h):
    """Approved Algorithms is a div-grid: rows of col-md-3 (name) + col-md-4 (ACVP link)."""
    am = re.search(r">Approved Algorithms<.*?<div[^>]*\bcol-md-9\b[^>]*>(.*)", h, re.S)
    if not am:
        return []
    block = am.group(1)
    cut = re.search(r'<div class="row padrow">', block)
    if cut:
        block = block[:cut.start()]
    out = []
    for row in re.finditer(r'<div class="col-md-3">([^<]+)</div>\s*<div class="col-md-4">(.*?)</div>',
                           block, re.S):
        name = _clean(row.group(1))
        if not name:
            continue
        entry = {"name": name}
        link = re.search(r"validation=(\d+)\"[^>]*>([^<]*)</a>", row.group(2))
        if link:
            entry["acvpValidationId"] = int(link.group(1))
            entry["acvpCert"] = _clean(link.group(2))
        out.append(entry)
    return out


def parse_cert(cert, h):
    standard = _field(h, "Standard") or ""
    if "140-3" not in standard:
        # the Standard row on 140-3 pages reads "FIPS 140-3"; anything else is out of scope
        std_hdr = re.search(r"module-standard[^>]*>\s*(FIPS\s*140-\d)", h)
        standard = std_hdr.group(1) if std_hdr else standard
    vh = []
    for row in _rows(h, "Validation History"):
        if len(row) >= 3 and row[0] and row[0][0].isdigit():
            vh.append({"date": row[0], "type": row[1], "lab": row[2]})
    algos = _algorithms(h)
    tested = _field(h, "Tested Configuration(s)") or _field(h, "Tested Configuration")
    lvl = _field(h, "Overall Level")
    overall = int(lvl) if (lvl or "").isdigit() else lvl
    return {
        "approvedAlgorithms": algos,
        "moduleName": _field(h, "Module Name"),
        "standard": standard or "FIPS 140-3",
        "status": _field(h, "Status"),
        "sunsetDate": _field(h, "Sunset Date"),
        "caveat": _field(h, "Caveat"),
        "moduleType": _field(h, "Module Type"),
        "embodiment": _field(h, "Embodiment"),
        "description": _field(h, "Description"),
        "overallLevel": overall,
        "testedConfigurations": [tested] if tested else [],
        "vendor": _vendor(h),
        "validationHistory": vh,
        "hardwareVersions": [], "firmwareVersions": [], "softwareVersions": [],
        "allowedAlgorithms": [], "securityLevelExceptions": [],
    }


def sp_pages(cert):
    """Download the SP PDF and return its per-page text via pdftotext, or []."""
    pdf = _get(SP_URL.format(n=cert), binary=True)
    if not pdf or pdf[:4] != b"%PDF":
        return [], None
    sha = hashlib.sha256(pdf).hexdigest()
    tmp = os.path.join(SPTEXT, f".{cert}.pdf")
    open(tmp, "wb").write(pdf)
    try:
        out = subprocess.run(["pdftotext", "-layout", tmp, "-"], capture_output=True, timeout=120)
        text = out.stdout.decode("utf-8", "replace")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        os.remove(tmp)
        return [], sha
    os.remove(tmp)
    pages = text.split("\f")
    return pages, sha


def build_record(cert):
    h = _get(CERT_URL.format(n=cert))
    if not h or "Module Name" not in h:
        return None
    c = parse_cert(cert, h)
    if not c.get("moduleName") or "140-3" not in (c.get("standard") or ""):
        return None
    pages, sp_sha = sp_pages(cert)
    if pages:
        open(os.path.join(SPTEXT, f"{cert}.txt"), "w", encoding="utf-8").write("\f".join(pages))
    return {
        "certNumber": cert,
        "schemaVersion": "1.0-metadata",
        "source": {
            "certificateUrl": CERT_URL.format(n=cert),
            "securityPolicyUrl": SP_URL.format(n=cert) if pages else None,
            "securityPolicyPdfSha256": sp_sha,
        },
        "certificate": c,
        "securityPolicy": {
            "standard": c["standard"], "pageCount": len(pages),
            "sections": [], "tables": [], "services": [], "portsAndInterfaces": [],
            "approvedAlgorithmsDetailed": [], "sensitiveSecurityParameters": [],
            "securityLevels": [], "revisionHistory": [], "figures": [], "tableProfiles": [],
        },
        "extraction": {"level": "metadata+text", "tables": False},
    }


def main(argv):
    os.makedirs(RECORDS, exist_ok=True)
    os.makedirs(SPTEXT, exist_ok=True)
    if "--range" in argv:
        i = argv.index("--range")
        lo, hi = int(argv[i + 1]), int(argv[i + 2])
        certs = range(lo, hi + 1)
    else:
        certs = [int(x) for x in argv if x.isdigit()]
    ok = skip = 0
    for cert in certs:
        path = os.path.join(RECORDS, f"{cert}.json")
        if os.path.exists(path):
            skip += 1
            continue
        try:
            rec = build_record(cert)
        except Exception as e:
            print(f"  #{cert}: ERROR {type(e).__name__}: {e}", flush=True)
            time.sleep(2)
            continue
        if rec:
            json.dump(rec, open(path, "w"), indent=1)
            ok += 1
            print(f"  #{cert}: {rec['certificate']['moduleName'][:60]}"
                  f" ({rec['securityPolicy']['pageCount']}p)", flush=True)
        time.sleep(1.5)  # be polite to csrc.nist.gov
    print(f"done: {ok} fetched, {skip} already present", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
