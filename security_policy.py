"""Best-effort extraction of structure from a non-proprietary Security Policy PDF.

Unlike the certificate page, Security Policies are free-form documents authored
by each vendor/lab, so extraction here is heuristic. We pull:
  - title, page count
  - revision history
  - the table of contents (section number -> title -> page)
  - the FIPS 140-3 security-levels table (Table 1), when detectable
  - a lightweight text fingerprint used for evidence-coverage linting

This is exactly the layer where LLM assistance pays off for the long tail of
heterogeneous documents; the deterministic heuristics below establish the
schema target and already handle the common ISO 19790 / SP 800-140B layout.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from typing import Any

try:                       # only needed for the (upstream) PDF-extraction stage,
    import pdfplumber       # not for the analysis tier that reads pre-extracted records
except ModuleNotFoundError:
    pdfplumber = None

from profiles import match_profile, map_row, content_profile

# Canonical FIPS 140-3 / ISO 19790 clause titles (used for TOC/section matching).
REQUIRED_SECTIONS = [
    "General",
    "Cryptographic Module Specification",
    "Cryptographic Module Interfaces",
    "Roles, Services, and Authentication",
    "Software/Firmware Security",
    "Operational Environment",
    "Physical Security",
    "Non-Invasive Security",
    "Sensitive Security Parameter Management",
    "Self-Tests",
    "Life-Cycle Assurance",
    "Mitigation of Other Attacks",
]

# Tolerant keyword patterns per required clause. Vendors vary titles (singular vs
# plural, "SSP" vs full form, punctuation), so match on distinctive tokens rather
# than exact strings.
SECTION_KEYWORDS = {
    # matched with re.search against section titles; keep them tolerant of vendor
    # wording — "^general$" missed real titles like "Generals" and "SECTION 1 - GENERAL",
    # and requiring the plural "roles" missed "Role, services, and authentication".
    "General": r"\bgeneral\b",
    "Cryptographic Module Specification": r"module specification",
    "Cryptographic Module Interfaces": r"module interface",
    "Roles, Services, and Authentication": r"role.*(service|authentication)",
    "Software/Firmware Security": r"(software|firmware) security",
    "Operational Environment": r"operational environment",
    "Physical Security": r"physical security",
    "Non-Invasive Security": r"non.?invasive",
    "Sensitive Security Parameter Management": r"sensitive security parameter",
    "Self-Tests": r"self.?tests?",
    "Life-Cycle Assurance": r"life.?cycle",
    "Mitigation of Other Attacks": r"mitigation of other attacks",
}


# FIPS 140-2 uses a DIFFERENT clause set (Finite State Model, EMI/EMC, Key
# Management, Design Assurance — none of which are 140-3 clauses). Checking a
# 140-2 SP against the 140-3 list above false-fails every document, so the
# standard is detected and the matching set is used.
REQUIRED_SECTIONS_140_2 = [
    "Cryptographic Module Specification",
    "Cryptographic Module Ports and Interfaces",
    "Roles, Services, and Authentication",
    "Finite State Model",
    "Physical Security",
    "Operational Environment",
    "Cryptographic Key Management",
    "EMI/EMC",
    "Self-Tests",
    "Design Assurance",
    "Mitigation of Other Attacks",
]

# Keyword sets are matched against the SP's own section titles. 140-2 vendors title
# the mandated clauses with their own words, so each pattern also lists the common
# vendor headings that genuinely satisfy the clause per the FIPS 140-2 DTR (e.g.
# "Cryptographic Boundary"/"Modes of Operation" are Specification sub-requirements;
# "Critical Security Parameters" IS key management; "Secure Operation"/"Security
# Rules and Guidance" are the Design-Assurance operator-guidance sub-requirement).
# Finite State Model and EMI/EMC are deliberately NOT broadened: they are typically
# a separate document or a one-line prose statement with no heading, so a keyword
# hit would be a false positive — that residual is the AI-prose mapper's job.
SECTION_KEYWORDS_140_2 = {
    "Cryptographic Module Specification": r"module specification|cryptographic boundary|modes? of operation|cryptographic functionalit",
    "Cryptographic Module Ports and Interfaces": r"ports? and interface|module interface|physical ports|logical interface",
    "Roles, Services, and Authentication": r"\brole|\bservices?\b|authentication|identification and auth",
    "Finite State Model": r"finite state|state machine|state transition",
    "Physical Security": r"physical security",
    "Operational Environment": r"operational environment|operating environment",
    "Cryptographic Key Management": r"key management|key\s*/?\s*csp|critical security parameter|\bcsps?\b|key and csp",
    "EMI/EMC": r"emi\s*/?\s*emc|electromagnetic",
    "Self-Tests": r"self.?tests?",
    "Design Assurance": r"design assurance|secure operation|security rules|crypto[- ]?officer guidance|delivery and operation|\bguidance\b",
    "Mitigation of Other Attacks": r"mitigation of other attacks",
}

SECTION_SETS = {
    "FIPS 140-2": (REQUIRED_SECTIONS_140_2, SECTION_KEYWORDS_140_2),
    "FIPS 140-3": (REQUIRED_SECTIONS, SECTION_KEYWORDS),
}


def required_sections(standard: str | None = None) -> list[str]:
    """The required-clause list for the given standard (defaults to 140-3)."""
    return SECTION_SETS.get(standard or "FIPS 140-3", SECTION_SETS["FIPS 140-3"])[0]


def detect_standard(text: str) -> str:
    """Sniff FIPS 140-2 vs 140-3 from the SP text (used when the authoritative
    certificate-page 'Standard' field is unavailable, e.g. the batch path)."""
    head = (text or "")[:20000]
    n3 = len(re.findall(r"140[-\s]?3|19790", head))
    n2 = len(re.findall(r"140[-\s]?2", head))
    if n3 >= n2 and n3:
        return "FIPS 140-3"
    return "FIPS 140-2" if n2 else "FIPS 140-3"


def section_present(section_titles: list[str], required_name: str,
                    standard: str | None = None) -> bool:
    """True if any parsed SP section title matches the required clause's keyword,
    using the keyword set for the given standard (defaults to 140-3)."""
    _, kwmap = SECTION_SETS.get(standard or "FIPS 140-3", SECTION_SETS["FIPS 140-3"])
    pat = kwmap.get(required_name)
    if not pat:
        return False
    rx = re.compile(pat, re.I)
    return any(rx.search(t or "") for t in section_titles)

# TOC lines come in three shapes across vendors/standards:
#   "1. General ......... 5"     numbered, dotted leaders  (FIPS 140-3, most)
#   "Introduction ....... 3"      UNnumbered, dotted leaders (some 140-2, e.g. Cisco)
#   "1. Introduction      3"      numbered, space-aligned   (some 140-2, e.g. Titaniam)
# Dotted-leader lines are unambiguous and matched anywhere; the leading number is
# optional. Space-aligned lines look too much like body/table text, so they are
# matched ONLY inside the located TOC region (see _extract_toc).
_TOC_DOTTED = re.compile(r"^\s*(?:(\d+(?:\.\d+)*)\.?\s+)?(.+?)\s*\.{2,}\s*(\d{1,4})\s*$")
_TOC_SPACED = re.compile(r"^\s*(\d+(?:\.\d+)*)\.?\s+(.+?)\s{2,}(\d{1,4})\s*$")
_TOC_START = re.compile(r"^\s*(?:table of\s+)?contents\s*$", re.I)
_TOC_END = re.compile(r"^\s*(list of (tables|figures)|revision history)\s*$", re.I)
_REV_RE = re.compile(r"^\s*(\d+\.\d+[a-z]?)\s+([A-Z][a-z]+ \d{1,2},? \d{4})\s+(.*)$")


def _fmt_pdfdate(v: str) -> str:
    m = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?", v)
    if not m:
        return v
    y, mo, d, hh, mm = m.groups()
    out = f"{y}-{mo}-{d}"
    return out + (f" {hh}:{mm}" if hh and mm else "")


def _pdftotext_layout(pdf_path: str) -> str:
    try:
        return subprocess.run(
            ["pdftotext", "-layout", pdf_path, "-"],
            capture_output=True, text=True, check=True,
        ).stdout
    except Exception:
        return ""


def _extract_title(lines: list[str]) -> str | None:
    for l in lines[:8]:
        s = l.strip()
        if s and "security policy" not in s.lower() and len(s) > 3:
            return s
    return lines[0].strip() if lines else None


def _extract_revision_history(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    m = re.search(r"Revision History(.+?)(?:Notice|Table of Contents)", text, re.S | re.I)
    block = m.group(1) if m else text[:4000]
    for line in block.splitlines():
        rm = _REV_RE.match(line)
        if rm:
            out.append({
                "revision": rm.group(1),
                "date": rm.group(2).replace(",", ""),
                "description": re.sub(r"\s+", " ", rm.group(3)).strip() or None,
            })
    return out


def _extract_toc(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    # Locate the TOC region so space-aligned entries (which look like body text)
    # are only trusted inside it. Dotted-leader entries are matched everywhere.
    region_lo = region_hi = None
    for i, l in enumerate(lines):
        if _TOC_START.match(l):
            region_lo = i + 1
            region_hi = min(i + 200, len(lines))
            for j in range(region_lo, region_hi):
                if _TOC_END.match(lines[j]):
                    region_hi = j
                    break
            break
    seen, out = set(), []
    for i, line in enumerate(lines):
        m = _TOC_DOTTED.match(line)
        if not m and region_lo is not None and region_lo <= i < region_hi:
            m = _TOC_SPACED.match(line)
        if not m:
            continue
        num = (m.group(1) or "").strip(". ") or None
        title = re.sub(r"\s+", " ", m.group(2)).strip().rstrip(". ")
        page = int(m.group(3))
        # skip list-of-tables/figures noise and lines without real words
        if title.lower().startswith(("table ", "figure ", "appendix table")):
            continue
        if len(re.sub(r"[^a-z]", "", title.lower())) < 3 or page > 2000:
            continue
        key = (num, title.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"number": num, "title": title, "page": page})
    return out


_URL_RE = re.compile(r"(?:https?://|www\.)[^\s)\]<>\"']+", re.I)


def _extract_urls(text: str) -> list[dict[str, str]]:
    """URLs referenced in the SP body — download/support links, standards
    citations, references. Useful to keep and query, not boilerplate."""
    seen, out = set(), []
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:)]}'\"")
        if len(url) < 8:
            continue
        norm = re.sub(r"^https?://", "", url.lower()).rstrip("/")
        if norm in seen:
            continue
        seen.add(norm)
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        out.append({"url": url, "domain": host})
    return out


def _extract_security_levels(text: str) -> list[dict[str, Any]]:
    """Table 1: ISO 19790 area -> claimed level. Heuristic line matching."""
    out = []
    areas = [
        "Cryptographic Module Specification", "Cryptographic Module Interfaces",
        "Roles, Services, and Authentication", "Software/Firmware Security",
        "Operational Environment", "Physical Security", "Non-Invasive Security",
        "Sensitive Security Parameter Management", "Self-Tests",
        "Life-Cycle Assurance", "Mitigation of Other Attacks",
    ]
    for area in areas:
        m = re.search(re.escape(area) + r"\s+(\d(?:\s*/\s*\w+)?|N/?A)", text)
        if m:
            out.append({"area": area, "level": m.group(1).strip()})
    return out


def _cell(v: str | None) -> str:
    return re.sub(r"\s+", " ", (v or "").replace("\n", " ")).strip()


# A cell like "[Number Below]" / "[See below]" is a header annotation telling the
# reader where the values are, not data. When a whole row is only such notes it is
# a layout artifact (e.g. under the "ISO/IEC 24759 Section" header of Table 1) and
# must be dropped so it does not become a junk typed row.
_PLACEHOLDER_CELL_RE = re.compile(
    r"^\[[^\]]*\b(?:below|above|following|see|number|left|right|next|column|row)\b[^\]]*\]$",
    re.IGNORECASE)


def _is_placeholder_row(row: list[str]) -> bool:
    cells = [c.strip() for c in row if c and c.strip()]
    return bool(cells) and all(_PLACEHOLDER_CELL_RE.match(c) for c in cells)


def _normalize_table(rows: list[list[str]]) -> list[list[str]] | None:
    """Pad rows to a common width, then drop columns that are empty in EVERY row
    (header included). pdfplumber routinely invents empty separator columns (e.g.
    a 3-column table detected as 6); those add noise and mis-align rendering."""
    if not rows:
        return None
    ncols = max(len(r) for r in rows)
    rows = [r + [""] * (ncols - len(r)) for r in rows]
    keep = [i for i in range(ncols) if any(rows[j][i].strip() for j in range(len(rows)))]
    if not keep:
        return None
    return [[r[i] for i in keep] for r in rows]


def _is_degenerate_table(rows: list[list[str]]) -> bool:
    """A single-column strip or a table with <=2 filled cells is almost always a
    header label that pdfplumber split into its own tiny 'table' (e.g. 'Indicato'
    / 'r', or 'SSP' / 'Access'), not real tabular data."""
    ncols = len(rows[0]) if rows else 0
    filled = sum(1 for r in rows for c in r if c.strip())
    return ncols <= 1 or filled <= 2


def _extract_tables(pdf) -> list[dict[str, Any]]:
    """Every real table in the document, as structured rows, with pdfplumber
    artifacts cleaned up: empty separator columns dropped, degenerate fragment
    tables filtered. (The verbatim text sidecar remains the lossless anchor.)"""
    out = []
    for pnum, page in enumerate(pdf.pages, start=1):
        try:
            tables = page.extract_tables()
        except Exception:
            continue
        for idx, tbl in enumerate(tables):
            rows = [[_cell(c) for c in row] for row in tbl if any((c or "").strip() for c in row)]
            rows = [r for r in rows if not _is_placeholder_row(r)]
            rows = _normalize_table(rows)
            if not rows or _is_degenerate_table(rows):
                continue
            out.append({
                "page": pnum,
                "index": idx,
                "nRows": len(rows),
                "nCols": len(rows[0]),
                "rows": rows,
            })
    return out


_HEADER_WORDS = {
    "name", "strength", "service", "services", "description", "role", "roles",
    "ssp", "csp", "key", "keys", "generation", "storage", "zeroization", "use",
    "import", "export", "type", "port", "ports", "interface", "access", "input",
    "output", "algorithm", "function", "functions", "command", "commands",
    "standard", "rights", "indicator", "approved", "security", "ssps", "cavp",
    "cert", "mode", "method", "reference", "properties", "size",
    # tested-configuration / version table labels
    "model", "hardware", "firmware", "version", "features", "part", "number",
    "distinguishing", "processor", "processors", "platform", "operating", "system",
}


def _hnorm(s: str) -> str:
    return re.sub(r"[^a-z0-9 ]+", " ", (s or "").lower()).strip()


def _is_repeat_header(name: str) -> bool:
    n = _hnorm(name)
    return n in _HEADER_WORDS or (len(n.split()) <= 3 and all(w in _HEADER_WORDS for w in n.split()) and n != "")


def _is_spillover(row: list[str], ncols: int) -> bool:
    """A near-empty row (e.g. one filled cell out of many) is almost always a
    header/caption line that leaked into the body, not a data row."""
    nonempty = sum(1 for c in row if (c or "").strip())
    return ncols >= 4 and nonempty <= 1


def _echo_hit(row: list[str], echo_cells: set[str]) -> bool:
    """True if a body row is really a repeat of the table's header. `echo_cells`
    is the exact set of normalized header cells (from every physical header row,
    so multi-row headers are covered). Uses EXACT equality — 'Opcode inputs' is a
    real value, not the header word 'input' — and needs >=2 hits to avoid a single
    coincidental collision. Verbose data cells (SSP 'use' text) never match."""
    rcells = [_hnorm(c) for c in row if (c or "").strip()]
    if not echo_cells or not rcells:
        return False
    hits = sum(1 for c in rcells if c in echo_cells)
    return hits >= 2


def _join_rows(rows: list[list[str]], k: int, ncols: int) -> list[str]:
    out = []
    for i in range(ncols):
        parts = [rows[j][i] for j in range(k) if i < len(rows[j]) and rows[j][i]]
        out.append(" ".join(parts).strip())
    return out


def _all_header_words(cell: str) -> bool:
    ws = _hnorm(cell).split()
    return bool(ws) and all(w in _HEADER_WORDS for w in ws)


def _header_block_size(rows: list[list[str]], maxscan: int = 10) -> int:
    """How many leading rows are header. Data starts at the first row whose name
    column (col 0) holds a real value — not empty and not a header label. This
    handles headers stacked across many rows (approved-services tables put their
    column labels 5-7 rows deep)."""
    for i in range(1, min(len(rows), maxscan)):
        c0 = (rows[i][0] if rows[i] else "").strip()
        if c0 and not _all_header_words(c0):
            return i
    return 1


def _best_header(rows: list[list[str]], ncols: int):
    """Join the full leading header block (1..N rows) and return the candidate
    whose profile match scores highest, preferring the more complete header on
    ties. Handles single-row, 2-3 row stacked (SSP 'Security'/'Function and'/
    'Cert. Number'), and deep 5-7 row (approved-services) headers."""
    hb = _header_block_size(rows)
    best = None
    for k in range(1, max(2, hb + 1)):
        if k > len(rows) - 1:
            break
        hdr = rows[0] if k == 1 else _join_rows(rows, k, ncols)
        data = rows[k:]
        m = match_profile(hdr)
        score = m["score"] if m else -1
        if best is None or score > best[0] or (score == best[0] and k > best[4]):
            best = (score, m, hdr, data, k)
    if best is None:
        return match_profile(rows[0]), rows[0], rows[1:], rows[:1]
    return best[1], best[2], best[3], rows[:best[4]]  # match, header, data, header_rows


def _repair_column_drift(match: dict, data_rows: list[list[str]], ncols: int) -> None:
    """Fix pdfplumber header/data misalignment: when a header label lands one
    column away from its values (e.g. 'CAVP Cert' header in col2 but the A-number
    values in col1), a mapped field points at an empty column. If the mapped
    column is mostly empty and an unmapped neighbor is mostly filled, shift it.
    """
    if not data_rows:
        return
    nd = len(data_rows)
    fill = [0] * ncols
    for r in data_rows:
        for i in range(min(ncols, len(r))):
            if (r[i] or "").strip():
                fill[i] += 1
    rate = [f / nd for f in fill]
    mapping = match["mapping"]
    used = set(mapping.values())
    for field, idx in list(mapping.items()):
        if idx >= ncols or rate[idx] >= 0.2:
            continue  # column is adequately filled — leave it
        for j in (idx - 1, idx + 1):
            if 0 <= j < ncols and j not in used and rate[j] > 0.5:
                mapping[field] = j
                used.discard(idx)
                used.add(j)
                break


def _promote_typed_tables(tables: list[dict[str, Any]]) -> dict[str, Any]:
    """Promote recognized SSP / service / ports tables into typed, queryable
    objects using the shared table profiles, stitching multi-page continuations.

    Also returns a `tableProfiles` list: one entry per matched table with its
    profile type and which expected columns were found vs. missing — an
    extraction-confidence signal derived from the cross-document constraints.
    """
    from collections import defaultdict

    def _effective_ncols(t):
        # columnFill's denominator: real columns only. pdfplumber routinely splits
        # a cell boundary into a phantom all-empty column ("Service | | Description"
        # is a 2-col table reported as 3-4 cols); counting those in the denominator
        # made cleanly-typed 140-2 service/SSP tables score < 0.5 and read as weak.
        ncols = t.get("nCols", 0)
        rows = t.get("rows", [])
        ne = sum(1 for i in range(ncols)
                 if any((r[i] if i < len(r) else "").strip() for r in rows))
        return ne or ncols

    collections: dict[str, list[dict]] = defaultdict(list)
    for _p in (None,):  # ensure the core collections always exist even if empty
        collections["sensitiveSecurityParameters"]
        collections["services"]
        collections["portsAndInterfaces"]
    profile_hits: list[dict] = []
    cur = None  # dict(match, header, nCols, last_page)

    for t in tables:
        rows = t.get("rows", [])
        # Need ≥2 real (non-empty) columns: a 2-col Service|Description or acronym
        # table is legitimate and mandated, but a 1-col list isn't a typed table.
        if len(rows) < 2 or _effective_ncols(t) < 2:
            cur = None
            continue
        src = {"page": t["page"], "index": t["index"]}
        match, header, data_rows, header_rows = _best_header(rows, t["nCols"])
        echo = {_hnorm(c) for hr in header_rows for c in hr if (c or "").strip()}
        echo |= {_hnorm(c) for c in header if (c or "").strip()}

        # Continuation if it adjoins the current typed table and doesn't present a
        # *stronger* header of its own — then inherit the richer header so column
        # mapping stays consistent across the page break.
        adjoins = (cur and t["nCols"] == cur["nCols"] and 0 <= t["page"] - cur["page"] <= 3)
        is_continuation = adjoins and (
            match is None
            or (match["collection"] == cur["match"]["collection"]
                and match["score"] <= cur["match"]["score"]))

        if is_continuation:
            m, hdr = cur["match"], cur["header"]
            cur["page"] = t["page"]
            added = 0
            for r in rows:  # repeated headers / spillover filtered below
                if _is_spillover(r, t["nCols"]) or _echo_hit(r, cur["echo"]):
                    continue
                obj = map_row(m, hdr, r, src)
                if obj.get("name") and not _is_repeat_header(obj["name"]):
                    collections[m["collection"]].append(obj)
                    added += 1
            if profile_hits and profile_hits[-1]["type"] == m["type"]:
                profile_hits[-1]["rows"] += added
                profile_hits[-1]["continuationPages"] = \
                    profile_hits[-1].get("continuationPages", []) + [t["page"]]
        elif match:  # a new table with its own recognized header
            _repair_column_drift(match, data_rows, t["nCols"])
            cur = {"match": match, "header": header, "nCols": t["nCols"],
                   "page": t["page"], "echo": echo}
            n0 = len(collections[match["collection"]])
            for r in data_rows:
                if _is_spillover(r, t["nCols"]) or _echo_hit(r, echo):
                    continue
                obj = map_row(match, header, r, src)
                if obj.get("name") and not _is_repeat_header(obj["name"]):
                    collections[match["collection"]].append(obj)
            profile_hits.append({
                "type": match["type"], "page": t["page"], "index": t["index"],
                "matchedColumns": match["matchedColumns"],
                "missingExpected": match["missingExpected"],
                "coverage": round(match["score"] / match["expectedCount"], 2),
                "coreCoverage": match["coreCoverage"],
                "columnFill": round(len(match["mapping"]) / max(1, _effective_ncols(t)), 2),
                "rows": len(collections[match["collection"]]) - n0,
            })
        else:
            # No header matched. Try content-based recognition: an algorithm table
            # whose header the parser dropped still has a cert-label column and an
            # algorithm-name column we can detect directly. Treat all rows as data.
            cmatch = content_profile(rows)
            if cmatch:
                hdr = [""] * t["nCols"]
                cur = {"match": cmatch, "header": hdr, "nCols": t["nCols"],
                       "page": t["page"], "echo": set()}
                n0 = len(collections[cmatch["collection"]])
                for r in rows:
                    if _is_spillover(r, t["nCols"]):
                        continue
                    obj = map_row(cmatch, hdr, r, src)
                    if obj.get("name") and not _is_repeat_header(obj["name"]):
                        collections[cmatch["collection"]].append(obj)
                profile_hits.append({
                    "type": cmatch["type"], "page": t["page"], "index": t["index"],
                    "matchedColumns": cmatch["matchedColumns"], "missingExpected": [],
                    "coverage": round(cmatch["score"] / cmatch["expectedCount"], 2),
                    "coreCoverage": cmatch["coreCoverage"], "byContent": True,
                    "columnFill": round(len(cmatch["mapping"]) / max(1, _effective_ncols(t)), 2),
                    "rows": len(collections[cmatch["collection"]]) - n0,
                })
            else:
                cur = None

    result = dict(collections)
    result["tableProfiles"] = profile_hits
    return result


_FIG_RE = re.compile(r"(Figure \d+[^.]+?)\s*\.{2,}\s*(\d+)")


def extract_figures(pdf_path: str, sp_text: str, out_dir: str, cert) -> list[dict[str, Any]]:
    """Parse the List-of-Figures inventory and crop each figure image out of its
    page, so the reconstruction can show the module photographs in place."""
    inv, seen = [], set()
    for m in _FIG_RE.finditer(sp_text):
        label = re.sub(r"\s+", " ", m.group(1)).strip()
        page = int(m.group(2))
        if page not in seen:
            seen.add(page)
            inv.append((label, page))
    figures = []
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for label, pg in inv:
                if pg > len(pdf.pages):
                    continue
                page = pdf.pages[pg - 1]
                imgs = page.images or []
                if not imgs:
                    continue
                big = max(imgs, key=lambda im: (im["x1"] - im["x0"]) * (im["bottom"] - im["top"]))
                w, h = big["x1"] - big["x0"], big["bottom"] - big["top"]
                if w * h < 5000:  # skip the small repeated logo header
                    continue
                try:
                    box = (max(0, big["x0"]), max(0, big["top"]),
                           min(page.width, big["x1"]), min(page.height, big["bottom"]))
                    fn = f"{cert}.fig-p{pg}.png"
                    page.crop(box).to_image(resolution=120).save(os.path.join(out_dir, fn))
                    figures.append({"label": label, "page": pg, "imageFile": fn,
                                    "width": round(w), "height": round(h)})
                except Exception:
                    continue
    except Exception:
        pass
    return figures


def parse_security_policy(pdf_path: str, extract_tables: bool = True) -> dict[str, Any]:
    warnings: list[str] = []
    text = _pdftotext_layout(pdf_path)
    page_count = None
    tables: list[dict[str, Any]] = []
    pdf_meta: dict[str, Any] = {}
    try:
        with pdfplumber.open(pdf_path) as pdf:
            page_count = len(pdf.pages)
            for k, v in (pdf.metadata or {}).items():
                if k in ("Title", "Author", "Subject", "Creator", "Producer",
                         "CreationDate", "ModDate") and v:
                    pdf_meta[k] = _fmt_pdfdate(str(v)) if k.endswith("Date") else str(v)
            if not text:  # fallback if pdftotext unavailable
                text = "\n".join((p.extract_text() or "") for p in pdf.pages)
            if extract_tables:
                tables = _extract_tables(pdf)
    except Exception as e:
        warnings.append(f"pdfplumber failed: {e}")

    if not text:
        return {"securityPolicy": None, "warnings": ["could not extract any text from SP PDF"]}

    lines = text.splitlines()
    toc = _extract_toc(text)
    low = text.lower()

    n_cells = sum(t["nRows"] * t["nCols"] for t in tables)
    promoted = _promote_typed_tables(tables)
    typed_collections = {k: v for k, v in promoted.items() if k != "tableProfiles"}
    sp = {
        "title": _extract_title(lines),
        "standard": detect_standard(text),
        "pageCount": page_count,
        "pdfMetadata": pdf_meta,
        "revisionHistory": _extract_revision_history(text),
        "sections": toc,
        "securityLevels": _extract_security_levels(text),
        "urls": _extract_urls(text),
        # Typed collections promoted from profiled tables (core + mined profiles).
        **typed_collections,
        "tableProfiles": promoted["tableProfiles"],
        "tables": tables,
        "rawText": {
            "chars": len(text),
            "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
            "sidecarFile": None,  # set by extract.py when the archival copy is written
        },
        "textFingerprint": {
            "charCount": len(text),
            "tableCount": len(tables),
            "tableCells": n_cells,
            "hasSelfTestSection": bool(re.search(r"\bself[- ]tests?\b", low)),
            "mentionsEntropy": ("entropy" in low) or bool(re.search(r"\bent\s*\(", low)),
            "mentionsFirmwareIntegrity": "firmware integrity" in low,
        },
        "_text": text,  # retained transiently for linter/sidecar; stripped before serialize
    }
    if not toc:
        warnings.append("no TOC parsed from Security Policy")
    return {"securityPolicy": sp, "warnings": warnings}
