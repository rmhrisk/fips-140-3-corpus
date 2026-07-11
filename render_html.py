#!/usr/bin/env python3
"""Reconstruct a readable, PAGE-ANCHORED HTML document from a normalized record.

Visual round-trip QA: rebuild the document from the structured JSON and open it
beside the original PDF. Two design choices make the comparison actually work:

  * Page anchoring — every table and typed row already carries its real pdfplumber
    source page. The body is rendered in source-page order under "Page N" anchors
    (with a jump nav), so reconstruction "Page 69" lines up with PDF page 69. We do
    NOT fake pagination; we group by recorded provenance.

  * No empty columns — typed rows are grouped back into the physical table they
    came from, and each table shows only the columns that table actually has. This
    avoids the sparse-superset problem (e.g. the service-command table and the
    approved-services table have different columns and shouldn't share a grid).

Usage:
    python render_html.py records/4703.json                 # -> records/4703.html
    python render_html.py records/4703.json --pdf sp.pdf    # + fidelity banner
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys

from profiles import _PROFILE_BY_TYPE
from specs import SPECS, linkify_refs, name_link
from review_graph import extract_clues, to_mermaid_cluetier, to_mermaid_lanes

try:
    import markdown as _MD
except Exception:
    _MD = None

_BOILER = re.compile(r"(?i)(non-?proprietary security policy|^\s*\d{1,3}\s*$|"
                     r"copyright|all rights reserved|page \d+ of \d+)")


_HEAD_RE = re.compile(r"^\s*\d+(\.\d+)*\s+\S")


def _reflow(lines: list[str]) -> list[str]:
    """Turn hard-wrapped layout lines into flowing paragraphs: split on section
    headings, join wrapped lines (de-hyphenating line-end breaks)."""
    paras, cur = [], []
    def flush():
        if not cur:
            return
        out = ""
        for p in cur:
            p = p.strip()
            if out.endswith("-"):
                out = out[:-1] + p
            elif out:
                out += " " + p
            else:
                out = p
        paras.append(out.strip())
        cur.clear()
    for l in lines:
        if _HEAD_RE.match(l):
            flush()
            paras.append(l.strip())
        else:
            cur.append(l)
    flush()
    return [p for p in paras if p]


def _toks(s: str) -> set:
    return {w for w in re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).split() if len(w) >= 2}


_FRONTMATTER = {"table of contents": "toc", "list of tables": "lot", "list of figures": "lof"}
# Bullet markers: glyphs (• ● ▪ ■ ‣ ◦ ∙), a standalone "o" sub-bullet, and a
# spaced en/em dash — all common in these PDFs' flattened lists.
_BULLET_RE = re.compile(r"(?:\s*[•●▪■‣◦∙]\s*|\s+o\s+(?=[A-Z0-9*(])|\s+[–—]\s+)")


def _page_lines(page_texts, pg: int) -> list[str]:
    if not page_texts or pg < 1 or pg > len(page_texts):
        return []
    return [l for l in page_texts[pg - 1].splitlines() if l.strip() and not _BOILER.search(l)]


def _frontmatter_kind(lines: list[str]):
    return _FRONTMATTER.get(lines[0].strip().lower()) if lines else None


def _leader_entries(lines: list[str]) -> list[tuple]:
    """Parse 'Label ...... 12' dotted-leader lines (TOC / list-of-tables/figures)."""
    out = []
    for l in lines:
        m = re.match(r"^\s*(.+?)\s*\.{2,}\s*(\d+)\s*$", l)
        if m:
            out.append((re.sub(r"\s+", " ", m.group(1)).strip(), int(m.group(2))))
    return out


_NUM_RE = re.compile(r"\s(\d{1,2})[.)]\s+(?=[A-Z(])")  # " 3. This…" / " 4) After…"


def _bulletize(text: str) -> str:
    """Structure a paragraph into a real list (numbered <ol> or bulleted <ul>);
    plain text stays a <p>. Deterministic markdown-style structuring so prose
    reads cleanly instead of as a wall of text."""
    # numbered list ("1. …  2. …") — keep the source's starting number
    nparts = _NUM_RE.split(" " + text)
    if len(nparts) >= 5:  # lead + >=2 numbered items
        lead = nparts[0].strip()
        pairs = list(zip(nparts[1::2], nparts[2::2]))
        html = f"<p class='prose'>{esc(lead)}</p>" if lead else ""
        html += (f"<ol class='prose' start='{esc(pairs[0][0])}'>"
                 + "".join(f"<li>{esc(it.strip())}</li>" for _, it in pairs) + "</ol>")
        return html
    # bulleted list (glyphs / "o" sub-bullets / dashes)
    segs = [s.strip() for s in _BULLET_RE.split(" " + text)]
    lead, items = segs[0], [s for s in segs[1:] if s]
    html = f"<p class='prose'>{esc(lead)}</p>" if lead else ""
    if items:
        html += "<ul class='prose'>" + "".join(f"<li>{esc(it)}</li>" for it in items) + "</ul>"
    return html


_SECNUM_RE = re.compile(r"^\s*(\d+(?:\.\d+)*)\s+\S")
_GAP_RE = re.compile(r" {2,}")   # column-gap runs left by pdftotext in flattened tables


def _render_prose(paras: list[str]) -> str:
    out = []
    for p in paras:
        ps = p.strip()
        # Drop stray extraction fragments (a lone number or one/two symbols on a line).
        if len(ps) <= 3 and re.fullmatch(r"[\d\W]{1,3}", ps):
            continue
        # A table or TOC that pdfplumber did not capture as structure falls into the
        # verbatim prose with its COLUMN-GAP spacing (runs of 2+ spaces) intact. Real
        # narrative prose is single-spaced, so a high density of gaps marks a flattened
        # table. Present those as a collapsed, monospace "extracted as text" block that
        # keeps the column alignment, instead of letting them masquerade as prose.
        _gaps = len(_GAP_RE.findall(p))
        if _gaps >= 6 and _gaps / max(1, len(p.split())) >= 0.10:
            out.append("<details class='rawtbl'><summary>Table, extracted as text "
                       "(did not parse into structured rows)</summary>"
                       f"<pre class='rawtxt'>{esc(p)}</pre></details>")
            continue
        m = _SECNUM_RE.match(p)
        # A real section heading is short AND, unlike a flattened security-level table
        # row or an acronym-glossary line, does not end in a level value ("... 1",
        # "... N/A") and has no spaced dash ("ACRONYM - Definition"). pdftotext
        # flattens those tables into numbered text that otherwise mimics headings.
        if (m and len(p) <= 70
                and not re.search(r"\s(?:n/?a|\d{1,3})$", p, re.I)
                and not re.search(r"\s[–—-]\s", p)):
            depth = min(m.group(1).count(".") + 1, 4)
            out.append(f"<div class='sec sec{depth}'>{esc(p)}</div>")
        else:
            out.append(_bulletize(p))
    return "".join(out)


def _page_prose(page_texts, pg: int, table_tokens=frozenset()) -> list[str]:
    """Narrative prose paragraphs for a physical page (1-based), with content we
    already show elsewhere removed at the LINE level (not the page level, since a
    page can have both prose and tables): TOC/list-of-tables lines (dotted
    leaders) and lines whose text is already in a table on this page are dropped."""
    if not page_texts or pg < 1 or pg > len(page_texts):
        return []
    narrative = []
    for l in page_texts[pg - 1].splitlines():
        if not l.strip() or _BOILER.search(l) or re.search(r"\.{4,}", l):
            continue  # boilerplate or a TOC/LoT/LoF entry
        tk = _toks(l)
        if tk and table_tokens and len(tk & table_tokens) / len(tk) >= 0.6:
            continue  # this line's content is already shown in a table on this page
        narrative.append(l)
    paras = _reflow(narrative)
    # keep only substantive paragraphs: a section heading, or real prose (>=4 words).
    # This drops stray table-cell fragments that leak onto table pages ("E",
    # "R W W E", "2.4.A", "C.A") which tokenize to nothing and evade the dedup.
    return [p for p in paras
            if _SECNUM_RE.match(p) or len(re.findall(r"[A-Za-z]{2,}", p)) >= 4]


def esc(x) -> str:
    return html.escape("" if x is None else str(x))


def cavp_url(validation_id):
    """CAVP algorithm-validation detail page for a numeric ACVP validation id."""
    if validation_id in (None, ""):
        return None
    return ("https://csrc.nist.gov/projects/Cryptographic-Algorithm-Validation-Program"
            f"/details?validation={validation_id}")


# ---- deterministic cross-linking (no model): restated ACVP cert labels and
# "section N.N" cross-references are linked using maps built from the record. ----
_ACVP_URLS: dict = {}
_ACVP_RE = None
_SEC_PAGES: dict = {}
_SEC_RE = re.compile(r"\b(section|clause|§)(\s*)(\d+(?:\.\d+)*)", re.IGNORECASE)


def _setup_crosslinks(record):
    """Build per-record maps: ACVP label -> CAVP url (only labels that resolve to
    a numeric validation id, so part numbers like 'A300' are never linked) and
    section number -> page anchor."""
    global _ACVP_URLS, _ACVP_RE, _SEC_PAGES
    labels = {}
    for a in record.get("certificate", {}).get("approvedAlgorithms", []):
        vid = a.get("acvpValidationId")
        if not vid:
            continue
        for lbl in re.findall(r"[AC]\d{3,5}", a.get("acvpCert") or ""):
            labels.setdefault(lbl, vid)
    _ACVP_URLS = {l: cavp_url(v) for l, v in labels.items()}
    _ACVP_RE = (re.compile(r"(?<![A-Za-z0-9])(#?)("
                + "|".join(sorted(map(re.escape, labels), key=len, reverse=True))
                + r")(?![0-9A-Za-z])") if labels else None)
    _SEC_PAGES = {}
    for s in (record.get("securityPolicy") or {}).get("sections", []):
        num = (s.get("number") or "").strip().rstrip(".")
        if num and s.get("page"):
            _SEC_PAGES.setdefault(num, s["page"])


def _link_acvp(text):
    if not _ACVP_RE:
        return text
    return _ACVP_RE.sub(
        lambda m: (f"{m.group(1)}<a href='{_ACVP_URLS[m.group(2)]}'>{m.group(2)}</a>"
                   if _ACVP_URLS.get(m.group(2)) else m.group(0)), text)


def _link_sections(text):
    if not _SEC_PAGES:
        return text
    return _SEC_RE.sub(
        lambda m: (f"{m.group(1)}{m.group(2)}<a href='#p{_SEC_PAGES[m.group(3)]}'>{m.group(3)}</a>"
                   if _SEC_PAGES.get(m.group(3)) else m.group(0)), text)


def linkify_all(escaped_text):
    """All deterministic cross-links over already-escaped text: section refs ->
    page anchors, ACVP labels -> CAVP, FIPS/SP references -> NIST."""
    return linkify_refs(_link_acvp(_link_sections(escaped_text)))


def _linkify_html(html_str):
    """Apply linkify_all only to text between tags, so we never inject links
    inside an existing tag or href (used for already-rendered prose HTML)."""
    parts, i = [], 0
    for m in re.finditer(r"<[^>]+>", html_str):
        parts.append(linkify_all(html_str[i:m.start()]))
        parts.append(m.group())
        i = m.end()
    parts.append(linkify_all(html_str[i:]))
    return "".join(parts)


def kv_card(title, pairs):
    rows = "".join(
        f"<tr><th class='k'>{esc(k)}</th><td class='v'>{esc(v)}</td></tr>"
        for k, v in pairs if v not in (None, "", [], {}))
    return f"<section class='card'><h2>{esc(title)}</h2><table class='kv'>{rows}</table></section>"


def html_table(headers, rows, cls=""):
    thead = ("<thead><tr>" + "".join(f"<th>{esc(h)}</th>" for h in headers) + "</tr></thead>") if headers else ""
    body = "".join("<tr>" + "".join(f"<td>{linkify_all(esc(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table class='{cls}'>{thead}<tbody>{body}</tbody></table>"



# Acronyms to keep upper-cased when a normalized field key is turned into a label.
_COL_ACRONYMS = {"iso", "cavp", "acvp", "kdf", "drbg", "aes", "rsa", "hmac", "sha", "tls",
                 "ssp", "csp", "id", "oe", "sp", "fips", "api", "os", "cvl", "ecdsa", "dsa",
                 "kts", "kat", "cast", "sed", "tcg", "lba", "cm", "hw", "usb", "pci"}


def _label_words(k, keep_lower=False):
    """Split a camelCase / snake_case field key into readable words."""
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", k or "").replace("_", " ").split()
    out = [w.upper() if w.lower() in _COL_ACRONYMS else (w.lower() if keep_lower else w) for w in words]
    s = " ".join(out)
    return s[:1].upper() + s[1:] if s else ""


def _col_label(k):
    """Human-readable column header from a normalized key (blank for positional placeholders)."""
    if re.fullmatch(r"col\d+", k or "", re.I):
        return ""
    return _label_words(k)


# A cell that is only brackets / parens / punctuation is PDF-extraction residue
# (e.g. "[ [", "( (", a lone "]"), never real content, so it is treated as empty.
_NOISE_CELL = re.compile(r"^[\s\[\]\(\)\{\}·•.,;:/\\|_\-–—]*$")


def _clean_cell(v: str) -> str:
    v = (v or "").strip()
    return "" if _NOISE_CELL.match(v) else v


def _type_label(t):
    """Human-readable label for a table type, e.g. approvedAlgorithm -> 'Approved algorithm'."""
    words = [w for w in re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", t or "").replace("_", " ").split()
             if w.lower() != "table"]
    return _label_words(" ".join(words), keep_lower=True)


def _objects_table(rows, ordered_cols):
    extra_keys = []
    for r in rows:
        for k in (r.get("extraColumns") or {}):
            if k not in extra_keys:
                extra_keys.append(k)
    val = lambda r, c: _clean_cell(r.get(c, ""))
    xval = lambda r, k: _clean_cell((r.get("extraColumns") or {}).get(k, ""))
    # keep only columns that carry at least one real (non-noise) value
    cols = [c for c in ordered_cols if any(val(r, c) for r in rows)]
    xcols = [k for k in extra_keys if any(xval(r, k) for r in rows)]
    headers = [_col_label(c) for c in cols] + [_col_label(k) for k in xcols]
    trows = [[val(r, c) for c in cols] + [xval(r, k) for k in xcols] for r in rows]
    return headers, trows


def _canonical_order(ptype):
    prof = _PROFILE_BY_TYPE.get(ptype, {})
    return ["name"] + [c for c in prof.get("expectedColumns", {}) if c != "name"]


def render(record: dict, page_texts=None) -> str:
    _setup_crosslinks(record)
    cert = record.get("certificate", {})
    sp = record.get("securityPolicy") or {}
    certno = record.get("certNumber")
    page_texts = page_texts or []
    parts: list[str] = []

    # ---------- top matter (not page-anchored) ----------
    src = record.get("source", {})
    sp_url, cert_url = src.get("securityPolicyUrl"), src.get("certificateUrl")
    cc_url = src.get("consolidatedCertificateUrl")
    sp_sha = src.get("securityPolicyPdfSha256") or ""
    meta = sp.get("pdfMetadata", {})
    link = lambda u, t: f"<a href='{esc(u)}'>{esc(t)}</a>" if u else esc(t)

    # ---- formatted document header (masthead) ----
    meta_fields = [
        ("Certificate", f"#{certno}"), ("Standard", cert.get("standard")),
        ("Level", cert.get("overallLevel")), ("Type", cert.get("moduleType")),
        ("Embodiment", cert.get("embodiment")), ("Status", cert.get("status")),
        ("Vendor", (cert.get("vendor") or {}).get("name")),
    ]
    chips = "".join(f"<span class='chip'><span class='k'>{esc(k)}</span>"
                    f"<span class='v'>{esc(v)}</span></span>"
                    for k, v in meta_fields if v not in (None, ""))
    srcs = [("Certificate page", cert_url), ("Security Policy PDF", sp_url),
            ("Signed certificate", cc_url)]
    src_line = " ".join(f"{link(u, t)}" for t, u in srcs if u)
    parts.append(f"""
    <header class='masthead'>
      <div class='eyebrow'>CMVP Validated Module · FIPS 140-3 Security Policy</div>
      <h1>{esc(cert.get('moduleName'))}</h1>
      <div class='chips'>{chips}</div>
      <div class='src'><span class='lbl'>Sources</span> {src_line}</div>
    </header>""")
    parts.append(kv_card("Certificate", [
        ("Standard", cert.get("standard")), ("Overall level", cert.get("overallLevel")),
        ("Module type", cert.get("moduleType")), ("Embodiment", cert.get("embodiment")),
        ("Status", cert.get("status")), ("Sunset date", cert.get("sunsetDate")),
        ("Entropy", cert.get("entropy")), ("Caveat", cert.get("caveat")),
        ("Vendor", (cert.get("vendor") or {}).get("name")),
        ("Hardware versions", ", ".join(cert.get("hardwareVersions", []))),
    ]))
    vend = cert.get("vendor") or {}
    if vend.get("productUrl") or vend.get("supportUrl"):
        status = vend.get("supportStatus", "")
        badge = (f"<span class='badge badge-{esc(status)}'>{esc(status)} support</span>"
                 if status else "")
        rows = []
        if vend.get("productUrl"):
            rows.append(f"<tr><th class='k'>Product page</th><td class='v'>"
                        f"{link(vend['productUrl'], vend['productUrl'])}</td></tr>")
        if vend.get("supportUrl"):
            rows.append(f"<tr><th class='k'>Support page</th><td class='v'>"
                        f"{link(vend['supportUrl'], vend['supportUrl'])} {badge}</td></tr>")
        for i, d in enumerate(vend.get("docLinks", []) or []):
            lbl = "Documentation" if i == 0 else ""
            rows.append(f"<tr><th class='k'>{lbl}</th><td class='v'>{link(d, d)}</td></tr>")
        if vend.get("supportNote"):
            rows.append(f"<tr><th class='k'>Assessment</th>"
                        f"<td class='v muted'>{esc(vend['supportNote'])}</td></tr>")
        parts.append("<section class='card'><h2>Vendor resources "
                     "<span class='muted'>(verify with the vendor)</span></h2>"
                     f"<table class='kv'>{''.join(rows)}</table></section>")
    algos = cert.get("approvedAlgorithms", [])
    if algos:
        arows = []
        for a in algos:
            name = a.get("name") or ""
            name_esc = esc(name)
            name_html = linkify_refs(name_esc)  # link any embedded FIPS/SP reference
            if name_html == name_esc:           # else link the whole name to its family spec
                sid, surl = name_link(name)
                if surl:
                    name_html = (f"<a href='{surl}' "
                                 f"title='{esc(SPECS.get(sid, {}).get('title', ''))}'>{name_esc}</a>")
            certlbl = a.get("acvpCert") or ""
            url = cavp_url(a.get("acvpValidationId"))
            cell = link(url, certlbl) if (url and certlbl) else esc(certlbl)
            arows.append(f"<tr><td>{name_html}</td><td>{cell}</td></tr>")
        atable = ("<table class='scroll'><thead><tr><th>Algorithm</th><th>ACVP Cert</th>"
                  "</tr></thead><tbody>" + "".join(arows) + "</tbody></table>")
        parts.append(f"<section class='card'><h2>Approved Algorithms "
                     f"<span class='muted'>({len(algos)})</span></h2>"
                     + atable + "</section>")
    if sp.get("securityLevels"):
        parts.append("<section class='card'><h2>Security Levels (Table 1)</h2>"
                     + html_table(["Requirement area", "Level"],
                                  [(l.get("area"), l.get("level")) for l in sp["securityLevels"]]) + "</section>")

    # ---------- Review-Risk Graph (Mermaid) ----------
    # The reviewer surface is ALWAYS the full 4-tier graph (Clue→Inference→Risk→
    # Evidence), framed as review prompts, not findings:
    #   - a stored `reviewGraph` (model-refined, via `review_graph.py --graph`) wins;
    #   - otherwise a deterministic 4-tier baseline is generated here;
    #   - the raw clue tier is demoted to a collapsed debug block (never the surface);
    #   - with no clues at all, the section is omitted.
    module = cert.get("moduleName") or "module"
    stored = (sp.get("reviewGraph") or "").strip()
    clues = []
    if not stored:
        try:
            clues = extract_clues(record, "\f".join(page_texts or []))
        except Exception:
            clues = []
    graph = stored or (to_mermaid_lanes(module, clues) if clues else "")
    if graph:
        section = (f"<section class='card'><h2>Derived Review-Risk Graph "
                   f"<span class='muted'>(review prompts, not findings)</span></h2>"
                   f"<pre class='mermaid'>{esc(graph)}</pre>")
        if clues:  # keep the clue evidence available, collapsed; plain text (not a
            # second rendered diagram — Mermaid renders at zero width inside <details>)
            section += ("<details class='muted'><summary>Underlying clues</summary>"
                        f"<pre>{esc(to_mermaid_cluetier(module, clues))}</pre></details>")
        parts.append(section + "</section>")
    # (The Table of Contents renders in place at its own page in the body below.)

    def contents_table():
        rows = "".join(
            f"<tr><td>{esc(s.get('number'))}</td><td>{esc(s.get('title'))}</td>"
            f"<td class='pg'>" + (f"<a href='#p{s['page']}'>{s['page']}</a>" if s.get("page") else "")
            + "</td></tr>" for s in sp.get("sections", []))
        return ("<div class='cap muted'>Table of Contents</div>"
                "<table class='toc'><thead><tr><th>#</th><th>Section</th><th>Page</th></tr>"
                f"</thead><tbody>{rows}</tbody></table>")

    def leader_table(title, entries):
        rows = "".join(f"<tr><td>{esc(lbl)}</td><td class='pg'>"
                       f"<a href='#p{pg}'>{pg}</a></td></tr>" for lbl, pg in entries)
        return (f"<div class='cap muted'>{esc(title)}</div>"
                f"<table class='toc'><thead><tr><th>Item</th><th>Page</th></tr>"
                f"</thead><tbody>{rows}</tbody></table>")

    # ---------- assemble page-anchored blocks ----------
    # map each profiled table (one tableProfiles entry) to its rows, by source page
    type2coll = {t: p["collection"] for t, p in _PROFILE_BY_TYPE.items()}
    prof_locs = {}     # (page,index) -> profile hit  (the header table)
    cont_pages = {}    # continuation page -> owning hit
    for p in sp.get("tableProfiles", []):
        prof_locs[(p["page"], p["index"])] = p
        for cp in p.get("continuationPages", []):
            cont_pages[cp] = p

    blocks = []  # (start_page, kind, payload)
    for p in sp.get("tableProfiles", []):
        pages = {p["page"]} | set(p.get("continuationPages", []))
        coll = type2coll.get(p["type"], "")
        rows = [o for o in sp.get(coll, []) if o.get("source", {}).get("page") in pages]
        if rows:
            blocks.append((p["page"], "typed", p, rows))
    # raw (unprofiled) tables — render verbatim so nothing is hidden
    for t in sp.get("tables", []):
        loc = (t["page"], t["index"])
        if loc in prof_locs or t["page"] in cont_pages:
            continue
        blocks.append((t["page"], "raw", t, None))
    from collections import defaultdict
    by_page = defaultdict(list)
    for b in blocks:
        by_page[b[0]].append(b)

    # text of the tables on each page, so duplicated lines can be stripped from prose
    page_tbl_tokens = defaultdict(set)
    for t in sp.get("tables", []):
        for r in t["rows"]:
            for c in r:
                page_tbl_tokens[t["page"]] |= _toks(c)

    # front-matter pages (TOC / list of tables / figures) rendered in place
    pagecount = sp.get("pageCount") or len(page_texts)
    frontmatter = {}
    for pg in range(1, (pagecount or 0) + 1):
        lines = _page_lines(page_texts, pg)
        kind = _frontmatter_kind(lines)
        if kind == "toc":
            frontmatter[pg] = contents_table()
        elif kind in ("lot", "lof"):
            entries = _leader_entries(lines[1:])
            if entries:
                frontmatter[pg] = leader_table(lines[0].strip(), entries)

    # narrative prose per page, with table/TOC content removed (see _page_prose)
    narrative = {}
    for pg in range(1, (pagecount or 0) + 1):
        if pg in frontmatter:
            continue
        paras = _page_prose(page_texts, pg, page_tbl_tokens.get(pg, frozenset()))
        if paras:
            narrative[pg] = paras

    # A page gets a marker if it starts a table OR has narrative prose. Pure table
    # continuation pages get no marker (their content is in the table above) but do
    # get an invisible anchor so Contents links into them still resolve.
    fig_by_page = defaultdict(list)
    for fig in sp.get("figures", []):
        fig_by_page[fig["page"]].append(fig)

    all_pages = sorted(set(by_page) | set(narrative) | set(frontmatter) | set(fig_by_page))
    anchored = set(all_pages)
    cont_anchor = defaultdict(list)
    for p in sp.get("tableProfiles", []):
        for cp in p.get("continuationPages", []):
            if cp not in anchored:
                cont_anchor[p["page"]].append(cp)
                anchored.add(cp)

    body = ["<h2 class='sectionhdr'>Security Policy, page by page</h2>"]
    for pg in all_pages:
        extra = "".join(f"<span id='p{cp}'></span>" for cp in cont_anchor.get(pg, []))
        body.append(f"<div class='pagemark' id='p{pg}'>Page {pg}"
                    f" <a class='top' href='#'>↑</a></div>{extra}")
        if pg in frontmatter:
            body.append(f"<div class='tbl'>{frontmatter[pg]}</div>")
            continue
        for start, kind, payload, rows in sorted(by_page.get(pg, []), key=lambda b: b[1] != "typed"):
            if kind == "typed":
                p = payload
                label = _type_label(p["type"])
                cap = f"<div class='tblcap'>{esc(label)}</div>" if label else ""
                headers, trows = _objects_table(rows, _canonical_order(p["type"]))
                body.append(f"<div class='tbl'>{cap}"
                            + html_table(headers, trows, cls="typed") + "</div>")
            else:  # raw table — treat its first row as the (bold) header
                t = payload
                headers = t["rows"][0] if t["rows"] else None
                trows = t["rows"][1:] if t["rows"] else []
                body.append(f"<div class='tbl'>"
                            + html_table(headers, trows, cls="raw") + "</div>")
        ai_md = (sp.get("proseMarkdown") or {}).get(str(pg))
        if ai_md and _MD:  # AI-structured markdown for this page (preferred)
            body.append("<div class='aimd'>"
                        + _linkify_html(_MD.markdown(ai_md, extensions=["tables", "sane_lists"])) + "</div>")
        else:
            prose = _render_prose(narrative.get(pg, []))
            if prose:
                body.append(_linkify_html(prose))
        for fig in fig_by_page.get(pg, []):
            src_attr = fig.get("_dataUri") or esc(fig.get("imageFile", ""))
            body.append(f"<figure class='fig'><img src='{src_attr}' alt='{esc(fig.get('label'))}'>"
                        f"<figcaption>{esc(fig.get('label'))}</figcaption></figure>")
    # anchors for any Contents target pages still unaccounted for (keep links live)
    for s in sp.get("sections", []):
        if s.get("page") and s["page"] not in anchored:
            body.append(f"<span id='p{s['page']}'></span>")
            anchored.add(s["page"])
    parts.append("<section class='card'>" + "".join(body) + "</section>")

    if sp.get("urls"):
        links = "".join(f"<li><a href='{esc(u['url'])}'>{esc(u['url'])}</a></li>" for u in sp["urls"])
        parts.append(f"<section class='card'><h2>Referenced URLs</h2><ul>{links}</ul></section>")

    return DOCUMENT.format(title=esc(cert.get("moduleName") or f"Cert {certno}"), body="".join(parts))


DOCUMENT = """<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>{title} (reconstructed)</title>
<style>
  :root {{
    --navy:#1e3a5f; --accent:#2f6fb0; --ink:#24313d; --muted:#71808f;
    --line:#e4e9f0; --line-soft:#eef1f6; --bg:#f4f6f9; --card:#ffffff;
    --pill:#eef3f9; --radius:12px;
    --fs-1:1.6rem; --fs-2:1.12rem; --fs-3:.98rem; --fs-body:.9rem; --fs-sm:.8rem; --fs-xs:.72rem;
    --sp:1rem;
  }}
  * {{ box-sizing:border-box; }}
  html {{ -webkit-text-size-adjust:100%; scroll-behavior:smooth; }}
  body {{ font:var(--fs-body)/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
          color:var(--ink); margin:0 auto; padding:1.6rem 1.4rem 5rem; max-width:940px; background:var(--bg); }}
  h1 {{ font-size:var(--fs-1); font-weight:700; margin:.2rem 0 1.2rem; color:var(--navy); line-height:1.2;
        letter-spacing:-.01em; }}
  h2 {{ font-size:var(--fs-2); font-weight:650; color:var(--navy); margin:0 0 .7rem;
        padding-bottom:.4rem; border-bottom:1px solid var(--line); letter-spacing:-.005em; }}
  a {{ color:var(--accent); text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .muted {{ color:var(--muted); font-size:.9em; }}

  .masthead {{ background:var(--card); border:1px solid var(--line); border-top:4px solid var(--navy);
               border-radius:var(--radius); padding:1.1rem 1.2rem 1rem; margin-bottom:1.4rem;
               box-shadow:0 1px 3px rgba(30,58,95,.05); }}
  .masthead .eyebrow {{ font-size:var(--fs-xs); text-transform:uppercase; letter-spacing:.06em;
                        color:var(--muted); font-weight:600; }}
  .masthead h1 {{ margin:.25rem 0 .7rem; }}
  .chips {{ margin-bottom:.7rem; }}
  .chip {{ display:inline-block; background:var(--pill); border:1px solid var(--line);
           border-radius:999px; padding:.15rem .65rem; margin:0 .3rem .35rem 0; font-size:var(--fs-sm);
           white-space:nowrap; }}
  .chip .k {{ color:var(--muted); text-transform:uppercase; letter-spacing:.03em; font-size:.82em; }}
  .chip .k::after {{ content:'\\00a0'; }}
  .chip .v {{ color:var(--ink); font-weight:600; }}
  .badge {{ display:inline-block; border-radius:999px; padding:.05rem .5rem; margin-left:.4rem;
            font-size:.78em; font-weight:600; border:1px solid var(--line); white-space:nowrap; }}
  .badge-open {{ background:#e6f4ea; color:#1e7d34; border-color:#bfe3c9; }}
  .badge-partial {{ background:#fdf3e0; color:#96610a; border-color:#f0dcb4; }}
  .badge-closed {{ background:#fbe9e9; color:#b02a2a; border-color:#f2c9c9; }}
  .masthead .src {{ font-size:var(--fs-sm); margin-bottom:.25rem; }}
  .masthead .src .lbl, .masthead .prov {{ color:var(--muted); }}
  .masthead .src .lbl {{ text-transform:uppercase; letter-spacing:.03em; font-size:.82em; font-weight:600;
                         margin-right:.3rem; }}
  .masthead .src a {{ margin-right:.5rem; }}
  .masthead .prov {{ font-size:var(--fs-xs); }}
  .masthead code {{ background:var(--pill); padding:.05rem .3rem; border-radius:4px; }}

  .card {{ background:var(--card); border:1px solid var(--line); border-radius:var(--radius);
           padding:1.1rem 1.2rem; margin:0 0 1.2rem; box-shadow:0 1px 3px rgba(30,58,95,.05); }}

  /* ---- unified table style ---- */
  .tbl {{ margin:.5rem 0 1.1rem; overflow-x:auto; -webkit-overflow-scrolling:touch;
          border:1px solid var(--line); border-radius:8px; }}
  table {{ border-collapse:collapse; width:100%; font-size:var(--fs-sm); }}
  th, td {{ padding:7px 10px; text-align:left; vertical-align:top; border-bottom:1px solid var(--line-soft); }}
  thead th {{ background:#f1f5fa; color:var(--navy); font-weight:600; font-size:var(--fs-xs);
              text-transform:uppercase; letter-spacing:.03em; white-space:nowrap;
              border-bottom:1px solid var(--line); position:sticky; top:0; }}
  tbody tr:nth-child(even) td {{ background:#fafbfd; }}
  tbody tr:last-child td {{ border-bottom:none; }}
  .typed td:first-child {{ font-weight:600; color:var(--navy); }}
  .scroll {{ display:block; max-height:400px; overflow:auto; }}
  .rawtbl {{ margin:.4rem 0 .8rem; }}
  .rawtbl > summary {{ cursor:pointer; font-size:var(--fs-xs); color:var(--muted); list-style:revert; }}
  .rawtbl > summary:hover {{ color:var(--navy); }}
  .rawtbl pre.rawtxt {{ white-space:pre-wrap; word-break:break-word; margin:.35rem 0 0; padding:10px 12px;
     font:11.5px/1.55 ui-monospace,'SF Mono',Menlo,Consolas,monospace; color:var(--ink);
     background:var(--pill); border:1px solid var(--line); border-radius:8px; overflow-x:auto; }}

  /* key/value card (certificate) */
  table.kv {{ font-size:var(--fs-body); }}
  table.kv, table.kv thead th {{ border:none; }}
  table.kv th.k {{ width:180px; color:var(--muted); font-weight:500; background:none;
                   border-bottom:1px solid var(--line-soft); padding:7px 14px 7px 0; white-space:normal;
                   text-transform:none; letter-spacing:0; position:static; }}
  table.kv td.v {{ border-bottom:1px solid var(--line-soft); padding:7px 0; }}
  table.toc td:last-child, td.pg {{ text-align:right; white-space:nowrap; }}
  table.raw {{ font-size:var(--fs-xs); }}

  /* ---- page dividers (light, not heavy dark bars) ---- */
  .sectionhdr {{ margin-top:1.6rem; color:var(--muted); font-size:var(--fs-sm); font-weight:600;
                 text-transform:uppercase; letter-spacing:.05em; border:none; }}
  .pagemark {{ position:sticky; top:0; z-index:3; margin:1.7rem 0 .7rem; padding:.35rem .1rem;
               background:var(--bg); border-bottom:2px solid var(--accent);
               font-size:var(--fs-xs); font-weight:700; color:var(--navy);
               text-transform:uppercase; letter-spacing:.06em; }}
  .pagemark .top {{ float:right; color:var(--muted); font-weight:400; }}

  /* ---- prose (markdown-style) ---- */
  p.prose, ul.prose, ol.prose {{ font-size:var(--fs-body); color:var(--ink); margin:.4rem 0; line-height:1.6; }}
  ul.prose, ol.prose {{ padding-left:1.4rem; }}
  ul.prose li, ol.prose li {{ margin:.18rem 0; }}
  .sec {{ font-weight:700; color:var(--navy); line-height:1.3; margin:1.1rem 0 .4rem; }}
  .sec1 {{ font-size:var(--fs-2); border-bottom:1px solid var(--line); padding-bottom:.2rem; }}
  .sec2 {{ font-size:var(--fs-3); }}
  .sec3 {{ font-size:var(--fs-body); color:var(--accent); }}
  .sec4 {{ font-size:var(--fs-sm); color:var(--accent); }}

  /* ---- figures ---- */
  figure.fig {{ margin:.8rem 0; text-align:center; }}
  figure.fig img, .aimd img {{ max-width:100%; height:auto; border:1px solid var(--line);
                               border-radius:8px; box-shadow:0 1px 3px rgba(30,58,95,.08); }}
  figure.fig figcaption {{ font-size:var(--fs-sm); color:var(--muted); margin-top:.4rem; font-style:italic; }}

  /* ---- AI markdown block ---- */
  .aimd {{ font-size:var(--fs-body); color:var(--ink); line-height:1.6; }}
  .aimd h2 {{ font-size:var(--fs-3); color:var(--navy); border:none; margin:1rem 0 .3rem; padding:0; }}
  .aimd ol, .aimd ul {{ margin:.3rem 0 .7rem; padding-left:1.4rem; }}
  .aimd li {{ margin:.15rem 0; }}
  .aimd table {{ margin:.4rem 0 .8rem; border:1px solid var(--line); border-radius:8px; overflow:hidden; }}

  /* ---- captions & type badges (one consistent style) ---- */
  .cap {{ margin:.1rem 0 .4rem; font-size:var(--fs-xs); color:var(--muted); }}
  .tblcap {{ margin:.9rem 0 .35rem; font-size:var(--fs-sm); font-weight:600; color:var(--ink); }}
  .tag {{ display:inline-block; padding:.1rem .5rem; border-radius:999px; font-size:var(--fs-xs);
          font-weight:600; letter-spacing:.02em; background:var(--pill); color:var(--navy);
          border:1px solid var(--line); }}
  .tag::before {{ content:''; display:inline-block; width:6px; height:6px; border-radius:50%;
                  background:var(--accent); margin-right:.35rem; vertical-align:middle; }}
  .t-sensitiveSecurityParameter::before {{ background:#3f9a52; }}
  .t-service::before {{ background:#2f6fb0; }}
  .t-approvedAlgorithm::before {{ background:#8256b5; }}
  .t-portsAndInterfaces::before {{ background:#c9822e; }}
  .t-selfTest::before {{ background:#c0436a; }}
  .t-securityLevelTable::before, .t-moduleConfiguration::before,
  .t-acronyms::before, .t-apiCall::before {{ background:#8a97a5; }}

  @media (max-width:640px) {{
    body {{ padding:1rem .8rem 3rem; }}
    :root {{ --fs-1:1.35rem; --fs-2:1.05rem; }}
    .card {{ padding:.8rem .8rem; }}
    table.kv th.k {{ width:auto; min-width:110px; }}
  }}
  .mermaid {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
              padding:.8rem; overflow-x:auto; }}
</style></head><body>{body}
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
  mermaid.initialize({{startOnLoad:false, securityLevel:'loose',
                       flowchart:{{useMaxWidth:true, htmlLabels:true, nodeSpacing:28, rankSpacing:44}},
                       themeVariables:{{fontSize:'16px'}},
                       theme:(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'neutral')}});
  mermaid.run({{querySelector:'.mermaid'}}).catch(function(e){{console.error(e);}});
</script>
<noscript>The review-risk graph renders with JavaScript enabled.</noscript>
</body></html>
"""


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("record")
    ap.add_argument("-o", "--out")
    ap.add_argument("--pdf")
    args = ap.parse_args(argv)
    record = json.load(open(args.record))
    # load the verbatim per-page text sidecar (form-feed separated) so table-less
    # pages can show their real prose instead of an empty page marker
    page_texts = []
    side = (record.get("securityPolicy") or {}).get("rawText", {}).get("sidecarFile")
    if side:
        path = os.path.join(os.path.dirname(os.path.abspath(args.record)), side)
        if os.path.exists(path):
            page_texts = open(path).read().split("\f")
    # base64-embed figure images so the HTML is self-contained
    import base64
    recdir = os.path.dirname(os.path.abspath(args.record))
    for fig in (record.get("securityPolicy") or {}).get("figures", []):
        fp = os.path.join(recdir, fig.get("imageFile", ""))
        if fig.get("imageFile") and os.path.exists(fp):
            fig["_dataUri"] = "data:image/png;base64," + base64.b64encode(open(fp, "rb").read()).decode()

    out = args.out or os.path.splitext(args.record)[0] + ".html"
    with open(out, "w") as f:
        f.write(render(record, page_texts))
    print(f"wrote {out}")
    if args.pdf:
        try:
            from coverage import measure, _pdf_text
            b, _ = measure(_pdf_text(args.pdf), record)
            print(f"  table typing {b['typedCells']}/{b['tableCells']} ({100*b['typedCellShare']:.0f}%) "
                  f"| typed-recall {100*b['typedRecall']:.0f}%")
        except Exception as e:
            print(f"  (banner skipped: {e})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
