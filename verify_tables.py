#!/usr/bin/env python3
"""Systematically verify every extracted table in a record.

For each table it reports size, density, whether a profile typed it, and any
issues; for every typed row it runs correctness checks (leaked-header names,
malformed CAVP certs, empty columns). The goal is to KNOW the state of all
tables, not to spot-check a few.

Usage:
    python verify_tables.py records/4703.json
    python verify_tables.py records/4703.json --list suspicious   # show flagged tables
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter

from profiles import _PROFILE_BY_TYPE

_HEADER_WORDS = {"name", "strength", "service", "description", "role", "roles", "ssp",
                 "csp", "key", "keys", "generation", "storage", "zeroization", "use",
                 "type", "port", "interface", "access", "input", "output", "algorithm",
                 "function", "cavp", "cert", "standard", "mode", "method", "reference",
                 "properties", "indicator"}
_CAVP_RE = re.compile(r"^#?[A-Za-z]{0,2}\d")


def _density(t):
    cells = t["nRows"] * t["nCols"]
    filled = sum(1 for r in t["rows"] for c in r if c.strip())
    return filled / cells if cells else 0


def _empty_cols(t):
    return sum(1 for i in range(t["nCols"])
               if not any((r[i] if i < len(r) else "").strip() for r in t["rows"]))


def verify(rec: dict):
    sp = rec.get("securityPolicy") or {}
    tables = sp.get("tables", [])
    type2coll = {ty: p["collection"] for ty, p in _PROFILE_BY_TYPE.items()}

    # which tables were typed (profiled), and by what
    prof_at = {}
    for p in sp.get("tableProfiles", []):
        prof_at[(p["page"], p["index"])] = p
        for cp in p.get("continuationPages", []):
            prof_at[(cp, None)] = p  # continuation marker (index unknown)

    def is_profiled(t):
        if (t["page"], t["index"]) in prof_at:
            return prof_at[(t["page"], t["index"])]
        # continuation page?
        for p in sp.get("tableProfiles", []):
            if t["page"] in p.get("continuationPages", []):
                return p
        return None

    classes = Counter()
    issues = []
    for t in tables:
        prof = is_profiled(t)
        dens = _density(t)
        ec = _empty_cols(t)
        flag = None
        if prof:
            cc = prof.get("coreCoverage", 1.0)
            cls = "typed-clean" if cc >= 1.0 and prof.get("columnFill", 0) >= 0.5 else "typed-weak"
            if cls == "typed-weak":
                flag = f"weak typing (core {cc}, fill {prof.get('columnFill')})"
        elif dens >= 0.45:
            cls = "raw-dense"          # real table, no profile yet → backlog
            flag = "dense but no profile — candidate for a new profile"
        else:
            cls = "raw-sparse"
            flag = f"sparse (density {dens:.2f})" if dens < 0.3 else None
        if ec:
            flag = (flag + "; " if flag else "") + f"{ec} empty column(s)"
        classes[cls] += 1
        if flag:
            issues.append((t["page"], t["index"], f"{t['nRows']}x{t['nCols']}", cls, flag))

    # row-level correctness of typed collections
    row_issues = Counter()
    row_examples = {}
    for ty, coll in type2coll.items():
        for o in sp.get(coll, []):
            nm = (o.get("name") or "").strip()
            if not nm:
                row_issues["empty name"] += 1
            elif nm.lower() in _HEADER_WORDS or (len(nm.split()) <= 2 and all(w.lower() in _HEADER_WORDS for w in nm.split())):
                row_issues["leaked-header name"] += 1
                row_examples.setdefault("leaked-header name", f"{coll}: {nm!r}")
            if ty == "approvedAlgorithm":
                cc = (o.get("cavpCert") or "").strip()
                if cc and not _CAVP_RE.match(cc):
                    row_issues["malformed cavpCert"] += 1
                    row_examples.setdefault("malformed cavpCert", f"{o.get('name')}: {cc!r}")

    # Value-fill: of the cells that map to a canonical column, how many are
    # non-empty. Catches the "field typed but value missing" problem (empty
    # cavpCert) that the typed/total ratio alone would not show.
    fill_filled = fill_total = 0
    for p in sp.get("tableProfiles", []):
        coll = type2coll.get(p["type"])
        if not coll:
            continue
        pages = {p["page"]} | set(p.get("continuationPages", []))
        rows = [o for o in sp.get(coll, []) if o.get("source", {}).get("page") in pages]
        for o in rows:
            for c in p.get("matchedColumns", []):
                fill_total += 1
                if str(o.get(c, "")).strip():
                    fill_filled += 1

    total_typed_rows = sum(len(sp.get(c, [])) for c in set(type2coll.values()))
    return {
        "tables": len(tables), "classes": classes, "issues": issues,
        "typedRows": total_typed_rows, "rowIssues": row_issues, "rowExamples": row_examples,
        "valueFill": (fill_filled, fill_total),
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("record")
    ap.add_argument("--list", choices=["suspicious", "all"], default="suspicious")
    args = ap.parse_args(argv)
    rec = json.load(open(args.record))
    r = verify(rec)

    print(f"Table verification — {args.record}")
    print("=" * 60)
    print(f"  Tables: {r['tables']}   Typed rows: {r['typedRows']}")
    print("  Table classes:")
    for cls in ("typed-clean", "typed-weak", "raw-dense", "raw-sparse"):
        print(f"     {cls:<12} {r['classes'].get(cls, 0)}")
    clean = r["classes"].get("typed-clean", 0)
    print(f"  Cleanly-typed share: {100*clean/max(1,r['tables']):.0f}% of tables")
    vf, vt = r["valueFill"]
    print(f"  Value-fill (mapped cells non-empty): {vf}/{vt} = {100*vf/max(1,vt):.0f}%")

    if r["rowIssues"]:
        print("\n  Row-level issues (typed collections):")
        for k, n in r["rowIssues"].most_common():
            ex = r["rowExamples"].get(k, "")
            print(f"     {k}: {n}   {('e.g. '+ex) if ex else ''}")
    else:
        print("\n  Row-level issues: none")

    flagged = r["issues"]
    if args.list == "all" or flagged:
        print(f"\n  Flagged tables ({len(flagged)}):")
        for pg, idx, size, cls, flag in flagged[:40]:
            print(f"     p{pg} t{idx} {size:<7} [{cls}] {flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
