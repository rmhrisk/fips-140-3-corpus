#!/usr/bin/env python3
"""Add raw pdfplumber table structure to the metadata+text records.

fetch_cmvp.py captured cert metadata + verbatim SP text (pdftotext) but no table
structure, so those records' Security-Policy tables render only as flattened text.
This one-time pass re-downloads each such record's SP PDF and adds
`securityPolicy.tables` (raw pdfplumber grids: {page,index,rows,nRows,nCols}) so the
reconstruction renders them as real tables. It does NOT change the record's
extraction tier (still metadata+text) — only raw tables are added.

Like the fetcher, this is a throwaway harness, not part of `make all` (the pipeline
reads the committed records). Run with the venv that has pdfplumber:
    .venv/bin/python extract_tables.py            # all metadata+text records
    .venv/bin/python extract_tables.py 4675       # only these certs (testing)
Resumable: skips records that already carry securityPolicy.tables.
"""
import json, glob, io, sys, hashlib
import pdfplumber
from fetch_cmvp import SP_URL, _get

RECORDS = "corpus140_3/records"


def extract(pdf_bytes):
    tables = []
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        idx = 0
        for pi, page in enumerate(pdf.pages, 1):
            for t in (page.extract_tables() or []):
                rows = [[(c or "").replace("\n", " ").strip() for c in row] for row in t]
                rows = [r for r in rows if any(cell for cell in r)]   # drop all-empty rows
                if rows and any(len(r) >= 2 for r in rows):
                    tables.append({"page": pi, "index": idx, "rows": rows,
                                   "nRows": len(rows), "nCols": max(len(r) for r in rows)})
                    idx += 1
    return tables


def main(argv):
    want = {int(x) for x in argv if x.isdigit()}
    todo = []
    for f in sorted(glob.glob(f"{RECORDS}/*.json")):
        r = json.load(open(f))
        sp = r.get("securityPolicy") or {}
        if (r.get("extraction") or {}).get("level") != "metadata+text":
            continue
        if sp.get("tables"):
            continue
        if want and r.get("certNumber") not in want:
            continue
        todo.append((f, r))
    print(f"{len(todo)} record(s) to extract", flush=True)
    ok = fail = 0
    for i, (f, r) in enumerate(todo, 1):
        cert = r.get("certNumber")
        pdf = _get(SP_URL.format(n=cert), binary=True)
        if not pdf or pdf[:4] != b"%PDF":
            print(f"  [{i}/{len(todo)}] #{cert}: no PDF", flush=True); fail += 1; continue
        try:
            tables = extract(pdf)
        except Exception as e:
            print(f"  [{i}/{len(todo)}] #{cert}: extract failed: {e}", flush=True); fail += 1; continue
        r.setdefault("securityPolicy", {})["tables"] = tables
        r["securityPolicy"]["pdfTablesSha256"] = hashlib.sha256(pdf).hexdigest()
        json.dump(r, open(f, "w"), indent=1)
        ok += 1
        if i % 20 == 0 or i == len(todo) or want:
            print(f"  [{i}/{len(todo)}] #{cert}: {len(tables)} tables  (ok={ok} fail={fail})", flush=True)
    print(f"done: {ok} updated, {fail} failed", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
