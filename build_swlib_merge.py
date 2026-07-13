#!/usr/bin/env python3
"""Track B merge: fold web-fished published artifact hashes into the dataset.

    python3 build_swlib_merge.py [gofish_results.json]

Reads fips_swlib.trackA.json (deterministic base) and a go-fish results file
(list of {cert, found, artifacts[], notes}) produced by the fan-out workflow,
and writes:
    fips_swlib.json   -- merged dataset (the deliverable)
    fips_swlib.csv    -- flattened one-row-per-artifact view

Web-fished hashes are NOT deterministic, so this step is separated from the
reproducible Track A build. Each published hash carries its source URL and a
verified flag (an independent skeptic agent re-checked the URL).
"""
import json
import os
import sys
import csv
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
TRACKA = os.path.join(HERE, "fips_swlib.trackA.json")
GOFISH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "gofish_results.json")
OUT_JSON = os.path.join(HERE, "fips_swlib.json")
OUT_CSV = os.path.join(HERE, "fips_swlib.csv")
STAMP = datetime.date.today().isoformat()


def recompute_confidence(row):
    """Track A score, plus a Track B bonus for a verified published hash."""
    score, reasons = 0.0, []
    if row["component"]:
        score += 0.40; reasons.append("known-upstream-component")
    if row["module_software_versions"] or row["component_version"]:
        score += 0.20; reasons.append("version-pinned")
    if row["fingerprints"]["filenames"]:
        score += 0.20; reasons.append("filename-in-SP")
    if any(d["integrity_context"] for d in row["fingerprints"]["declared_digests"]):
        score += 0.10; reasons.append("declared-integrity-digest")
    pubs = row["fingerprints"]["published_artifacts"]
    if any(a.get("sha256") and a.get("verified") for a in pubs):
        score += 0.35; reasons.append("verified-published-hash")
    elif any(a.get("sha256") for a in pubs):
        score += 0.15; reasons.append("published-hash-unverified")
    elif any(a.get("download_url") for a in pubs):
        score += 0.05; reasons.append("published-artifact-no-hash")
    return round(min(score, 1.0), 2), reasons


def main():
    base = json.load(open(TRACKA))
    rows = base["rows"]
    fished = {}
    if os.path.exists(GOFISH):
        gf = json.load(open(GOFISH))
        gf = gf.get("results", gf) if isinstance(gf, dict) else gf
        fished = {r["cert"]: r for r in gf if r}
    else:
        print(f"WARNING: {GOFISH} not found; emitting Track A only", file=sys.stderr)

    n_enriched = n_hash = n_verified = n_searched_empty = 0
    for row in rows:
        g = fished.get(row["cert"])
        if g is not None:
            # record that Track B looked, even when nothing public was found
            row.setdefault("provenance", {})["trackB"] = f"web-fished-{STAMP}"
            row["provenance"]["trackB_found"] = bool(g.get("found") and g.get("artifacts"))
            if g.get("notes"):
                row["provenance"]["trackB_notes"] = g["notes"]
        if g and g.get("artifacts"):
            arts = []
            for a in g["artifacts"]:
                arts.append({
                    "filename": a.get("filename"),
                    "artifact_kind": a.get("artifact_kind"),
                    "version": a.get("version"),
                    "sha256": (a.get("sha256") or None),
                    "sha256_source_url": a.get("sha256_source_url"),
                    "download_url": a.get("download_url"),
                    "verified": bool(a.get("verified")),
                    "confidence": a.get("confidence"),
                    "evidence": a.get("evidence"),
                    "source": "web-fished",
                })
            row["fingerprints"]["published_artifacts"] = arts
            n_enriched += 1
            n_hash += sum(1 for a in arts if a["sha256"])
            n_verified += sum(1 for a in arts if a["sha256"] and a["verified"])
        elif g is not None:
            n_searched_empty += 1
        conf, reasons = recompute_confidence(row)
        row["identity_confidence"] = conf
        row["identity_evidence"] = reasons

    rows.sort(key=lambda r: r["cert"])
    doc = {
        "dataset": "fips-140-3-software-library-fingerprints",
        "description": "Probabilistic identifiers (filenames, versions, hashes) for "
                       "FIPS 140-3 validated software cryptographic modules.",
        "reference": base.get("reference", "2026-07"),
        "generated": STAMP,
        "n": len(rows),
        "tracks": {
            "A": "deterministic extraction from CMVP certs + Security-Policy text",
            "B": "web-fished published artifact hashes, each with source URL + skeptic verification",
        },
        "confidence_field": "identity_confidence in [0,1]; identity_evidence lists the contributing signals",
        "rows": rows,
    }
    json.dump(doc, open(OUT_JSON, "w"), indent=1)

    # flattened CSV: one row per (module, published artifact); modules with no
    # published artifact still emit a row so the SP filenames are visible.
    with open(OUT_CSV, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["cert", "module_name", "vendor", "component", "component_version",
                    "module_versions", "sp_filenames", "artifact_filename", "artifact_kind",
                    "artifact_version", "sha256", "verified", "artifact_confidence",
                    "sha256_source_url", "identity_confidence"])
        for r in rows:
            sp_files = ";".join(a["file"] for a in r["fingerprints"]["filenames"])
            mvers = ";".join(r["module_software_versions"])
            pubs = r["fingerprints"]["published_artifacts"]
            if pubs:
                for a in pubs:
                    w.writerow([r["cert"], r["module_name"], r["vendor"], r["component"],
                                r["component_version"], mvers, sp_files, a["filename"],
                                a["artifact_kind"], a["version"], a["sha256"] or "",
                                a["verified"], a["confidence"], a["sha256_source_url"] or "",
                                r["identity_confidence"]])
            else:
                w.writerow([r["cert"], r["module_name"], r["vendor"], r["component"],
                            r["component_version"], mvers, sp_files, "", "", "", "",
                            "", "", "", r["identity_confidence"]])

    print(f"modules:             {len(rows)}")
    print(f"  enriched (Track B):{n_enriched}")
    print(f"  searched, no public specimen: {n_searched_empty}")
    print(f"  published hashes:  {n_hash} ({n_verified} verified)")
    print(f"  confidence >= 0.8: {sum(1 for r in rows if r['identity_confidence'] >= 0.8)}")
    print(f"wrote {os.path.relpath(OUT_JSON, HERE)} and {os.path.relpath(OUT_CSV, HERE)}")


if __name__ == "__main__":
    main()
