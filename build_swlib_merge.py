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
import re
import sys
import csv
import datetime

HEX64 = re.compile(r"^[0-9a-f]{64}$")

HERE = os.path.dirname(os.path.abspath(__file__))
SPT = os.path.join(HERE, "sp_text")
TRACKA = os.path.join(HERE, "fips_swlib.trackA.json")


def sp_text_lower(cert):
    p = os.path.join(SPT, f"{cert}.txt")
    if not os.path.exists(p):
        return ""
    return open(p, encoding="utf-8", errors="ignore").read().lower()
GOFISH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "gofish_results.json")
OUT_JSON = os.path.join(HERE, "fips_swlib.json")
OUT_CSV = os.path.join(HERE, "fips_swlib.csv")
STAMP = datetime.date.today().isoformat()


# What a published hash actually lets you match, relative to a file on disk.
IDENTIFIES = {
    "shared-object": "on-disk-file",     # the exact .so/.dll a scanner would find
    "maven-jar": "on-disk-file",         # the jar IS the shipped file
    "distro-package": "package",         # the file is inside; package hash != file hash
    "source-tarball": "source",          # source code; no canonical binary hash
    "vendor-binary": "vendor-archive",
    "container-image": "container",
    "nvd-cpe": "reference",
    "other": "other",
}


def recompute_confidence(row):
    """Confidence a file matching these identifiers is this module."""
    score, reasons = 0.0, []
    if row["component"]:
        score += 0.40; reasons.append("known-upstream-component")
    if row["module_software_versions"] or row["component_version"]:
        score += 0.20; reasons.append("version-pinned")
    if row["fingerprints"]["filenames"]:
        score += 0.20; reasons.append("filename-in-SP")
    digs = row["fingerprints"]["declared_digests"]
    if any(d["kind"] in ("published-download-sha256", "published-file-sha256") for d in digs):
        score += 0.20; reasons.append("sp-published-hash")     # directly matchable
    elif any(d["kind"] == "module-integrity-hmac" for d in digs):
        score += 0.12; reasons.append("sp-module-hmac")        # asserted, key-dependent
    elif digs:
        score += 0.10; reasons.append("sp-selftest-digest")
    # published-hash block: a hash of the actual on-disk file beats a hash of the
    # source tarball or the containing package.
    pubs = row["fingerprints"]["published_artifacts"]

    def has(pred, verified=None):
        for a in pubs:
            if not a.get("sha256"):
                continue
            if verified is not None and bool(a.get("verified")) != verified:
                continue
            if pred(a):
                return True
        return False

    is_file = lambda a: a.get("identifies") == "on-disk-file"
    if has(is_file, verified=True):
        score += 0.35; reasons.append("verified-file-hash")
    elif has(lambda a: True, verified=True):
        score += 0.22; reasons.append("verified-source/package-hash")
    elif has(is_file):
        score += 0.20; reasons.append("file-hash-unverified")
    elif has(lambda a: True):
        score += 0.12; reasons.append("hash-unverified")
    elif any(a.get("download_url") for a in pubs):
        score += 0.05; reasons.append("artifact-no-hash")
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

    # canonical hash per exact filename, from agent-verified, well-formed digests.
    # A versioned artifact filename (bc-fips-2.0.0.jar) uniquely identifies content,
    # so a verified 64-hex hash for it is authoritative for peer-correction.
    canon = {}
    for g in fished.values():
        for a in (g.get("artifacts") or []):
            h = (a.get("sha256") or "").strip().lower()
            if a.get("verified") and HEX64.match(h):
                canon.setdefault(a.get("filename"), h)

    # Track C: real on-disk .so hashes extracted from distro packages.
    so_by_cert = {}
    so_path = os.path.join(HERE, "so_hashes.json")
    if os.path.exists(so_path):
        for pkg in json.load(open(so_path)).get("results", []):
            if pkg.get("status") != "ok":
                continue
            ok = bool(pkg.get("package_sha256_ok"))
            for s in pkg.get("shared_objects", []):
                if s.get("is_hmac_sidecar"):
                    continue
                for cert in pkg.get("certs", []):
                    so_by_cert.setdefault(cert, []).append({
                        "filename": s["filename"],
                        "artifact_kind": "shared-object",
                        "version": None,
                        "sha256": s["sha256"],
                        "sha256_source_url": pkg.get("download_url"),
                        "download_url": pkg.get("download_url"),
                        "verified": ok,
                        "verify_method": "package-extracted" if ok else "package-extracted-unconfirmed",
                        "confidence": 0.9 if ok else 0.7,
                        "evidence": f"SHA-256 of {s['filename']} extracted from {pkg['package']}"
                                    + (" (package hash independently confirmed)" if ok else ""),
                        "identifies": "on-disk-file",
                        "source": "package-extracted",
                    })

    n_enriched = n_hash = n_verified = n_searched_empty = n_malformed = n_corrected = n_so = 0
    for row in rows:
        g = fished.get(row["cert"])
        if g is not None:
            # record that Track B looked, even when nothing public was found
            row.setdefault("provenance", {})["trackB"] = f"web-fished-{STAMP}"
            row["provenance"]["trackB_found"] = bool(g.get("found") and g.get("artifacts"))
            if g.get("notes"):
                row["provenance"]["trackB_notes"] = g["notes"]
        if g and g.get("artifacts"):
            sp_low = sp_text_lower(row["cert"])
            arts = []
            for a in g["artifacts"]:
                h = (a.get("sha256") or "").strip().lower() or None
                note_extra = None
                # Reject malformed digests (a SHA-256 is exactly 64 hex). If the
                # bad value is a clean prefix of a canonical verified hash for the
                # same filename, it is a truncation we can correct; else drop it.
                if h and not HEX64.match(h):
                    cf = canon.get(a.get("filename"))
                    if cf and cf.startswith(h):
                        note_extra = f"[peer-corrected from truncated '{h}']"
                        h = cf
                        n_corrected += 1
                    else:
                        note_extra = f"[malformed digest omitted: '{h}']"
                        h = None
                        n_malformed += 1
                # Deterministic check: does this exact hash appear in the module's
                # own Security Policy text? That is authoritative and beats an
                # agent's re-fetch (which fails on PDF-only sources).
                sp_confirmed = bool(h and h in sp_low)
                if note_extra and "peer-corrected" in note_extra:
                    verified, method = True, "peer-corrected"
                elif sp_confirmed:
                    verified, method = True, "sp-text-confirmed"
                elif h and a.get("verified"):
                    verified, method = True, "web-reverified"
                elif h:
                    verified, method = False, "unconfirmed"
                else:
                    verified, method = False, ("malformed-omitted" if note_extra else None)
                ev = a.get("evidence")
                if note_extra:
                    ev = f"{ev} {note_extra}" if ev else note_extra
                arts.append({
                    "filename": a.get("filename"),
                    "artifact_kind": a.get("artifact_kind"),
                    "version": a.get("version"),
                    "sha256": h,
                    "sha256_source_url": a.get("sha256_source_url"),
                    "download_url": a.get("download_url"),
                    "verified": verified,
                    "verify_method": method,
                    "confidence": a.get("confidence"),
                    "evidence": ev,
                    "identifies": IDENTIFIES.get(a.get("artifact_kind"), "other"),
                    "source": "web-fished",
                })
            row["fingerprints"]["published_artifacts"] = arts
            n_enriched += 1
            n_hash += sum(1 for a in arts if a["sha256"])
            n_verified += sum(1 for a in arts if a["sha256"] and a["verified"])
        elif g is not None:
            n_searched_empty += 1
        # append extracted .so hashes (dedup by filename+sha256)
        sos = so_by_cert.get(row["cert"])
        if sos:
            pubs = row["fingerprints"]["published_artifacts"]
            have = {(a.get("filename"), a.get("sha256")) for a in pubs}
            for s in sos:
                if (s["filename"], s["sha256"]) not in have:
                    pubs.append(s); have.add((s["filename"], s["sha256"])); n_so += 1
            row.setdefault("provenance", {})["trackC"] = f"package-extracted-{STAMP}"
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
            "C": "on-disk .so/.dll hashes extracted from distro packages",
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
    print(f"  malformed hashes: {n_malformed} omitted, {n_corrected} peer-corrected")
    print(f"  on-disk .so hashes extracted (Track C): {n_so}")
    print(f"  published hashes:  {n_hash} ({n_verified} verified)")
    print(f"  confidence >= 0.8: {sum(1 for r in rows if r['identity_confidence'] >= 0.8)}")
    print(f"wrote {os.path.relpath(OUT_JSON, HERE)} and {os.path.relpath(OUT_CSV, HERE)}")


if __name__ == "__main__":
    main()
