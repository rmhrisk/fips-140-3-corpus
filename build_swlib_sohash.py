#!/usr/bin/env python3
"""Track C: extract real on-disk shared-object (.so) hashes from distro packages.

A source-tarball or RPM hash does NOT identify the .so a scanner finds on disk.
But the .so *is inside* the RPM, so we can download each distro package, verify
its own hash against what Track B recorded, extract it, and SHA-256 the actual
.so files. Those are the fingerprints that match a file on a running system.

    python3 build_swlib_sohash.py    # -> so_hashes.json

Network step (like the Track B fish), kept separate from the deterministic build.
Uses curl + bsdtar (libarchive understands the RPM/cpio payload); no rpm tooling.
"""
import json
import os
import subprocess
import tempfile
import hashlib
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "fips_swlib.json")
OUT = os.path.join(HERE, "so_hashes.json")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def fetch(url, dest):
    r = subprocess.run(["curl", "-sL", "--max-time", "90", "--max-filesize", "80m",
                        "-A", "Mozilla/5.0", "-o", dest, url],
                       capture_output=True)
    return r.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 0


def extract_sos(rpm, workdir):
    """Return {relpath: sha256} for every real .so* file in the package."""
    subprocess.run(["bsdtar", "-xf", rpm, "-C", workdir], capture_output=True)
    out = {}
    for root, _, files in os.walk(workdir):
        for fn in files:
            if ".so" not in fn:
                continue
            p = os.path.join(root, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            rel = os.path.relpath(p, workdir)
            out[rel] = sha256(p)
    return out


def main():
    d = json.load(open(DATA))
    # collect distinct distro-package downloads and which certs reference them
    jobs = {}  # download_url -> {"recorded_sha": .., "filename": .., "certs": set()}
    for r in d["rows"]:
        for a in r["fingerprints"]["published_artifacts"]:
            if a.get("artifact_kind") == "distro-package" and a.get("download_url"):
                j = jobs.setdefault(a["download_url"], {
                    "recorded_sha": a.get("sha256"), "filename": a.get("filename"), "certs": set()})
                j["certs"].add(r["cert"])

    results = []
    tmp = tempfile.mkdtemp(prefix="sohash_")
    try:
        for i, (url, j) in enumerate(sorted(jobs.items()), 1):
            rpm = os.path.join(tmp, f"pkg{i}.rpm")
            rec = {"package": j["filename"], "download_url": url,
                   "certs": sorted(j["certs"]), "recorded_package_sha256": j["recorded_sha"]}
            if not fetch(url, rpm):
                rec.update(status="download-failed", shared_objects=[])
                results.append(rec)
                print(f"[{i:2}/{len(jobs)}] DL FAIL  {j['filename']}")
                continue
            got = sha256(rpm)
            rec["package_sha256_ok"] = (got == j["recorded_sha"])
            rec["package_sha256_actual"] = got
            wd = os.path.join(tmp, f"x{i}")
            os.makedirs(wd, exist_ok=True)
            sos = extract_sos(rpm, wd)
            rec["status"] = "ok" if sos else "no-so-found"
            rec["shared_objects"] = [
                {"path": rel, "filename": os.path.basename(rel), "sha256": h,
                 "is_hmac_sidecar": rel.endswith(".hmac")}
                for rel, h in sorted(sos.items())]
            shutil.rmtree(wd, ignore_errors=True)
            os.remove(rpm)
            results.append(rec)
            nso = sum(1 for s in rec["shared_objects"] if not s["is_hmac_sidecar"])
            print(f"[{i:2}/{len(jobs)}] {'OK ' if sos else '?? '} pkg_hash={'ok' if rec['package_sha256_ok'] else 'MISMATCH'}  "
                  f"{nso} .so  {j['filename'][:44]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    json.dump({"n_packages": len(results), "results": results}, open(OUT, "w"), indent=1)
    ok = [r for r in results if r["status"] == "ok"]
    nso = sum(len([s for s in r["shared_objects"] if not s["is_hmac_sidecar"]]) for r in ok)
    print(f"\n{len(ok)}/{len(results)} packages extracted; {nso} .so hashes; "
          f"{sum(1 for r in ok if r.get('package_sha256_ok'))} package hashes confirmed")
    print(f"wrote {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
