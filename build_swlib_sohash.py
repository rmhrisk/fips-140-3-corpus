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
import re
import struct
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


# --- minimal ELF reader (build-robust metadata, no external tools) ----------
# Enough of ELF32/64 little-endian (x86_64 / aarch64) to read DT_SONAME,
# DT_NEEDED and the exported dynamic symbols. These identifiers survive a
# rebuild far better than a whole-file hash.
DT_NEEDED, DT_SONAME = 1, 14


def elf_metadata(path):
    try:
        data = open(path, "rb").read()
    except OSError:
        return {}
    if data[:4] != b"\x7fELF":
        return {}
    is64 = data[4] == 2
    if data[5] != 1:  # only little-endian
        return {}
    if is64:
        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    else:
        e_shoff = struct.unpack_from("<I", data, 0x20)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x30)
    if not e_shoff or not e_shnum:
        return {}
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if is64:
            name, typ, _fl, _ad, s_off, s_size, s_link, _inf, _al, s_ent = \
                struct.unpack_from("<IIQQQQIIQQ", data, off)
        else:
            name, typ, _fl, _ad, s_off, s_size, s_link, _inf, _al, s_ent = \
                struct.unpack_from("<IIIIIIIIII", data, off)
        secs.append(dict(name=name, type=typ, off=s_off, size=s_size, link=s_link, ent=s_ent))
    shstr = secs[e_shstrndx]
    def secname(s):
        base = shstr["off"] + s["name"]
        end = data.index(b"\0", base)
        return data[base:end].decode("latin1")
    byname = {secname(s): s for s in secs}

    def strat(strtab, idx):
        base = strtab["off"] + idx
        end = data.index(b"\0", base)
        return data[base:end].decode("latin1")

    meta = {"soname": None, "needed": [], "exported_symbols": 0,
            "symbol_signature": None, "notable_symbols": []}
    dynstr = byname.get(".dynstr")
    # .dynamic -> SONAME / NEEDED
    dyn = byname.get(".dynamic")
    if dyn and dynstr:
        entsz = 16 if is64 else 8
        for o in range(dyn["off"], dyn["off"] + dyn["size"], entsz):
            tag, val = struct.unpack_from("<qQ" if is64 else "<iI", data, o)
            if tag == 0:
                break
            if tag == DT_SONAME:
                meta["soname"] = strat(dynstr, val)
            elif tag == DT_NEEDED:
                meta["needed"].append(strat(dynstr, val))
    # .dynsym -> exported (defined, non-local) symbol names
    dynsym = byname.get(".dynsym")
    if dynsym and dynstr and dynsym["ent"]:
        names = []
        for o in range(dynsym["off"], dynsym["off"] + dynsym["size"], dynsym["ent"]):
            if is64:
                st_name, st_info, _oth, st_shndx = struct.unpack_from("<IBBH", data, o)
            else:
                st_name, st_value, st_size, st_info, _oth, st_shndx = \
                    struct.unpack_from("<IIIBBH", data, o)
            if st_shndx == 0 or (st_info >> 4) == 0:  # undefined or LOCAL
                continue
            nm = strat(dynstr, st_name)
            if nm:
                names.append(nm)
        names = sorted(set(names))
        meta["exported_symbols"] = len(names)
        if names:
            meta["symbol_signature"] = hashlib.sha256("\n".join(names).encode()).hexdigest()[:16]
        notable = re.compile(r"fips|FIPS|OSSL|provider|NSC_|softoken|freebl|kcapi|gcry_|nettle_|wolf|EVP_CIPHER", re.I)
        meta["notable_symbols"] = [n for n in names if notable.search(n)][:12]
    return meta


# named upstream banners (e.g. "OpenSSL 3.0.7 1 Nov 2022", "NSS 3.90")
BANNER_RE = re.compile(r"(OpenSSL\s+\d[\w.\- ]*|BoringSSL[\w.\- ]*|NSS\s+\d[\w.\- ]*|NSPR\s+\d[\w.\-]*"
                      r"|libgcrypt\s+\d[\w.\-]*|GnuTLS\s+\d[\w.\-]*|nettle\s+\d[\w.\-]*"
                      r"|wolfSSL\s+\d[\w.\-]*|libkcapi\s+\d[\w.\-]*)")
# a bare version, optionally with a build suffix ("3.0.7", "3.0.7-b27cdeb3ba51be46")
VER_LINE_RE = re.compile(r"^\d+\.\d+\.\d+[a-z]?([-+][0-9A-Za-z][0-9A-Za-z.]*)?$")
VER_BUILD_RE = re.compile(r"\b\d+\.\d+\.\d+[a-z]?[-+][0-9a-f]{7,}\b")  # version + build hash
OID_LIKE = re.compile(r"\d+\.\d+\.\d+\.\d+")  # skip ASN.1 OIDs / cipher maps


def version_strings(path):
    try:
        out = subprocess.run(["strings", "-a", path], capture_output=True, timeout=30).stdout.decode("latin1", "ignore")
    except Exception:
        return []
    hits = []
    for line in out.splitlines():
        line = line.strip()
        if not (4 <= len(line) <= 90) or ":" in line or OID_LIKE.search(line):
            continue
        m = VER_BUILD_RE.search(line)
        if m:
            hits.append(m.group(0))
        elif BANNER_RE.search(line) or VER_LINE_RE.match(line):
            hits.append(line)
    seen, keep = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h); keep.append(h)
    return keep[:12]


def fetch(url, dest):
    r = subprocess.run(["curl", "-sL", "--max-time", "90", "--max-filesize", "80m",
                        "-A", "Mozilla/5.0", "-o", dest, url],
                       capture_output=True)
    return r.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 0


def extract_sos(rpm, workdir):
    """Return {relpath: {sha256, metadata...}} for every real .so* file."""
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
            rec = {"sha256": sha256(p)}
            if not rel.endswith(".hmac"):
                rec.update(elf_metadata(p))
                rec["version_strings"] = version_strings(p)
            out[rel] = rec
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
                {"path": rel, "filename": os.path.basename(rel),
                 "is_hmac_sidecar": rel.endswith(".hmac"), **info}
                for rel, info in sorted(sos.items())]
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
