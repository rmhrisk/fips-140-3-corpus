"""Generic component identification for CMVP records.

Replaces the old hardcoded per-component shortlist: scans the WHOLE record (module
name, software/firmware versions, SP urls/revisions/sections/services, and table
cells) against a component catalog, normalizes to a CPE where one exists, and
records WHERE it was found (name/version field = strong; SP body = referenced) and
a best-effort version (flagging whether it looks upstream-mappable — the input the
version-exact CVE join needs, and the thing vendor forks obscure).
"""
import re

# (canonical name, detection regex, CPE or None, kind). CPE enables the NVD drift
# join; None means we can identify it but not (yet) pull component CVEs for it.
CATALOG = [
    ("OpenSSL",        r"\bopenssl\b",                                   "cpe:2.3:a:openssl:openssl",            "crypto-lib"),
    ("BoringSSL",      r"boringssl",                                     "cpe:2.3:a:google:boringssl",          "crypto-lib"),
    ("LibreSSL",       r"libressl",                                      "cpe:2.3:a:openbsd:libressl",          "crypto-lib"),
    ("GnuTLS",         r"gnutls",                                        "cpe:2.3:a:gnu:gnutls",                "crypto-lib"),
    ("libgcrypt",      r"libgcrypt",                                     "cpe:2.3:a:gnupg:libgcrypt",           "crypto-lib"),
    ("NSS",            r"\bnss\b|network security services",             "cpe:2.3:a:mozilla:nss",               "crypto-lib"),
    ("wolfSSL",        r"wolfssl|wolfcrypt",                             "cpe:2.3:a:wolfssl:wolfssl",           "crypto-lib"),
    ("mbedTLS",        r"mbed ?tls|polarssl",                            "cpe:2.3:a:arm:mbed_tls",              "crypto-lib"),
    ("Bouncy Castle",  r"bouncy ?castle",                                None,                                  "crypto-lib"),
    ("Botan",          r"\bbotan\b",                                     "cpe:2.3:a:botan_project:botan",       "crypto-lib"),
    ("libsodium",      r"libsodium",                                     "cpe:2.3:a:libsodium:libsodium",       "crypto-lib"),
    ("Crypto++",       r"crypto\+\+|cryptopp",                           None,                                  "crypto-lib"),
    ("Linux kernel",   r"linux kernel|kernel crypto|libkcapi|kernel cryptographic|\bcrypto api\b", "cpe:2.3:o:linux:linux_kernel", "os-kernel"),
    ("U-Boot",         r"u-?boot",                                       "cpe:2.3:a:denx:u-boot",               "bootloader"),
    ("GRUB",           r"\bgrub2?\b",                                    "cpe:2.3:a:gnu:grub2",                 "bootloader"),
    ("ARM TF-A",       r"trusted firmware|tf-a|arm trusted firmware|\batf\b", "cpe:2.3:a:arm:trusted_firmware-a", "firmware"),
    ("coreboot",       r"coreboot",                                      "cpe:2.3:a:coreboot:coreboot",         "firmware"),
    ("EDK2 / UEFI",    r"\bedk2\b|tianocore",                            "cpe:2.3:a:tianocore:edk2",            "firmware"),
    ("OpenSBI",        r"opensbi",                                       None,                                  "firmware"),
    ("BusyBox",        r"busybox",                                       "cpe:2.3:a:busybox:busybox",           "utility"),
    ("OpenSSH",        r"openssh",                                       "cpe:2.3:a:openbsd:openssh",           "utility"),
    ("strongSwan",     r"strongswan",                                    "cpe:2.3:a:strongswan:strongswan",     "utility"),
]
_COMPILED = [(n, re.compile(rx, re.I), cpe, kind) for n, rx, cpe, kind in CATALOG]

def _raws(xs):
    return [x.get("raw", "") if isinstance(x, dict) else str(x) for x in (xs or [])]

def _strong_fields(record):
    """Name / vendor / version fields — a hit here means the module IS/ships the component."""
    c = record.get("certificate") or {}
    return " | ".join([c.get("moduleName") or "", (c.get("vendor") or {}).get("name") or ""]
                      + _raws(c.get("softwareVersions")) + _raws(c.get("firmwareVersions")))

def _body_fields(record):
    """SP body — urls, revisions, section titles, service names, table cells (referenced)."""
    sp = record.get("securityPolicy") or {}
    parts = [u.get("url", "") for u in sp.get("urls", [])]
    parts += [r.get("description", "") or "" for r in sp.get("revisionHistory", [])]
    parts += [s.get("title", "") for s in sp.get("sections", [])]
    parts += [s.get("name", "") for s in sp.get("services", [])][:300]
    cells = []
    for t in sp.get("tables", [])[:80]:
        for row in t.get("rows", [])[:50]:
            cells += [str(x) for x in row]
    return " \n ".join(parts + cells[:3000])

_VER = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")
_UPSTREAM = re.compile(r"^\d+\.\d+\.\d+$|^20\d\d\.\d\d$")   # X.Y.Z or YYYY.MM (upstream-shaped)

def extract_components(record):
    strong = _strong_fields(record); body = _body_fields(record)
    blob = (strong + " \n " + body).lower(); strong_l = strong.lower()
    out = {}
    for name, rx, cpe, kind in _COMPILED:
        m = rx.search(blob)
        if not m:
            continue
        sm = rx.search(strong_l)
        where = "name/version" if sm else "referenced-in-SP"
        ver = None
        if sm:                                   # best-effort version near the strong-field hit
            vm = _VER.search(strong_l[sm.end():sm.end() + 48])
            if vm:
                ver = vm.group(1)
        out[name] = {"name": name, "cpe": cpe, "kind": kind, "where": where,
                     "version": ver, "version_upstream_mappable": bool(ver and _UPSTREAM.match(ver))}
    return list(out.values())
