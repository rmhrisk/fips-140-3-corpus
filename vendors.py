"""Deterministic vendor-name normalization and product-family clustering.

Both are derived from the record data alone (no network), so the corpus stays
byte-reproducible. The goal is conservative entity resolution: merge the obvious
punctuation/legal-suffix variants of a vendor ("Cisco Systems, Inc." vs "Cisco
Systems, Inc"), and cluster certificates of the same product into families so a
per-certificate "never updated" can be read against whether the vendor validated
a successor. It is intentionally conservative — it under-merges rather than
inventing links it cannot support from the public record.
"""
import re

# Trademark marks and legal-entity suffixes that do not distinguish an organization.
_TM = re.compile(r"[®™©]|\(r\)|\(tm\)|\(c\)", re.I)
_LEGAL = {"inc", "llc", "ltd", "corp", "corporation", "gmbh", "co", "company", "sa",
          "bv", "pty", "limited", "plc", "ag", "kk", "oy", "ab", "srl", "spa", "llp",
          "lp", "nv", "sas", "kg", "as", "aps", "oyj", "sro", "ulc", "pte"}


def norm_vendor(name: str) -> str:
    """Canonical vendor key: drop trademark marks, trailing legal suffixes, and
    punctuation. 'Cisco Systems, Inc.' / 'Cisco Systems, Inc' -> 'cisco systems'."""
    if not name or "@" in name:            # an email address is not a vendor name
        return ""
    n = _TM.sub(" ", name).lower().replace(",", " ")
    toks = [t.replace(".", "").strip() for t in n.split()]
    toks = [t for t in toks if t]
    while toks and toks[-1] in _LEGAL:     # strip trailing "inc", "llc", ...
        toks.pop()
    return " ".join(toks).strip()


# Boilerplate words that appear in most module names and do not identify a product.
_NOISE = {"cryptographic", "crypto", "module", "modules", "fips", "library", "libraries",
          "for", "the", "and", "of", "provider", "cryptography", "security", "hardware",
          "software", "firmware"}
_VER = re.compile(r"\bv?\d+(?:\.\d+)+\b|\b\d{3,}\b|\brev\.?\s*\d+\b|\br\d+\b", re.I)


def family_key(vendor_norm: str, module: str) -> str:
    """Conservative product-family key: normalized vendor + de-noised module name
    (multi-part versions, long build numbers, and boilerplate words removed). Certs
    that share this key are treated as one product family. Kept conservative — it
    preserves model/distro tokens, so distinct-named products stay distinct."""
    m = _TM.sub(" ", module or "").lower()
    m = _VER.sub(" ", m)
    m = re.sub(r"[^a-z0-9 ]", " ", m)
    toks = [t for t in m.split() if t and t not in _NOISE]
    return vendor_norm + " :: " + " ".join(toks)
