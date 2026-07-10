#!/usr/bin/env python3
"""Standards registry + linkifier.

Turns cryptographic standard references (FIPS 197, SP 800-38D, …) and algorithm
names (AES-GCM, ECDSA, ML-KEM, …) into links to the governing NIST publication,
so a reader viewing the reconstructed document can click straight through to the
spec. Data lives in specs.json; this module is the lookup + HTML linkification.

    from specs import linkify_refs, name_link
    linkify_refs("AES-GCM per SP 800-38D")   # -> '... <a ...>SP 800-38D</a>'
    name_link("ECDSA KeyGen (FIPS186-4)")    # -> ('FIPS 186-4', <url>)
"""
from __future__ import annotations

import json
import os
import re

_DATA = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "specs.json")))
SPECS = _DATA["specs"]
FAMILIES = _DATA["algorithmFamilies"]

# Explicit references in free text / cells: "FIPS 197", "FIPS PUB 186-4",
# "FIPS186-4", "SP 800-38D", "SP800-108", "SP 800-56A rev3".
_REF_RE = re.compile(
    r"\b(FIPS(?:\s+PUB)?\s*-?\s*\d{3}(?:-\d+)?"
    r"|SP\s*-?\s*800-\d+[A-Za-z]?(?:\s*(?:r|rev\.?\s*)\d+)?)\b",
    re.IGNORECASE,
)


def canon_ref(s: str) -> str | None:
    """Normalize a raw reference to a registry key (revision stripped)."""
    t = re.sub(r"\s+", " ", s.upper().replace("PUB", "")).strip()
    m = re.match(r"FIPS\s*-?\s*(\d{3}(?:-\d+)?)", t)
    if m:
        return f"FIPS {m.group(1)}"
    m = re.match(r"SP\s*-?\s*(800-\d+[A-Z]?)", t)
    if m:
        return f"SP {m.group(1)}"
    return None


def spec_url(ref_key: str) -> str | None:
    spec = SPECS.get(ref_key)
    return spec["url"] if spec else None


def name_link(algorithm_name: str):
    """Governing (spec_id, url) for an algorithm name, or (None, None).

    Scans the ordered family list; the first token found wins, so mode-specific
    and PQC tokens (checked first in specs.json) beat the generic family.
    """
    up = algorithm_name.upper()
    for token, spec_id in FAMILIES:
        if token.upper() in up:
            return spec_id, spec_url(spec_id)
    return None, None


def linkify_refs(escaped_text: str, _link=None) -> str:
    """Wrap explicit FIPS/SP references in already-HTML-escaped text with links.

    Safe to run on escaped cell/prose text: references contain no HTML-special
    characters, and we never recurse into an existing tag because escaped text
    has no live tags.
    """
    link = _link or (lambda u, t: f"<a href='{u}'>{t}</a>")

    def repl(m):
        raw = m.group(1)
        key = canon_ref(raw)
        url = spec_url(key) if key else None
        title = SPECS[key]["title"] if key and key in SPECS else ""
        if not url:
            return raw
        return f"<a href='{url}' title='{title}'>{raw}</a>"

    return _REF_RE.sub(repl, escaped_text)


if __name__ == "__main__":
    for t in ["AES-GCM per SP 800-38D and FIPS197",
              "RSA SigVer (FIPS186-4)", "KDF SP800-108", "ML-KEM", "HMAC-SHA2-256"]:
        print(f"{t!r:40} name->{name_link(t)}  refs->{linkify_refs(t)}")
