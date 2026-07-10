# What a FIPS certificate actually tells you

A corpus-wide read of the public **FIPS 140-3** validated-module record (CMVP
certificates plus their Security Policies), extracted and analyzed
deterministically. The question it answers is not "did this module pass" but
"what do these public artifacts reliably reveal about the module and the trusted
computing base around it, and where should a security review look first."

Everything here is reproducible from the committed corpus snapshot and NVD caches
with **pure Python standard library** (Python 3.8+). No network and no
third-party packages are needed to rebuild any artifact; `make all` regenerates
every output byte-for-byte.

## At a glance (reference date 2026-07, n = 136 modules, certs #4650 to #5159)

- **72%** of modules have never been re-validated since their initial certificate.
- **60 months** median certificate window (validation to sunset).
- **90%** still carry at least one legacy primitive (SHA-1 / ECB / 3DES).
- **TCB surfaces** are visible across the corpus even when components are not
  named: debug/recovery interface (25), network crypto parser (24), HSM/SE
  firmware trust anchor (20), firmware-update authentication (20), boot-chain
  verification (9), kernel crypto consumer (9).
- **Component-level CVE drift** is measurable for **30 of 136** modules (the ones
  that name a CPE-mappable component); the rest, disproportionately hardware and
  appliance modules, name nothing the join can reach. That gap is itself a finding.
- The **boot chain** is treated as a first-class security property: 3 HSMs ship
  U-Boot inside the validated boundary, the exact surface of Binarly's U-Boot FIT
  signature-verification bypass (CVE-2026-46728).

## What a FIPS certificate is good for here

A certificate attests one module version, in one approved-mode configuration, at
one moment. Read across the whole corpus, the certificate and its Security Policy
still deliver three things a reviewer can act on:

1. **A map of the trusted-computing-base surfaces** around each module (boot chain,
   firmware update, debug/recovery, host/OE, network service, HSM/SE trust anchor).
2. **A measure of how far named components have drifted** since validation, joined
   to NVD.
3. **A ranked view of where a review should look first**, by archetype and staleness.

It is best read as a map of what to verify in a deployment rather than proof of
the deployment itself, which is exactly what makes it a fast way to aim that
verification.

## Repository layout

Everything runs from the repo root (scripts use root-relative paths).

```
corpus140_3/records/*.json   provided corpus snapshot (138 fetched CMVP records)
                             — the analysis operates on this; no re-fetch needed

components.py                generic component identification (full-record scan vs a CPE catalog)
motifs.py                    TCB-surface motifs (the architectural patterns a review should check)
analyze_corpus.py            core analyzer  -> corpus_analysis.json
build_drift.py               NVD component-drift join (cached)  -> drift.json
build_version_exact.py       NVD version-exact refinement (cached)  -> version_exact.json
report_html.py               the report  -> corpus_report.html
findings_md.py               the findings memo  -> FINDINGS.md
build_explorer.py            interactive review-priority explorer  -> explorer.html
verify_tables.py, profiles.py, security_policy.py, specs.py, specs.json
                             helper modules used by analyze_corpus

corpus_analysis.json         committed intermediate (analyzer output)
drift.json, version_exact.json           committed NVD-join outputs
drift_cache.json, ve_cache.json          committed NVD response caches (offline replay)

corpus_report.html           rendered report        (open in a browser)
explorer.html                interactive explorer   (open in a browser)
FINDINGS.md                  findings memo
```

## The pipeline

```
corpus140_3/records/  ──analyze_corpus.py──▶  corpus_analysis.json ─┐
                      ──build_drift.py─────▶  drift.json           ─┤
                             (drift.json) ──build_version_exact.py▶  version_exact.json ─┤
                                                                                          ├─▶ report_html.py    ▶ corpus_report.html
                                                                                          ├─▶ findings_md.py    ▶ FINDINGS.md
                                                                                          └─▶ build_explorer.py ▶ explorer.html
```

- **Analysis** (`analyze_corpus.py`) reads the provided records and is fully
  offline and deterministic.
- **NVD joins** (`build_drift.py`, `build_version_exact.py`) query the NVD CVE
  API, but ship with response caches so they replay offline. They only touch the
  network on a cache miss.
- **Render** (`report_html.py`, `findings_md.py`, `build_explorer.py`) are
  standard-library only and read the committed intermediates.

## Reproduce it

```
make all        # rebuild every artifact from the committed corpus + caches (offline)
make analyze    # records -> corpus_analysis.json
make drift      # records + cache -> drift.json
make version-exact
make render     # report + findings + explorer
make verify     # rebuild and confirm the committed artifacts are byte-identical
make clean      # remove generated artifacts (all regenerate from make all)
```

Requires only Python 3.8+. Re-running the NVD stages against the live API (after
`rm drift_cache.json ve_cache.json`) reproduces the same joins as of a current
NVD snapshot.

## Data provenance

- **Modules and Security Policies**: NIST CMVP validated-module list and the
  per-module Security Policy PDFs, swept over certificate range #4650 to #5159,
  reference date 2026-07. The fetched, normalized records are provided under
  `corpus140_3/records/`. The upstream fetch and PDF-extraction toolchain is not
  shipped here; the corpus it produced is.
- **Vulnerability data**: NVD CVE API v2 (CPE `virtualMatchString`), cached in
  this repo for offline replay.
- External anchor cited in the boot-chain analysis: Binarly, "Unfit to Boot:
  Breaking U-Boot's FIT Signature Verification" (CVE-2026-46728).

## Scope

This project reads public evidence. It does not observe deployments, and it does
not assert vulnerabilities. A matched TCB surface means the architectural pattern
where a bug class would matter is present, which is where a review should ask its
next question. Component drift counts how far a named upstream has moved since a
certificate froze, which is a review trigger, not an exploit. Where the public
record goes dark (an unnamed component, an unstated configuration), the report
says so and points to what a reviewer should collect next.

## License

Code is released under the MIT License (see `LICENSE`). The underlying CMVP and
NVD data are public U.S. Government works.
