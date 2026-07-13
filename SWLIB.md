# FIPS 140-3 software-library fingerprints

A dataset for **probabilistically identifying** which FIPS 140-3 validated
software cryptographic module a file on disk corresponds to — by filename,
version, and (where obtainable) hash.

The CMVP certificate and Security Policy were never designed to let you
fingerprint a shipped binary: they attest *one module version, in one approved
configuration, at one moment*, and they rarely publish the hash of the artifact
you would actually find on a system. This dataset extracts every identifier the
public record *does* reveal, then goes looking on the open web for the concrete
downloadable artifact and its published hash — and it is honest, via a
`confidence` field, about how strong each identification is.

## Files

| File | What it is | Reproducible? |
|---|---|---|
| `build_swlib.py` | Track A builder — deterministic extraction from the committed corpus | yes, stdlib only |
| `fips_swlib.trackA.json` | Track A output | yes |
| `build_swlib_sohash.py` | Track C — download distro packages, hash the actual `.so` inside | network |
| `so_hashes.json` | Track C output (extracted on-disk `.so` hashes) | — |
| `build_swlib_merge.py` | merge — folds Track B + Track C into the base | mechanical |
| `fips_swlib.json` | **the merged deliverable** (Track A + B + C) | Track A part yes; hashes are web/package-sourced |
| `fips_swlib.csv` | flattened one-row-per-artifact view | — |

Rebuild Track A: `python3 build_swlib.py`. Merge fished hashes:
`python3 build_swlib_merge.py gofish_results.json`.

## Scope

All **228 software-involving modules** in the corpus (`moduleType` = *Software*
or *Software-hybrid*). Hardware/firmware modules are excluded — you cannot
fingerprint them as a file.

## The two tracks

**Track A — deterministic (no network, byte-reproducible).** Per module:

- `fingerprints.filenames` — crypto artifact names parsed out of the Security
  Policy text (`libcrypto.so.1.1`, `fips.so`, `bc-fips-2.0.0.jar`, `bcm.o`, …).
  Present for **154 / 228** modules.
- `module_software_versions` — from the certificate.
- `component` / `cpe` / `component_version` — the known upstream crypto library
  (OpenSSL ×66, NSS, wolfSSL, libgcrypt, GnuTLS, BoringSSL, Bouncy Castle …),
  joined from the corpus component map. Present for **92 / 228**.
- `fingerprints.declared_digests` — any HMAC/SHA digest the Security Policy
  prints *in its own text* (a genuine anchor when present). **48 / 228**.

**Track B — web-fished (not reproducible).** One agent per module searches the
open web for the concrete shippable artifact and, where published, its SHA-256:

- distro packages (rpm/deb) for distro modules,
- Maven Central jars for Bouncy Castle / Java providers (exact artifact → exact
  hash: the strongest case),
- upstream source tarballs for library builds,
- vendor downloads.

Hard rule enforced on the fishers: **a hash is only recorded if it was read at a
specific published URL** (`sha256_source_url`); a hash that could not be sourced
is left `null` rather than guessed. Every reported hash is then re-checked by an
independent skeptic agent that re-fetches the source URL — the result is the
`verified` flag.

**Track C — on-disk `.so` hashes (network, deterministic).** A source-tarball or
RPM hash does **not** identify the `.so` a scanner finds on disk. But the `.so`
*is inside* the RPM, so `build_swlib_sohash.py` downloads each distro package,
verifies its own hash against what Track B recorded, extracts it with `bsdtar`
(libarchive reads the RPM/cpio payload — no `rpm` tooling), and SHA-256s the
actual shared objects. Those hashes (`artifact_kind: shared-object`) are the ones
that match a file on a running system.

Every published hash carries an **`identifies`** field so its meaning is explicit:
`on-disk-file` (the exact `.so`/`.dll`/`.jar` — Maven jars and Track-C `.so`s),
`package` (the file is inside this RPM/deb, whose hash differs), or `source`
(source code, whose compiled hash is build-dependent).

## The `confidence` field

`identity_confidence` ∈ [0, 1] sums the signals that actually tie an identifier
to the validated module; `identity_evidence` lists which fired:

| Signal | Weight |
|---|---|
| `known-upstream-component` | 0.40 |
| `verified-published-hash` | 0.35 |
| `version-pinned` | 0.20 |
| `filename-in-SP` | 0.20 |
| `published-hash-unverified` | 0.15 |
| `declared-integrity-digest` | 0.10 |
| `published-artifact-no-hash` | 0.05 |

Capped at 1.0. Read it as *"how confident are we that a file matching these
identifiers is this module"* — **not** as a claim that the hash is the exact
validated binary. A published upstream/distro hash usually identifies the
**family + version**, which is the honest ceiling for most modules: the exact
validated object depends on the tested build environment and is generally not
publicly recoverable. Bouncy Castle FIPS jars and Go BoringCrypto are the
cleanest exceptions, where the published artifact *is* the validated one.

## Caveats

- Track B hashes reflect the web at generation time (`generated` field) and can
  go stale or be superseded; always follow `sha256_source_url` to confirm.
- Absence of a published hash is expected for closed vendor appliances and is
  recorded honestly (`found: false`), not padded.
- This identifies *libraries*, not *deployments*: a matching file is evidence the
  validated module is present, not proof it runs in the approved mode.
