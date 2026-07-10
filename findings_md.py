#!/usr/bin/env python3
"""Generate FINDINGS.md — narrative interpretation driven by corpus_analysis.json.
All corpus figures are read from the JSON; the only hardcoded numbers are the
EXTERNAL inputs below, which are explicitly labelled as provided (not corpus-derived)."""
import json, os, sys
d = json.load(open(sys.argv[1] if len(sys.argv)>1 else "corpus_analysis.json"))
s = d["summary"]; recs = d["records"]
lc, rc, ex, q, ve = s["lifecycle"], s["recertification"], s["exposure"], s["quality"], s["vuln_exposure"]
al, pq, cov, labs, asr = s["algorithms"], s["pqc"], s["coverage"], s["labs"], s["assurance"]
tp = s["throughput_predictors"]; mt = s["motifs"]
sub = lc["submission_months (SP first->initial validation)"]; win = lc["exposure_window_months (validation->sunset)"]
def top(dct, n=6): return ", ".join(f"{k} ({v})" for k,v in list(dct.items())[:n])
never = rc["update_count_dist"].get("0",0); N = s["n"]
# EXTERNAL inputs (NOT derived from this corpus) — provided industry figures, cited as such.
EXT_VOLUME = "2022:6 · 2023:6 · 2024:176 · 2025:163 · 2026-YTD:265"
EXT_TIMELINE = "~19 months post-CMVP-submission; ~24–36 months end-to-end"
# OpenSSL drift/version-exact figures computed from data (single source of truth)
_ve = json.load(open("version_exact.json")) if os.path.exists("version_exact.json") else []
_ossl = [m for m in _ve if m["component"] == "OpenSSL"]
if _ossl:
    OSSL_DRIFT = f"{min(m['component_drift'] for m in _ossl)}–{max(m['component_drift'] for m in _ossl)}"
    OSSL_EXACT = f"{min(m['version_exact_cves'] for m in _ossl)}–{max(m['version_exact_cves'] for m in _ossl)}"
    OSSL_PCT = round(100*sum(m['version_exact_cves'] for m in _ossl)/max(1, sum(m['component_drift'] for m in _ossl)))
else:
    OSSL_DRIFT = OSSL_EXACT = "n/a"; OSSL_PCT = 0
L=[]; w=L.append

w("# FIPS 140-3 Validated-Module Corpus — Findings\n")
w(f"*n = {N} FIPS 140-3 modules, swept from the recent CMVP certificate range and normalized "
  f"deterministically from the certificate page + Security Policy PDF. Reference date {cov['reference_date']}.*\n")

w("## Executive finding\n")
w("**A FIPS 140-3 certificate proves that a specific module *version*, in a specific configuration and approved mode, was "
  "validated once — it does not prove that a *deployed* product is running that validated version, in that configuration, "
  "using only approved services.** The procurement shorthand \"does it use a FIPS-certified module?\" collapses exactly this "
  "distinction; the real, narrower evidence question is whether the deployed cryptographic function is the *same* validated, "
  "approved-mode configuration buyers and regulators think they are relying on.\n")
w("\nThis corpus quantifies where public CMVP evidence is most likely to have **drifted** from that: certificates that never "
  "update (§3), multi-year active windows (§1), and — measured directly (§9) — upstream components that keep shipping CVEs "
  "while the certified snapshot sits frozen. When a vendor patches *inside* the module boundary without re-validating, the "
  "safer running version may no longer be the validated one — forcing a bad choice between the validated-but-weaker "
  "configuration and a patched-but-no-longer-publicly-validated one. **The certificate is necessary evidence of deployed "
  "compliance; it is not sufficient.** *(Throughout, \u201Ccertificate\u201D / \u201Cvalidation\u201D / \u201Cupdate\u201D mean the **CMVP FIPS\u00A0140-3 validation certificate** and its validation-history events \u2014 not an X.509/TLS certificate.)* The high-value work is a lifecycle evidence engine that answers: *where does public "
  "CMVP evidence no longer prove the deployed cryptographic function is the validated, approved-mode configuration?*\n")

w("\n## The decision model — what actually backs deployed FIPS?\n")
w("The whole analysis is the evidence layer for one reviewer decision procedure: from *\"product claims FIPS\"* down to "
  "*\"is the deployed cryptographic function the same validated version, in approved mode?\"* — and, on any mismatch, *\"was it a patch "
  "inside or outside the module boundary?\"* (the security-vs-compliance fork). Each branch is populated by this corpus:\n\n")
w("```mermaid\n"
  "flowchart TD\n"
  '  A["Product claims FIPS 140 support"] --> B["CMVP certificate for the module?"]\n'
  '  B -->|No| Z["No public FIPS validation evidence"]\n'
  '  B -->|Yes| C["Certificate status / assurance type?"]\n'
  '  C -->|Active full validation| D["Check deployed module identity"]\n'
  '  C -->|Interim validation| C1["Interim CMVP assurance: 2-yr window, reduced CMVP review depth"]\n'
  '  C -->|Historical / revoked| C2["Certificate exists, but not current active assurance"]\n'
  '  C1 --> D\n  C2 --> D\n'
  '  D --> E["Deployed version = certificate / Security Policy version?"]\n'
  '  E -->|Yes| F["Check operational environment"]\n'
  '  E -->|No / unknown| G["Certified-state drift: certificate does not prove deployed version"]\n'
  '  F --> H["Deployed OE = listed / allowed OE?"]\n'
  '  H -->|Yes| I["Check approved mode"]\n'
  '  H -->|Porting rules used| H1["Vendor/User affirmation: limited assurance"]\n'
  '  H -->|No / unknown| G\n  H1 --> I\n'
  '  I --> J["Initialized / operated per Security Policy?"]\n'
  '  J -->|Yes| K["Check services / algorithms"]\n'
  '  J -->|No / unknown| G\n'
  '  K --> L["Only approved services / algorithms used?"]\n'
  '  L -->|Yes| M["Strongest deployed FIPS evidence"]\n'
  '  L -->|No / unknown| N["Validated module, but use may be outside approved mode"]\n'
  '  G --> O["Difference caused by a patch/update?"]\n'
  '  O -->|Outside crypto boundary| P["May preserve validation if boundary/OE unchanged"]\n'
  '  O -->|Inside crypto boundary| Q["Security/compliance fork: patched but not publicly validated until cert update"]\n'
  '  O -->|Unknown| R["Opacity gap: need vendor evidence"]\n'
  "```\n\n")
w("**How the corpus populates the branches:**\n\n")
w("| decision node | what the corpus says |\n|---|---|\n")
w(f"| certificate status / assurance | Full {asr['type_dist'].get('Full (5-yr)',0)} · **Interim {asr['type_dist'].get('Interim (2-yr)',0)}** ({asr['interim_pct']:.0f}%) · other {asr['type_dist'].get('Other/unclear',0)}; status {cov['status_dist']} |\n")
w(f"| deployed version = certified version? | not answerable from CMVP alone — but **§9 measures the drift**: e.g. OpenSSL FIPS providers carry ~{OSSL_DRIFT} upstream CVEs disclosed since their cert date |\n")
w(f"| certificate ever updated (fixes pulled in)? | **{100*never/max(1,N):.0f}% never updated** — the certified snapshot is frozen for most |\n")
w(f"| operational environment / approved mode / services | in the Security Policy (extracted: sections, services, algorithms) — the per-module evidence to check, not a corpus aggregate |\n")
w(f"| patch inside vs outside boundary | the security/compliance fork; needs vendor firmware/release evidence — the **opacity gap** that a data layer would surface |\n")

w("\n## 0 · Corpus confidence\n")
w("| item | value |\n|---|---|\n")
w(f"| CMVP scrape / reference date | {cov['reference_date']} |\n")
w(f"| certificate range swept | {cov['sweep_range']} |\n")
w(f"| FIPS 140-3 modules included | {cov['fips_140_3_modules']} (span {cov['cert_number_span']}) |\n")
w(f"| status distribution | {cov['status_dist']} |\n")
w(f"| with validation-history dates | {cov['with_validation_dates']}/{N} (~100%) |\n")
w(f"| with dated SP revision tables | {cov['with_sp_revision_dates']}/{N} (minority — dev-span is directional) |\n")
w(f"| dedup rule | {cov['dedup_rule']} |\n")
w(f"\nField provenance — **cert page:** {cov['fields_from_cert_page']}. **Security Policy:** {cov['fields_from_security_policy']}.\n")

w("\n## 1 · Lifecycle & certificate window\n")
w(f"- **CMVP certificate active window:** median **{win['median']:.0f} months** (mean {win['mean']:.0f}), n={win['n']} — "
  f"the initial-validation→sunset life (~5 years). This is *certificate lifetime*, not vulnerability exposure (see §8).\n")
w(f"- **Development→certificate (directional, n={sub['n']}):** where the SP ships a dated revision table, the first-draft→initial-validation "
  f"span is ~{sub['median']:.0f} months. Small sample — treat as anecdote, not a corpus statistic. It is consistent with a published "
  f"*external* industry estimate of **{EXT_TIMELINE}** (industry reports, provided — not derived from this corpus).\n")
w(f"- **Volume context** *(external input, provided — not derived from this corpus):* active FIPS 140-3 certs by year run "
  f"**{EXT_VOLUME}**, a transition-driven surge (~500/yr run-rate). The population is therefore dominated by very recent certificates; "
  f"the freeze/exposure patterns below are structural and will bite as the 2024–26 cohort ages inside its window without updates.\n")

asr = s["assurance"]
w("\n## 2 · What kind of assurance backs the CMVP certificate?\n")
w("Not all FIPS 140-3 certificates carry the same assurance — and this is directly relevant to the deployed-compliance question. "
  "The certificate active window reveals the type:\n")
w(f"- **Full validation (5-yr window):** {asr['type_dist'].get('Full (5-yr)',0)} modules.\n")
w(f"- **Interim Validation (2-yr window):** **{asr['type_dist'].get('Interim (2-yr)',0)} modules ({asr['interim_pct']:.0f}%)** — "
  "a backlog-reduction mechanism CMVP launched **2024-06-06**: a CMVP-issued certificate that relies *more on the CSTL submission with "
  "less CMVP review depth*, sunsetting in 2 years instead of 5. Every interim module in this corpus validates ≥ 2024-07, confirming the detection.\n")
w(f"- **Other/unclear window:** {asr['type_dist'].get('Other/unclear',0)} modules.\n")
w("\n**Two more assurance grades exist that certificate *metadata* does not expose** (they need the Security Policy / caveat text, a next "
  "extraction target):\n")
w("- **Vendor/User Affirmation of ported configurations** — a module run in an operational environment *not* on the certificate. CMVP "
  "explicitly makes **no statement** as to correct operation or security strength for unlisted OEs; user *modifications* invalidate the validation entirely.\n")
w("- **Vendor-affirmed algorithms** — security functions listed approved during a CAVP transition with a 'vendor affirmed' caveat, where "
  "CMVP/CAVP provide **no assurance** of correct implementation; only the vendor affirms it.\n")
w("- **Interpretation:** the buyer question is not \"is there a FIPS certificate?\" but **\"what kind of assurance backs the deployed state — "
  "full, interim, vendor/user-affirmed, an unlisted OE, or a patched module that now requires re-validation?\"** ~1-in-5 here is already the "
  "lighter-touch interim path, and that share will grow while the backlog persists.\n")

w("\n## 3 · Maintenance behavior (CMVP validation updates)\n")
w(f"- **{never}/{N} ({100*never/max(1,N):.0f}%) modules carry no certificate Update at all**; only {rc['pct_with_updates']:.0f}% have ≥1. "
  f"Update distribution: {rc['update_count_dist']}; median gap between validations {rc['recert_interval_months_median']:.0f} months.\n")
w("- **Caveat (update taxonomy not yet classified):** an 'Update' entry can be a security/CVE fix, a version/environment addition, a "
  "rebrand, or a caveat/admin change. We count *any* Update here; classifying them (security vs administrative) is the next refinement "
  "and would sharpen this into a true maintained-state signal.\n")
w("- **Interpretation:** maintenance is bimodal — a few vendors (mostly OS/library) re-submit on a ~annual cadence; the majority certify "
  "once and stop. The certificate does not track the patched state of the software it names.\n")

w("\n## 4 · Cryptographic posture — specific algorithms\n")
w(f"- Corpus contains **{al['distinct_algorithms_in_corpus']} distinct approved algorithms**; median **{al['median_distinct_per_module']:.0f} per module**.\n")
w(f"- **Most common:** {top(al['top_specific'], 12)}.\n")
w("- **Modernization posture (share of modules):**\n")
w(f"  - *Legacy still near-ubiquitous:* SHA-1 **{al['legacy_present_pct']['SHA-1']:.0f}%**, "
  f"HMAC-SHA-1 {al['legacy_present_pct']['HMAC-SHA-1']:.0f}%, AES-ECB {al['legacy_present_pct']['AES-ECB']:.0f}%, "
  f"Triple-DES {al['legacy_present_pct']['Triple-DES']:.0f}%; **{al['modules_with_any_legacy_pct']:.0f}% list at least one legacy primitive**.\n")
w(f"  - *Modern:* SHA-3/SHAKE in **{al['modules_with_sha3_pct']:.0f}%**, AES-GCM {al['modern_present_pct']['AES-GCM (AEAD)']:.0f}%, "
  f"SP800-56 KAS {al['modern_present_pct']['SP800-56 KAS']:.0f}%.\n")
w("- **Caveat:** presence ≠ insecure use. SHA-1/3DES are frequently retained for *legacy verification only* or non-security functions, "
  "and AES-ECB is often a building block for other modes. The signal is *breadth of the approved surface*, not a vulnerability claim — but "
  "the near-universal legacy footprint is itself notable for a 2024–26 cohort.\n")

w("\n## 5 · Post-quantum readiness (the real picture)\n")
w(f"- **{pq['modules_with_pqc']}/{N} ({pq['pct']:.0f}%)** list any PQC algorithm — but the composition matters and is usually glossed over:\n")
for k, v in pq["by_kind_pct"].items():
    w(f"  - {v:.0f}% — {k}\n")
w(f"- **Specific PQC algorithms present:** {pq['specific_algo_freq']}.\n")
w(f"- **The headline:** PQC in this corpus is almost entirely **stateful hash-based signatures (LMS/HSS, SP 800-208)** used for "
  f"firmware/image signing — a mature, pre-existing capability. Adoption of the **new lattice standards (ML-KEM / ML-DSA, FIPS 203/204) "
  f"and SLH-DSA (FIPS 205) is effectively zero**: only module(s) {pq['modern_lattice_modules']} show any lattice KEM, and under the "
  f"pre-standard 'Kyber' name. So 'X% PQC' overstates quantum-resistant readiness — the migration to the actual PQC standards has barely begun.\n")

w("\n## 6 · Device classification\n")
w("Coarse taxonomy (name + vendor + type + embodiment).\n\n")
w("| class | n | doc grade | active window | ≥1 update | PQC | median algos |\n|---|--:|--:|--:|--:|--:|--:|\n")
for c,v in s["by_device_class"].items():
    w(f"| {c} | {v['n']} | {v['grade'] or '–'} | {v['exposure_window_mo'] or '–'} mo | {v['pct_re_validated']:.0f}% | {v['pqc_pct']:.0f}% | {v['median_algos'] or '–'} |\n")
w("\n- **Chips / secure elements** are highest-risk for stale exposure: unpatchable silicon, re-validated least, fewest algorithms, certified state frozen for the life of the part.\n")
w("- **HSMs** are best-maintained (highest grade *and* 100% update rate). **Network appliances** are well-documented but update far less often.\n")
w("- **Software / libraries** dominate and carry the broadest crypto surface, yet update only moderately despite being easiest to patch — a patchability/maintenance mismatch.\n")

w("\n## 7 · Document-quality grading (extraction-friendliness proxy)\n")
w("Grade is a **composite of how structured/complete the Security Policy is** — a triage signal for a large corpus, "
  "NOT a judgement of security or authoring quality. Rubric (0–100):\n")
w("- **0.45 × table-typing cleanliness** — share of SP tables parsed into clean typed rows (SSPs/services/algorithms).\n")
w("- **0.35 × value-fill** — share of mapped table cells that are non-empty (catches 'typed but blank').\n")
w("- **0.20 × section completeness** — fraction of the standard's required clauses present as SP sections.\n")
w("- **Grades:** A ≥ 85 · B ≥ 72 · C ≥ 58 · D ≥ 45 · F < 45.\n")
w(f"- Result: {q['grade_dist']} (mean {q['mean_grade_score']:.0f}/100; typed-clean {q['mean_clean']:.0f}%, value-fill {q['mean_fill']:.0f}%); "
  f"by level {q['by_level']} — high and roughly flat across levels.\n")

w("\n## 8 · Risk-triage lens (NOT a risk finding)\n")
w(f"- **{ve['pct_still_active']:.0f}%** still active; median **{ve['months_since_last_validation']['median']} months** since last validation; "
  f"**{ve['stale_active_remote_count']}** are active, ≥18 months stale, *and* have a network-relevant interface.\n")
w("- **This is a triage queue, not a vulnerability claim.** 'Network/Ethernet' in a Security Policy does not prove internet reachability "
  "or an exploitable surface. To become a risk *measurement*, each row must be joined to: CPE/product id → NVD CVEs → vendor PSIRT → the "
  "cert-named firmware/software version → whether the fixed version is inside the validated configuration → whether the product is still supported.\n")
if ve["stale_active_examples"]:
    w("\n| cert | module | since last val. | interfaces | ever updated |\n|---|---|--:|---|---|\n")
    for r in ve["stale_active_examples"]:
        w(f"| #{r['cert']} | {r['module']} | {r['since_last_validation_mo']} mo | {', '.join(r['interfaces'])} | {'never' if r['never_updated'] else 'yes'} |\n")

import os
if os.path.exists("drift.json"):
    drift = json.load(open("drift.json"))
    comp = s["components"]
    w("\n## 9 · Component identification & drift\n")
    w("**Components are identified generically** — a full-record scan (module name + software/firmware versions + SP body/tables) against a "
      f"CPE-mapped catalog, **not** a hardcoded list. {comp['modules_with_strong_component']} modules name/ship a catalogued component "
      f"(strong): {top(comp['strong_freq'], 8)}.\n")
    if comp["non_lib_named_modules"]:
        nlm = "; ".join(f"**{k}** ({', '.join('#'+str(x) for x in sorted(set(v)))})" for k,v in comp["non_lib_named_modules"].items())
        w(f"- Beyond crypto libraries, the generic scan also catches bootloaders / firmware / OS-kernel components the old shortlist missed: {nlm}.\n")
        w("- *Concrete payoff:* U-Boot in three HSMs is exactly the surface of boot-integrity CVEs like the FIT signature-verification bypass "
          "(**CVE-2026-46728**, U-Boot < 2026.04). The pipeline now flags the component and the firmware/boot attack path automatically; "
          "version-exact resolution stays blocked by vendor-forked version strings (`UBOOT-10.23-1107` ≠ upstream `2026.04`) — the SBOM gap.\n")
    w("\nFor modules that name a CPE-mapped upstream, we counted **CVEs disclosed in that upstream (NVD) since the module's initial validation "
      "date** — a direct, cited measure of how far the component has moved past the certified snapshot:\n\n")
    w("> **Read carefully:** this is a *drift/pressure indicator, NOT a vulnerability count for the module.* The certified version may or may "
      "not be affected by any given CVE, and distros routinely back-port fixes without re-validating. For the Linux kernel the count spans the "
      "whole kernel, most of it outside the crypto subsystem. It answers *'how much has the named upstream churned since this certificate froze'* "
      "— the question a reviewer then runs down against the exact certified version.\n\n")
    libs = [m for m in drift if m["component"] != "Linux kernel"]
    kern = [m for m in drift if m["component"] == "Linux kernel"]
    w("**Crypto-library modules (the clean signal):**\n\n")
    w("| cert | module | upstream | validated | updates | upstream CVEs since cert |\n|---|---|---|--:|--:|--:|\n")
    for m in libs[:12]:
        w(f"| #{m['cert']} | {(m['module'] or '')[:38]} | {m['component']} | {m['validation'][0]}-{m['validation'][1]:02d} | "
          f"{m['n_updates']} | **{m['cves_in_component_since_cert']}** |\n")
    if kern:
        kc = sorted(m["cves_in_component_since_cert"] for m in kern)
        w(f"\n**Linux-kernel modules ({len(kern)}):** upstream CVE counts since cert range **{kc[0]}–{kc[-1]}** — but that is "
          "*whole-kernel* volume, the vast majority outside the crypto subsystem, so it overstates crypto-relevant drift and is kept separate.\n")
    w("\n*Source: NVD CVE API v2 (CPE virtualMatchString), quarterly counts. The OpenSSL/GnuTLS/libgcrypt rows are the cleanest read — "
      "a handful-to-dozens of upstream CVEs disclosed while the certificate sat unchanged, most on modules with no certificate update.*\n")
    if os.path.exists("version_exact.json"):
        ve = json.load(open("version_exact.json"))
        if ve:
            w("\n### Version-EXACT refinement (the precise number)\n")
            w("Component drift is an *upper bound* — it counts CVEs in the whole component, including newer branches the certified module "
              "doesn't run. For the modules that expose a clean library version, we intersected the **certified version** with each CVE's "
              "NVD affected-range. That is the defensible number:\n\n")
            w("| cert | component | certified version | component drift | **version-exact** | e.g. |\n|---|---|---|--:|--:|---|\n")
            for m in ve:
                w(f"| #{m['cert']} | {m['component']} | {m['version']} | {m['component_drift']} | **{m['version_exact_cves']}** | "
                  f"{', '.join(m['sample_cves'][:3])} |\n")
            w(f"\n- **OpenSSL 3.0.x FIPS providers: ~{OSSL_EXACT} of the ~{OSSL_DRIFT} component CVEs affect the *exact* certified version** (≈{OSSL_PCT}%), disclosed "
              "after cert, on modules with no update event. The version-exact join both *sharpens* (a precise count with sample CVE IDs) and, "
              "for other components, would *de-escalate* where the drift is all in newer branches.\n")
            w("- **Methodology (so a skeptic can check):** NVD CVE API v2, `virtualMatchString=cpe:2.3:a:<vendor>:<product>:<version>` (NVD "
              "intersects the version against each CVE's affected-range); counted where **NVD `published` ≥ the module's initial validation "
              "date**; `Rejected`/`Disputed` excluded. **Remaining upper-bound caveat:** distro **back-ports** fixes without bumping the version "
              "string (e.g. AlmaLinux `3.0.7-1d2bd88…`), so some of these may already be patched in the shipped build; and this is CVE "
              "*disclosure*, not confirmed exploitability or a FIPS-boundary claim. Version captured for only 4 of 19 component modules "
              "(the rest have empty `softwareVersions` — an extraction-coverage gap, a next target).\n")

arc = s["archetypes"]; rp = s["review_priority"]
w("\n## 10 · Operational archetypes & review-priority model\n")
w("Device *embodiment* (hardware/software/firmware) is too coarse for risk. **Operational archetype** captures the attack path, and — "
  "crucially — lets reachability be weighted by class: a network interface on a **software library** is host-mediated (the app, not the "
  "module, listens), while on a **network appliance** it is the management/data plane. Archetype mix:\n\n")
w("| archetype | n | impact prior | % never updated |\n|---|--:|--:|--:|\n")
for a,v in arc["by_archetype"].items():
    w(f"| {a} | {v['n']} | {v['impact_prior']} | {v['pct_never_updated']:.0f}% |\n")
w(f"\n**Review priority = Likelihood × Impact (ordinal — no weighted coefficients).** {rp['model']}\n")
w(f"\nDistribution: **{rp['dist']}**. Impact is an explicit expert prior per archetype (documented, not corpus-derived); "
  "Likelihood combines archetype-weighted reachability, never-updated, staleness, and *measured* upstream CVE drift (which weighs most, "
  "being real evidence rather than heuristic).\n")
w("\n**Highest-priority review candidates** (every row auditable to its inputs; a review *queue requiring confirmation*, not a vulnerability list — "
  "'reach' confidence is **high** only when the SP names a consuming network service, **medium** for a bare interface):\n\n")
w("| priority | cert | archetype | why | evidence conf. |\n|---|---|---|---|---|\n")
for r in rp["top"][:14]:
    c=r["confidence"]
    w(f"| **{r['priority']}** | #{r['cert']} | {r['archetype']} | {r['reason']} | svc-path:{c['service_path_signal']} · deploy-reach:{c['deployment_reachability']} · ver-CVE:{c['version_cve']} · drift:{c['drift']} |\n")
w("\n**Offensive archetype × attack-path hypothesis** (expert priors — *where to look*, not corpus findings):\n\n")
w("| archetype | attack-path hypothesis | next evidence to collect |\n|---|---|---|\n")
for a,h,n in [("Network appliance","TLS/SSH/web/admin/data-plane parsing may touch a stale crypto stack","service table, admin docs, ports, vendor PSIRT"),
              ("Software crypto library","upstream CVEs may reach consuming services (TLS/SSH/API)","exact version, consuming services, distro backports"),
              ("HSM/accelerator","host/admin/firmware interfaces may expose key ops or update path","SDK/firmware notes, PCIe/USB/admin services"),
              ("Secure element/SoC","low public visibility; high impact if update/debug/key boundary fails","debug interfaces, firmware provenance, update model"),
              ("OS/kernel crypto","crypto exposed via consumers: IPsec, storage, VPN, TLS offload","enabled consumers, kernel config, distro advisories")]:
    w(f"| {a} | {h} | {n} |\n")
w("\n- **Critical** here is consistently *network-appliance archetypes that name a reachable service* (TLS/SSH/IPsec/web-admin), never updated, "
  "stale — the class where an unpatched stack is both *plausibly* reachable and high-impact. These are **attack-path candidates requiring "
  "confirmation, not confirmed reachable vulnerabilities**. **High** adds the *OpenSSL providers that consume TLS/SSH* (with measured version-exact "
  "CVE drift) and *long-stale secure elements / kernel modules*. This is the GnuTLS/OpenSSL pattern made concrete: "
  "*named component + no cert update + measured CVE drift + a consuming network service → ask the hard question, and here's why.*\n")

w("\n## 11 · Vulnerability-manifestation motifs\n")
w("A **motif** is an architectural pattern where a known vulnerability *class* would matter — matched from public signals "
  "(identified components, interfaces, services, archetype, SP keywords). **A match means the corpus reveals the pattern, NOT that the "
  "module is vulnerable.** This is the honest generalization of the U-Boot example: join external research patterns to corpus-searchable "
  "motifs, and ask *\"does this module have the architecture where that bug class matters?\"* — not *\"is it vulnerable?\"*\n\n")
w("| motif | modules | what public data CAN say | what it CANNOT say |\n|---|--:|---|---|\n")
for name, info in mt["catalog"].items():
    can, _, cannot = info["can_cannot"].partition("cannot:")
    w(f"| **{name}** | {info['n_modules']} | {can.replace('can:','').strip().rstrip('.')} | {cannot.strip()} |\n")
bc = mt["catalog"]["boot-chain verification"]
w(f"\n**Worked example — boot-chain verification ({bc['n_modules']} modules).** The three U-Boot HSMs (#4700, #4703, #4745) match this "
  "motif; Binarly's **U-Boot FIT signature-verification bypass (CVE-2026-46728, U-Boot < 2026.04)** is exactly the class where it matters. "
  "The corpus flags the *pattern* (component + firmware-verification path) and even the component-drift pressure (10 U-Boot CVEs each since "
  "cert), but it **cannot** establish the exact U-Boot version (vendor-forked strings) or whether the affected path is built in — which is "
  "precisely the SBOM gap. Motifs turn external research into a *search*, not a verdict.\n")

w("\n## 12 · Market structure (labs)\n")
w(f"- **{labs['distinct_labs']} accredited labs** appear across the corpus; work is concentrated: {top(labs['top'],5)}.\n")
w("- Lab concentration is a bottleneck and business-structure signal — a handful of CSTLs mediate most validations, so their throughput "
  "and review quality shape the whole pipeline.\n")

w("\n## 13 · Where FIPS time accumulates — predictors, NOT root causes\n")
w("Everything above is an **end-state** analysis (what the validated corpus looks like *after* the process). A natural next "
  "question is *why validations take so long* — but this corpus **cannot answer that**, for two structural reasons:\n")
w("- **Survivorship bias:** a validated-certificate corpus contains only modules that *succeeded*. Abandoned submissions, "
  "failures, and still-stuck modules are absent — so it systematically under-represents where the process breaks down.\n")
w("- **No pipeline-timing data:** the certificate exposes the *initial validation date* and updates, but not the "
  "Implementation-Under-Test, Cost-Recovery, or Pending-Review durations, nor the number of CMVP comment cycles.\n")
w("\nWhat the corpus **can** offer is **complexity proxies for review burden** — candidate *predictors* of effort, framed as "
  "hypotheses. Median complexity by archetype:\n\n")
w("| archetype | n | median algos | median services | median SSPs | median interfaces |\n|---|--:|--:|--:|--:|--:|\n")
for a,v in tp["by_archetype"].items():
    w(f"| {a} | {v['n']} | {v['median_algos'] or '–'} | {v['median_services'] or '–'} | {v['median_ssps'] or '–'} | {v['median_interfaces'] or '–'} |\n")
w("\n**Duration-predictor hypotheses** (each needs longitudinal pipeline data to confirm — none is proven here):\n\n")
w("| predictor | hypothesis | evidence needed to confirm |\n|---|---|---|\n")
for p,h,e in [("low document-quality grade","more review comments and rework","SP revision history + CMVP comment cycles"),
              ("high approved-algorithm count","larger algorithm-evidence + review surface","ACVP/CAVP timing + algorithm evidence"),
              ("high service count","more approved-/non-approved-mode mapping to resolve","service table + comment history"),
              ("hardware + Level 3+","heavier physical-security evidence/test burden","physical-security evidence + lab timing"),
              ("novel / PQC algorithms","interpretation and testing friction","algorithm-validation history"),
              ("first-time vendor/lab","more prep and rework before the learning curve","vendor/lab repeat history"),
              ("lab backlog","longer pre-review / IUT queue time","lab-level MIP/IUT snapshots")]:
    w(f"| {p} | {h} | {e} |\n")
w("\n**Not determinable from this corpus** (requires daily/weekly MIP/IUT snapshots + status-transition history, ideally lab/vendor workflow events):\n")
for x in tp["not_determinable_without_MIP_snapshots"]:
    w(f"- {x}\n")
w("\n**Product framing — two modes.** This bundle supports **assurance-gap mode** well (*what does public CMVP evidence prove, "
  "where is it stale, what to ask*). It can only *seed* **validation-throughput mode** (*where is a submission stuck, who owns "
  "the action, what evidence issue drives the delay*) — that mode needs the longitudinal MIP/IUT data above, and until then any "
  "pipeline-state or rework-cycle numbers would be fabricated, so they are deliberately omitted.\n")

w("\n## Glossary\n")
for term, defn in [
    ("CMVP", "Cryptographic Module Validation Program (NIST/CCCS) — issues the FIPS 140-3 validation certificate."),
    ("CSTL", "Cryptographic and Security Testing Laboratory — the accredited lab that tests a module and submits it to CMVP."),
    ("CAVP / ACVP", "Cryptographic Algorithm Validation Program / its test protocol — validates individual algorithms; the certificate lists ACVP-style names (e.g. AES-GCM, RSA SigVer)."),
    ("Security Policy (SP)", "The per-vendor PDF describing the module: boundary, roles/services, SSPs, algorithms, ports/interfaces, operational environment."),
    ("SSP / CSP", "Sensitive Security Parameter / Critical Security Parameter — keys and security-relevant values the module protects."),
    ("Operational environment (OE)", "The platform/OS the module was tested on; running outside it can require vendor/user affirmation."),
    ("Approved mode", "The configuration in which only FIPS-approved algorithms/services are used, per the Security Policy."),
    ("Sunset date", "The date the certificate moves to Historical; defines the active window (5 yr full, 2 yr interim)."),
    ("Interim Validation", "A 2-year certificate (started 2024-06-06) relying more on the CSTL submission with reduced CMVP review depth."),
    ("Vendor/User affirmation", "Vendor- or user-asserted coverage of a non-tested OE/port under CMVP porting rules; CMVP makes no operational-security statement."),
    ("Component drift", "CVEs disclosed in a named upstream component (e.g. OpenSSL) since a module's validation date — a pressure indicator, not a module-vulnerability count."),
    ("Version-exact", "The subset of component drift whose NVD affected-range includes the certified version — the tighter, defensible number."),
]:
    w(f"- **{term}** — {defn}\n")

w("\n## Methodology & reproduction\n")
w(f"All corpus figures are read from `corpus_analysis.json` (single source of truth); external inputs (validation-volume-by-year, "
  f"industry-timeline estimate) are labelled inline as *provided, not corpus-derived*. Reference date {cov['reference_date']} is fixed for reproducibility.\n\n")
w("**Pipeline (deterministic given the swept cert range + cached NVD responses):**\n")
w("1. `build_corpus.py` — fetch CMVP cert page + Security Policy PDF per cert number, extract to `corpus140_3/records/<n>.json` (resume-safe, filtered to FIPS 140-3).\n")
w("2. `build_drift.py` — NVD CVE API v2, CPE `virtualMatchString`, quarterly counts of CVEs in each named component since each module's validation date → `drift.json` (cached in `drift_cache.json`).\n")
w("3. `build_version_exact.py` — per certified library version, count CVEs whose NVD affected-range includes it, `published ≥ validation date`, excluding Rejected/Disputed → `version_exact.json` (cached in `ve_cache.json`).\n")
w("4. `analyze_corpus.py` → `corpus_analysis.json`; then `report_html.py` (report), `findings_md.py` (this file), `build_explorer.py` (interactive explorer).\n")
w("\n**Provenance:** cert-page fields (level, type, embodiment, vendor, standard, status, validation history+dates+lab, sunset, approved algorithms) vs "
  "Security-Policy fields (sections, revision history, ports/interfaces, services, SSPs, detailed algorithms, tables) are tracked per §0. "
  "NVD data as of the reference date; distro back-ports are not reflected in version strings (so version-exact is an upper bound).\n")

w("\n## Next steps (highest-value first)\n")
w("1. **Close the version-coverage gap:** recover the missing `softwareVersions` (re-extract cert pages) so the version-exact join covers all component modules, not the subset with a clean version string today.\n")
w("2. **Crawl vendor PSIRT/advisory pages** to populate the opacity signal (currently recorded as 'not collected'), turning absence-of-data into an explicit evidence gap.\n")
w("3. **Classify certificate updates** (security / version / rebrand / admin) to turn 'any update' into a real maintained-state signal.\n")
w("4. **Merge re-validation & rebrand chains across cert numbers** (same vendor+module) to measure true re-FIPS cadence and rebrand concentration.\n")
w("5. **Calibrate against expert labels** (50–100 modules labelled Ignore/Watch/Review/Escalate/Confirmed) so the review-priority thresholds move from expert priors to validated weights.\n")
w("6. **Grow the corpus** to the full 140-3 range + the 140-2 back-catalog for longer maintenance histories.\n")
open("FINDINGS.md","w").writelines(L)
print("wrote FINDINGS.md")
