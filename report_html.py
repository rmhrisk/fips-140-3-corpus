#!/usr/bin/env python3
"""Render corpus_analysis.json into a self-contained findings report (no deps)."""
import json, html, sys, re

def esc(s): return html.escape(str(s))

def bars(d, unit="", maxw=None, fmt=str):
    if not d: return "<p class='muted'>no data</p>"
    items = list(d.items())
    mx = maxw or max((v for _, v in items if isinstance(v,(int,float))), default=1) or 1
    rows = []
    for k, v in items:
        w = 100*v/mx if isinstance(v,(int,float)) else 0
        rows.append(f"<div class='bar'><span class='bl'>{esc(k)}</span>"
                    f"<span class='bt'><span class='bf' style='width:{w:.0f}%'></span></span>"
                    f"<span class='bv'>{esc(fmt(v))}{esc(unit)}</span></div>")
    return "".join(rows)

def kpi(label, value, sub=""):
    return (f"<div class='kpi'><div class='kv'>{esc(value)}</div>"
            f"<div class='kl'>{esc(label)}</div>{f'<div class=ks>{esc(sub)}</div>' if sub else ''}</div>")

def main():
    d = json.load(open(sys.argv[1] if len(sys.argv)>1 else "corpus_analysis.json"))
    s = d["summary"]; recs = d["records"]
    # Modules with full pdfplumber SP extraction. Metrics that read the SP structure
    # (TCB surfaces, document quality, review-priority) are computed over this subset;
    # lifecycle / archetype / algorithm / drift metrics use the whole corpus.
    frecs = [r for r in recs if r.get("full_extraction")]
    NF = s.get("n_full_extraction", len(frecs))
    lc, rc, ex, q, ve = s["lifecycle"], s["recertification"], s["exposure"], s["quality"], s["vuln_exposure"]
    al, pq, cov, labs = s["algorithms"], s["pqc"], s["coverage"], s["labs"]
    asr = s["assurance"]
    import os as _os
    _ve = json.load(open("version_exact.json")) if _os.path.exists("version_exact.json") else []
    _ossl = [m for m in _ve if m["component"]=="OpenSSL"]
    if _ossl:
        OSSL_DRIFT=f"{min(m['component_drift'] for m in _ossl)}\u2013{max(m['component_drift'] for m in _ossl)}"
        OSSL_EXACT=f"{min(m['version_exact_cves'] for m in _ossl)}\u2013{max(m['version_exact_cves'] for m in _ossl)}"
        OSSL_PCT=round(100*sum(m['version_exact_cves'] for m in _ossl)/max(1,sum(m['component_drift'] for m in _ossl)))
    else: OSSL_DRIFT=OSSL_EXACT="n/a"; OSSL_PCT=0
    sub = lc["submission_months (SP first->initial validation)"]
    win = lc["exposure_window_months (validation->sunset)"]
    kpi_strip = "".join([
        kpi("modules analyzed", s["n"], esc(cov['cert_number_span'])),
        kpi("median active window", f"{win['median']:.0f} mo", "listed-valid: validation → sunset"),
        kpi("no recorded update", f"{100-rc['pct_with_updates']:.0f}%", f"{s['n']-rc['modules_with_updates']} of {s['n']} certificates"),
        kpi("lattice PQC present", f"{pq['by_kind_pct'].get('ML-KEM (FIPS 203)',0):.0f}%", "ML-KEM / ML-DSA / SLH-DSA"),
        kpi("carry a legacy primitive", f"{al['modules_with_any_legacy_pct']:.0f}%", "SHA-1 / ECB / 3DES"),
    ])
    mast = (
        "<header class='mast'><div class='mast-in'>"
        "<div class='eyebrow'>CMVP · FIPS 140-3 validated-module corpus</div>"
        "<h1>What a FIPS 140 certificate actually tells you</h1>"
        "<p class='dek'>Read across the public corpus, FIPS certificates and their Security Policies are a structured record of how cryptographic systems are built, validated, and maintained. They show the trusted-computing-base surfaces around each module, how far its components have drifted since validation, and where a security review should look first.</p>"
        f"<div class='meta'><span>{s['n']} modules</span><span>{NF} with full SP extraction</span><span>ref {esc(cov['reference_date'])}</span>"
        f"<span>{esc(cov['cert_number_span'])}</span><span>source: CMVP + NVD</span></div>"
        f"<div class='kpis'>{kpi_strip}</div>"
        "</div></header>"
    )
    lead = (
        "<p class='lead'><b>Executive finding.</b> A FIPS certificate and its Security Policy are a structured, corpus-wide security record, and this report reads them for what they reliably deliver: a map of the <b>trusted-computing-base surfaces</b> around each module (§6), a measure of how far its named components have <b>drifted</b> since validation (§5), and a ranked view of <b>where a review should look first</b> (§9). A certificate attests one module <b>version</b>, in one approved-mode configuration, at one moment, so it is best read as a map of what to verify in a deployment, which is exactly what makes these artifacts a fast way to aim that verification.</p>"
        "<p class='fine'><b>Terminology.</b> Throughout, “certificate” / “validation” / “update” refer to the "
        "<b>CMVP FIPS 140-3 validation certificate</b> and its validation-history events — <b>not</b> an X.509/TLS certificate.</p>"
        f"<p class='fine'><b>Corpus composition.</b> The corpus is a near-census of the {s['n']} FIPS 140-3 modules "
        f"validated in cert window {esc(cov['cert_number_span'])}. Lifecycle, archetype, algorithm and component-drift "
        f"findings use all {s['n']}. The Security-Policy-structure findings, TCB surfaces (§6), review-priority (§9, §10) "
        f"and document quality (§11), require the full pdfplumber SP extraction and are computed over the <b>{NF}</b> "
        f"modules that carry it; the rest are metadata-and-text records fetched from CMVP.</p>"
    )
    P = []

    P.append("<div class='part'><div class='pk'>Part I</div><div class='pt'>What a certificate proves</div><div class='pd'>A CMVP certificate attests a module version, once. This part establishes exactly what that certifies, and how to read it.</div></div>")
    P.append("<h2>0 · Corpus confidence</h2>")
    covrows = [("reference date", cov['reference_date']), ("range swept", cov['sweep_range']),
               ("140-3 modules", f"{cov['fips_140_3_modules']} (span {cov['cert_number_span']})"),
               ("status", cov['status_dist']), ("with validation dates", f"{cov['with_validation_dates']}/{s['n']}"),
               ("with dated SP revision tables", f"{cov['with_sp_revision_dates']}/{s['n']} (dev-span directional)"),
               ("dedup rule", cov['dedup_rule'])]
    P.append("<div class='card'><table><tbody>" +
             "".join(f"<tr><td class='muted'>{esc(k)}</td><td>{esc(v)}</td></tr>" for k,v in covrows) +
             "</tbody></table></div>")

    P.append("<h2>The decision model — what actually backs deployed FIPS?</h2>")
    P.append("<p class='muted'>The whole analysis is the evidence layer for one reviewer decision: from “product claims FIPS” down to "
             "“is the deployed crypto function the <i>same validated version, in approved mode</i>?” — and on any mismatch, “was it a patch "
             "<i>inside</i> or <i>outside</i> the module boundary?” (the security-vs-compliance fork). Corpus data populates the branches below.</p>")
    P.append("<div class='card'><pre class='mermaid'>"
             "flowchart TD\n"
             '  A["Product claims FIPS 140 support"] --> B["CMVP certificate for the module?"]\n'
             '  B -->|No| Z["No public FIPS validation evidence"]\n'
             '  B -->|Yes| C["Certificate status / assurance type?"]\n'
             '  C -->|Active full validation| D["Check deployed module identity"]\n'
             '  C -->|Interim validation| C1["Interim CMVP assurance<br/>2-yr window, reduced review depth"]\n'
             '  C -->|Historical / revoked| C2["Exists, but not current active assurance"]\n'
             '  C1 --> D\n  C2 --> D\n'
             '  D --> E["Deployed version = certificate version?"]\n'
             '  E -->|Yes| F["Check operational environment"]\n'
             '  E -->|No / unknown| G["Certified-state drift"]\n'
             '  F --> H["Deployed OE = listed / allowed OE?"]\n'
             '  H -->|Yes| I["Check approved mode"]\n'
             '  H -->|Porting rules used| H1["Vendor/User affirmation<br/>limited assurance"]\n'
             '  H -->|No / unknown| G\n  H1 --> I\n'
             '  I --> J["Operated per Security Policy?"]\n'
             '  J -->|Yes| K["Check services / algorithms"]\n'
             '  J -->|No / unknown| G\n'
             '  K --> L["Only approved services / algorithms?"]\n'
             '  L -->|Yes| M["Strongest deployed FIPS evidence"]\n'
             '  L -->|No / unknown| N["Validated module, use outside approved mode"]\n'
             '  G --> O["Caused by a patch/update?"]\n'
             '  O -->|Outside crypto boundary| P1["May preserve validation if boundary/OE unchanged"]\n'
             '  O -->|Inside crypto boundary| Q["Security/compliance fork:<br/>patched but not validated until cert update"]\n'
             '  O -->|Unknown| R["Opacity gap: need vendor evidence"]\n'
             "</pre></div>")
    P.append(f"<p class='muted'>Corpus populates the branches: <b>status/assurance</b> — Full {asr['type_dist'].get('Full (5-yr)',0)} · "
             f"Interim {asr['type_dist'].get('Interim (2-yr)',0)} · other {asr['type_dist'].get('Other/unclear',0)}; "
             f"<b>ever updated</b> — {rc['pct_with_updates']:.0f}% (so most are frozen at the “version = certified?” branch); "
             f"<b>drift</b> — measured in §5 (OpenSSL providers ~{OSSL_DRIFT} upstream CVEs since cert); the <b>patch-boundary fork</b> and "
             f"OE/mode branches need per-module Security-Policy + vendor evidence (the opacity gap a data layer surfaces).</p>")

    P.append("<div class='part'><div class='pk'>Part II</div><div class='pt'>The certified state, and how it freezes</div><div class='pd'>How long certificates stay valid, how rarely they are re-validated, and how that frozen snapshot drifts.</div></div>")
    P.append("<h2>1 · Lifecycle &amp; certificate window</h2>")
    P.append("<div class='cols'>")
    P.append(f"<div class='card'><h3>CMVP certificate active window (n={win['n']})</h3>"
             f"<p class='big'>{win['median']:.0f} months</p><p class='muted'>median (mean {win['mean']:.0f}). The "
             f"<b>active window</b> is how long CMVP lists a certificate as valid, from initial validation to sunset "
             f"(its removal from the active list). It is the module's certification lifetime, not an X.509 certificate's "
             f"validity period, and it measures the certified state's shelf life, not vulnerability exposure (see §9).</p></div>")
    P.append(f"<div class='card'><h3>Development→certificate <span class='muted'>(directional, n={sub['n']})</span></h3>"
             f"<p class='big'>~{sub['median']:.0f} mo</p><p class='muted'>where the SP ships a dated revision table (small sample — anecdote, "
             f"not a corpus statistic). Consistent with a published <i>external</i> industry estimate (~19 mo post-submission / ~24–36 mo end-to-end; provided, not corpus-derived).</p></div>")
    P.append("</div>")
    P.append("<p class='muted'>Volume context <i>(external input, provided \u2014 not corpus-derived)</i>: active 140-3 certs by year run 2022:6 · 2023:6 · 2024:176 · 2025:163 · 2026-YTD:265 \u2014 a "
             "transition-driven surge (~500/yr). The population skews to very recent certificates, so the freeze/exposure patterns are "
             "structural and will bite as the 2024–26 cohort ages inside its window without updates.</p>")
    asr = s["assurance"]
    P.append("<h3 style='margin-top:16px'>Assurance type — certificates differ in what backs them</h3>")
    P.append(f"<div class='cols'><div class='card'>{bars(asr['type_dist'],' mod')}</div>"
             f"<div class='card muted'><b>Interim Validation ({asr['interim_pct']:.0f}% here)</b> — a backlog-reduction path CMVP launched "
             "2024-06-06: CMVP-issued but relying more on the CSTL submission with less CMVP review depth, initially with a shorter active "
             "window (it can follow a path to a full five-year period). Detected authoritatively from the CMVP <b>caveat</b> ('Interim "
             "validation…'), not from certificate duration. Two further grades — <b>vendor/user affirmation</b> (unlisted OE, CMVP makes "
             "no statement) and <b>vendor-affirmed algorithms</b> (CAVP transition, no CMVP/CAVP assurance) — aren't in cert metadata but matter: "
             "the buyer question is <i>what kind of assurance backs the deployed state</i>, not merely 'is there a certificate?'</div></div>")

    P.append("<h2>2 · CMVP re-validation cadence</h2>")
    P.append("<p class='muted'>How often a certificate carries an Update entry (any kind — security, version, OE, administrative, or rebrand; "
             "we do <i>not</i> yet classify the type). If a certificate is never updated, public CMVP evidence does not show that later "
             "product fixes, firmware updates, or dependency changes are part of the validated configuration.</p>")
    P.append("<div class='cols'>")
    upd_dist = {f'{k} update(s)':v for k,v in sorted(rc['update_count_dist'].items(),key=lambda x:int(x[0]))}
    pct_upd = f"{rc['pct_with_updates']:.0f}%"; gap = f"{rc['recert_interval_months_median']:.0f} mo"
    P.append(f"<div class='card'><h3>Updates per module</h3>{bars(upd_dist, ' modules')}</div>")
    P.append(f"<div class='card'><h3>Cadence</h3>{kpi('≥ 1 CMVP validation update', pct_upd)}"
             f"{kpi('median gap between validations', gap)}"
             f"{kpi('avg updates / module', rc['avg_updates_per_module'])}</div>")
    P.append("</div>")
    fam = s.get("families", {})
    if fam:
        frows = "".join(f"<tr><td>{esc(x['family'])}</td>"
                        f"<td class='muted'>{', '.join('#'+str(c) for c in x['certs'])}</td></tr>"
                        for x in fam.get("largest", [])[:6])
        P.append("<div class='card'><h3>Certificate families and successors <span class='muted'>(the “never updated” caveat)</span></h3>"
                 "<p class='muted'>A per-certificate “never updated” can understate maintenance: a vendor often validates a "
                 "<b>successor under a new certificate number</b> instead of updating the old one. Clustering the "
                 f"{s['n']} certificates into <b>{fam['n_families']} product families</b> (normalized vendor + de-noised module "
                 f"name; {fam['n_multi_cert_families']} span more than one certificate) shows "
                 f"<b>{fam['never_updated_with_successor']} of the {fam['never_updated']} never-updated modules "
                 f"({fam['never_updated_with_successor_pct']:.0f}%)</b> have a later-validated family-mate — a likely successor "
                 "rather than an abandoned certificate. It is a conservative, deterministic lower bound (no NIST “replaced-by” "
                 "data), so the true successor share is at least this; the rest is the genuinely-frozen population.</p>"
                 f"<table><thead><tr><th>largest product families</th><th>certificates</th></tr></thead><tbody>{frows}</tbody></table></div>")

    P.append("<div class='part'><div class='pk'>Part III</div><div class='pt'>Inside the validated boundary</div><div class='pd'>What cryptography the certificate actually covers, from the algorithms in use to the legacy still present to post-quantum readiness.</div></div>")
    P.append("<h2>3 · Cryptographic posture — specific algorithms</h2>")
    P.append(f"<p class='muted'>{al['distinct_algorithms_in_corpus']} distinct normalized approved-algorithm labels (operation-level, e.g. “RSA SigVer”, “ECDSA KeyGen”, not distinct primitives); median "
             f"{al['median_distinct_per_module']:.0f} per module. <b>Presence ≠ insecure use</b> — legacy primitives are often retained "
             f"for verify-only/legacy paths, and AES-ECB is a building block; the signal is breadth of the approved surface.</p>")
    P.append("<div class='cols'>")
    P.append(f"<div class='card'><h3>Most common algorithms</h3>{bars(dict(list(al['top_specific'].items())[:14]),' mod')}</div>")
    lm = {k:v for k,v in al['legacy_present_pct'].items()}; mm = {k:v for k,v in al['modern_present_pct'].items()}
    P.append(f"<div class='card'><h3>Legacy present (% of modules)</h3>{bars(lm,'%',100)}"
             f"<h3 style='margin-top:12px'>Modern present (%)</h3>{bars(mm,'%',100)}</div>")
    P.append("</div>")

    P.append("<h2>4 · Post-quantum readiness</h2>")
    P.append(f"<p class='muted'>{pq['modules_with_pqc']}/{s['n']} ({pq['pct']:.0f}%) list any PQC algorithm — but composition matters: "
             f"it is almost entirely <b>stateful hash-based signatures (LMS/HSS, SP 800-208)</b> for firmware signing. Adoption of the new "
             f"lattice standards <b>ML-KEM/ML-DSA (FIPS 203/204) and SLH-DSA (FIPS 205) is effectively zero</b> "
             f"(lattice module(s): {esc(pq['modern_lattice_modules']) or 'none'}, under the pre-standard 'Kyber' name).</p>")
    P.append("<div class='cols'>")
    P.append(f"<div class='card'><h3>PQC by NIST family (% of modules)</h3>{bars(pq['by_kind_pct'],'%',100)}</div>")
    P.append(f"<div class='card'><h3>Specific PQC algorithms</h3>{bars(pq['specific_algo_freq'],' mod')}</div>")
    P.append("</div>")

    P.append("<div class='part'><div class='pk'>Part IV</div><div class='pt'>The trusted computing base around the module</div><div class='pd'>What the Security Policy reveals about the boot chain, firmware, components, and interfaces the module's security rests on.</div></div>")
    import os
    if os.path.exists("drift.json"):
        drift = json.load(open("drift.json"))
        P.append("<h2>5 · Component identification &amp; drift</h2>")
        comp = s["components"]
        P.append("<p class='muted'>Components are identified <b>generically</b> — a full-record scan (module name + software/firmware "
                 "versions + SP body/tables) against an extensible, CPE-mapped catalog (generic whole-record scanning rather than certificate-specific rules). <b>Strong</b> = the module names/ships "
                 "it (name/version field); a CPE enables the NVD drift join below.</p>")
        P.append("<p class='muted'>Naming the actual code is the <b>highest-resolution</b> view of a module's trust boundary the "
                 "public record offers — and the <b>sparsest</b>: it exists only where a component is named. It is the component-level "
                 "counterpart to the surface-level TCB view in §6, which stays visible for the many modules that name nothing. "
                 "Where this section goes dark, §6 still sees the surface.</p>")
        nlm = "; ".join(f"{k} ({', '.join('#'+str(x) for x in sorted(set(v)))})"
                        for k, v in comp['non_lib_named_modules'].items())
        P.append("<div class='cols'>"
                 f"<div class='card'><h3>Named components (strong, {comp['modules_with_strong_component']} modules)</h3>"
                 f"{bars(comp['strong_freq'],' mod')}</div>"
                 "<div class='card'><h3>Beyond crypto libraries</h3>"
                 "<p class='muted'>Because identification is generic, the scan also names bootloaders, firmware, and "
                 "OS-kernel components that a crypto-library shortlist would miss:</p>"
                 f"<p>{esc(nlm) or '-'}</p>"
                 "<p class='muted' style='font-size:11px'>One of these, U-Boot inside HSMs, is consequential enough for its "
                 "own spotlight below.</p></div></div>")
        # Spotlight: boot chain as a first-class security property (the setup above leads here)
        from collections import Counter as _Ct
        BOOT_MOTIFS = ("boot-chain verification", "firmware-update authentication", "HSM/SE firmware trust anchor")
        HW_ARCH = ("HSM/accelerator", "Secure element/SoC", "Network appliance")
        _mf = s.get("motifs", {}).get("freq", {})
        boot = [m for m in drift if m.get("kind") in ("bootloader", "firmware")]
        boot_any = [r for r in frecs if any(mm in (r.get("motifs") or []) for mm in BOOT_MOTIFS)]
        hw = [r for r in frecs if r.get("archetype") in HW_ARCH]
        hw_boot = [r for r in hw if any(mm in (r.get("motifs") or []) for mm in BOOT_MOTIFS)]
        boot_by_arch = _Ct(r["archetype"] for r in boot_any)
        table_block = ""
        if boot:
            brows = "".join(
                f"<tr><td>#{esc(m['cert'])}</td><td>{esc(m['module'] or '')}</td>"
                f"<td>{esc(m['component'])}</td><td class='muted'>{esc(m['version'] or '?')}</td>"
                f"<td>{esc(m['validation'][0])}-{m['validation'][1]:02d}</td>"
                f"<td><b>{esc(m['cves_in_component_since_cert'])}</b></td></tr>" for m in boot)
            table_block = (
                "<h3 style='margin-top:14px'>The bootloaders the corpus can name</h3>"
                "<p>Identifying the <i>surface</i> is generic; naming the <i>component</i> is the ceiling. Only where a module "
                "names a CPE-mappable bootloader can the corpus move from “has a boot chain” to “check this CVE.” "
                f"Today that is {len(boot)} modules, all shipping <b>U-Boot</b> inside the boundary, the exact surface Binarly's "
                "<a href='https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification' target='_blank' rel='noopener'>"
                "U-Boot FIT signature-verification bypass</a> (CVE-2026-46728, U-Boot &lt; 2026.04) targets:</p>"
                "<table><thead><tr><th>cert</th><th>module</th><th>component</th><th>version as listed</th>"
                f"<th>validated</th><th>upstream CVEs since initial validation</th></tr></thead><tbody>{brows}</tbody></table>")
        if boot_any:
            P.append(
                "<div class='card' style='border-left:3px solid var(--accent)'>"
                "<h3>The boot chain is a first-class security property</h3>"
                "<p>For a hardware crypto module the boot chain is the root of trust: if secure-boot or firmware-signature "
                "verification can be bypassed, the whole validated crypto boundary can be swapped out underneath the certificate. "
                "So the corpus treats boot integrity as a <b>population</b>, not an anecdote, keyed to archetype rather than to "
                "whether one component happened to be named. Across the archetypes where it is a core property, "
                f"<b>{len(hw_boot)} of the {len(hw)} hardware modules</b> (HSM, secure element, network appliance) expose a "
                "boot-integrity, firmware-update, or firmware-trust-anchor surface.</p>"
                "<div class='cols' style='margin-top:6px'>"
                f"<div><h3>Boot-related surface, by archetype</h3>{bars(dict(boot_by_arch.most_common()),' mod')}</div>"
                f"<div><h3>By TCB surface (§6)</h3>{bars({k: _mf[k] for k in BOOT_MOTIFS if k in _mf},' mod')}"
                "<p class='muted' style='font-size:11px'>A module can match more than one; these are architectural patterns "
                "where the bug class matters, not vulnerabilities.</p></div></div>"
                + table_block +
                "<p class='callout warn'><b>How to use this.</b> Make boot-chain review standard for <i>any</i> hardware crypto module: the corpus reliably flags the whole population that carries the surface. Where the bootloader is named, rebase its version against CVE-2026-46728; where it is not, the flagged surface is the prompt to ask the vendor for the actual boot-loader lineage. Either way the output is a concrete next step.</p></div>")
        P.append("<h3 style='margin-top:14px'>Component drift — the certified-state freeze, measured</h3>")
        P.append("<p class='muted'>For modules that wrap a well-known upstream (OpenSSL, GnuTLS, libgcrypt, Linux kernel, NSS), this counts "
                 "<b>CVEs disclosed in that upstream component (CPE-matched in NVD) since the module's initial validation date</b>. "
                 "It measures how far the upstream has moved past the certified snapshot.</p>")
        _covered = sorted({m['cert'] for m in drift})
        _bycomp = _Ct(m['component'] for m in drift)
        P.append(f"<p class='muted'><b>Coverage is component-shaped, and mostly crypto libraries.</b> A drift signal is only "
                 "possible where a module both names a component <i>and</i> that component maps to an NVD CPE. That holds for "
                 f"<b>{len(_covered)} of {s['n']}</b> modules (" + ", ".join(f"{esc(k)} {v}" for k, v in _bycomp.most_common()) +
                 f"). The other <b>{s['n']-len(_covered)}</b>, disproportionately the hardware, firmware, and appliance modules, "
                 "name no CPE-mappable component, so they get <b>no</b> component-level drift signal at all. That blank is a <b>prompt</b>: for the hardware, firmware, and appliance modules where boot and firmware integrity matter most (the spotlight above), the component is simply unnamed at this resolution, so §6 reads them at <b>surface</b> resolution instead, where they stay legible.</p>")
        P.append("<p class='callout warn'>"
                 "<b>Read carefully — this is a drift/pressure indicator, NOT a vulnerability count for the module.</b> "
                 "The certified version may or may not be affected by any given CVE, and distros routinely back-port fixes without re-validating. "
                 "For the Linux kernel the count spans the whole kernel, most of it outside the crypto subsystem. "
                 "The number answers 'how much has the named upstream churned since this certificate froze', which is the question a reviewer should then run down.</p>")
        libs = [m for m in drift if m["component"] != "Linux kernel" and m.get("kind") not in ("bootloader", "firmware")]
        kern = [m for m in drift if m["component"] == "Linux kernel"]
        drows = ""
        for m in libs:
            vdate = f"{m['validation'][0]}-{m['validation'][1]:02d}"
            drows += (f"<tr><td>#{esc(m['cert'])}</td><td>{esc(m['module'] or '')}</td><td>{esc(m['component'])}</td>"
                      f"<td>{esc(vdate)}</td><td>{esc(m['n_updates'])}</td>"
                      f"<td><b>{esc(m['cves_in_component_since_cert'])}</b></td></tr>")
        P.append(f"<div class='card'><h3>Crypto-library modules, by upstream CVE drift since validation</h3><table><thead><tr><th>cert</th><th>module</th>"
                 f"<th>upstream</th><th>validated</th><th>updates</th><th>upstream CVEs since initial validation</th></tr></thead>"
                 f"<tbody>{drows}</tbody></table>"
                 f"<p class='muted'>Source: NVD CVE API v2 (CPE virtualMatchString), quarterly counts, as of {esc(cov['reference_date'])}.</p></div>")
        if kern:
            kc = sorted(m["cves_in_component_since_cert"] for m in kern)
            P.append(f"<p class='muted'><b>Linux-kernel modules ({len(kern)}):</b> upstream CVE counts since cert range "
                     f"{kc[0]}–{kc[-1]} — but that is <i>whole-kernel</i> volume, the vast majority outside the crypto subsystem, so it "
                     f"overstates crypto-relevant drift and is kept separate from the table above.</p>")
        if os.path.exists("version_exact.json"):
            vex = json.load(open("version_exact.json"))
            if vex:
                verows = ""
                for m in vex:
                    verows += (f"<tr><td>#{esc(m['cert'])}</td><td>{esc(m['component'])}</td><td>{esc(m['version'])}</td>"
                               f"<td>{esc(m['component_drift'])}</td><td><b>{esc(m['version_exact_cves'])}</b></td>"
                               f"<td class='muted'>{esc(', '.join(m['sample_cves'][:2]))}</td></tr>")
                P.append("<div class='card'><h3>Version-exact CVEs, drift narrowed to the certified version</h3>"
                         "<p class='muted'>Drift counts the whole component, incl. newer branches the module doesn't run. Intersecting the "
                         "<b>certified version</b> with each CVE's NVD affected-range gives the defensible count:</p>"
                         f"<table><thead><tr><th>cert</th><th>component</th><th>certified ver</th><th>drift</th>"
                         f"<th>version-exact</th><th>e.g.</th></tr></thead><tbody>{verows}</tbody></table>"
                         f"<p class='muted'>~{OSSL_EXACT} of the ~{OSSL_DRIFT} OpenSSL drift CVEs affect the exact certified 3.0.x version (≈{OSSL_PCT}%). "
                         "<b>Method:</b> NVD v2 <code>virtualMatchString=cpe:…:&lt;version&gt;</code>; counted where <code>published</code> ≥ "
                         "validation date; Rejected/Disputed excluded. <b>Upper-bound caveat:</b> distros back-port fixes without bumping the "
                         "version string, and this is CVE <i>disclosure</i>, not a vuln or FIPS-boundary claim. Version captured for 4 of 19 "
                         "component modules (rest have empty softwareVersions — coverage gap).</p></div>")

    mt = s["motifs"]
    P.append("<h2>6 · TCB surfaces visible in public FIPS artifacts</h2>")
    P.append("<p class='muted'>FIPS validation certifies a defined cryptographic-module boundary; the <i>security</i> of that "
             "boundary usually depends on the surrounding <b>trusted computing base</b> (TCB): the boot chain, firmware-update "
             "path, debug/recovery controls, host/OE dependencies, network-management services, and secure-element/HSM trust "
             "anchors. A Security Policy is not an SBOM, but it is often enough to <b>sketch the core TCB surfaces</b> around the "
             "module, which is a more useful thing to ask of it than deployment proof.</p>")
    P.append("<p class='callout'><b>What “TCB surface” means here.</b> Public evidence of the mechanisms that decide whether the validated cryptographic boundary stays the code and configuration users rely on: the boot chain, firmware-update path, debug/recovery controls, host/OE dependencies, and trust anchors. Each surface below is an architectural pattern (a <i>motif</i>) matched from public signals, so <b>a match locates the surface</b> where that bug class would matter, pointing a review straight to where to look.</p>")
    P.append("<div class='card'><h3>TCB-surface frequency</h3>" + bars(mt['freq'], ' mod') + "</div>")
    TCB = {
        "boot-chain verification": ("secure/verified boot, ROM, bootloader (U-Boot), FIT image",
            "Runs before the crypto boundary; can replace or subvert validated code at the earliest root of trust."),
        "firmware-update authentication": ("firmware update, signed image, LMS/HSS, anti-rollback",
            "Governs whether patched or swapped code can enter the boundary, and whether it can be rolled back."),
        "debug/recovery interface": ("JTAG, UART, SPI, I²C, USB/DFU, recovery mode",
            "A local path that can bypass normal runtime controls and reach keys or state directly."),
        "kernel crypto consumer": ("Linux kernel, OS/kernel crypto, IPsec / dm-crypt / TLS offload",
            "The host / operational environment mediates access to the module's keys and services."),
        "network crypto parser/protocol": ("TLS / SSH / IKE via OpenSSL, GnuTLS, mbedTLS, wolfSSL",
            "The likely path where untrusted parsers and authentication controls meet the crypto."),
        "HSM/SE firmware trust anchor": ("HSM, secure element / SoC, sub-chip, firmware versions",
            "High-impact root of key custody; the device's whole trust chain hinges on its firmware lineage."),
    }
    ORDER = ["boot-chain verification", "firmware-update authentication", "debug/recovery interface",
             "kernel crypto consumer", "network crypto parser/protocol", "HSM/SE firmware trust anchor"]
    trows = ""
    for name in ORDER:
        info = mt["catalog"].get(name)
        if not info:
            continue
        signals, why = TCB[name]
        _, _, cannot = info["can_cannot"].partition("cannot:")
        trows += (f"<tr><td><b>{esc(name)}</b></td><td>{esc(info['n_modules'])}</td>"
                  f"<td class='muted'>{signals}</td><td class='muted'>{esc(why)}</td>"
                  f"<td class='muted'>{esc(cannot.strip())}</td></tr>")
    P.append("<div class='card'><table><thead><tr><th>TCB-adjacent surface</th><th>n</th><th>corpus signal</th>"
             "<th>why it matters</th><th>what to confirm next</th></tr></thead>"
             f"<tbody>{trows}</tbody></table>"
             "<p class='muted'>Every row reads the same way: the corpus locates the <i>surface</i>, external research supplies "
             "the bug <i>class</i>. The boot-chain row is worked through in the §5 spotlight (three HSMs naming U-Boot, mapped "
             "to Binarly's CVE-2026-46728); the others are the questions a reviewer should raise for a module of that shape.</p></div>")
    P.append("<p class='lead'>Bottom line: public FIPS artifacts are <b>genuinely useful TCB-surface "
             "evidence</b>. They reveal where boot, firmware-update, debug/recovery, host/OE, network-service, and "
             "component-version questions should be asked, turning a certificate into a map of what to verify. Where a component is unnamed (§5), that map still marks the spot to check.</p>")

    P.append("<h2>7 · What the devices expose</h2>")
    P.append("<div class='cols'>")
    P.append(f"<div class='card'><h3>Exposed interfaces</h3>{bars(ex['interface_freq'],' mod')}</div>")
    P.append(f"<div class='card'><h3>Algorithm families</h3>{bars(ex['algo_family_freq'],' mod')}</div>")
    P.append("</div><div class='cols'>")
    P.append(f"<div class='card'><h3>Security level</h3>{bars({f'Level {k}':v for k,v in sorted(ex['level_dist'].items())},' mod')}</div>")
    P.append(f"<div class='card'><h3>Type / embodiment</h3>{bars(ex['type_dist'],' mod')}<div style='height:8px'></div>{bars(ex['embodiment_dist'],' mod')}</div>")
    P.append("</div>")

    P.append("<h2>8 · Device classification</h2>")
    P.append("<p class='muted'>Coarse taxonomy from name + vendor + type + embodiment. The classes behave very differently — "
             "chips are frozen silicon (rarely re-validated), HSMs are actively maintained (100% re-validated), "
             "network appliances are well-documented but re-validate less, and software carries the broadest crypto surface.</p>")
    dc = s["by_device_class"]
    drows = ""
    for c, v in dc.items():
        reval = f"{v['pct_re_validated']:.0f}%"; pqcp = f"{v['pqc_pct']:.0f}%"
        drows += (f"<tr><td>{esc(c)}</td><td>{esc(v['n'])}</td><td>{esc(v['grade'] or '–')}</td>"
                  f"<td>{esc(v['exposure_window_mo'] or '–')} mo</td><td>{esc(reval)}</td>"
                  f"<td>{esc(pqcp)}</td><td>{esc(v['median_algos'] or '–')}</td></tr>")
    P.append(f"<div class='card'><table><thead><tr><th>class</th><th>n</th><th>doc grade</th>"
             f"<th>exposure window</th><th>re-validated</th><th>PQC</th><th>median algos</th></tr></thead>"
             f"<tbody>{drows}</tbody></table></div>")

    P.append("<div class='part'><div class='pk'>Part V</div><div class='pt'>Where to look first</div><div class='pd'>Turning the evidence into a prioritized review queue, ranking which modules and which questions come first.</div></div>")
    P.append("<h2>9 · Risk-triage lens</h2>")
    P.append("<p class='muted'>An <b>active</b> module whose <b>last validation is old</b> and which exposes a <b>remote/networked interface</b> "
             "is where an unpatched CVE would matter — its certified state predates the fix and no re-validation has pulled the fix in. "
             "This is the internal signal to correlate against external CVE/advisory timelines (NVD, vendor PSIRTs).</p>")
    pct_active = f"{ve['pct_still_active']:.0f}%"
    P.append(f"<div class='card' style='display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;padding:0;overflow:hidden'>"
             f"{kpi('still active', pct_active)}"
             f"{kpi('median months since last validation', ve['months_since_last_validation']['median'])}"
             f"{kpi('stale + network-relevant', ve['stale_active_remote_count'], 'active, ≥18mo stale, networked iface')}</div>")
    rows = "".join(f"<tr><td>#{esc(r['cert'])}</td><td>{esc(r['module'])}</td>"
                   f"<td>{esc(r['since_last_validation_mo'])} mo</td><td>{esc(', '.join(r['interfaces']))}</td>"
                   f"<td>{'never' if r['never_updated'] else 'yes'}</td></tr>" for r in ve["stale_active_examples"])
    P.append(f"<div class='card'><h3>Stale + network-relevant modules (triage queue)</h3>"
             f"<table><thead><tr><th>cert</th><th>module</th><th>since last val.</th><th>interfaces</th><th>ever updated?</th></tr></thead>"
             f"<tbody>{rows}</tbody></table></div>")

    arc = s["archetypes"]; rp = s["review_priority"]
    P.append("<h2>10 · Operational archetypes &amp; review-priority</h2>")
    P.append("<p class='muted'>Embodiment (hw/sw/fw) is too coarse for risk. <b>Operational archetype</b> captures the attack path and lets "
             "reachability be weighted by class — a network interface on a <b>software library</b> is host-mediated (the app listens, not the "
             "module), on a <b>network appliance</b> it is the management/data plane. <b>Review priority = Likelihood + Impact</b> as ordinal ranks (a rank sum, not a product) banded into tiers, "
             "explicit rules, <i>no weighted coefficients</i>; measured upstream CVE drift weighs most (real evidence, not heuristic). The tiers are review-order candidates, <b>not</b> vulnerability severities.</p>")
    P.append("<div class='cols'>")
    P.append(f"<div class='card'><h3>Archetype mix</h3>{bars(arc['dist'],' mod')}</div>")
    P.append(f"<div class='card'><h3>Review-priority distribution</h3>{bars(rp['dist'],' mod')}"
             "<p class='muted' style='margin-top:8px'>Impact is a documented expert prior per archetype; Likelihood = archetype-weighted "
             "reachability + never-updated + ≥18mo stale + upstream CVE drift.</p></div>")
    P.append("</div>")
    # Update behavior crossed with archetype: which classes get patched, which stay frozen.
    ba = arc["by_archetype"]
    uorder = sorted(ba.items(), key=lambda kv: (-kv[1]["pct_never_updated"], -kv[1]["n"]))
    urows = ""
    for a, v in uorder:
        ms = v["median_months_stale"]
        ms_txt = f"{ms:g} mo" if ms is not None else "–"
        urows += (f"<tr><td>{esc(a)}</td><td>{v['n']}</td>"
                  f"<td>{v['pct_never_updated']:.0f}%</td><td>{ms_txt}</td></tr>")
    P.append("<div class='card'><h3>Update behavior by archetype <span class='muted'>(which classes get patched, which stay frozen)</span></h3>"
             f"<table><thead><tr><th>archetype</th><th>modules</th><th>never updated</th><th>median months since last validation</th></tr></thead><tbody>{urows}</tbody></table>"
             "<p class='muted'>The classes that are hardest to reship are the ones that go unpatched. <b>Secure elements and SoCs</b>, "
             "where the cryptography is baked into silicon and a change means a new part, are the least maintained "
             f"({ba.get('Secure element/SoC',{}).get('pct_never_updated',0):.0f}% show no CMVP update). "
             f"<b>HSM/accelerator</b> modules are the best maintained "
             f"({ba.get('HSM/accelerator',{}).get('pct_never_updated',0):.0f}% never updated, n={ba.get('HSM/accelerator',{}).get('n',0)}), "
             "consistent with serviceable devices carrying an ongoing vendor maintenance relationship, though that count is still "
             "small. Two confounders keep this a heuristic, not a law: many <b>software libraries</b> ship a "
             "<i>new certificate</i> per release rather than an update entry on the old one, so their no-update share overstates "
             "how frozen any given deployment is; and a missing update entry is a maintenance-friction proxy, not proof a module "
             "is insecure. Read it alongside the median-staleness column, which shows how long each class's certified state has "
             "actually stood.</p></div>")
    prows = ""
    for r in rp["top"][:14]:
        c = r["confidence"]
        confcell = f"svc-path:{c['service_path_signal']} · deploy-reach:{c['deployment_reachability']} · ver-CVE:{c['version_cve']} · drift:{c['drift']}"
        prows += (f"<tr><td><b>{esc(r['priority'])}</b></td><td>#{esc(r['cert'])}</td><td>{esc(r['archetype'])}</td>"
                  f"<td>{esc(r['reason'])}</td><td class='muted' style='font-size:11px'>{esc(confcell)}</td></tr>")
    P.append(f"<div class='card'><h3>Highest-priority review candidates <span class='muted'>(ranked, start here)</span></h3>"
             f"<table><thead><tr><th>priority</th><th>cert</th><th>archetype</th><th>why</th><th>evidence confidence</th></tr></thead><tbody>{prows}</tbody></table>"
             "<p class='muted'>Critical = network-appliance archetypes naming a reachable service (TLS/SSH/IPsec/admin), no cert update, stale — "
             "attack-path candidates <b>requiring confirmation</b>. High = OpenSSL providers that consume TLS/SSH with measured CVE drift, plus long-stale secure elements/kernels. "
             "'reach' confidence is <b>high</b> only when a consuming network service is named, <b>medium</b> for a bare interface.</p></div>")
    # offensive archetype × hypothesis (expert priors — attack-path framing, not corpus-derived)
    HYP = [("Network appliance","TLS/SSH/web/admin/data-plane parsing may touch a stale crypto stack","service table, admin docs, ports, vendor PSIRT"),
           ("Software crypto library","upstream CVEs may reach consuming services (TLS/SSH/API)","exact version, consuming services, distro backports"),
           ("HSM/accelerator","host/admin/firmware interfaces may expose key operations or update path","SDK/firmware notes, PCIe/USB/admin services"),
           ("Secure element/SoC","low public visibility; high impact if update/debug/key boundary fails","debug interfaces, firmware provenance, update model"),
           ("OS/kernel crypto","crypto exposed via consumers: IPsec, storage, VPN, TLS offload","enabled consumers, kernel config, distro advisories")]
    hrows = "".join(f"<tr><td>{esc(a)}</td><td>{esc(h)}</td><td class='muted'>{esc(n)}</td></tr>" for a,h,n in HYP)
    P.append("<div class='card'><h3>Offensive archetype × hypothesis <span class='muted'>(expert priors on where to look)</span></h3>"
             f"<table><thead><tr><th>archetype</th><th>attack-path hypothesis</th><th>next evidence to collect</th></tr></thead><tbody>{hrows}</tbody></table></div>")

    P.append("<div class='part'><div class='pk'>Part VI</div><div class='pt'>The evidence and the market</div><div class='pd'>How good the public documents are, and the vendor and lab structure that produces them.</div></div>")
    P.append("<h2>11 · Machine-readability &amp; extraction confidence</h2>")
    P.append("<p class='muted'>An <b>extraction-friendliness / completeness</b> proxy, not a judgement of security. It measures whether "
             "the Security Policy is structured, complete, and machine-readable — a triage signal for a large corpus, not authoring quality per se.</p>")
    P.append("<div class='card'><h3>Rubric — composite score (0–100)</h3><table><tbody>"
             "<tr><td><b>0.45</b> × table-typing cleanliness</td><td class='muted'>% of Security-Policy tables parsed into clean, typed rows (SSPs, services, algorithms…)</td></tr>"
             "<tr><td><b>0.35</b> × value-fill</td><td class='muted'>% of mapped table cells that are non-empty (catches 'typed but blank')</td></tr>"
             "<tr><td><b>0.20</b> × section completeness</td><td class='muted'>fraction of the standard's required clauses present in the SP's sections</td></tr>"
             "<tr><td colspan=2 class='muted' style='padding-top:6px'><b>Grades:</b> A ≥ 85 · B ≥ 72 · C ≥ 58 · D ≥ 45 · F &lt; 45</td></tr>"
             "</tbody></table></div>")
    P.append("<div class='cols'>")
    P.append(f"<div class='card'><h3>Grade distribution</h3>{bars({k:q['grade_dist'][k] for k in ['A','B','C','D','F'] if k in q['grade_dist']},' docs')}</div>")
    P.append(f"<div class='card'><h3>Mean grade by security level</h3>{bars({f'Level {k}':v for k,v in q['by_level'].items()},'', 100)}"
             f"<h3 style='margin-top:12px'>by type</h3>{bars(q['by_type'],'',100)}</div>")
    P.append("</div>")

    if s.get("vendors_multi_cert"):
        ven = s.get("vendors", {})
        P.append("<h2>12 · Vendors with multiple certificates</h2>")
        P.append("<p class='muted'>Vendor names are <b>entity-normalized</b> (trademark marks, legal suffixes, and "
                 f"punctuation removed), so “Cisco Systems, Inc.” and “Cisco Systems, Inc” count once: "
                 f"{ven.get('distinct_raw','?')} raw name strings collapse to <b>{ven.get('distinct_entities','?')}</b> "
                 "organizations. Parent/subsidiary and rebrand relationships are not resolved.</p>")
        P.append(f"<div class='card'>{bars(s['vendors_multi_cert'],' certs')}</div>")

    P.append("<h2>13 · Market structure (labs)</h2>")
    P.append(f"<p class='muted'>{labs['distinct_labs']} accredited labs; work is concentrated in a few CSTLs — concentrated delivery capacity and a potential systemic dependency. Where validation delay actually arises cannot be established from issued certificates alone (see the caveat in §14).</p>")
    P.append(f"<div class='card'>{bars(labs['top'],' validations')}</div>")
    tp = s["throughput_predictors"]
    P.append("<h2>14 · Where FIPS time accumulates</h2>")
    P.append("<p class='callout warn'>"
             "<b>This corpus cannot explain why validations take so long.</b> It is <b>survivorship-biased</b> (only modules that "
             "<i>succeeded</i>; abandoned/failed/stuck submissions are absent) and carries <b>no pipeline-timing data</b> "
             "(no IUT / Cost-Recovery / Pending-Review durations, no comment cycles). So the below are <b>candidate predictors / "
             "hypotheses of review burden</b>, not measured time drivers. A true root-cause model needs longitudinal MIP/IUT snapshots.</p>")
    P.append("<div class='card'><pre class='mermaid'>"
             "flowchart LR\n"
             '  A["Vendor product / module design"] --> B["Boundary, services, SSPs, OE defined"]\n'
             '  B --> C["Security Policy + evidence package"]\n'
             '  C --> D["CSTL testing / pre-validation"]\n'
             '  D --> E["Implementation Under Test"]\n'
             '  E --> F["Cost Recovery / admin queue"]\n'
             '  F --> G["Pending CMVP Review"]\n'
             '  G --> H["CMVP Review"]\n'
             '  H -->|comments| I["Comment resolution loop"]\n'
             '  I -->|vendor + CSTL response| H\n'
             '  H -->|accepted| J["Finalization"]\n'
             '  J --> K["Certificate issued + SP posted"]\n'
             '  K --> L["Patch / version / dependency / CVE event"]\n'
             '  L --> M{"Change inside crypto boundary?"}\n'
             '  M -->|No / outside| Nn["May not require update if assumptions unchanged"]\n'
             '  M -->|Yes / unclear| O["Update / revalidation path"]\n'
             '  O --> C\n'
             "  classDef queue fill:#fff7e6,stroke:#d6a642;\n  classDef rework fill:#fbe9e9,stroke:#c25b5b;\n"
             "  class E,F,G,H,J queue;\n  class I,O rework;\n"
             "</pre><p class='muted'>A <i>timing model</i> (where time can accumulate + rework loops), NOT a complete CMVP rule model.</p></div>")
    tprows = ""
    for a,v in tp["by_archetype"].items():
        tprows += (f"<tr><td>{esc(a)}</td><td>{esc(v['n'])}</td><td>{esc(v['median_algos'] or '–')}</td>"
                   f"<td>{esc(v['median_services'] or '–')}</td><td>{esc(v['median_ssps'] or '–')}</td><td>{esc(v['median_interfaces'] or '–')}</td></tr>")
    P.append(f"<div class='card'><h3>Complexity by archetype (review-burden proxies)</h3>"
             f"<table><thead><tr><th>archetype</th><th>n</th><th>median algos</th><th>median services</th><th>median SSPs</th><th>median interfaces</th></tr></thead>"
             f"<tbody>{tprows}</tbody></table></div>")
    nd = "".join(f"<li>{esc(x)}</li>" for x in tp["not_determinable_without_MIP_snapshots"])
    P.append(f"<p class='muted'><b>Not determinable from this corpus</b> (needs MIP/IUT snapshots + status-transition history): <ul class='muted'>{nd}</ul>"
             "<b>Two modes:</b> this bundle supports <i>assurance-gap mode</i> (what does public evidence prove, where is it stale) well; it only <i>seeds</i> "
             "<i>validation-throughput mode</i> (where is a submission stuck, who owns the action) — pipeline-state and rework numbers are omitted because they would be fabricated without the longitudinal data.</p>")

    P.append("<div class='part'><div class='pk'>Appendix</div><div class='pt'>Method &amp; provenance</div>"
             "<div class='pd'>How the corpus was built, and what it deliberately does not claim.</div></div>")
    P.append("<h2>Method, reproduction &amp; caveats</h2>")
    P.append("<p class='muted'><b>Pipeline (deterministic given the swept cert range + cached NVD responses):</b> "
             "<code>build_corpus.py</code> (fetch cert page + Security Policy PDF → per-module JSON) → "
             "<code>build_drift.py</code> (NVD CVE API v2, CPE virtualMatchString, CVEs in each named component since validation date) → "
             "<code>build_version_exact.py</code> (CVEs whose affected-range includes the certified version, published ≥ validation date, "
             "Rejected/Disputed excluded) → <code>analyze_corpus.py</code> → this report / findings / explorer. All corpus figures come "
             "from <code>corpus_analysis.json</code>; external inputs (volume-by-year, industry timeline) are labelled inline as provided, not corpus-derived.</p>")
    P.append("<ul class='muted'>")
    P.append("<li>Corpus is a swept sample of the recent CMVP certificate-number range, filtered to FIPS 140-3 — not the full population.</li>")
    P.append("<li>Validation-history timing (windows, cadence, staleness) has ~100% coverage; SP-revision development-span only where the SP ships a dated revision table (a minority).</li>")
    P.append("<li>Component/version-exact CVE counts are upstream <i>pressure</i> indicators, not module-vulnerability counts; distro back-ports are not reflected in the version string, so version-exact is an upper bound. NVD data as of the reference date.</li>")
    P.append("<li>The risk-triage lens and review-priority are <i>attack-path hypotheses requiring confirmation</i>, not confirmed vulnerabilities; L5 (confirmed exposure) is never reached from public CMVP+NVD data alone. Impact is an expert prior; thresholds are not yet calibrated against expert labels.</li>")
    P.append("<li>Document grades reflect extraction-friendliness + completeness, not authoring or security quality.</li>")
    P.append("<li><b>Terms:</b> CMVP = the FIPS 140-3 validation program/certificate; CSTL = accredited test lab; Security Policy = the per-vendor module PDF; SSP/CSP = protected keys/parameters; OE = operational environment; sunset = certificate end-of-active-window.</li></ul>")

    css = """
    :root{
      --paper:#f4f6f8; --surface:#ffffff; --surface-2:#f8fafb;
      --ink:#0f1720; --ink-2:#47535f; --ink-3:#7c8894; --line:#e2e7ec; --line-2:#eef1f4;
      --accent:#0e6e6e; --accent-2:#0a5a5a; --accent-wash:#e6f0ef; --accent-line:#bcdad7;
      --crit-fg:#9e1f24; --crit-bg:#f8e4e4; --high-fg:#8a5410; --high-bg:#f7e8d3;
      --med-fg:#535f6c; --med-bg:#e9edf1; --low-fg:#2f6b58; --low-bg:#e2efe9;
      --serif:'Iowan Old Style','Palatino Linotype',Palatino,'Book Antiqua',Georgia,serif;
      --sans:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      --mono:ui-monospace,'SF Mono','JetBrains Mono',Menlo,Consolas,monospace;
    }
    @media(prefers-color-scheme:dark){:root{
      --paper:#0d1216; --surface:#141b21; --surface-2:#101820;
      --ink:#e6ecf1; --ink-2:#a6b2bc; --ink-3:#72808b; --line:#243039; --line-2:#1b242c;
      --accent:#43b9af; --accent-2:#5fc9bf; --accent-wash:#12302e; --accent-line:#1f4b48;
      --crit-fg:#e98a8f; --crit-bg:#341d1f; --high-fg:#dba766; --high-bg:#31261a;
      --med-fg:#9fabb6; --med-bg:#1e262d; --low-fg:#6fc2a8; --low-bg:#16281f;
    }}
    :root[data-theme=light]{--paper:#f4f6f8;--surface:#fff;--surface-2:#f8fafb;--ink:#0f1720;--ink-2:#47535f;--ink-3:#7c8894;--line:#e2e7ec;--line-2:#eef1f4;--accent:#0e6e6e;--accent-2:#0a5a5a;--accent-wash:#e6f0ef;--accent-line:#bcdad7;--crit-fg:#9e1f24;--crit-bg:#f8e4e4;--high-fg:#8a5410;--high-bg:#f7e8d3;--med-fg:#535f6c;--med-bg:#e9edf1;--low-fg:#2f6b58;--low-bg:#e2efe9}
    :root[data-theme=dark]{--paper:#0d1216;--surface:#141b21;--surface-2:#101820;--ink:#e6ecf1;--ink-2:#a6b2bc;--ink-3:#72808b;--line:#243039;--line-2:#1b242c;--accent:#43b9af;--accent-2:#5fc9bf;--accent-wash:#12302e;--accent-line:#1f4b48;--crit-fg:#e98a8f;--crit-bg:#341d1f;--high-fg:#dba766;--high-bg:#31261a;--med-fg:#9fabb6;--med-bg:#1e262d;--low-fg:#6fc2a8;--low-bg:#16281f}
    *{box-sizing:border-box} html{scroll-behavior:smooth}
    body{font:15.5px/1.62 var(--sans);margin:0;color:var(--ink);background:var(--paper);-webkit-font-smoothing:antialiased}
    @media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}

    .mast{border-bottom:1px solid var(--line);background:var(--surface)}
    .mast-in{max-width:900px;margin:0 auto;padding:44px 32px 30px}
    .eyebrow{font:600 11.5px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin-bottom:16px}
    .mast h1{font:600 40px/1.08 var(--serif);letter-spacing:-.015em;margin:0;text-wrap:balance;max-width:18ch}
    .dek{font-size:17px;line-height:1.5;color:var(--ink-2);margin:14px 0 0;max-width:62ch}
    .dek em{color:var(--ink);font-style:italic}
    .meta{display:flex;flex-wrap:wrap;gap:8px;margin:22px 0 0}
    .meta span{font:500 12px/1 var(--mono);color:var(--ink-2);background:var(--surface-2);border:1px solid var(--line);border-radius:5px;padding:6px 10px}
    .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;margin:26px 0 0;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden}
    .kpi{background:var(--surface);padding:16px 18px}
    .kv{font:600 27px/1.05 var(--serif);letter-spacing:-.01em;font-variant-numeric:tabular-nums;color:var(--ink)}
    .kl{font-size:12.5px;color:var(--ink-2);margin-top:5px;font-weight:500} .ks{font-size:11px;color:var(--ink-3);margin-top:3px}

    /* Content is a single 900px column centered on the page, identical to the
       overview and the module pages, so navigating between them does not shift
       or resize the text. The section TOC lives in the left gutter (fixed) only
       when the viewport is wide enough to hold it beside that column. */
    .wrap{max-width:900px;margin:0 auto;padding:0 32px}
    .toc{position:fixed;top:70px;left:calc(50% - 694px);width:216px;max-height:calc(100vh - 90px);overflow:auto;padding:6px 0;font-size:13px}
    .toc-h{font:600 11px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--ink-3);padding:0 0 4px 12px;margin-bottom:8px}
    .toc a{display:flex;gap:9px;align-items:baseline;text-decoration:none;color:var(--ink-2);padding:5px 12px;border-left:2px solid transparent;line-height:1.3;border-bottom:0}
    .toc a:hover{color:var(--ink);border-left-color:var(--accent-line);background:var(--surface-2)}
    .toc a.on{color:var(--accent);border-left-color:var(--accent);font-weight:600}
    .toc .tn{flex:0 0 auto;font:600 11px/1.5 var(--mono);color:var(--ink-3);min-width:1.4em}
    .toc a.on .tn{color:var(--accent)}
    .toc-part{font:600 10px/1.3 var(--mono);letter-spacing:.11em;text-transform:uppercase;color:var(--accent);padding:16px 12px 5px;margin-top:6px;border-top:1px solid var(--line-2)}
    .toc-part:first-of-type{margin-top:0}
    main{padding:34px 0 10px;min-width:0}
    .lead{font-size:16px;line-height:1.62;color:var(--ink-2);border-left:3px solid var(--accent);padding:2px 0 2px 20px;margin:0 0 6px;max-width:70ch}
    .lead b{color:var(--ink)} .fine{font-size:12.5px;color:var(--ink-3);margin:16px 0 0;max-width:70ch}

    h2{font:600 23px/1.2 var(--serif);letter-spacing:-.01em;margin:0 0 10px;padding-top:44px;text-wrap:balance;scroll-margin-top:18px}
    h2 .secnum{font:600 13px/1 var(--mono);color:var(--accent);vertical-align:2px;margin-right:12px;padding:4px 7px;background:var(--accent-wash);border-radius:5px}
    h3{font:600 13px/1.3 var(--sans);letter-spacing:.03em;text-transform:uppercase;color:var(--ink-3);margin:0 0 9px}
    p{margin:11px 0} main p{max-width:70ch} a{color:var(--accent);text-decoration:none;border-bottom:1px solid var(--accent-line)} a:hover{border-bottom-color:var(--accent)}
    a:focus-visible,.toc a:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:2px}
    .muted{color:var(--ink-2)} .big{font:600 30px/1 var(--serif)}
    code,.mono{font:.92em var(--mono)} b,strong{font-weight:600;color:var(--ink)}
    hr,.rule{border:0;border-top:1px solid var(--line-2);margin:34px 0}
    .part{margin:56px 0 8px;padding-top:26px;border-top:2px solid var(--accent)}
    main>.part:first-child{margin-top:8px;border-top:0;padding-top:0}
    .part+h2,.part+*{padding-top:14px}
    .part .pk{font:600 12px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--accent)}
    .part .pt{font:600 27px/1.15 var(--serif);letter-spacing:-.015em;margin:10px 0 0;color:var(--ink);text-wrap:balance}
    .part .pd{font-size:14.5px;line-height:1.5;color:var(--ink-2);margin:8px 0 0;max-width:66ch}

    .cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(268px,1fr));gap:14px;margin:14px 0}
    .card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:14px 0}
    .cols{margin-block:14px} .cols>.card{margin:0}
    .card h3{margin-bottom:10px}

    .bar{display:flex;align-items:center;gap:10px;margin:5px 0;font-size:13px}
    .bl{flex:0 0 42%;text-align:right;color:var(--ink-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .bt{flex:1;background:var(--line-2);border-radius:3px;height:9px;overflow:hidden}
    .bf{display:block;height:100%;background:var(--accent);border-radius:3px}
    .bv{flex:0 0 auto;font:500 12.5px var(--mono);font-variant-numeric:tabular-nums;color:var(--ink-2);min-width:44px}

    .callout{background:var(--surface-2);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:0 10px 10px 0;padding:13px 16px;margin:14px 0;font-size:14px;color:var(--ink-2)}
    .callout b{color:var(--ink)} .callout.warn{border-left-color:var(--high-fg);background:var(--high-bg)}

    .tw{overflow-x:auto;margin:12px 0} table{width:100%;border-collapse:collapse;font-size:13.5px}
    th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line-2)}
    th{font:600 11px/1.2 var(--sans);letter-spacing:.05em;text-transform:uppercase;color:var(--ink-3)}
    td{font-variant-numeric:tabular-nums} tr:last-child td{border-bottom:0}
    tbody tr:hover{background:var(--surface-2)}

    .tag{display:inline-block;font:600 11px/1 var(--sans);padding:4px 9px;border-radius:20px;letter-spacing:.01em}
    .t-crit{background:var(--crit-bg);color:var(--crit-fg)} .t-high{background:var(--high-bg);color:var(--high-fg)}
    .t-med{background:var(--med-bg);color:var(--med-fg)} .t-low{background:var(--low-bg);color:var(--low-fg)}
    .chip{display:inline-block;font:500 11.5px var(--mono);padding:3px 8px;border-radius:5px;background:var(--surface-2);border:1px solid var(--line);color:var(--ink-2);margin:2px 3px 2px 0}

    .mermaid{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;margin:14px 0;overflow-x:auto}

    .foot{border-top:1px solid var(--line);background:var(--surface);margin-top:44px}
    .foot-in{max-width:1120px;margin:0 auto;padding:26px 32px 40px;font-size:12.5px;color:var(--ink-3);display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px}

    /* Not enough gutter for the fixed sidebar: collapse the TOC to an inline
       pill list above the content. The content column itself stays centered and
       the same width, so there is still no cross-page jump. */
    @media(max-width:1439px){
      .toc{position:static;left:auto;width:auto;max-height:none;padding:18px 0 6px;margin:0;
           display:flex;flex-wrap:wrap;gap:6px 4px;border-bottom:1px solid var(--line)}
      .toc-h{flex-basis:100%;padding-left:0;margin-bottom:2px}
      .toc-part{flex-basis:100%;border-top:0;margin-top:2px;padding:10px 0 2px}
      .toc a{display:inline-flex;border-left:0;border-radius:20px;padding:4px 10px;margin:0;background:var(--surface-2)}
      .toc a.on{border-left:0;background:var(--accent-wash)}
    }
    @media(max-width:860px){
      .wrap{padding:0 20px} .mast-in{padding:32px 20px 24px} .mast h1{font-size:31px}
      main{padding:14px 0} h2{padding-top:32px}
    }
    """
    # A type=module script runs after DOMContentLoaded, so startOnLoad:true would
    # register a listener that never fires. Initialize with startOnLoad:false and
    # call mermaid.run() explicitly so the diagrams render regardless of timing.
    mermaid = ("<script type='module'>import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';"
               "mermaid.initialize({startOnLoad:false,theme:(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'neutral')});"
               "mermaid.run().catch(function(e){console.error('mermaid',e);});</script>")

    # --- assemble: masthead + contents rail + main + footer -------------------
    body = "".join(P)
    secs = []
    def _h2(m):
        inner = m.group(1).strip()
        sid = f"s{len(secs)}"
        if "·" in inner:
            num, lab = inner.split("·", 1); num = num.strip(); lab = lab.strip()
            secs.append((sid, num, re.sub(r"<[^>]+>", "", lab).strip()))
            return f"<h2 id='{sid}'><span class='secnum'>{esc(num)}</span>{lab}</h2>"
        secs.append((sid, "", re.sub(r"<[^>]+>", "", inner).strip()))
        return f"<h2 id='{sid}'>{inner}</h2>"
    body = re.sub(r"<h2>(.*?)</h2>", _h2, body, flags=re.S)
    # wide tables scroll inside their own container so nothing bleeds past the card edge
    body = body.replace("<table>", "<div class='tw'><table>").replace("</table>", "</table></div>")
    # TOC walks the body in order, grouping section links under their Part header.
    # lab is already entity-safe HTML (tags stripped, entities preserved) — do NOT re-escape
    toc_items = []
    for m in re.finditer(r"<div class='pt'>(.*?)</div>|<h2 id='(s\d+)'>(?:<span class='secnum'>([^<]*)</span>)?(.*?)</h2>", body, re.S):
        if m.group(1) is not None:
            toc_items.append(("part", m.group(1).strip()))
        else:
            toc_items.append(("sec", m.group(2), (m.group(3) or "").strip(),
                              re.sub(r"<[^>]+>", "", m.group(4)).strip()))
    toc = "".join(
        (f"<div class='toc-part'>{it[1]}</div>" if it[0] == "part"
         else f"<a href='#{it[1]}'><span class='tn'>{esc(it[2]) if it[2] else '·'}</span><span>{it[3]}</span></a>")
        for it in toc_items)

    footer = ("<footer class='foot'><div class='foot-in'>"
              f"<span>FIPS 140-3 validated-module corpus &nbsp;·&nbsp; n={s['n']} &nbsp;·&nbsp; ref {esc(cov['reference_date'])}</span>"
              "<span>Deterministic extraction from public CMVP + NVD &nbsp;·&nbsp; "
              "review priorities and TCB-surface signal</span>"
              "</div></footer>")
    spy = ("<script>(function(){var L=[].slice.call(document.querySelectorAll('.toc a')),M={};"
           "L.forEach(function(a){M[a.getAttribute('href').slice(1)]=a;});"
           "if(!('IntersectionObserver'in window))return;"
           "var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){"
           "L.forEach(function(a){a.classList.remove('on');});var t=M[e.target.id];if(t)t.classList.add('on');}});},"
           "{rootMargin:'0px 0px -78% 0px'});"
           "document.querySelectorAll('main h2[id]').forEach(function(h){io.observe(h);});})();</script>")

    out = ("<!doctype html><meta charset=utf-8>"
           "<meta name=viewport content='width=device-width,initial-scale=1'>"
           "<title>FIPS 140-3 Corpus Analysis — the certificate–deployment gap</title>"
           f"<style>{css}</style>{mast}"
           f"<div class='wrap'><nav class='toc'><div class='toc-h'>Contents</div>{toc}</nav>"
           f"<main>{lead}{body}</main></div>{footer}{mermaid}{spy}")
    out = out.replace(" — ", ", ").replace("—", ", ")   # no em dashes in output copy
    open("corpus_report.html","w").write(out)
    print(f"wrote corpus_report.html ({len(out)//1024} KB, {len(secs)} sections)")

if __name__ == "__main__":
    main()
