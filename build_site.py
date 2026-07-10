#!/usr/bin/env python3
"""Generate the published static site into docs/ (GitHub Pages ready):

    docs/index.html            landing page
    docs/report.html           the corpus analysis report (wrapped with site nav)
    docs/modules/index.html    browsable index of every module
    docs/modules/<cert>.html   one detail page per module

All pages share one design system and one top navigation. Pure stdlib; reads
corpus_analysis.json + drift.json, and wraps the already-rendered corpus_report.html.
"""
import json, html, os, re, base64
import render_html  # the pipeline's Security-Policy document reconstruction

def esc(s): return html.escape("" if s is None else str(s))

d = json.load(open("corpus_analysis.json"))
S = d["summary"]; RECS = d["records"]
DRIFT = {m["cert"]: m for m in json.load(open("drift.json"))} if os.path.exists("drift.json") else {}
REF = S["coverage"]["reference_date"]; N = S["n"]

CERT_URL = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{}"
PRI_ORD = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
PRI_CLS = {"Critical": "t-crit", "High": "t-high", "Medium": "t-med", "Low": "t-low"}
EV_CLS = {"complete": "ok", "named": "ok", "exact": "ok", "measured": "ok",
          "partial": "part", "component-only": "part",
          "not captured": "miss", "none/unknown": "miss", "not collected": "miss", "unknown": "miss",
          "n/a": "na", "opaque": "miss", "low": "part", "high": "ok"}

CSS = """
:root{
  --paper:#f4f6f8;--surface:#fff;--surface-2:#f8fafb;--ink:#0f1720;--ink-2:#47535f;--ink-3:#7c8894;
  --line:#e2e7ec;--line-2:#eef1f4;--accent:#0e6e6e;--accent-2:#0a5a5a;--accent-wash:#e6f0ef;--accent-line:#bcdad7;
  --crit-fg:#9e1f24;--crit-bg:#f8e4e4;--high-fg:#8a5410;--high-bg:#f7e8d3;--med-fg:#535f6c;--med-bg:#e9edf1;--low-fg:#2f6b58;--low-bg:#e2efe9;
  --serif:'Iowan Old Style','Palatino Linotype',Palatino,'Book Antiqua',Georgia,serif;
  --sans:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --mono:ui-monospace,'SF Mono','JetBrains Mono',Menlo,Consolas,monospace;
}
@media(prefers-color-scheme:dark){:root{
  --paper:#0d1216;--surface:#141b21;--surface-2:#101820;--ink:#e6ecf1;--ink-2:#a6b2bc;--ink-3:#72808b;
  --line:#243039;--line-2:#1b242c;--accent:#43b9af;--accent-2:#5fc9bf;--accent-wash:#12302e;--accent-line:#1f4b48;
  --crit-fg:#e98a8f;--crit-bg:#341d1f;--high-fg:#dba766;--high-bg:#31261a;--med-fg:#9fabb6;--med-bg:#1e262d;--low-fg:#6fc2a8;--low-bg:#16281f;
}}
:root[data-theme=light]{--paper:#f4f6f8;--surface:#fff;--surface-2:#f8fafb;--ink:#0f1720;--ink-2:#47535f;--ink-3:#7c8894;--line:#e2e7ec;--line-2:#eef1f4;--accent:#0e6e6e;--accent-2:#0a5a5a;--accent-wash:#e6f0ef;--accent-line:#bcdad7;--crit-fg:#9e1f24;--crit-bg:#f8e4e4;--high-fg:#8a5410;--high-bg:#f7e8d3;--med-fg:#535f6c;--med-bg:#e9edf1;--low-fg:#2f6b58;--low-bg:#e2efe9}
:root[data-theme=dark]{--paper:#0d1216;--surface:#141b21;--surface-2:#101820;--ink:#e6ecf1;--ink-2:#a6b2bc;--ink-3:#72808b;--line:#243039;--line-2:#1b242c;--accent:#43b9af;--accent-2:#5fc9bf;--accent-wash:#12302e;--accent-line:#1f4b48;--crit-fg:#e98a8f;--crit-bg:#341d1f;--high-fg:#dba766;--high-bg:#31261a;--med-fg:#9fabb6;--med-bg:#1e262d;--low-fg:#6fc2a8;--low-bg:#16281f}
*{box-sizing:border-box} html{scroll-behavior:smooth}
body{font:15.5px/1.62 var(--sans);margin:0;color:var(--ink);background:var(--paper);-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid var(--accent-line)} a:hover{border-bottom-color:var(--accent)}
a:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:2px}
b,strong{font-weight:600;color:var(--ink)} .muted{color:var(--ink-2)} .mono{font:.92em var(--mono)}
code{font:.92em var(--mono);background:var(--surface-2);border:1px solid var(--line);border-radius:4px;padding:1px 5px}

.nav{border-bottom:1px solid var(--line);background:var(--surface)}
.nav-in{max-width:1120px;margin:0 auto;padding:12px 32px;display:flex;align-items:baseline;gap:22px}
.nav .brand{font:600 14px/1 var(--mono);letter-spacing:.02em;color:var(--ink);border:0;white-space:nowrap}
.nav a{font:500 13.5px/1 var(--sans);color:var(--ink-2);border:0;padding:4px 0}
.nav a:hover{color:var(--ink)} .nav a.on{color:var(--accent)}
.nav .sp{flex:1}

.wrap{max-width:1120px;margin:0 auto;padding:0 32px}
main{max-width:900px;margin:0 auto;padding:34px 32px 56px}
h1{font:600 34px/1.1 var(--serif);letter-spacing:-.015em;margin:0 0 6px;text-wrap:balance}
h2{font:600 22px/1.2 var(--serif);letter-spacing:-.01em;margin:36px 0 10px;text-wrap:balance}
h3{font:600 12px/1.3 var(--sans);letter-spacing:.04em;text-transform:uppercase;color:var(--ink-3);margin:0 0 9px}
p{margin:11px 0;max-width:70ch} .dek{font-size:18px;line-height:1.5;color:var(--ink-2);margin:10px 0 0;max-width:64ch}
.eyebrow{font:600 11.5px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin-bottom:14px}

.obs{display:flex;flex-direction:column;gap:1px;margin:22px 0;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.obs-row{display:grid;grid-template-columns:150px 1fr;gap:22px;background:var(--surface);padding:16px 18px;align-items:baseline}
.obs-k{align-self:baseline}
.obs-v{font:600 25px/1.05 var(--serif);font-variant-numeric:tabular-nums;color:var(--ink)}
.obs-l{font-size:11.5px;color:var(--ink-3);margin-top:4px;text-transform:uppercase;letter-spacing:.03em}
.obs-why{font-size:14px;line-height:1.5;color:var(--ink-2);max-width:66ch} .obs-why b{color:var(--ink)}
@media(max-width:600px){.obs-row{grid-template-columns:1fr;gap:6px}}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin:20px 0}
.card{display:block;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:18px 20px;color:inherit}
a.card:hover{border-color:var(--accent-line);background:var(--surface-2)}
.card h3{color:var(--accent);margin-bottom:8px} .card .big{font:600 19px/1.2 var(--serif);color:var(--ink);margin:0 0 4px}
.card p{font-size:13.5px;color:var(--ink-2);margin:6px 0 0}

.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:14px 0}
.pull{margin:18px 0 8px;padding:6px 0 6px 22px;border-left:3px solid var(--accent);max-width:60ch}
.pull p{margin:0;max-width:none;font:italic 400 21px/1.4 var(--serif);color:var(--ink);text-wrap:balance}
.pull p+p{margin-top:12px;font-size:17px;line-height:1.5;color:var(--ink-2)}
.chk{margin:10px 0 4px;padding-left:24px;list-style:none} .chk li{margin:8px 0;max-width:70ch;position:relative}
.chk li::before{content:'✓';position:absolute;left:-22px;top:1px;color:var(--accent);font-weight:700}
.panel h3{color:var(--accent)} .panel p{font-size:14px;margin:6px 0 0}
.cols2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:16px 0}
.cols3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:16px 0}
@media(max-width:720px){.cols2,.cols3{grid-template-columns:1fr}}
.flow{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:16px 0}
.flow .step{font:500 13px var(--sans);background:var(--surface);border:1px solid var(--line);border-radius:20px;padding:6px 13px;color:var(--ink-2)}
.flow .step.end{border-color:var(--accent-line);background:var(--accent-wash);color:var(--accent-2);font-weight:600}
.flow .arr{color:var(--ink-3);font-size:13px}
.kv{display:flex;flex-wrap:wrap;gap:6px 22px;font-size:14px} .kv div{min-width:0} .kv .k{color:var(--ink-3);font-size:12px}
.chip{display:inline-block;font:500 12px var(--mono);padding:3px 9px;border-radius:6px;background:var(--surface-2);border:1px solid var(--line);color:var(--ink-2);margin:3px 4px 3px 0}
.tag{display:inline-block;font:600 11px/1 var(--sans);padding:4px 10px;border-radius:20px;letter-spacing:.01em}
.t-crit{background:var(--crit-bg);color:var(--crit-fg)} .t-high{background:var(--high-bg);color:var(--high-fg)}
.t-med{background:var(--med-bg);color:var(--med-fg)} .t-low{background:var(--low-bg);color:var(--low-fg)}
.pill{display:inline-block;font:600 10.5px/1 var(--sans);padding:3px 8px;border-radius:20px}
.ok{background:var(--low-bg);color:var(--low-fg)} .part{background:var(--high-bg);color:var(--high-fg)} .miss{background:var(--crit-bg);color:var(--crit-fg)} .na{background:var(--med-bg);color:var(--med-fg)}
.ev{display:flex;justify-content:space-between;align-items:center;font-size:13px;padding:6px 0;border-bottom:1px solid var(--line-2)} .ev:last-child{border-bottom:0}
ul{margin:6px 0;padding-left:20px} li{margin:3px 0;font-size:14px;color:var(--ink-2)}

.tw{overflow-x:auto;margin:14px 0} table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line-2)} td{font-variant-numeric:tabular-nums}
th{font:600 11px/1.2 var(--sans);letter-spacing:.05em;text-transform:uppercase;color:var(--ink-3)}
tbody tr:hover{background:var(--surface-2)} tbody tr[data-href]{cursor:pointer} td .cn{font:600 12.5px var(--mono);color:var(--ink-3)}
tr:last-child td{border-bottom:0}

.crumb{font-size:13px;color:var(--ink-3);margin:0 0 6px} .crumb a{color:var(--ink-2)}
.foot{border-top:1px solid var(--line);background:var(--surface);margin-top:44px}
.foot-in{max-width:1120px;margin:0 auto;padding:22px 32px 40px;font-size:12.5px;color:var(--ink-3);display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px}
@media(max-width:720px){.nav-in,main,.wrap,.foot-in{padding-left:18px;padding-right:18px} h1{font-size:27px}}
"""

def nav(base, active):
    L = [("Overview", base + "index.html", "home"),
         ("Report", base + "report.html", "report"),
         ("Modules", base + "modules/index.html", "modules")]
    links = "".join(f"<a href='{h}'{' class=on' if k==active else ''}>{t}</a>" for t, h, k in L)
    return (f"<nav class='nav'><div class='nav-in'>"
            f"<a class='brand' href='{base}index.html'>FIPS&nbsp;140&#8209;3</a>"
            f"{links}</div></nav>")

def foot():
    return ("<footer class='foot'><div class='foot-in'>"
            f"<span>FIPS 140-3 validated-module corpus &nbsp;·&nbsp; n={N} &nbsp;·&nbsp; ref {esc(REF)}</span>"
            "<span>Deterministic extraction from public CMVP + NVD</span></div></footer>")

def page(title, base, active, body):
    return ("<!doctype html><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{esc(title)}</title><style>{CSS}</style>"
            f"{nav(base, active)}{body}{foot()}")

def tagp(p): return f"<span class='tag {PRI_CLS.get(p,'t-med')}'>{esc(p)} review</span>"

# ---- landing ---------------------------------------------------------------
def build_index():
    lc = S["lifecycle"]; rc = S["recertification"]
    win = lc["exposure_window_months (validation->sunset)"]["median"]
    no_update = N - rc["modules_with_updates"]
    interim = S["assurance"]["type_dist"].get("Interim (2-yr)", 0)
    upstream = len({m["cert"] for m in json.load(open("drift.json"))}) if os.path.exists("drift.json") else 0
    have_ver = 0
    for p in sorted(__import__("glob").glob("corpus140_3/records/*.json")):
        c = json.load(open(p)).get("certificate") or {}
        if (c.get("softwareVersions") or c.get("firmwareVersions")):
            have_ver += 1

    # Each statistic carries a one-sentence reading of why it matters, so the
    # numbers are interpreted rather than left to speak for themselves.
    obs = [
        (f"{N}", "sampled modules",
         "Large enough to show how the certified state ages in aggregate, while staying a directional "
         "cross-section rather than a census of every FIPS 140-3 module."),
        (f"{no_update}", "no recorded update",
         "Most certified modules show no public update after their first validation, so their approved-mode "
         "code is effectively frozen while the world around it keeps moving."),
        (f"{win:.0f} mo", "median active window",
         "A module is presented as current for about five years, long enough for legacy primitives and "
         "unpatched components to accumulate well before the certificate lapses."),
        (f"{interim}", "interim validations",
         "Nearly a fifth arrived through the backlog-reduction path, which grants a shorter, less deeply "
         "reviewed certificate, so two certificates do not always carry the same assurance."),
        (f"{have_ver}", f"record a version ({round(100*have_ver/N)}%)",
         "Almost four in ten certificates pin no software or firmware version, so for those modules you "
         "cannot even check whether your deployed build is the one that was validated."),
    ]
    th = "".join(f"<div class='obs-row'><div class='obs-k'><div class='obs-v'>{esc(v)}</div>"
                 f"<div class='obs-l'>{esc(l)}</div></div><div class='obs-why'>{esc(w)}</div></div>"
                 for v, l, w in obs)

    # Estimated validation timeline (elapsed time, not hard benchmark). The post-submission
    # phases are anchored to KeyPair's 2024 public analysis; everything else is an industry estimate.
    TL = [
        ("Module scoping", "Define the cryptographic boundary, embodiment, operational environment, security level, algorithm set, versioning, and approved-mode model.", "2 to 8 weeks", "estimate"),
        ("Product remediation", "Fix gaps before formal testing: self-tests, approved vs non-approved behavior, services, key management, build and version alignment.", "1 to 6+ months", "estimate"),
        ("Algorithm &amp; entropy prerequisites", "Complete CAVP algorithm validation, entropy-source evidence, RNG documentation, and dependency mapping.", "1 to 4+ months", "estimate"),
        ("CSTL testing &amp; package prep", "The accredited lab tests the module, prepares evidence, reviews the Security Policy, and assembles the submission.", "3 to 9 months", "estimate"),
        ("Fees &amp; intake", "The CMVP cost-recovery fee is paid, the submission is received, and early package defects are resolved before it reaches the review queue.", "weeks to a few months", "estimate"),
        ("Pending &amp; CMVP review", "The submission waits for CMVP review resources, then undergoes document review.", "~12 months (366-day avg)", "benchmark"),
        ("Coordination &amp; finalization", "CMVP comments are resolved through lab and vendor; documents are revised; the certificate is finalized and posted.", "~7 months (213-day avg)", "benchmark"),
        ("Total post-submission", "From CMVP receipt of the validation report to certificate issuance.", "~19 months (579-day avg)", "benchmark"),
        ("Total end-to-end", "Vendor preparation, remediation, lab testing, CMVP review, comment resolution, and finalization.", "~24 to 36+ months", "estimate"),
    ]
    trows = ""
    for ph, what, tm, conf in TL:
        top = " style='border-top:2px solid var(--line)'" if ph.startswith("Total") else ""
        cls = "ok" if conf == "benchmark" else "na"
        trows += (f"<tr{top}><td><b>{ph}</b></td><td class='muted'>{what}</td>"
                  f"<td style='white-space:nowrap'>{tm}</td><td><span class='pill {cls}'>{conf}</span></td></tr>")

    # inline, theme-aware diagram: the product's functionality as feature blocks, then
    # the scope narrowing twice into the module and into the approved functions.
    feats = [("User interface", 36, 58), ("Networking", 189, 58), ("Storage", 342, 58), ("Logging", 495, 58),
             ("Config / updates", 36, 110), ("Business logic", 189, 110), ("OS / runtime", 342, 110), ("Admin &amp; APIs", 495, 110)]
    fcells = "".join(
        f"<rect x='{x}' y='{y}' width='143' height='44' rx='8' fill='var(--surface)' stroke='var(--line)'/>"
        f"<text x='{x+71}' y='{y+27}' text-anchor='middle' font-size='12' fill='var(--ink-2)'>{lbl}</text>"
        for lbl, x, y in feats)
    boundary_svg = (
        "<svg viewBox='0 0 676 290' role='img' style='width:100%;height:auto;margin:10px 0;font-family:var(--sans)' "
        "aria-label='The validated scope is a single small box, the FIPS-approved functions, inside the full-width "
        "cryptographic module, which is itself a small part of the product'>"
        "<text x='22' y='32' font-size='11' letter-spacing='1.4' fill='var(--ink-3)'>A PRODUCT AND ALL OF ITS FUNCTIONALITY</text>"
        "<rect x='18' y='44' width='640' height='236' rx='14' fill='var(--surface-2)' stroke='var(--line)'/>"
        + fcells +
        "<rect x='36' y='170' width='602' height='94' rx='10' fill='var(--surface)' stroke='var(--ink-3)' stroke-width='1.5'/>"
        "<text x='52' y='196' font-size='12.5' font-weight='600' fill='var(--ink)'>Cryptographic module</text>"
        "<text x='52' y='214' font-size='10.5' fill='var(--ink-3)'>non-approved functions here are out of scope</text>"
        "<rect x='489' y='184' width='133' height='64' rx='8' fill='var(--accent-wash)' stroke='var(--accent)' stroke-width='2'/>"
        "<text x='555' y='206' text-anchor='middle' font-size='10' font-weight='600' fill='var(--accent-2)'>FIPS-approved functions</text>"
        "<text x='555' y='221' text-anchor='middle' font-size='8.5' fill='var(--accent-2)'>in approved mode</text>"
        "<text x='555' y='239' text-anchor='middle' font-size='9' font-style='italic' fill='var(--accent-2)'>the validated scope</text>"
        "</svg>")

    body = (
        "<main>"
        "<div class='eyebrow'>CMVP · Cryptographic Module Validation Program</div>"
        "<h1>FIPS 140-3 validation, in practice</h1>"
        "<p class='dek'>FIPS 140-3 is the US and Canadian government standard for validating that a cryptographic "
        "module correctly implements approved algorithms and meets a defined security bar. It exists to give buyers, "
        "originally federal agencies, assurance before they procure. It is widely referenced, expensive and slow to "
        "obtain, and frequently misunderstood. This site reads the public validation record for a sampled set of "
        "modules to make what a certificate does and does not cover concrete.</p>"

        "<h2>What FIPS 140-3 validates</h2>"
        "<p>The standard (aligned with <a href='https://www.iso.org/standard/52906.html' target='_blank' "
        "rel='noopener'>ISO/IEC 19790</a>) is run by the <b>CMVP</b>, jointly operated by NIST in the US and "
        "the CCCS in Canada. A validation covers a defined <b>cryptographic module</b>: a specific boundary of "
        "hardware, software, or firmware, at one of four <b>security levels</b>. Within that boundary it confirms the "
        "module implements NIST-approved algorithms correctly (through the separate CAVP program), enforces an "
        "<b>approved mode</b> of operation, protects its keys, and runs its self-tests. Every validation names a "
        "specific module <b>version</b>, configuration, and operational environment.</p>"
        "<div class='panel' style='padding:18px 20px'>" + boundary_svg +
        "<p class='muted' style='margin-top:6px'>The scope narrows twice. A validation covers only the "
        "<b>cryptographic module</b>, a small boundary inside the product; and within that, only the "
        "<b>FIPS-approved functions operated in the approved mode</b>. Non-approved algorithms can sit inside the same "
        "module and are not part of the validation, and everything the product does outside the module is not covered "
        "at all. That is why a product can be built around a validated module and still run cryptography that was "
        "never validated.</p>"
        "<p class='muted' style='font-size:13px'>For example, the same module operated outside approved mode "
        "might seed a key from a non-approved source, such as the C library's <code>rand()</code>, which is fast but "
        "predictable and nothing like the validated DRBG and entropy path. The certificate says nothing about that "
        "mode.</p></div>"
        "<p class='muted'>The four security levels roughly escalate from “the cryptography is implemented correctly” to "
        "increasingly strong physical protection:</p>"
        "<div class='tw'><table><thead><tr><th>level</th><th>roughly</th><th>what it adds</th></tr></thead><tbody>"
        "<tr><td><b>Level 1</b></td><td>Implementation correct</td><td>Approved algorithms, correctly implemented; no "
        "physical security required. Software modules live here.</td></tr>"
        "<tr><td><b>Level 2</b></td><td>Tamper-evident</td><td>Tamper-evidence (you can tell if the module was opened) "
        "and role-based authentication.</td></tr>"
        "<tr><td><b>Level 3</b></td><td>Tamper-resistant</td><td>Tamper detection and response (the module zeroizes its "
        "keys on intrusion) and identity-based authentication.</td></tr>"
        "<tr><td><b>Level 4</b></td><td>Tamper-resistant, hardened</td><td>A complete protection envelope that also "
        "detects and responds to environmental attacks.</td></tr>"
        "</tbody></table></div>"

        "<h2>Who it was built for</h2>"
        "<p>FIPS validation is a <b>procurement</b> instrument. US federal agencies are required to use validated "
        "cryptography, so a certificate is largely the gate for selling cryptographic products into government, and "
        "into the regulated industries that inherit the requirement. It was designed as a purchasing bar and a "
        "point-in-time assurance record, not as a vulnerability-hunting tool. That origin explains much of its shape, "
        "and much of what people get wrong about it.</p>"

        "<h2>What it is commonly misunderstood to mean</h2>"
        "<div class='cols3'>"
        "<div class='panel'><h3>“FIPS certified” is not product-wide</h3><p>A product can embed a validated "
        "module and still run cryptography <b>outside</b> the validated boundary or outside approved mode. Both "
        "<a href='https://wiki.openssl.org/index.php/FIPS_Warnings_and_Cautions' target='_blank' rel='noopener'>OpenSSL"
        "</a> and <a href='https://web.archive.org/web/20220724205359/https://firefox-source-docs.mozilla.org/security/nss/legacy/fips_mode_-_an_explanation/index.html' target='_blank' rel='noopener'>Mozilla NSS</a> "
        "document this explicitly.</p></div>"
        "<div class='panel'><h3>Not all validations are equal</h3><p>Level, embodiment, and assurance type differ "
        "materially, and the <b>overall level is the lowest of the per-area levels</b>, so one part of a module can be "
        "Level 4 while another is Level 1. Even two modules at the same overall level are not equivalent: the level is "
        "a category and a floor, not a measure of real-world security. An interim two-year validation is not a full "
        "five-year one either.</p></div>"
        "<div class='panel'><h3>A certificate is a snapshot</h3><p>It attests a version, configuration, and approved "
        "mode at one moment. It does not, by itself, establish that a product shipping today still runs that same "
        "validated state, which is where the public record starts to leave questions.</p></div>"
        "</div>"
        "<p class='muted'>Further reading on how these labels get conflated: "
        "<a href='https://unmitigatedrisk.com/?p=991' target='_blank' rel='noopener'>TPMs, TEEs, and Everything In "
        "Between</a>; and on what an HSM actually protects: <a href='https://unmitigatedrisk.com/?p=877' "
        "target='_blank' rel='noopener'>HSMs Largely Protect Keys from Theft Rather Than Abuse</a>.</p>"

        "<h2>What it costs</h2>"
        "<p>Validation is a multi-year, multi-party process, and much of the elapsed time is spent <b>before</b> a "
        "package reaches the review queue and <b>after</b> CMVP returns comments, not only in the government queue. "
        "The one relatively clean public benchmark is post-submission: "
        "<a href='https://keypair.us/2024/02/fips-140-3-validation-times/' target='_blank' rel='noopener'>KeyPair's "
        "2024 analysis</a> found an average of <b>579 days</b> from CMVP receipt of the validation report to "
        "certificate issuance, roughly 366 days of review plus 213 of coordination. The phases below are best read as "
        "<b>estimated elapsed time</b>; only the post-submission rows are anchored to that benchmark.</p>"
        "<div class='tw'><table><thead><tr><th>phase</th><th>what happens</th><th>estimated elapsed</th>"
        f"<th>basis</th></tr></thead><tbody>{trows}</tbody></table></div>"
        "<p class='muted'>The controllable areas are pre-submission readiness, documentation quality, evidence "
        "traceability, and comment-response speed; the least controllable is the CMVP pending-review queue itself. "
        "NIST's <a href='https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process' "
        "target='_blank' rel='noopener'>Modules in Process</a> status definitions describe the same states, where the "
        "current action may sit with NIST, the lab, or the vendor. Money tracks time: accredited-lab fees plus the "
        "internal engineering to scope, remediate, and evidence a module make validation a substantial investment "
        "well before the certificate is posted.</p>"
        "<p>This lag is now a live constraint on the post-quantum transition. Google has said it wants to be "
        "post-quantum ready by 2029, and a recent White House executive order set a 2030 federal target, five years "
        "earlier than the prior goal. Yet at the time of writing (July 2026) not a single FIPS certificate has been "
        "issued for the core post-quantum algorithms, apart from ML-KEM used in TLS and SLH-DSA, whose utility so far "
        "is narrow and targeted. The time and cost of validation are themselves holding the rollout back. It is a bit "
        "like waiting on a permit in a big city: for months the answer has been “any day now,” with no firm date "
        "anyone can point to.</p>"

        "<h2>Certified once, attacked continuously</h2>"
        "<p>Validation is slow and static; the threat landscape is neither. For decades Patch Tuesday has delivered a "
        "steady stream of fixes, and the pace only accelerates as automated and AI-assisted discovery lowers the cost "
        "of finding bugs. The number of vulnerabilities disclosed each year keeps "
        "<a href='https://www.cve.org/about/Metrics' target='_blank' rel='noopener'>climbing</a>, and attackers do not "
        "care whether a module holds a FIPS certificate; they care whether the deployed system can be broken into. A "
        "certificate frozen at a 2024 version says nothing about the patches that shipped after it.</p>"
        "<p>The public CVE count also understates the churn. A single CVE can cover many distinct issues, and many "
        "issues are fixed quietly, in a release or a firmware update, with no CVE ever assigned. So “no CVEs against "
        "the certified version” is not the same as “nothing changed that a reviewer should reconcile.”</p>"
        "<p>The code under that pressure is rarely memory-safe. These modules, including the parts that parse messages "
        "from the outside world, are typically written in C, so a single mistake in handling a malformed input can put "
        "an attacker inside the security perimeter. Parsers are a classic way in; so are "
        "<a href='https://blog.randomoracle.io/2015/08/13/safenet-hsm-key-extraction-vulnerability-part-i/' "
        "target='_blank' rel='noopener'>forgotten capabilities left enabled and never tightened down</a>. The larger "
        "and more complicated the module's inner workings, the more surface there is for one of these to hide in.</p>"
        "<p>The modules where this matters most are often the hardest to inspect. Much of the assurance around HSMs "
        "rests on obscurity rather than transparency: firmware is obfuscated, binaries and documentation sit behind "
        "paywalls and support licenses, and access to the devices is gated by cost. Independent review is difficult, "
        "which is part of why the public CMVP record, what this corpus reads, is often all an outsider has to work "
        "with.</p>"
        "<p>And under the hood many of these devices are modest: a Linux server with a PCI-e cryptographic card, where "
        "only a small surface of that card sits inside the validated envelope. The certificate covers that envelope. "
        "The operating system, the drivers, the management plane, and everything else around it are not what was "
        "validated, which is exactly the boundary shown above.</p>"

        "<h2>What is actually being protected</h2>"
        "<p>The cryptography is rarely what breaks. What gets attacked is how the keys are held and how they can be "
        "used, and physical theft of a rack-mounted HSM is rarely the real vector. The datacenter around it, with its "
        "own access, personnel, and monitoring controls, is usually the true physical protection. Physical theft "
        "matters far more for the small devices you can pocket, such as smart cards and cryptocurrency wallets.</p>"
        "<p>The objective security an HSM buys is getting the key material out of the application's process and into a "
        "separate protection domain, so compromising the application does not directly hand over the key. But that only "
        "helps if the device is not simply a signing oracle. If an attacker who reaches the application can ask the HSM "
        "to sign arbitrary data, the key never has to leave. In the "
        "<a href='https://www.enisa.europa.eu/sites/default/files/all_files/Operation_Black_Tulip_v2.pdf' "
        "target='_blank' rel='noopener'>DigiNotar</a> compromise, reportedly the work of Iran-affiliated attackers "
        "targeting dissidents, the intruder used a certificate authority's signing capability to mint hundreds of "
        "fraudulent, publicly trusted certificates and, according to Fox-IT's investigation, intercept the encrypted "
        "traffic of Iranian internet users, simply by asking the device to sign.</p>"
        "<p>Stronger designs move production of the signed object inside the device and constrain what it will do: a "
        "single-purpose transaction model rather than a general oracle. Cryptocurrency hardware wallets are the "
        "clearest example. A sign-transaction API where the device enforces the amount, the destination address, and "
        "other parameters means an online attacker cannot pull out arbitrary signatures, which the oracle model cannot "
        "prevent. A FIPS certificate speaks to the module's cryptography and physical protection, not to which of these "
        "usage models it implements, and that choice is often where the real security lives.</p>"

        "<h2>Where this corpus fits</h2>"
        "<blockquote class='pull'><p>A FIPS certificate is an unexpectedly rich source of architectural intelligence.</p>"
        "<p>If you read enough Security Policies, you can start to understand how the industry actually builds "
        "cryptographic systems.</p></blockquote>"
        "<p>This static site reads the public CMVP certificates and Security Policies for a sampled certificate-number "
        "sweep of FIPS 140-3 modules. It turns the abstractions above into something you can inspect: what a given "
        "module actually had validated, how long its certified state has stood, and where the public record stops and "
        "vendor or deployment evidence would have to take over.</p>"
        "<div class='cards'>"
        "<a class='card' href='modules/index.html'><h3>Inspect</h3><div class='big'>Browse the "
        f"{N} modules</div><p>Open any module to see its full Security Policy and the questions the public record "
        "cannot resolve.</p></a>"
        "<a class='card' href='report.html'><h3>Understand</h3><div class='big'>Read the corpus findings</div>"
        "<p>How the certified state ages across the sampled set, and the method behind it.</p></a>"
        "</div>"

        "<div class='panel' style='padding:18px 22px'>"
        "<h3 style='margin-bottom:12px'>Reading a certificate in practice</h3>"
        "<ul class='chk'>"
        "<li>Start from the full <b>Security Policy</b>, not the one-line certificate summary.</li>"
        "<li>Confirm the exact <b>module version</b>, the <b>operational environments</b> listed, and that your "
        "configuration is an <b>approved-mode</b> service the certificate actually covers.</li>"
        "<li>Check how the vendor <b>maintains</b> the certificate: the patch cadence, and whether fixes ship as "
        "revalidations or quietly outside the boundary. Absence of a listed successor does not prove the module is "
        "unmaintained, only that the public record is silent.</li>"
        "<li>For high-assurance use such as CAs and key management, prefer <b>Level 3 or above</b> hardware, "
        "<b>constrained</b> signing services over general-purpose oracles, and evidence of how the key-handling TCB is "
        "protected.</li>"
        "<li>Treat <b>no known CVEs</b> against the certified version as necessary, not sufficient, and reconcile it "
        "against the vendor's full change and disclosure history.</li>"
        "</ul>"
        "<p class='muted' style='font-size:13px;margin-top:6px'>Authoritative starting points: NIST's "
        "<a href='https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search' "
        "target='_blank' rel='noopener'>Validated Modules</a> search, "
        "<a href='https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process' "
        "target='_blank' rel='noopener'>Modules in Process</a>, the "
        "<a href='https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards' "
        "target='_blank' rel='noopener'>CMVP standards and Implementation Guidance</a>, and "
        "<a href='https://csrc.nist.gov/pubs/fips/140-3/final' target='_blank' rel='noopener'>FIPS 140-3</a> itself.</p>"
        "</div>"

        "<h2>What we observed in the sampled corpus</h2>"
        "<p class='muted'>Findings from a sampled sweep that took every third certificate from #4700 to #5157, not the complete "
        "FIPS 140-3 population. Absence of a successor or update entry does not prove none exists.</p>"
        f"<div class='obs'>{th}</div>"
        "<p class='muted' style='font-size:13px;margin-top:18px'>The timeline is estimated elapsed time, strongest for "
        "the post-submission phases and industry-estimate elsewhere. Corpus figures are deterministic extractions from "
        "public CMVP and NVD data; they are review prompts, not vulnerability findings.</p>"
        "</main>")
    return page("FIPS 140-3 validation, in practice", "", "home", body)

# ---- module index ----------------------------------------------------------
def build_modules_index():
    rows = sorted(RECS, key=lambda r: -(r.get("months_since_last_validation") or 0))
    tr = ""
    for r in rows:
        surfaces = len(r.get("motifs") or [])
        stale = r.get('months_since_last_validation')
        tr += (f"<tr data-href='{r['cert']}.html'>"
               f"<td><span class='cn'><a href='{r['cert']}.html'>#{r['cert']}</a></span></td>"
               f"<td>{esc(r['module'])}</td><td class='muted'>{esc(r['vendor'])}</td>"
               f"<td>{esc(r['archetype'])}</td>"
               f"<td>{surfaces or ''}</td>"
               f"<td>{esc(stale)}{' mo' if stale is not None else ''}</td></tr>")
    body = ("<main>"
            "<p class='crumb'><a href='../index.html'>Overview</a> &nbsp;/&nbsp; Modules</p>"
            f"<h1>All {N} modules</h1>"
            "<p class='dek'>Sorted by time since last validation. Each row opens the module's full Security Policy, "
            "with the analysis signals folded into the top.</p>"
            "<div class='tw'><table><thead><tr><th>cert</th><th>module</th><th>vendor</th><th>archetype</th>"
            "<th>TCB surfaces</th><th>since last val.</th></tr></thead>"
            f"<tbody>{tr}</tbody></table></div></main>"
            "<script>document.querySelectorAll('tr[data-href]').forEach(function(r){"
            "r.addEventListener('click',function(e){if(e.target.closest('a'))return;location.href=r.dataset.href;});});</script>")
    return page(f"All {N} modules", "../", "modules", body)

# ---- per-module Security-Policy document view (render_html, re-skinned) -----
# Remap render_html's own CSS variables to the site tokens (light + dark) and drop
# in the site nav, so the document reconstruction reads as part of the site.
POLICY_SKIN = (
    "<style>"
    ":root{--navy:#0a5a5a;--accent:#0e6e6e;--ink:#0f1720;--muted:#47535f;--line:#e2e7ec;--line-soft:#eef1f4;--bg:#f4f6f8;--card:#fff;--pill:#f8fafb}"
    "@media(prefers-color-scheme:dark){:root{--navy:#5fc9bf;--accent:#43b9af;--ink:#e6ecf1;--muted:#a6b2bc;--line:#243039;--line-soft:#1b242c;--bg:#0d1216;--card:#141b21;--pill:#101820}}"
    ":root[data-theme=light]{--navy:#0a5a5a;--accent:#0e6e6e;--ink:#0f1720;--muted:#47535f;--line:#e2e7ec;--line-soft:#eef1f4;--bg:#f4f6f8;--card:#fff;--pill:#f8fafb}"
    ":root[data-theme=dark]{--navy:#5fc9bf;--accent:#43b9af;--ink:#e6ecf1;--muted:#a6b2bc;--line:#243039;--line-soft:#1b242c;--bg:#0d1216;--card:#141b21;--pill:#101820}"
    "html,body{background:var(--bg)}"
    # match the native pages: ~15.5px body text, full-width nav, a 900px centered content column
    "html{font-size:17.2px}"
    "body{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:none!important;margin:0!important;padding:0!important}"
    ".docwrap{max-width:900px;margin:0 auto;padding:22px 32px 56px}"
    "h1,.masthead h1{font-family:'Iowan Old Style','Palatino Linotype',Palatino,'Book Antiqua',Georgia,serif}"
    ".sitenav{border-bottom:1px solid var(--line);background:var(--card)}"
    ".sitenav-in{max-width:1120px;margin:0 auto;padding:12px 32px;display:flex;align-items:baseline;gap:22px}"
    ".sitenav .brand{font:600 14px/1 ui-monospace,'SF Mono','JetBrains Mono',Menlo,Consolas,monospace;letter-spacing:.02em;color:var(--ink);text-decoration:none;white-space:nowrap}"
    ".sitenav a{font:500 13.5px/1 ui-sans-serif,system-ui,sans-serif;color:var(--muted);text-decoration:none;padding:4px 0}.sitenav a:hover{color:var(--ink)}.sitenav a.on{color:var(--accent)}"
    ".sitenav .sp{flex:1}.backbar{margin:0 0 8px;padding:0;font-size:13px}"
    # render_html hardcodes light zebra/header backgrounds; theme them so dark mode is readable
    "table tbody tr:nth-child(even) td{background:var(--pill)!important}"
    "table thead th{background:var(--pill)!important}"
    # the typed-table first column used the bright accent for the whole cell; make it
    # readable ink so only the standard links stay teal
    ".typed td:first-child{color:var(--ink)}"
    "</style>")

def _placeholder_fig(fig):
    lbl = re.sub(r"<[^>]+>", "", str(fig.get("label") or "Figure"))[:60]
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' width='480' height='120'>"
           "<rect width='100%' height='100%' fill='none' stroke='#9aa4b0' stroke-dasharray='5 4' rx='8'/>"
           f"<text x='50%' y='44%' fill='#9aa4b0' font-family='sans-serif' font-size='13' text-anchor='middle'>{esc(lbl)}</text>"
           f"<text x='50%' y='66%' fill='#b6bec9' font-family='sans-serif' font-size='11' text-anchor='middle'>"
           f"diagram on Security Policy page {esc(fig.get('page'))}, not extracted</text></svg>")
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()

# The module page IS the full Security-Policy document reconstruction (render_html),
# re-skinned to the site, with the analysis signals folded into its masthead.
def build_module(r):
    cert = r["cert"]
    raw = json.load(open(f"corpus140_3/records/{cert}.json", encoding="utf-8"))
    # embed figure images where we have them; a clear placeholder otherwise
    for fig in (raw.get("securityPolicy") or {}).get("figures", []):
        fp = os.path.join("figs", fig.get("imageFile", ""))
        if fig.get("imageFile") and os.path.exists(fp):
            fig["_dataUri"] = "data:image/png;base64," + base64.b64encode(open(fp, "rb").read()).decode()
        else:
            fig["_dataUri"] = _placeholder_fig(fig)
    ptf = f"sp_text/{cert}.txt"
    page_texts = open(ptf, encoding="utf-8", errors="replace").read().split("\f") if os.path.exists(ptf) else []
    doc = render_html.render(raw, page_texts)

    # fold the analysis signals into the document as one review strip under the masthead
    prio = r["review_priority"]; surfaces = r.get("motifs") or []
    dr = DRIFT.get(cert); stale = r.get("months_since_last_validation")
    sep = " &nbsp;·&nbsp; "
    bits = [f"<b>{esc(prio)}</b> review priority"]
    bits.append(f"exposes {esc(', '.join(surfaces))}" if surfaces else "no TCB surface named")
    if dr:
        bits.append(f"<b>{esc(dr['component'])}</b> has moved {esc(dr['cves_in_component_since_cert'])} "
                    f"upstream CVEs since certification")
    if stale is not None:
        bits.append(f"last validated {esc(stale)} months ago")
    strip = (f"<div style='max-width:100%;margin:14px 0;padding:12px 16px;border:1px solid var(--line);"
             f"border-left:3px solid var(--accent);border-radius:0 10px 10px 0;background:var(--pill);font-size:14px'>"
             f"{sep.join(bits)}. "
             f"<a href='../report.html' style='color:var(--accent)'>How this is derived &#8594;</a></div>")
    doc = doc.replace("</header>", "</header>" + strip, 1)

    navbar = ("<nav class='sitenav'><div class='sitenav-in'>"
              "<a class='brand' href='../index.html'>FIPS&nbsp;140&#8209;3</a>"
              "<a href='../index.html'>Overview</a><a href='../report.html'>Report</a>"
              "<a href='index.html' class='on'>Modules</a><span class='sp'></span></div></nav>")
    backbar = "<div class='backbar'>&#8592; <a href='index.html'>All modules</a></div>"
    doc = doc.replace("</head>", POLICY_SKIN + "</head>", 1)
    # full-width nav bar, then a 900px centered content column (matches the native pages)
    doc = doc.replace("<body>", "<body>" + navbar + "<div class='docwrap'>" + backbar, 1)
    doc = doc.replace("</body>", "</div></body>", 1)
    return doc

# ---- report (wrap the standalone report with the site nav) -----------------
def build_report():
    h = open("corpus_report.html", encoding="utf-8").read()
    navcss = (".sitenav{border-bottom:1px solid var(--line);background:var(--surface)}"
              ".sitenav-in{max-width:1120px;margin:0 auto;padding:12px 32px;display:flex;align-items:baseline;gap:22px}"
              ".sitenav .brand{font:600 14px/1 var(--mono);letter-spacing:.02em;color:var(--ink);border:0;white-space:nowrap}"
              ".sitenav a{font:500 13.5px/1 var(--sans);color:var(--ink-2);border:0;padding:4px 0}.sitenav a:hover{color:var(--ink)}"
              ".sitenav a.on{color:var(--accent)}.sitenav .sp{flex:1}")
    navhtml = ("<nav class='sitenav'><div class='sitenav-in'>"
               "<a class='brand' href='index.html'>FIPS&nbsp;140&#8209;3</a>"
               "<a href='index.html'>Overview</a><a href='report.html' class='on'>Report</a>"
               "<a href='modules/index.html'>Modules</a><span class='sp'></span></div></nav>")
    h = h.replace("</style>", navcss + "</style>", 1)
    h = h.replace("<header class='mast'>", navhtml + "<header class='mast'>", 1)
    return h

# ---- emit ------------------------------------------------------------------
os.makedirs("docs/modules", exist_ok=True)
open("docs/index.html", "w").write(build_index())
open("docs/report.html", "w").write(build_report())
open("docs/modules/index.html", "w").write(build_modules_index())
for r in RECS:
    open(f"docs/modules/{r['cert']}.html", "w").write(build_module(r))
open("docs/.nojekyll", "w").write("")
print(f"wrote docs/ site: index + report + modules/index + {len(RECS)} full module pages")
