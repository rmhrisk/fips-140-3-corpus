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

.nav{border-bottom:1px solid var(--line);background:var(--surface)}
.nav-in{max-width:1120px;margin:0 auto;padding:12px 32px;display:flex;align-items:baseline;gap:22px}
.nav .brand{font:600 14px/1 var(--mono);letter-spacing:.02em;color:var(--ink);border:0;white-space:nowrap}
.nav .brand .dot{color:var(--accent)}
.nav a{font:500 13.5px/1 var(--sans);color:var(--ink-2);border:0;padding:4px 0}
.nav a:hover{color:var(--ink)} .nav a.on{color:var(--accent);font-weight:600}
.nav .sp{flex:1}

.wrap{max-width:1120px;margin:0 auto;padding:0 32px}
main{max-width:900px;margin:0 auto;padding:34px 32px 56px}
h1{font:600 34px/1.1 var(--serif);letter-spacing:-.015em;margin:0 0 6px;text-wrap:balance}
h2{font:600 22px/1.2 var(--serif);letter-spacing:-.01em;margin:36px 0 10px;text-wrap:balance}
h3{font:600 12px/1.3 var(--sans);letter-spacing:.04em;text-transform:uppercase;color:var(--ink-3);margin:0 0 9px}
p{margin:11px 0;max-width:70ch} .dek{font-size:18px;line-height:1.5;color:var(--ink-2);margin:10px 0 0;max-width:64ch}
.eyebrow{font:600 11.5px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin-bottom:14px}

.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;margin:22px 0;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.tile{background:var(--surface);padding:15px 17px}
.tile .v{font:600 25px/1.05 var(--serif);font-variant-numeric:tabular-nums;color:var(--ink)}
.tile .l{font-size:12px;color:var(--ink-2);margin-top:5px} .tile .s{font-size:11px;color:var(--ink-3);margin-top:2px}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin:20px 0}
.card{display:block;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:18px 20px;color:inherit}
a.card:hover{border-color:var(--accent-line);background:var(--surface-2)}
.card h3{color:var(--accent);margin-bottom:8px} .card .big{font:600 19px/1.2 var(--serif);color:var(--ink);margin:0 0 4px}
.card p{font-size:13.5px;color:var(--ink-2);margin:6px 0 0}

.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:14px 0}
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
            f"<a class='brand' href='{base}index.html'>FIPS&nbsp;140&#8209;3<span class='dot'>&nbsp;/</span>&nbsp;corpus</a>"
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
    lc = S["lifecycle"]; rc = S["recertification"]; mt = S["motifs"]
    win = lc["exposure_window_months (validation->sunset)"]["median"]
    no_update = N - rc["modules_with_updates"]
    interim = S["assurance"]["type_dist"].get("Interim (2-yr)", 0)
    upstream = len({m["cert"] for m in json.load(open("drift.json"))}) if os.path.exists("drift.json") else 0
    have_ver = 0
    for p in sorted(__import__("glob").glob("corpus140_3/records/*.json")):
        c = json.load(open(p)).get("certificate") or {}
        if (c.get("softwareVersions") or c.get("firmwareVersions")):
            have_ver += 1

    tiles = [
        (f"{N}", "sampled modules", "sweep #4700 to #5157, step 3"),
        (f"{no_update}", "no recorded update", f"of {N} sampled certificates"),
        (f"{win:.0f} mo", "median validation-to-sunset", "how long the certified state stands"),
        (f"{interim}", "interim validations", "2-year window, reduced review depth"),
        (f"{have_ver}", "record a software/firmware version", f"{round(100*have_ver/N)}%; the rest cannot be version-checked from the record"),
    ]
    th = "".join(f"<div class='tile'><div class='v'>{esc(v)}</div><div class='l'>{esc(l)}</div>"
                 f"{'<div class=s>'+esc(s)+'</div>' if s else ''}</div>" for v, l, s in tiles)

    steps = ["certificate found", "deployed module identified", "version matched",
             "operational environment matched", "approved mode confirmed",
             "patches &amp; dependencies reconciled"]
    flow = "<span class='arr'>&#8594;</span>".join(f"<span class='step'>{s}</span>" for s in steps)
    flow += "<span class='arr'>&#8594;</span><span class='step end'>claim supported</span>"

    BASIS = {
        "boot-chain verification": ("derived / keyword", "part"),
        "firmware-update authentication": ("keyword clue", "part"),
        "network crypto parser/protocol": ("derived from structured fields", "na"),
        "debug/recovery interface": ("declared / keyword", "part"),
        "kernel crypto consumer": ("derived from structured fields", "na"),
        "HSM/SE firmware trust anchor": ("derived from structured fields", "na"),
    }
    clues = "".join(
        f"<div class='ev'><span><b>{esc(k)}</b> <span class='muted'>&nbsp;·&nbsp; {v} modules</span></span>"
        f"<span class='pill {BASIS.get(k,('',''))[1]}'>{esc(BASIS.get(k,('unclassified',''))[0])}</span></div>"
        for k, v in mt["freq"].items())

    body = (
        "<main>"
        "<div class='eyebrow'>CMVP · FIPS 140-3 · sampled certificate-number sweep</div>"
        "<h1>What a FIPS certificate actually tells you</h1>"
        "<p class='dek'>This static corpus organizes public CMVP certificates and Security Policies so you can inspect "
        "the validated module, version, operational environments, services, interfaces, and update history, and see "
        "where the public record leaves questions about the product deployed today. A certificate is <b>necessary</b> "
        "evidence of deployed FIPS compliance, but not <b>sufficient</b> evidence that the running cryptographic "
        "function still matches the validated state.</p>"

        "<div class='cards'>"
        "<a class='card' href='modules/index.html'><h3>Inspect</h3><div class='big'>Browse the "
        f"{N} modules</div><p>Open any module to see its full Security Policy and the questions the public record "
        "cannot resolve.</p></a>"
        "<a class='card' href='report.html'><h3>Understand</h3><div class='big'>Read the corpus findings</div>"
        "<p>How the certified state ages, what the public record does and does not establish, and the method behind "
        "it.</p></a>"
        "</div>"

        "<h2>Start here</h2>"
        "<div class='cols3'>"
        "<div class='panel'><h3>Evaluating a specific module</h3><p>Open the <a href='modules/index.html'>module "
        "index</a> and its pre-generated detail page for that certificate.</p></div>"
        "<div class='panel'><h3>Understanding the lifecycle problem</h3><p>Read the <a href='report.html'>corpus "
        "findings and methodology</a> for the deployed-state assurance gap across the sampled set.</p></div>"
        "<div class='panel'><h3>Reviewing a product's FIPS claim</h3><p>Use the module page to identify what was "
        "validated, then compare that public record with evidence supplied by the vendor or operator. The site does "
        "not perform that comparison.</p></div>"
        "</div>"

        "<h2>What each module page contains</h2><ul>"
        "<li>module and certificate identity</li>"
        "<li>validation status and dates</li>"
        "<li>documented versions and operational environments</li>"
        "<li>declared algorithms, services, interfaces, and module-boundary clues</li>"
        "<li>the certificate update history</li>"
        "<li>named upstream components and maintenance activity, where available</li>"
        "<li>the specific questions the public record cannot resolve</li></ul>"

        "<h2>What you can learn here</h2>"
        "<p class='muted'>The CMVP certificate remains the authoritative validation record. This site restructures "
        "that public information so a reviewer can more quickly understand the validated claim and locate the "
        "questions that still require vendor or deployment evidence.</p>"
        "<div class='cols3'>"
        "<div class='panel'><h3>What was validated</h3><p>The module identity, version, environment, approved "
        "services, and certificate status documented in the public record.</p></div>"
        "<div class='panel'><h3>What has changed publicly</h3><p>Certificate updates, elapsed time, successor clues, "
        "and upstream maintenance activity that may need to be reconciled.</p></div>"
        "<div class='panel'><h3>What remains unknown</h3><p>The installed module version, patch provenance, "
        "approved-mode configuration, actual consuming services, and whether changes occurred inside the validated "
        "boundary.</p></div>"
        "</div>"
        "<p class='muted'>Establishing a deployed claim runs a chain; any step the public record cannot close reads as "
        "<b>additional evidence required</b>, not as a finding.</p>"
        f"<div class='flow'>{flow}</div>"

        "<h2>What we observed in the sampled corpus</h2>"
        "<p class='muted'>Findings from the sampled certificate-number sweep, not the complete FIPS 140-3 population.</p>"
        f"<div class='tiles'>{th}</div>"

        "<h2>Trust-relevant clues in the public record</h2>"
        "<p class='muted'>Interfaces, services, update paths, boot mechanisms, and trust anchors explicitly stated or "
        "deterministically derived from public Security Policies. They are prompts for review, not findings of "
        "exposure or vulnerability. A single module can raise several; counts are of modules.</p>"
        f"<div class='panel'>{clues}</div>"

        "<h2>Methodology &amp; limitations</h2>"
        "<p class='muted'>The corpus is a <b>sampled</b> certificate-number sweep (#4700 to #5157, step 3), so it does "
        "not represent every FIPS 140-3 validation, and absence of a successor or update entry does not prove none "
        "exists. Every signal sits in one of three layers, and they are not interchangeable:</p>"
        "<div class='cols3'>"
        "<div class='panel'><h3>Public fact</h3><p>Stated directly in the certificate metadata or the Security "
        "Policy.</p></div>"
        "<div class='panel'><h3>Derived review clue</h3><p>A deterministic inference from structured public "
        "evidence, or a keyword detected in the text. A prompt to confirm, not a conclusion.</p></div>"
        "<div class='panel'><h3>Deployment-dependent conclusion</h3><p>Needs vendor, product, SBOM, package, or "
        "operator evidence; it cannot be reached from the public corpus alone.</p></div>"
        "</div>"
        "<p class='dek' style='font-size:16px;margin-top:28px'>The result is not a vulnerability verdict. It is a "
        "deployed-assurance workflow: identify the validated claim, test its correspondence to the deployed state, "
        "and turn each unresolved gap into a specific evidence request.</p>"
        "</main>")
    return page("What a FIPS certificate actually tells you", "", "home", body)

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
    "body{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}"
    "h1,.masthead h1{font-family:'Iowan Old Style','Palatino Linotype',Palatino,'Book Antiqua',Georgia,serif}"
    ".sitenav{border-bottom:1px solid var(--line);background:var(--card)}"
    ".sitenav-in{max-width:1120px;margin:0 auto;padding:12px 32px;display:flex;align-items:baseline;gap:22px}"
    ".sitenav .brand{font:600 14px/1 ui-monospace,'SF Mono',Menlo,monospace;color:var(--ink);text-decoration:none;white-space:nowrap}.sitenav .brand .dot{color:var(--accent)}"
    ".sitenav a{font:500 13.5px/1 ui-sans-serif,system-ui,sans-serif;color:var(--muted);text-decoration:none}.sitenav a:hover{color:var(--ink)}.sitenav a.on{color:var(--accent);font-weight:600}"
    ".sitenav .sp{flex:1}.backbar{max-width:1120px;margin:8px auto 0;padding:0 32px;font-size:13px}"
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

    # fold the analysis signals into the document: extra chips in the masthead + a strip
    prio = r["review_priority"]; surfaces = r.get("motifs") or []
    dr = DRIFT.get(cert); stale = r.get("months_since_last_validation")
    extra = f"<span class='chip'><span class='k'>Review priority</span><span class='v'>{esc(prio)}</span></span>"
    if surfaces:
        extra += f"<span class='chip'><span class='k'>TCB surfaces</span><span class='v'>{len(surfaces)}</span></span>"
    if dr:
        extra += (f"<span class='chip'><span class='k'>Upstream drift</span><span class='v'>"
                  f"{esc(dr['component'])} {esc(dr['cves_in_component_since_cert'])} CVEs</span></span>")
    doc = doc.replace("<div class='chips'>", "<div class='chips'>" + extra, 1)

    surf_txt = ", ".join(surfaces) if surfaces else "none named"
    drift_txt = (f" &nbsp;·&nbsp; upstream drift: <b>{esc(dr['component'])}</b> "
                 f"{esc(dr['cves_in_component_since_cert'])} CVEs since cert" if dr else "")
    stale_txt = f" &nbsp;·&nbsp; {esc(stale)} months since last validation" if stale is not None else ""
    strip = (f"<div style='max-width:100%;margin:14px 0;padding:12px 16px;border:1px solid var(--line);"
             f"border-left:3px solid var(--accent);border-radius:0 10px 10px 0;background:var(--pill);font-size:14px'>"
             f"<b>Review priority: {esc(prio)}</b> &nbsp;·&nbsp; TCB surfaces: {esc(surf_txt)}{drift_txt}{stale_txt}. "
             f"<a href='../report.html' style='color:var(--accent)'>Analysis &amp; methodology &#8594;</a></div>")
    doc = doc.replace("</header>", "</header>" + strip, 1)

    nav = ("<nav class='sitenav'><div class='sitenav-in'>"
           "<a class='brand' href='../index.html'>FIPS&nbsp;140&#8209;3<span class='dot'>&nbsp;/</span>&nbsp;corpus</a>"
           "<a href='../index.html'>Overview</a><a href='../report.html'>Report</a>"
           "<a href='index.html' class='on'>Modules</a><span class='sp'></span></div></nav>"
           "<div class='backbar'>&#8592; <a href='index.html'>All modules</a></div>")
    doc = doc.replace("</head>", POLICY_SKIN + "</head>", 1)
    doc = doc.replace("<body>", "<body>" + nav, 1)
    return doc

# ---- report (wrap the standalone report with the site nav) -----------------
def build_report():
    h = open("corpus_report.html", encoding="utf-8").read()
    navcss = (".sitenav{border-bottom:1px solid var(--line);background:var(--surface)}"
              ".sitenav-in{max-width:1120px;margin:0 auto;padding:12px 32px;display:flex;align-items:baseline;gap:22px}"
              ".sitenav .brand{font:600 14px/1 var(--mono);color:var(--ink);border:0;white-space:nowrap}.sitenav .brand .dot{color:var(--accent)}"
              ".sitenav a{font:500 13.5px/1 var(--sans);color:var(--ink-2);border:0}.sitenav a:hover{color:var(--ink)}"
              ".sitenav a.on{color:var(--accent);font-weight:600}.sitenav .sp{flex:1}")
    navhtml = ("<nav class='sitenav'><div class='sitenav-in'>"
               "<a class='brand' href='index.html'>FIPS&nbsp;140&#8209;3<span class='dot'>&nbsp;/</span>&nbsp;corpus</a>"
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
