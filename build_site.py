#!/usr/bin/env python3
"""Generate the published static site into docs/ (GitHub Pages ready):

    docs/index.html            landing page
    docs/report.html           the corpus analysis report (wrapped with site nav)
    docs/modules/index.html    browsable index of every module
    docs/modules/<cert>.html   one detail page per module

All pages share one design system and one top navigation. Pure stdlib; reads
corpus_analysis.json + drift.json, and wraps the already-rendered corpus_report.html.
"""
import json, html, os, re
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
.nav .brand{font:600 14px/1 var(--mono);letter-spacing:.02em;color:var(--ink);border:0}
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
tbody tr:hover{background:var(--surface-2)} td .cn{font:600 12.5px var(--mono);color:var(--ink-3)}
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
            f"<a class='brand' href='{base}index.html'>FIPS&nbsp;140-3<span class='dot'>&nbsp;/</span>&nbsp;corpus</a>"
            f"{links}<span class='sp'></span>"
            f"<span style='color:var(--ink-3);font:500 12px/1 var(--mono)'>ref {esc(REF)}</span>"
            f"</div></nav>")

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
    lc = S["lifecycle"]; rc = S["recertification"]; al = S["algorithms"]; mt = S["motifs"]
    win = lc["exposure_window_months (validation->sunset)"]["median"]
    tiles = [
        ("v", f"{N}", "modules analyzed", esc(S["coverage"]["cert_number_span"])),
        ("v", f"{100-rc['pct_with_updates']:.0f}%", "never re-validated", f"{N-rc['modules_with_updates']} of {N}"),
        ("v", f"{win:.0f} mo", "median cert window", "validation to sunset"),
        ("v", f"{al['modules_with_any_legacy_pct']:.0f}%", "carry a legacy primitive", "SHA-1 / ECB / 3DES"),
    ]
    th = "".join(f"<div class='tile'><div class='v'>{v}</div><div class='l'>{esc(l)}</div>"
                 f"{'<div class=s>'+s+'</div>' if s else ''}</div>" for _, v, l, s in tiles)
    surf = "".join(f"<span class='chip'>{esc(k)} &nbsp;{v}</span>" for k, v in mt["freq"].items())
    body = (
        "<main>"
        "<div class='eyebrow'>CMVP · FIPS 140-3 validated-module corpus</div>"
        "<h1>What a FIPS certificate actually tells you</h1>"
        "<p class='dek'>Read across the public corpus, FIPS certificates and their Security Policies reveal far more "
        "than a pass/fail stamp. They show the trusted-computing-base surfaces around each module, how far its "
        "components have drifted since validation, and where a security review should look first.</p>"
        f"<div class='tiles'>{th}</div>"
        "<div class='cards'>"
        "<a class='card' href='report.html'><h3>The analysis</h3><div class='big'>Corpus report</div>"
        "<p>The full read of the corpus: what a certificate proves, how the certified state freezes, the TCB surfaces "
        "the artifacts reveal, and where to look first.</p></a>"
        "<a class='card' href='modules/index.html'><h3>Browse</h3><div class='big'>All modules</div>"
        f"<p>Every one of the {N} modules, each with its own page: archetype, TCB surfaces, component drift, review "
        "priority, and what to confirm next.</p></a>"
        "</div>"
        "<h2>What these artifacts are good for</h2>"
        "<p>A certificate attests one module version, in one approved-mode configuration, at one moment. Read across "
        "the whole corpus it still delivers three things a reviewer can act on: a map of the trusted-computing-base "
        "surfaces around each module, a measure of how far its named components have drifted since validation, and a "
        "ranked view of where a review should look first. It is best read as a map of what to verify in a deployment, "
        "which is what makes it a fast way to aim that verification.</p>"
        f"<h2>TCB surfaces across the corpus</h2><p class='muted'>Architectural patterns where a bug class would matter, "
        f"visible even when the component behind them is not named.</p><p>{surf}</p>"
        "</main>")
    return page("What a FIPS certificate actually tells you", "", "home", body)

# ---- module index ----------------------------------------------------------
def build_modules_index():
    rows = sorted(RECS, key=lambda r: (-PRI_ORD.get(r["review_priority"], 0),
                                       -(r.get("months_since_last_validation") or 0)))
    tr = ""
    for r in rows:
        surfaces = len(r.get("motifs") or [])
        tr += (f"<tr><td><span class='cn'><a href='{r['cert']}.html'>#{r['cert']}</a></span></td>"
               f"<td>{esc(r['module'])}</td><td class='muted'>{esc(r['vendor'])}</td>"
               f"<td>{esc(r['archetype'])}</td><td>{tagp(r['review_priority'])}</td>"
               f"<td>{surfaces or ''}</td>"
               f"<td>{esc(r.get('months_since_last_validation'))}{' mo' if r.get('months_since_last_validation') is not None else ''}</td></tr>")
    body = ("<main>"
            "<p class='crumb'><a href='../index.html'>Overview</a> &nbsp;/&nbsp; Modules</p>"
            f"<h1>All {N} modules</h1>"
            "<p class='dek'>Sorted by review priority, then by time since last validation. Each row links to a full "
            "module page. Priority is a place to start a review, not a vulnerability finding.</p>"
            "<div class='tw'><table><thead><tr><th>cert</th><th>module</th><th>vendor</th><th>archetype</th>"
            "<th>review priority</th><th>TCB surfaces</th><th>since last val.</th></tr></thead>"
            f"<tbody>{tr}</tbody></table></div></main>")
    return page(f"All {N} modules", "../", "modules", body)

# ---- per-module page -------------------------------------------------------
def build_module(r):
    cert = r["cert"]
    facts = [("assurance", r.get("assurance")), ("security level", f"Level {r.get('level')}"),
             ("embodiment", r.get("type")), ("status", r.get("status")),
             ("initial validation", r.get("initial_validation")), ("last validation", r.get("last_validation")),
             ("CMVP updates", r.get("n_updates")), ("months since last val.", r.get("months_since_last_validation")),
             ("cert window (mo)", r.get("exposure_window_months")), ("doc grade", r.get("grade"))]
    kv = "".join(f"<div><div class='k'>{esc(k)}</div><div>{esc(v)}</div></div>" for k, v in facts if v is not None and v != "")
    def chips(items): return "".join(f"<span class='chip'>{esc(x)}</span>" for x in items) or "<span class='muted'>none named</span>"
    motifs = chips(r.get("motifs") or [])
    comps = chips([c.get("name") for c in (r.get("components") or [])])
    ifaces = chips(r.get("interfaces") or [])
    net = chips(r.get("net_services") or [])
    drivers = "".join(f"<li>{esc(x)}</li>" for x in (r.get("drivers") or [])) or "<li class='muted'>none</li>"
    reducers = "".join(f"<li>{esc(x)}</li>" for x in (r.get("reducers") or [])) or "<li class='muted'>none</li>"
    ev = "".join("<div class='ev'><span>" + esc(k) + "</span><span class='pill " +
                 EV_CLS.get(str(v).lower(), "na") + "'>" + esc(v) + "</span></div>"
                 for k, v in (r.get("evidence") or {}).items())
    dr = DRIFT.get(cert)
    drift_html = ""
    if dr:
        drift_html = (
            "<h2>Component drift</h2>"
            "<p class='muted'>CVEs disclosed in the named upstream component (CPE-matched in NVD) since this module's "
            "initial validation. A measure of how far the upstream moved past the certified snapshot, and a review "
            "trigger, not a vulnerability count for the module.</p>"
            f"<div class='panel'><div class='kv'>"
            f"<div><div class='k'>component</div><div><b>{esc(dr['component'])}</b></div></div>"
            f"<div><div class='k'>version as listed</div><div>{esc(dr.get('version') or '?')}</div></div>"
            f"<div><div class='k'>upstream CVEs since cert</div><div><b>{esc(dr['cves_in_component_since_cert'])}</b></div></div>"
            f"</div></div>")
    body = (
        "<main>"
        f"<p class='crumb'><a href='../index.html'>Overview</a> &nbsp;/&nbsp; <a href='index.html'>Modules</a> "
        f"&nbsp;/&nbsp; #{cert}</p>"
        f"<div style='display:flex;gap:12px;align-items:baseline;flex-wrap:wrap'>"
        f"<span class='mono' style='color:var(--ink-3);font-size:15px'>#{cert}</span>{tagp(r['review_priority'])}</div>"
        f"<h1>{esc(r['module'])}</h1>"
        f"<p class='dek'>{esc(r['vendor'])} &nbsp;·&nbsp; {esc(r['archetype'])}</p>"
        f"<div class='panel'><div class='kv'>{kv}</div></div>"
        f"<p><a href='{cert}-policy.html'><b>Read the full Security Policy detail for #{cert}</b> &#8594;</a> "
        "<span class='muted'>(algorithms, sections, tables, and validation history, reconstructed from the record)</span></p>"
        f"<h2>TCB surfaces</h2><p class='muted'>Architectural patterns where a bug class would matter (see the "
        f"<a href='../report.html'>report</a> for what each means). Present, not a finding.</p><p>{motifs}</p>"
        f"<h2>Identified components</h2><p>{comps}</p>"
        f"<h2>Interfaces &amp; services</h2><div class='kv'><div><div class='k'>interfaces</div><div>{ifaces}</div></div>"
        f"<div><div class='k'>network services named</div><div>{net}</div></div></div>"
        f"{drift_html}"
        f"<h2>Why it is prioritized</h2><div class='cards' style='grid-template-columns:1fr 1fr'>"
        f"<div class='panel'><h3>Drivers</h3><ul>{drivers}</ul></div>"
        f"<div class='panel'><h3>Not established / reducers</h3><ul>{reducers}</ul></div></div>"
        f"<h2>Evidence completeness</h2><div class='panel'>{ev}</div>"
        f"<h2>What to confirm next</h2><ul>"
        "<li>exact deployed component version versus the certified version</li>"
        "<li>which services consume this crypto, and whether any are reachable pre-authentication</li>"
        "<li>vendor advisory / firmware / release-note visibility</li>"
        "<li>distro or vendor back-port status for any named CVEs</li></ul>"
        f"<p style='margin-top:20px'><a href='{CERT_URL.format(cert)}' target='_blank' rel='noopener'>"
        "View the CMVP certificate on csrc.nist.gov &nbsp;&#8599;</a></p>"
        "</main>")
    return page(f"#{cert} {r['module']}", "../", "modules", body)

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
    ".sitenav-in{max-width:1120px;margin:0 auto;padding:12px 22px;display:flex;align-items:baseline;gap:20px}"
    ".sitenav .brand{font:600 14px/1 ui-monospace,'SF Mono',Menlo,monospace;color:var(--ink);text-decoration:none}.sitenav .brand .dot{color:var(--accent)}"
    ".sitenav a{font:500 13.5px/1 ui-sans-serif,system-ui,sans-serif;color:var(--muted);text-decoration:none}.sitenav a:hover{color:var(--ink)}"
    ".sitenav .sp{flex:1}.backbar{max-width:1120px;margin:8px auto 0;padding:0 22px;font-size:13px}"
    "</style>")

def build_policy(r):
    cert = r["cert"]
    doc = render_html.render(r, [])
    nav = ("<nav class='sitenav'><div class='sitenav-in'>"
           "<a class='brand' href='../index.html'>FIPS&nbsp;140-3<span class='dot'>&nbsp;/</span>&nbsp;corpus</a>"
           "<a href='../index.html'>Overview</a><a href='../report.html'>Report</a>"
           "<a href='index.html'>Modules</a><span class='sp'></span></div></nav>"
           f"<div class='backbar'>&#8592; <a href='{cert}.html'>Back to the analysis summary for #{cert}</a></div>")
    doc = doc.replace("</head>", POLICY_SKIN + "</head>", 1)
    doc = doc.replace("<body>", "<body>" + nav, 1)
    return doc

# ---- report (wrap the standalone report with the site nav) -----------------
def build_report():
    h = open("corpus_report.html", encoding="utf-8").read()
    navcss = (".sitenav{border-bottom:1px solid var(--line);background:var(--surface)}"
              ".sitenav-in{max-width:1120px;margin:0 auto;padding:12px 32px;display:flex;align-items:baseline;gap:22px}"
              ".sitenav .brand{font:600 14px/1 var(--mono);color:var(--ink);border:0}.sitenav .brand .dot{color:var(--accent)}"
              ".sitenav a{font:500 13.5px/1 var(--sans);color:var(--ink-2);border:0}.sitenav a:hover{color:var(--ink)}"
              ".sitenav a.on{color:var(--accent);font-weight:600}.sitenav .sp{flex:1}")
    navhtml = ("<nav class='sitenav'><div class='sitenav-in'>"
               "<a class='brand' href='index.html'>FIPS&nbsp;140-3<span class='dot'>&nbsp;/</span>&nbsp;corpus</a>"
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
    open(f"docs/modules/{r['cert']}-policy.html", "w").write(build_policy(r))
open("docs/.nojekyll", "w").write("")
print(f"wrote docs/ site: index + report + modules/index + {len(RECS)} analysis + {len(RECS)} policy pages")
