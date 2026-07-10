#!/usr/bin/env python3
"""Interactive three-panel review-priority explorer (self-contained HTML, no deps):
filters | ranked queue | evidence card. Reads corpus_analysis.json records."""
import json, html
d = json.load(open("corpus_analysis.json")); recs = d["records"]

def cert_url(r): return f"https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{r['cert']}"

# slim projection for the client
rows = []
for r in recs:
    rows.append({
        "cert": r["cert"], "module": r["module"] or "", "vendor": r["vendor"] or "",
        "arch": r["archetype"], "prio": r["review_priority"],
        "drift": r["drift_badge"], "plaus": r["plausibility_badge"], "impact": r["impact"],
        "assurance": r["assurance"], "reach": r["reachability"], "net": r["net_services"],
        "stale": r["months_since_last_validation"], "never": r["n_updates"] == 0,
        "cve": r["cve_pressure"], "level": r["level"], "type": r["type"],
        "clvl": r["claim_level"], "clvls": r["claim_levels"], "motifs": r.get("motifs", []),
        "comps": [c["name"] for c in r.get("components", []) if c["where"]=="name/version"],
        "ifaces": r["interfaces"], "drivers": r["drivers"], "reducers": r["reducers"],
        "evidence": r["evidence"], "conf": r["confidence"], "url": cert_url(r),
    })
PRI = {"Critical":3,"High":2,"Medium":1,"Low":0}
rows.sort(key=lambda x:(-PRI[x["prio"]], -(x["cve"] or 0), -(x["stale"] or 0)))
DATA = json.dumps(rows)

CSS = """
:root{
  --paper:#f4f6f8;--surface:#fff;--surface-2:#f8fafb;--ink:#0f1720;--ink-2:#47535f;--ink-3:#7c8894;
  --line:#e2e7ec;--line-2:#eef1f4;--accent:#0e6e6e;--accent-wash:#e6f0ef;--accent-line:#bcdad7;
  --crit-fg:#9e1f24;--crit-bg:#f8e4e4;--high-fg:#8a5410;--high-bg:#f7e8d3;--med-fg:#535f6c;--med-bg:#e9edf1;--low-fg:#2f6b58;--low-bg:#e2efe9;
  --serif:'Iowan Old Style','Palatino Linotype',Palatino,'Book Antiqua',Georgia,serif;
  --sans:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --mono:ui-monospace,'SF Mono','JetBrains Mono',Menlo,Consolas,monospace;
}
@media(prefers-color-scheme:dark){:root{
  --paper:#0d1216;--surface:#141b21;--surface-2:#101820;--ink:#e6ecf1;--ink-2:#a6b2bc;--ink-3:#72808b;
  --line:#243039;--line-2:#1b242c;--accent:#43b9af;--accent-wash:#12302e;--accent-line:#1f4b48;
  --crit-fg:#e98a8f;--crit-bg:#341d1f;--high-fg:#dba766;--high-bg:#31261a;--med-fg:#9fabb6;--med-bg:#1e262d;--low-fg:#6fc2a8;--low-bg:#16281f;
}}
:root[data-theme=light]{--paper:#f4f6f8;--surface:#fff;--surface-2:#f8fafb;--ink:#0f1720;--ink-2:#47535f;--ink-3:#7c8894;--line:#e2e7ec;--line-2:#eef1f4;--accent:#0e6e6e;--accent-wash:#e6f0ef;--accent-line:#bcdad7;--crit-fg:#9e1f24;--crit-bg:#f8e4e4;--high-fg:#8a5410;--high-bg:#f7e8d3;--med-fg:#535f6c;--med-bg:#e9edf1;--low-fg:#2f6b58;--low-bg:#e2efe9}
:root[data-theme=dark]{--paper:#0d1216;--surface:#141b21;--surface-2:#101820;--ink:#e6ecf1;--ink-2:#a6b2bc;--ink-3:#72808b;--line:#243039;--line-2:#1b242c;--accent:#43b9af;--accent-wash:#12302e;--accent-line:#1f4b48;--crit-fg:#e98a8f;--crit-bg:#341d1f;--high-fg:#dba766;--high-bg:#31261a;--med-fg:#9fabb6;--med-bg:#1e262d;--low-fg:#6fc2a8;--low-bg:#16281f}
*{box-sizing:border-box}
body{font:14px/1.55 var(--sans);margin:0;color:var(--ink);background:var(--paper);display:flex;flex-direction:column;height:100vh;-webkit-font-smoothing:antialiased}
header{padding:14px 20px;background:var(--surface);border-bottom:1px solid var(--line);flex:0 0 auto}
header .eyebrow{font:600 11px/1 var(--mono);letter-spacing:.13em;text-transform:uppercase;color:var(--accent);margin-bottom:7px}
header h1{font:600 20px/1.15 var(--serif);letter-spacing:-.01em;margin:0}
header p{margin:5px 0 0;color:var(--ink-2);font-size:12px;max-width:118ch} header p b{color:var(--ink)}
.wrap{display:grid;grid-template-columns:216px 1fr 384px;gap:14px;padding:14px;flex:1;min-height:0}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow:auto;padding:14px}
.panel h2{font:600 11px/1 var(--mono);text-transform:uppercase;letter-spacing:.1em;color:var(--ink-3);margin:0 0 12px}
.f{margin:0 0 12px} .f label{display:block;font-size:12px;color:var(--ink-2);margin:0 0 4px;font-weight:500}
.f select,.f input[type=text]{width:100%;font:13px var(--sans);color:var(--ink);background:var(--surface-2);border:1px solid var(--line);border-radius:7px;padding:6px 8px}
.f select:focus,.f input:focus-visible{outline:2px solid var(--accent);outline-offset:1px;border-color:var(--accent)}
.chk{display:flex;align-items:center;gap:7px;font-size:12.5px;color:var(--ink-2);margin:6px 0} .chk input{accent-color:var(--accent)}
.row{padding:10px 12px;border:1px solid var(--line-2);border-radius:10px;margin-bottom:7px;cursor:pointer;transition:border-color .12s,background .12s}
.row:hover{border-color:var(--accent-line);background:var(--surface-2)}
.row.sel{border-color:var(--accent);background:var(--accent-wash)}
.row .m{font:600 13px/1.3 var(--sans);color:var(--ink)} .row .m .cn{font:600 12px var(--mono);color:var(--ink-3);margin-right:5px}
.row .s{font-size:11px;color:var(--ink-2);margin-top:4px}
.badge{display:inline-block;font:600 10px/1 var(--sans);padding:3px 8px;border-radius:20px;margin-right:5px;letter-spacing:.02em}
.Critical{background:var(--crit-bg);color:var(--crit-fg)} .High{background:var(--high-bg);color:var(--high-fg)} .Medium{background:var(--med-bg);color:var(--med-fg)} .Low{background:var(--low-bg);color:var(--low-fg)}
.b3{display:inline-block;font:500 11px var(--mono);padding:2px 7px;border-radius:5px;margin:0 4px 4px 0;background:var(--surface-2);border:1px solid var(--line);color:var(--ink-2)}
.card h3{margin:0 0 3px;font:600 16px/1.25 var(--serif);color:var(--ink)} .card .sub{color:var(--ink-2);font-size:12px;margin-bottom:10px}
.card h4{margin:14px 0 6px;font:600 11px/1 var(--mono);text-transform:uppercase;letter-spacing:.08em;color:var(--ink-3)}
.card ul{margin:4px 0;padding-left:18px} .card li{margin:3px 0;font-size:12.5px;color:var(--ink-2)}
.ev{display:flex;justify-content:space-between;align-items:center;font-size:12px;padding:5px 0;border-bottom:1px solid var(--line-2)} .ev:last-child{border-bottom:0}
.ev b{font-weight:500;color:var(--ink-2)} .pill{font:600 10.5px/1 var(--sans);padding:3px 8px;border-radius:20px}
.ok{background:var(--low-bg);color:var(--low-fg)} .part{background:var(--high-bg);color:var(--high-fg)} .miss{background:var(--crit-bg);color:var(--crit-fg)} .na{background:var(--med-bg);color:var(--med-fg)}
.claim{background:var(--surface-2);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:0 8px 8px 0;padding:10px 12px;font-size:12px;line-height:1.5;color:var(--ink-2);margin:10px 0} .claim b{color:var(--ink)}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid var(--accent-line)} a:hover{border-bottom-color:var(--accent)}
.count{color:var(--ink-3);font:500 12px var(--mono);font-weight:400} .muted{color:var(--ink-3)}
::-webkit-scrollbar{width:10px;height:10px} ::-webkit-scrollbar-thumb{background:var(--line);border-radius:6px;border:2px solid var(--surface)}
@media(max-width:820px){.wrap{grid-template-columns:1fr;height:auto;overflow:auto} body{height:auto;min-height:100vh} .panel{max-height:none}}
"""

JS = """
const DATA=__DATA__; const PRI={Critical:3,High:2,Medium:1,Low:0};
const $=id=>document.getElementById(id);
const E=s=>String(s==null?'':s).replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
function opts(field,label){const vals=[...new Set(DATA.map(r=>r[field]).flat())].filter(x=>x!=null).sort();
  return `<div class=f><label>${label}</label><select id=f_${field}><option value=''>all</option>${vals.map(v=>`<option>${v}</option>`).join('')}</select></div>`;}
function filters(){
  $('filters').innerHTML =
   opts('prio','Review priority')+opts('clvl','Max claim level')+opts('arch','Archetype')+opts('motifs','Manifestation motif')+opts('assurance','Assurance')+opts('impact','Impact')+
   `<div class=chk><input type=checkbox id=f_never><label for=f_never>no cert update only</label></div>`+
   `<div class=chk><input type=checkbox id=f_net><label for=f_net>names a network service</label></div>`+
   `<div class=chk><input type=checkbox id=f_ver><label for=f_ver>version-exact CVE data</label></div>`;
  $('filters').querySelectorAll('select,input').forEach(e=>e.addEventListener('input',render));
}
function pass(r){
  for(const f of ['prio','clvl','arch','assurance','impact']){const v=$('f_'+f).value; if(v&&r[f]!=v)return false;}
  {const mv=$('f_motifs').value; if(mv&&!(r.motifs||[]).includes(mv))return false;}
  if($('f_never').checked&&!r.never)return false;
  if($('f_net').checked&&(!r.net||!r.net.length))return false;
  if($('f_ver').checked&&r.conf.version_cve!='high')return false;
  return true;
}
function pill(v){const m={complete:'ok',named:'ok',exact:'ok',measured:'ok',partial:'part','component-only':'part','not captured':'miss','none/unknown':'miss','not collected':'miss',unknown:'miss','n/a':'na'};return `<span class='pill ${m[v]||'na'}'>${v}</span>`;}
let selCert=null;
function render(){
  const list=DATA.filter(pass);
  $('count').textContent=list.length+' of '+DATA.length;
  $('queue').innerHTML=list.map(r=>`<div class='row ${r.cert==selCert?'sel':''}' data-c='${r.cert}'>
    <div class=m><span class=cn>#${r.cert}</span>${E(r.module)}</div>
    <div class=s><span class='badge ${r.prio}'>${r.prio} review</span>${E(r.arch)} · ${r.stale!=null?r.stale+'mo':'?'} · ${r.never?'no CMVP update':'CMVP-updated'}${r.net&&r.net.length?' · consumes '+E(r.net.slice(0,2).join('/')):''}</div></div>`).join('');
  $('queue').querySelectorAll('.row').forEach(e=>e.onclick=()=>{selCert=+e.dataset.c;render();card();});
  if(!selCert&&list.length){selCert=list[0].cert;} card();
}
function card(){
  const r=DATA.find(x=>x.cert==selCert); if(!r){$('card').innerHTML='';return;}
  const ev=Object.entries(r.evidence).map(([k,v])=>`<div class=ev><b>${k}</b>${pill(v)}</div>`).join('');
  $('card').innerHTML=`
   <div class=card>
    <h3>#${r.cert} — ${E(r.module)}</h3>
    <div class=sub>${E(r.vendor)} · ${E(r.arch)} · L${E(r.level)} ${E(r.type)}</div>
    <div><span class='badge ${r.prio}'>${r.prio} review</span> <span class=b3>claim level: ${(r.clvls||[]).join(' ')||'—'} (max ${r.clvl})</span></div>
    <div class=claim><b>Claim type:</b> attack-path / certified-state-drift hypothesis. <b>Known vulnerability:</b> not established.<br/>
     <b>Service-path signal:</b> ${r.conf.service_path_signal} ${r.net&&r.net.length?'(names '+E(r.net.slice(0,3).join('/'))+')':'(no network service named)'}.
     <b>Deployment reachability:</b> ${r.conf.deployment_reachability} — needs product/service-path evidence.</div>
    <h4>Claim levels (what is known vs inferred)</h4>
    <div style='font-size:12px'>L1 cert drift · L2 component CVE pressure · L3 version-intersecting · L4 service-path hypothesis · L5 confirmed exposure<br/>
     <b>this module: ${(r.clvls||[]).join(', ')||'none'}</b> (L5 is never reached from public CMVP+NVD data alone)</div>
    <h4>Identified components ${r.comps&&r.comps.length?'':'<span class=muted>(none named)</span>'}</h4>
    <div>${(r.comps||[]).map(x=>`<span class=b3>${E(x)}</span>`).join('')||'<span class=muted>—</span>'}</div>
    <h4>Vuln-manifestation motifs <span class=muted>(pattern present, not a vulnerability)</span></h4>
    <div>${(r.motifs||[]).map(x=>`<span class=b3>${E(x)}</span>`).join('')||'<span class=muted>none matched</span>'}</div>
    <h4>Assessment</h4>
    <div><span class=b3>assurance drift: ${r.drift}</span><span class=b3>attack-path plausibility: ${r.plaus}</span><span class=b3>impact: ${r.impact}</span></div>
    <h4>Why (priority drivers)</h4><ul>${r.drivers.map(x=>`<li>${E(x)}</li>`).join('')||'<li>none</li>'}</ul>
    <h4>Not proven / reducers</h4><ul>${r.reducers.map(x=>`<li>${E(x)}</li>`).join('')||'<li>—</li>'}</ul>
    <h4>Evidence completeness</h4>${ev}
    <h4>Next evidence to collect</h4><ul>
      <li>exact deployed component version (vs certified)</li>
      <li>which services consume this crypto (pre-auth?)</li>
      <li>vendor advisory / firmware / release-note visibility</li>
      <li>distro backport status for the named CVEs</li></ul>
    <p><a href='${r.url}' target=_blank>CMVP certificate ↗</a></p>
   </div>`;
}
filters();render();
"""

body = ("<header>"
        "<div class='eyebrow'>CMVP · FIPS 140-3 · review-priority explorer</div>"
        "<h1>Where to look first — and why</h1>"
        "<p>Evidence-backed review prioritization — attack-path hypotheses requiring confirmation, NOT confirmed vulnerabilities. "
        f"n={len(rows)} · ref 2026-07 · one view of the corpus evidence graph (corpus_analysis.json).<br/>"
        "<b>Terminology:</b> “certificate” / “validation” / “update” = the <b>CMVP FIPS 140-3 validation certificate</b> "
        "and its validation-history events — not an X.509/TLS certificate.</p></header>"
        "<div class='wrap'>"
        "<div class='panel'><h2>Filters</h2><div id='filters'></div></div>"
        "<div class='panel'><h2>Ranked queue <span class='count' id='count'></span></h2><div id='queue'></div></div>"
        "<div class='panel'><h2>Evidence card</h2><div id='card'></div></div>"
        "</div>")
out = (f"<!doctype html><meta charset=utf-8>"
       f"<meta name=viewport content='width=device-width,initial-scale=1'>"
       f"<title>FIPS 140-3 Review-Priority Explorer</title>"
       f"<style>{CSS}</style>{body}<script>{JS.replace('__DATA__', DATA)}</script>")
out = out.replace(" — ", ", ").replace("—", ", ")   # no em dashes in output copy
open("explorer.html","w").write(out)
print(f"wrote explorer.html ({len(out)//1024} KB, {len(rows)} modules)")
