#!/usr/bin/env python3
"""Render the software-library fingerprint dataset to an UNLISTED site page.

    python3 build_swlib_page.py   # -> docs/swlib.html

The page is self-contained (inline CSS/JS, data embedded), theme-aware to match
the rest of the site, and carries <meta name=robots content=noindex>. It is NOT
linked from index.html or the nav, so it is reachable only by direct URL — a
draft surface while the dataset is still being trusted.
"""
import json
import os
import html

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "fips_swlib.json")
OUT = os.path.join(HERE, "docs", "swlib.html")

doc = json.load(open(DATA))
rows = doc["rows"]

# compact display payload
disp = []
for r in rows:
    fp = r["fingerprints"]
    pubs = fp["published_artifacts"]
    disp.append({
        "cert": r["cert"],
        "name": r["module_name"],
        "vendor": r["vendor"],
        "type": r["module_type"],
        "comp": r["component"],
        "cver": r["component_version"],
        "mver": r["module_software_versions"],
        "files": [a["file"] for a in fp["filenames"]],
        "digs": [{"h": d["digest"], "k": d["kind"]} for d in fp["declared_digests"]],
        "pubs": [{
            "f": a["filename"], "k": a["artifact_kind"], "v": a["version"],
            "h": a["sha256"], "ver": a["verified"], "vm": a.get("verify_method"),
            "u": a["sha256_source_url"], "d": a["download_url"], "c": a["confidence"],
        } for a in pubs],
        "conf": r["identity_confidence"],
        "ev": r["identity_evidence"],
        "sp": r["security_policy_url"],
        "b": (r.get("provenance", {}) or {}).get("trackB_found"),
    })

n = len(disp)
n_hash = sum(1 for d in disp for p in d["pubs"] if p["h"])
n_verified = sum(1 for d in disp for p in d["pubs"] if p["h"] and p["ver"])
n_pub = sum(1 for d in disp if d["pubs"])
n_file = sum(1 for d in disp if d["files"])
n_comp = sum(1 for d in disp if d["comp"])
n_hi = sum(1 for d in disp if d["conf"] >= 0.8)

PALETTE = """:root{--paper:#f4f6f8;--surface:#fff;--surface-2:#f8fafb;--ink:#0f1720;--ink-2:#47535f;--ink-3:#7c8894;--line:#e2e7ec;--line-2:#eef1f4;--accent:#0e6e6e;--accent-2:#0a5a5a;--accent-wash:#e6f0ef;--accent-line:#bcdad7;--crit-fg:#9e1f24;--crit-bg:#f8e4e4;--high-fg:#8a5410;--high-bg:#f7e8d3;--med-fg:#535f6c;--med-bg:#e9edf1;--low-fg:#2f6b58;--low-bg:#e2efe9;--serif:'Iowan Old Style',Palatino,Georgia,serif;--sans:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;--mono:ui-monospace,'SF Mono',Menlo,Consolas,monospace}
@media(prefers-color-scheme:dark){:root{--paper:#0d1216;--surface:#141b21;--surface-2:#101820;--ink:#e6ecf1;--ink-2:#a6b2bc;--ink-3:#72808b;--line:#243039;--line-2:#1b242c;--accent:#43b9af;--accent-2:#5fc9bf;--accent-wash:#12302e;--accent-line:#1f4b48;--crit-fg:#e98a8f;--crit-bg:#341d1f;--high-fg:#dba766;--high-bg:#31261a;--med-fg:#9fabb6;--med-bg:#1e262d;--low-fg:#6fc2a8;--low-bg:#16281f}}
:root[data-theme=light]{--paper:#f4f6f8;--surface:#fff;--surface-2:#f8fafb;--ink:#0f1720;--ink-2:#47535f;--ink-3:#7c8894;--line:#e2e7ec;--line-2:#eef1f4;--accent:#0e6e6e;--accent-line:#bcdad7;--crit-fg:#9e1f24;--crit-bg:#f8e4e4;--high-fg:#8a5410;--high-bg:#f7e8d3;--med-fg:#535f6c;--med-bg:#e9edf1;--low-fg:#2f6b58;--low-bg:#e2efe9}
:root[data-theme=dark]{--paper:#0d1216;--surface:#141b21;--surface-2:#101820;--ink:#e6ecf1;--ink-2:#a6b2bc;--ink-3:#72808b;--line:#243039;--line-2:#1b242c;--accent:#43b9af;--accent-line:#1f4b48;--crit-fg:#e98a8f;--crit-bg:#341d1f;--high-fg:#dba766;--high-bg:#31261a;--med-fg:#9fabb6;--med-bg:#1e262d;--low-fg:#6fc2a8;--low-bg:#16281f}"""

CSS = """*{box-sizing:border-box}body{font:15px/1.6 var(--sans);margin:0;color:var(--ink);background:var(--paper);-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid var(--accent-line)}a:hover{border-bottom-color:var(--accent)}
.mono{font-family:var(--mono)}.wrap{max-width:1280px;margin:0 auto;padding:26px 26px 70px}
h1{font:600 30px/1.12 var(--serif);letter-spacing:-.015em;margin:0 0 4px}
.dek{font-size:17px;color:var(--ink-2);margin:6px 0 0;max-width:74ch}
.draft{display:inline-block;font:600 11px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--high-fg);background:var(--high-bg);border:1px solid var(--high-fg);border-radius:5px;padding:5px 9px;margin-bottom:14px}
.stats{display:flex;flex-wrap:wrap;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:11px;overflow:hidden;margin:20px 0}
.stat{background:var(--surface);padding:12px 18px;flex:1;min-width:120px}
.stat b{display:block;font:600 24px/1 var(--serif);color:var(--ink)}.stat span{font-size:12px;color:var(--ink-3)}
.legend{font-size:13px;color:var(--ink-2);background:var(--surface-2);border:1px solid var(--line);border-radius:9px;padding:12px 16px;margin:16px 0}
.controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:18px 0 10px;position:sticky;top:0;background:var(--paper);padding:10px 0;z-index:5}
input[type=search]{font:14px var(--sans);padding:8px 12px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--ink);min-width:240px;flex:1}
label.tog{font-size:13px;color:var(--ink-2);display:flex;align-items:center;gap:5px;cursor:pointer;user-select:none}
.count{font-size:13px;color:var(--ink-3);margin-left:auto}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line-2);vertical-align:top}
th{position:sticky;top:56px;background:var(--surface);font:600 11px/1.2 var(--sans);letter-spacing:.03em;text-transform:uppercase;color:var(--ink-3);cursor:pointer;white-space:nowrap;z-index:4}
th:hover{color:var(--accent)}tbody tr:hover{background:var(--surface-2)}
.chip{display:inline-block;font:.86em var(--mono);background:var(--surface-2);border:1px solid var(--line);border-radius:4px;padding:1px 5px;margin:1px 3px 1px 0;color:var(--ink-2)}
.hash{font-family:var(--mono);font-size:.84em;color:var(--ink-2);cursor:pointer;border-bottom:1px dotted var(--line)}
.hash:hover{color:var(--accent)}
.badge{font:600 10.5px/1 var(--mono);border-radius:4px;padding:2px 5px;white-space:nowrap}
.v-yes{color:var(--low-fg);background:var(--low-bg)}.v-no{color:var(--high-fg);background:var(--high-bg)}
.key{display:flex;flex-wrap:wrap;gap:8px 20px;margin:14px 0;padding:13px 16px;background:var(--surface-2);border:1px solid var(--line);border-radius:9px;font-size:12.5px}
.key .kt{font:600 11px/1.3 var(--sans);letter-spacing:.04em;text-transform:uppercase;color:var(--ink-3);width:100%;margin-bottom:2px}
.keyitem{display:flex;align-items:center;gap:7px;color:var(--ink-2)}
.conf{font:600 12px var(--mono);border-radius:5px;padding:2px 7px}
.c-hi{color:var(--low-fg);background:var(--low-bg)}.c-md{color:var(--med-fg);background:var(--med-bg)}.c-lo{color:var(--ink-3)}
.k{font-size:11px;color:var(--ink-3)}.artline{margin:2px 0}
td.name{max-width:260px}.small{font-size:12px;color:var(--ink-3)}"""

JS = """const D=window.__D__;const tb=document.getElementById('tb');const q=document.getElementById('q');
const oh=document.getElementById('oh');const cnt=document.getElementById('cnt');let sortK='conf',sortDir=-1;
function confCls(c){return c>=0.8?'c-hi':c>=0.5?'c-md':'c-lo'}
function esc(s){return (s==null?'':(''+s)).replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]))}
const vmLabel={'sp-text-confirmed':'SP-confirmed','web-reverified':'web-verified','peer-corrected':'peer-verified','unconfirmed':'unverified'};
function pubHtml(p){let h='';for(const a of p){const vt=a.h?(vmLabel[a.vm]||(a.ver?'verified':'unverified')):'';const badge=a.h?`<span class="badge ${a.ver?'v-yes':'v-no'}">${vt}</span>`:'';
 const hash=a.h?`<span class="hash" title="click to copy" onclick="navigator.clipboard.writeText('${a.h}')">${a.h.slice(0,20)}…</span>`:'<span class="small">no published hash</span>';
 const src=a.u?` <a href="${esc(a.u)}" target="_blank" rel="noopener">src</a>`:'';
 h+=`<div class="artline"><span class="chip">${esc(a.f)}</span> ${hash}${src} ${badge} <span class="k">${esc(a.k)} · c=${a.c}</span></div>`}return h}
function row(d){const files=d.files.map(f=>`<span class="chip">${esc(f)}</span>`).join('');
 const comp=d.comp?`${esc(d.comp)}${d.cver?' '+esc(d.cver):''}`:'<span class="small">—</span>';
 const mver=d.mver.length?`<div class="small">v ${esc(d.mver.join(', '))}</div>`:'';
 const digName={'module-integrity-hmac':'Module HMAC-SHA256','published-download-sha256':'Published SHA-256','published-file-sha256':'Published SHA-256','selftest-expected-digest':'Self-test digest'};
 const dig=d.digs.map(x=>`<div class="artline"><span class="k">${digName[x.k]||x.k}</span> <span class="hash" title="click to copy" onclick="navigator.clipboard.writeText('${x.h}')">${x.h.slice(0,20)}…</span></div>`).join('');
 const pubs=d.pubs.length?pubHtml(d.pubs):(d.b===false?'<span class="small">searched — no public specimen</span>':'');
 return `<tr><td class="mono"><a href="${esc(d.sp)}" target="_blank" rel="noopener">#${d.cert}</a></td>
 <td class="name">${esc(d.name)}<div class="small">${esc(d.vendor)}</div></td>
 <td>${comp}${mver}</td><td>${files||'<span class="small">—</span>'}${dig}</td>
 <td>${pubs}</td><td><span class="conf ${confCls(d.conf)}">${d.conf.toFixed(2)}</span><div class="small">${d.ev.join(', ')}</div></td></tr>`}
function render(){const term=q.value.toLowerCase();const only=oh.checked;
 let r=D.filter(d=>{if(only&&!d.pubs.some(p=>p.h))return false;if(!term)return true;
  return (d.name+' '+d.vendor+' '+(d.comp||'')+' '+d.files.join(' ')+' '+d.pubs.map(p=>p.f).join(' ')).toLowerCase().includes(term)});
 r.sort((a,b)=>{let x,y;if(sortK==='conf'){x=a.conf;y=b.conf}else if(sortK==='cert'){x=a.cert;y=b.cert}
  else if(sortK==='comp'){x=a.comp||'~';y=b.comp||'~'}else{x=a.name.toLowerCase();y=b.name.toLowerCase()}
  return x<y?-sortDir:x>y?sortDir:0});
 tb.innerHTML=r.map(row).join('');cnt.textContent=r.length+' / '+D.length+' modules'}
document.querySelectorAll('th[data-k]').forEach(th=>th.onclick=()=>{const k=th.dataset.k;
 if(sortK===k)sortDir=-sortDir;else{sortK=k;sortDir=(k==='name'||k==='comp')?1:-1}render()});
q.oninput=render;oh.onchange=render;render();"""

def stat(v, lbl):
    return f'<div class="stat"><b>{v}</b><span>{html.escape(lbl)}</span></div>'

page = f"""<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<meta name=robots content='noindex,nofollow'>
<title>Software-library fingerprints (draft) · FIPS 140-3 corpus</title>
<style>{PALETTE}
{CSS}</style>
<div class="wrap">
<div class="draft">Draft · unlisted</div>
<h1>FIPS 140-3 software-library fingerprints</h1>
<p class="dek">Probabilistic identifiers — filename, version, and hash — for the {n} validated
<b>software</b> cryptographic modules in the corpus, each with an explicit confidence. An
identifier match is evidence the validated library is present; for most modules a published
hash pins the <b>family + version</b>, not the exact CMVP-tested binary. Reference {html.escape(doc.get('reference','2026-07'))} · generated {html.escape(doc.get('generated',''))}.</p>
<div class="stats">
{stat(n,'software modules')}{stat(n_file,'with SP filename')}{stat(n_comp,'known component')}
{stat(n_pub,'public artifact')}{stat(n_hash,'published hashes')}{stat(n_verified,'verified')}{stat(n_hi,'confidence ≥ 0.8')}
</div>
<div class="legend"><b>confidence</b> = known-component (.40) + web-verified-hash (.35) + version (.20) + SP-filename (.20)
+ SP-published-hash (.20) + unverified-web-hash (.15) + SP-module-HMAC (.12) + SP-self-test-digest (.10)
+ artifact-no-hash (.05), capped at 1.0. <b>SP digests</b> are hashes the Security Policy prints in its own text,
kept only when the document labels what they are (module integrity HMAC, published download/file SHA-256, or
self-test expected value). A published hash is <b>SP-confirmed</b> when the exact hash also appears in the module's
own Security Policy text (authoritative, checked deterministically), <b>web-verified</b> when an independent agent
re-fetched its checksum source and matched it, else <b>unverified</b>. No hash is ever guessed.</div>
<div class="key">
<span class="kt">Hash verification key</span>
<span class="keyitem"><span class="badge v-yes">SP-confirmed</span> the exact hash also appears in the module's own Security Policy (authoritative)</span>
<span class="keyitem"><span class="badge v-yes">web-verified</span> an independent agent re-fetched the checksum source and it matched</span>
<span class="keyitem"><span class="badge v-yes">peer-verified</span> equals a verified hash for the identical artifact on another module</span>
<span class="keyitem"><span class="badge v-no">unverified</span> reported from a named source but not independently re-confirmed</span>
</div>
<div class="controls">
<input id="q" type="search" placeholder="filter by module, vendor, component, filename, artifact…">
<label class="tog"><input id="oh" type="checkbox"> only rows with a published hash</label>
<span class="count" id="cnt"></span></div>
<table><thead><tr>
<th data-k="cert">Cert</th><th data-k="name">Module / vendor</th><th data-k="comp">Component</th>
<th>SP fingerprints</th><th>Published artifact · hash</th><th data-k="conf">Confidence</th>
</tr></thead><tbody id="tb"></tbody></table>
</div>
<script>window.__D__={json.dumps(disp,separators=(',',':'),ensure_ascii=False)};
{JS}</script>"""

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write(page)
print(f"wrote {os.path.relpath(OUT, HERE)}  ({round(len(page)/1024)} KB)")
print(f"  {n} modules · {n_pub} with public artifact · {n_hash} hashes ({n_verified} verified) · {n_hi} conf>=0.8")
print("  UNLISTED: not linked from index.html or nav; noindex,nofollow set")
