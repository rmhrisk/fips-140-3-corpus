# FIPS 140-3 corpus analysis pipeline.
# Pure Python standard library (Python 3.8+). Every target reproduces a committed
# artifact from the provided corpus snapshot and NVD caches, fully offline.

PY ?= python3

# Pin the hash seed so set iteration order (and therefore serialized byte output)
# is identical on every machine. This is what makes `make verify` byte-exact.
export PYTHONHASHSEED := 0

.PHONY: all analyze drift version-exact render report findings site verify clean

all: analyze render

# analyze reads drift.json + version_exact.json for the CVE-drift signal that
# feeds review-priority, so those MUST be built first. Declaring them as
# prerequisites makes the order correct on a clean build and re-runs analyze
# whenever they change (a plain `all: analyze drift ...` ran analyze first and
# silently dropped the signal).
analyze: corpus_analysis.json
corpus_analysis.json: analyze_corpus.py components.py motifs.py verify_tables.py profiles.py security_policy.py drift.json version_exact.json
	$(PY) analyze_corpus.py

drift: drift.json
drift.json: build_drift.py components.py analyze_corpus.py drift_cache.json
	$(PY) build_drift.py

version-exact: version_exact.json
version_exact.json: build_version_exact.py analyze_corpus.py drift.json ve_cache.json
	$(PY) build_version_exact.py

# render = the report + the findings memo + the published static site (docs/).
render: report findings site

report: corpus_report.html
corpus_report.html: report_html.py corpus_analysis.json drift.json version_exact.json
	$(PY) report_html.py

findings: FINDINGS.md
FINDINGS.md: findings_md.py corpus_analysis.json drift.json version_exact.json
	$(PY) findings_md.py

# The published static site: landing + report + one page per module, into docs/
# (GitHub Pages: Settings -> Pages -> main branch, /docs folder).
site: docs/index.html
docs/index.html: build_site.py render_html.py review_graph.py corpus_report.html corpus_analysis.json drift.json
	$(PY) build_site.py

# Rebuild everything from scratch, then confirm the committed artifacts did not
# change. Cleans first so every stage genuinely re-runs (a plain `all` can skip
# up-to-date targets and verify nothing).
verify:
	@$(MAKE) -s clean all
	@if git diff --quiet -- corpus_analysis.json drift.json version_exact.json corpus_report.html FINDINGS.md docs; then \
		echo "OK: all artifacts and the docs/ site reproduce byte-identically"; \
	else \
		echo "CHANGED: regenerated artifacts differ from committed"; git --no-pager diff --stat; fi

clean:
	rm -f corpus_analysis.json drift.json version_exact.json corpus_report.html FINDINGS.md
	rm -rf docs
