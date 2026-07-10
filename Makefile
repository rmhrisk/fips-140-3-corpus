# FIPS 140-3 corpus analysis pipeline.
# Pure Python standard library (Python 3.8+). Every target reproduces a committed
# artifact from the provided corpus snapshot and NVD caches, fully offline.

PY ?= python3

# Pin the hash seed so set iteration order (and therefore serialized byte output)
# is identical on every machine. This is what makes `make verify` byte-exact.
export PYTHONHASHSEED := 0

.PHONY: all analyze drift version-exact render report findings explorer verify clean

all: analyze drift version-exact render

analyze: corpus_analysis.json
corpus_analysis.json: analyze_corpus.py components.py motifs.py verify_tables.py profiles.py security_policy.py
	$(PY) analyze_corpus.py

drift: drift.json
drift.json: build_drift.py components.py analyze_corpus.py drift_cache.json
	$(PY) build_drift.py

version-exact: version_exact.json
version_exact.json: build_version_exact.py analyze_corpus.py drift.json ve_cache.json
	$(PY) build_version_exact.py

render: report findings explorer

report: report_html.py corpus_analysis.json drift.json version_exact.json
	$(PY) report_html.py

findings: findings_md.py corpus_analysis.json drift.json version_exact.json
	$(PY) findings_md.py

explorer: build_explorer.py corpus_analysis.json
	$(PY) build_explorer.py

# Rebuild everything, then confirm the committed artifacts did not change.
verify:
	@$(MAKE) -s all
	@if git diff --quiet -- corpus_analysis.json drift.json version_exact.json corpus_report.html explorer.html FINDINGS.md; then \
		echo "OK: all artifacts reproduce byte-identically"; \
	else \
		echo "CHANGED: regenerated artifacts differ from committed"; git --no-pager diff --stat; fi

clean:
	rm -f corpus_analysis.json drift.json version_exact.json corpus_report.html explorer.html FINDINGS.md
