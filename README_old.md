# AI Bug Hunter — Recon Expansion, JSON Schema & Repo Scaffold

This document contains three immediate deliverables you asked for:

1. **Expanded Phase (Recon — Phase B)**: detailed task list, implementation notes, priorities, example commands and acceptance criteria.
2. **JSON schema** for the canonical asset & finding models (ready to use in Postgres/NoSQL + vector DB ingestion).
3. **Sample GitHub repo README + folder scaffold** you can copy-paste to start the project.

---

## 1) Expanded Phase B — Recon (Detailed TODOs)

**Goal:** Comprehensive, modular Recon subsystem that supplies high-fidelity, deduplicated signals to analysis and fuzzing layers.

### B.0 Architecture notes (for all collectors)

* Each collector is a *stateless* worker that outputs normalized records into a canonical ingestion queue (JSONL).
* Use structured schema (see JSON schema below) with `source`, `timestamp`, `confidence`, and `evidence` fields.
* Rate-limiters, backoff, and API key vault integration are mandatory.
* All collectors must emit diagnostics and `metrics` for observability.

### B.1: Cert / SSL Recon (High)

**Tasks:**

* Implement CRT.sh watcher + certstream ingestion.
* Parse SANs, CNs, validity windows, and public key types.
* Correlate with existing assets via domain canonicalization.

**Implementation tips:**

* Use `pyOpenSSL` or `cryptography` for parsing; for certstream, use `certstream-python`.
* Example pseudo-command:

```bash
python collectors/certstream_watcher.py --out /data/collector/certs.jsonl
```

**Acceptance:** New SANs produce new domain assets or update `ssl` evidence on existing assets.

### B.2: Passive DNS / Reverse WHOIS / Reverse IP (High)

**Tasks:**

* Pull passive DNS (SecurityTrails/OTX/DNSDB) and build reverse-IP / reverse-WHOIS correlation.
* Build TTL/history window to track removals/rotations.

**Implementation tips:**

* Normalize records to lower-case FQDNs, strip trailing dots, treat `www` variants canonical.
* Use batching & caching to reduce API calls.

**Acceptance:** For any IP, list all associated domains and store `relationship` edges.

### B.3: Subdomain Aggregator & Scraper (High)

**Tasks:**

* Aggregator collects from: crt.sh, VirusTotal, SecurityTrails, Censys, GitHub (searches), Wayback, Bug bounty disclosures.
* Implement dedupe + wildcard detection.
* Add test harness for each data source.

**Implementation tips:**

* Use `amass`/`subfinder` as local collectors; complement with API sources.
* Wildcard detection: create a randomized subdomain and check if it resolves uniformly.

**Acceptance:** Unique subdomains are added to inventory with `source` list and `first_seen` timestamp.

### B.4: Brute/Permutation Engine (Med-High)

**Tasks:**

* Implement configurable bruteforce engine supporting multiple strategies: wordlist, permutation, hybrid (word + digit suffix), path-as-subdomain.
* Add `rate_limit` and `concurrency` settings; respect scope policy.

**Implementation tips:**

* Use `massdns` or `masscan` with local resolver cache for performance.
* Provide templates for `ffuf` and `dnsx` commands.

Example `ffuf` pattern:

```bash
ffuf -u https://TARGET/FUZZ -w wordlists/common.txt -recursion -t 40 -o ffuf-results.json
```

**Acceptance:** Engine flags candidate subdomains with `confidence` and `method` metadata.

### B.5: Favicon Analysis & Fingerprinting (Med)

**Tasks:**

* Grab favicon.ico from domains; compute hash (e.g., MD5/sha1 of binary) and match against known DB to group assets.

**Implementation tips:**

* Store favicon hash -> vendor map; useful to find shared infra or panels.

**Acceptance:** Matches create `related_assets` edges and annotate probable origin.

### B.6: Shodan/Censys Collectors (High)

**Tasks:**

* Collect service banners for given netblocks; parse HTTP titles, exposed management endpoints, versions.

**Implementation tips:**

* Enrich with screenshot or request evidence for HTTP endpoints.

**Acceptance:** Add service records with `port`, `banner`, `product`, `version` fields.

### B.7: ASN & Netblock Discovery (Med)

**Tasks:**

* Map domain -> ASN -> sibling domains -> netblocks.
* Flag unusual hosting (cloud vs colo vs residential) for prioritization.

**Acceptance:** Asset inventory includes `asn` and `netblock` edges.

### B.8: Google-fu Engine & Custom Query Runner (Med)

**Tasks:**

* Maintain parametric saved-query templates (e.g., `site:example.com filetype:env`, trademark, privacy leaks).
* Run through multiple proxies / rate-limited scrapers.

**Acceptance:** Hits are stored as `discovery` items with snippet and link.

### B.9: O365 / 0365 Enumeration for Apex (Med)

**Tasks:**

* Query MX/SPF/DKIM/DMARC; attempt tenant discovery patterns for Office365/AzureAD misconfig.

**Acceptance:** If tenant-identifiers found, flag for account-enumeration investigation.

### B.10: Screenshotting & UI snapshot pipeline (High)

**Tasks:**

* Headless Playwright/Chromium pipeline for snapshots with network HAR capture for interesting pages.
* Browser-level JS console capture and DOM snapshot.

Example:

```bash
playwright run collectors/screenshotter.py --input subdomains.txt --out /artifacts/screenshots/
```

**Acceptance:** Each HTTP asset has at least one screenshot and a HAR file when applicable.

### B.11: Supply Chain & Crunchbase++ (Med)

**Tasks:**

* Harvest vendor/subsidiary relationships (Crunchbase, LinkedIn heuristics, third-party integrations).
* Map SaaS dependencies and plugin providers (e.g., payment gateway, analytics provider).

**Acceptance:** Create `supply_chain` edges: target -> vendor -> service.

### B.12: Wildcards, Linked Discovery & Advantageous Subs (High)

**Tasks:**

* Detect wildcard DNS and find origin servers behind CDNs/WAFs by using uncommon headers, distinct fingerprints, and `cdn-origin` heuristics.

**Acceptance:** Tag likely origin hosts and mark potential WAF-bypass targets.

---

## 2) JSON Schemas (canonical) — Assets & Findings

### 2.1 Asset schema (JSON Schema)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Asset",
  "type": "object",
  "properties": {
    "id": {"type":"string"},
    "type": {"type":"string", "enum":["domain","subdomain","host","ip","service","app"]},
    "value": {"type":"string"},
    "canonical": {"type":"string"},
    "first_seen": {"type":"string","format":"date-time"},
    "last_seen": {"type":"string","format":"date-time"},
    "sources": {"type":"array","items":{"type":"string"}},
    "metadata": {"type":"object"},
    "relationships": {"type":"array","items":{"type":"object"}},
    "evidence": {"type":"array","items":{"type":"object"}}
  },
  "required": ["id","type","value"]
}
```

### 2.2 Finding schema (JSON Schema)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Finding",
  "type": "object",
  "properties": {
    "id": {"type":"string"},
    "asset_id": {"type":"string"},
    "title": {"type":"string"},
    "description": {"type":"string"},
    "class": {"type":"string"},
    "subclass": {"type":"string"},
    "cvss": {"type":"number"},
    "cve": {"type":"string"},
    "confidence": {"type":"string","enum":["low","medium","high"]},
    "status": {"type":"string","enum":["new","triaged","verified","fixed","ignored"]},
    "evidence": {"type":"array","items":{"type":"object"}},
    "poC": {"type":"object"},
    "created_at": {"type":"string","format":"date-time"},
    "updated_at": {"type":"string","format":"date-time"}
  },
  "required": ["id","asset_id","title","description"]
}
```

> Note: These are intentionally compact. Add vendor-specific fields under `metadata` and `evidence` for screenshots, HARs, curl commands, and logs.

---

## 3) Sample GitHub README + Folder Scaffold

### 3.1 README (starter)

````markdown
# AI Bug Hunter — Recon Module (MVP)

This repository contains the Recon module for the AI Bug Hunter project. It is built as a set of modular collectors that normalize signals into the central inventory.

## Goals
- Collect domains, subdomains, certs, service banners, and supply chain signals.
- Produce canonical JSONL outputs consumable by the analysis pipeline.

## Quickstart (local)

1. Clone repo
```bash
git clone git@github.com:org/ai-bughunter-recon.git && cd ai-bughunter-recon
````

2. Create `.env` with API keys (SHODAN_API, SECURITYTRAILS_KEY, VT_KEY, CRTSH_PROXY)
3. Run collectors (example):

```bash
python collectors/certstream_watcher.py --out ./data/certs.jsonl
python collectors/subdomain_aggregator.py --out ./data/subs.jsonl
```

## Folder structure

* `collectors/` — small programs that fetch data from sources
* `ingest/` — normalization & dedupe logic
* `scripts/` — helpers (wordlist builders, wildcards tests)
* `artifacts/` — screenshots, HARs, pcaps
* `docs/` — cheatsheets and legal/scope

## Contributing

Follow `CONTRIBUTING.md`. Enforce API rate limits & update `SCOPE.md` before running noisy collectors.

```

### 3.2 Folder scaffold (tree)

```

ai-bughunter-recon/
├─ collectors/
│  ├─ certstream_watcher.py
│  ├─ cert_parser.py
│  ├─ subdomain_aggregator.py
│  ├─ shodan_collector.py
│  ├─ favicon_hunter.py
│  └─ screenshotter.py
├─ ingest/
│  ├─ normalizer.py
│  ├─ deduper.py
│  └─ canonical_schema.py
├─ data/
│  └─ (jsonl outputs)
├─ artifacts/
│  ├─ screenshots/
│  └─ hars/
├─ scripts/
│  ├─ build_wordlists.py
│  └─ wildcard_tester.py
├─ docs/
│  ├─ SCOPE.md
│  ├─ README_cheatsheets.md
│  └─ api_keys.md
├─ tests/
│  └─ test_collectors.py
├─ .env.example
├─ requirements.txt
└─ README.md

```

----

## Quick Next Steps I can do now (pick any, I will implement immediately):
- Expand `collectors/subdomain_aggregator.py` into a working starter script (include amass/subfinder wrappers).
- Produce a Postgres table DDL for `assets` and `findings` based on the JSON schemas.
- Create `certstream_watcher.py` starter that writes normalized JSONL.

Pick one (or say "all") and I will generate the code.

----

*End of document.*

```
