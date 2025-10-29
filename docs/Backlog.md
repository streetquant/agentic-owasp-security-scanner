# Granular Task List with Acceptance Criteria

Title: AOSS Implementation Backlog
Version: 0.1 (Initial)
Owner: Shayan Banerjee (@streetquant)
Status: Draft
Last Updated: 2025-10-29

This backlog breaks down the Agentic OWASP Security Scanner (AOSS) implementation into granular epics, stories, and tasks with explicit acceptance criteria (AC), definitions of done (DoD), and validation notes. It maps to the PRD (docs/PRD.md) and is designed to be exhaustive for v1.0 delivery.

---

## Epic 0: Repo, Build, Quality Gates

### Story 0.1: Project Scaffolding and Tooling
- Tasks:
  - T0.1.1 Create Python package layout with `src/` and Typer CLI entrypoint.
  - T0.1.2 Configure `pyproject.toml`, pinned `requirements.txt`, and optional constraints file.
  - T0.1.3 Add `.editorconfig`, `.gitattributes`, and VSCode settings.
  - T0.1.4 Configure `pre-commit` hooks (black, isort, flake8, bandit, detect-secrets).
  - T0.1.5 Add base GitHub Actions CI: lint, type-check, tests, build wheel.
- AC:
  - Running `pre-commit run -a` passes locally.
  - CI green on PR for lint/mypy/pytest.
  - `pip install -e .` works; `agentic-scanner --help` prints usage.
- DoD:
  - CI badge in README; contributing guide references hooks and CI.

### Story 0.2: Test Infrastructure
- Tasks:
  - T0.2.1 Configure `pytest`, `pytest-asyncio`, and coverage thresholds (≥ 80%).
  - T0.2.2 Add fixtures for mock HTTP server (aiohttp) and golden-response loader.
  - T0.2.3 Add factory for synthetic vulnerable endpoints used in E2E tests.
- AC:
  - `pytest -q` executes sample unit + async tests.
  - Coverage report ≥ 80% for core utilities.
- DoD:
  - CI gate enforces coverage.

---

## Epic 1: Configuration and Secrets

### Story 1.1: Config Schemas and Sources
- Tasks:
  - T1.1.1 Finalize Pydantic models for API, Testing, Auth, Reporting, Memory, Logging.
  - T1.1.2 Implement `from_env` and `from_file` (YAML) loaders with validation.
  - T1.1.3 Provide `--config` CLI option and env var precedence rules.
  - T1.1.4 Redaction rules for logging sensitive values.
- AC:
  - Invalid API key or target URL fails fast with precise error messages.
  - Env overrides for `MAX_CONCURRENT_TESTS`, `LOG_LEVEL`, `REDIS_URL` validated.
- DoD:
  - Docs: configuration matrix table and examples.

### Story 1.2: Secret Handling
- Tasks:
  - T1.2.1 Support `GOOGLE_AI_API_KEY` via env; warn if missing.
  - T1.2.2 Optional OS keyring / cloud secret manager hook (stub).
  - T1.2.3 Ensure secrets never printed or persisted unencrypted.
- AC:
  - Secrets redacted in logs (`****` masking) and reports.
- DoD:
  - Static analysis (bandit) shows no hardcoded secrets.

---

## Epic 2: Observability and Logging

### Story 2.1: Structured Logging
- Tasks:
  - T2.1.1 Implement Loguru sinks for console and rotating file.
  - T2.1.2 Add JSON log option; include correlation IDs per scan.
  - T2.1.3 Redaction filter middleware.
- AC:
  - Logs include timestamp, level, scan_id, agent name, URL when present.
- DoD:
  - Sample logs committed in `docs/samples/logs/`.

### Story 2.2: Metrics and Tracing (Phase 1)
- Tasks:
  - T2.2.1 Define metrics: http_requests_total, ai_calls_total, payload_success_rate.
  - T2.2.2 Expose in-process metrics provider interface; Prometheus hook stub.
  - T2.2.3 Add timing decorators for major code paths.
- AC:
  - Unit tests assert counters increment for success/error paths.
- DoD:
  - Metrics README with examples.

---

## Epic 3: Discovery and Reconnaissance

### Story 3.1: HTTP Client Utilities
- Tasks:
  - T3.1.1 Implement shared HTTP client with retry/backoff, cookies, SSL options.
  - T3.1.2 Respect `follow_redirects`, `timeout`, `custom_headers`, `verify_ssl`.
  - T3.1.3 Request/response recorders for evidence capture.
- AC:
  - 3xx follow tested; timeouts honored; backoff increases on 5xx.
- DoD:
  - Golden tests for header/cookie handling.

### Story 3.2: Crawler and Endpoint Discovery
- Tasks:
  - T3.2.1 Implement BFS/DFS crawling bounded by domain, depth, and path filters.
  - T3.2.2 Parse HTML for anchors/forms; parse JS for common XHR/fetch patterns (basic).
  - T3.2.3 Sitemap.xml and robots.txt readers; allow override flag.
- AC:
  - Crawl a seed site; discover ≥ 80% of known endpoints in synthetic fixture.
- DoD:
  - Store discovered URLs with source (link, form, sitemap, js) and timestamp.

### Story 3.3: Technology Fingerprinting
- Tasks:
  - T3.3.1 Fingerprint via headers (Server, X-Powered-By), TLS, favicon hash (optional stub).
  - T3.3.2 Heuristics for common frameworks (WordPress, Django, Rails, Spring, Express).
  - T3.3.3 Output structured tech stack with confidence scores.
- AC:
  - Unit tests assert correct detection for synthetic headers.

### Story 3.4: Authentication Analysis
- Tasks:
  - T3.4.1 Detect forms, OAuth/OpenID Connect endpoints, MFA hints, cookie flags.
  - T3.4.2 Implement optional scripted login with username/password.
  - T3.4.3 Session management: cookie jar, CSRF token capture.
- AC:
  - When creds provided, session persists; CSRF auto-included if present.

### Story 3.5: Parameter Enumeration
- Tasks:
  - T3.5.1 Extract query/form/json params with types; detect file upload fields.
  - T3.5.2 Track per-endpoint param schemas and example values.
  - T3.5.3 Persist to memory for agent use.
- AC:
  - Schema generated for ≥ 80% forms/endpoints in synthetic app.

---

## Epic 4: AI Reasoning and Payloads

### Story 4.1: Gemini Flash Integration
- Tasks:
  - T4.1.1 Initialize model with config; health check returns OK.
  - T4.1.2 Implement JSON-extraction regex and strict schema validation.
  - T4.1.3 Rate limiting per minute; jitter on bursts.
- AC:
  - Fallback behavior returns safe defaults on failures; no crashes.

### Story 4.2: Analysis Prompts and Parsers
- Tasks:
  - T4.2.1 Draft category-specific prompts with examples and negative patterns.
  - T4.2.2 Implement parsers to map to `AIAnalysisResult` with defensive defaults.
  - T4.2.3 Unit tests with golden AI responses (stored locally) for determinism.
- AC:
  - Parser handles malformed JSON and extraneous text robustly.

### Story 4.3: Payload Library and Generation
- Tasks:
  - T4.3.1 Seed canonical payloads for A01–A10; tag with safety levels.
  - T4.3.2 Implement templating and mutation strategies.
  - T4.3.3 Add custom payload generation via Gemini for given tech context.
- AC:
  - Generated payloads validated against allowlist; no destructive operations.

### Story 4.4: Learning Loop
- Tasks:
  - T4.4.1 Track payload effectiveness; moving average scores.
  - T4.4.2 Save knowledge patterns; retrieve top-N effective payloads per category.
  - T4.4.3 Derive false-positive filters from history (AI-assisted).
- AC:
  - Unit tests show payload ranking changes after success/failure events.

---

## Epic 5: OWASP Category Agents (A01–A10)

### Story 5.1: Base Agent Enhancements
- Tasks:
  - T5.1.1 Add parameter selection strategies (one-at-a-time, all-at-once, random).
  - T5.1.2 Add request templates for GET/POST/PUT/DELETE and JSON bodies.
  - T5.1.3 Evidence capture: raw HTTP, diffs, timing, and header deltas.
- AC:
  - Evidence bundle present for all findings; redacted per policy.

### Story 5.2: A01 – Broken Access Control
- Tasks:
  - T5.2.1 Forced browsing tests; IDOR enumeration; role matrix checks.
  - T5.2.2 JWT/Session manipulation; privilege escalation probes.
  - T5.2.3 AI triage with corroboration (status changes, content leaks).
- AC:
  - Detects synthetic IDOR and missing authorization in fixtures.

### Story 5.3: A02 – Cryptographic Failures
- Tasks:
  - T5.3.1 TLS/headers scan (HSTS, CSP, cookie flags).
  - T5.3.2 Weak hash/crypto hints; cert validation anomalies.
  - T5.3.3 Password storage heuristic (hash prefix patterns, timing hints).
- AC:
  - Reports missing HSTS, Secure/HttpOnly flags; correct CWE mapping.

### Story 5.4: A03 – Injection
- Tasks:
  - T5.4.1 SQLi boolean/time-based probes; NoSQLi; LDAP; XPath; template injection.
  - T5.4.2 Out-of-band (OOB) detection stub with note for future service.
  - T5.4.3 AI validation to reduce FPs using response diffs and timing.
- AC:
  - Detects synthetic SQLi in demo app; confidence ≥ 0.8 for confirmed cases.

### Story 5.5: A04 – Insecure Design
- Tasks:
  - T5.5.1 Business logic abuse scenarios; workflow bypasses.
  - T5.5.2 Rate limit checks; state machine inconsistencies.
  - T5.5.3 AI narrative analysis for complex flows.
- AC:
  - Finds at least one logic flaw in synthetic multi-step flow.

### Story 5.6: A05 – Security Misconfiguration
- Tasks:
  - T5.6.1 Header audit; default creds probes; directory listing; verbose errors.
  - T5.6.2 Admin panels exposure; known default endpoints.
  - T5.6.3 AI-supported config diagnosis with remediation.
- AC:
  - Flags missing headers and open admin endpoints in fixture.

### Story 5.7: A06 – Vulnerable and Outdated Components
- Tasks:
  - T5.7.1 Parse package manifests; JS libraries; backend banners.
  - T5.7.2 Map versions to CVEs via OSV API stub or local cache.
  - T5.7.3 Severity scoring and SBOM export stub (CycloneDX).
- AC:
  - Sample detection of outdated JS lib with CVE list.

### Story 5.8: A07 – Identification and Authentication Failures
- Tasks:
  - T5.8.1 Brute-force throttling checks (safe); weak policy heuristics.
  - T5.8.2 Session fixation/hijack probes (non-destructive); MFA presence hints.
  - T5.8.3 AI narrative for auth edge cases.
- AC:
  - Detects missing lockout and weak policy in fixture.

### Story 5.9: A08 – Software and Data Integrity Failures
- Tasks:
  - T5.9.1 Insecure deserialization probes; unsigned update flows (simulated).
  - T5.9.2 Supply-chain hooks; CI artifact trust hints.
  - T5.9.3 AI triage for integrity signals.
- AC:
  - Identifies deserialization sink in mock server.

### Story 5.10: A09 – Security Logging and Monitoring Failures
- Tasks:
  - T5.10.1 Log injection tests; missing event coverage heuristics.
  - T5.10.2 Alerting path presence (stub) and audit trail checks.
  - T5.10.3 AI suggestions for logging improvements.
- AC:
  - Flags missing auth event logs in synthetic app.

### Story 5.11: A10 – Server-Side Request Forgery (SSRF)
- Tasks:
  - T5.11.1 Internal IP/metadata endpoints tests; scheme and DNS rebinding safety notes.
  - T5.11.2 Blind SSRF heuristic using timing/content changes (no external callback svc in v1).
  - T5.11.3 AI corroboration of SSRF indicators.
- AC:
  - Detects SSRF-prone endpoint in fixture with safe probes.

---

## Epic 6: Orchestrator and Planning

### Story 6.1: Plan Creation and Optimization
- Tasks:
  - T6.1.1 Build discovery + vuln task DAG from templates.
  - T6.1.2 Topological sort and priority scheduling.
  - T6.1.3 Replanning on failure; dependency relaxation.
- AC:
  - Unit tests verify order and replanning logic on injected failures.

### Story 6.2: Concurrency and Resource Management
- Tasks:
  - T6.2.1 Semaphores for network, AI, CPU, bandwidth; config-driven.
  - T6.2.2 Per-agent concurrency caps; global rate limiting.
  - T6.2.3 Fairness across agents (round-robin batches).
- AC:
  - Load test shows stable throughput; no starvation.

---

## Epic 7: Memory, Persistence, and Knowledge

### Story 7.1: Session Persistence
- Tasks:
  - T7.1.1 Persist session metadata and findings (SQLite/SQLAlchemy models).
  - T7.1.2 Redis cache for hot session lookups; TTL control.
  - T7.1.3 Resume scan capability from session ID.
- AC:
  - Restarted process can load session and resume discovery or analysis.

### Story 7.2: Knowledge Base
- Tasks:
  - T7.2.1 Upsert knowledge patterns with effectiveness and metadata.
  - T7.2.2 Query top-N payloads per category; cache layer.
  - T7.2.3 Export/import knowledge snapshot.
- AC:
  - After multiple runs, payload selection changes based on learned scores.

---

## Epic 8: Reporting and Artifacts

### Story 8.1: HTML and JSON Reports
- Tasks:
  - T8.1.1 Implement report generator with templates; severity filters and search.
  - T8.1.2 Include PoC evidence, HTTP snippets, and remediation.
  - T8.1.3 JSON export for SIEM/pipelines; schema definition.
- AC:
  - Report opens locally; hyperlinks to endpoints and evidence work.

### Story 8.2: Export and Integrations (Phase 1)
- Tasks:
  - T8.2.1 CLI export to directory; archive option.
  - T8.2.2 Webhook stub for scan-complete; print payload.
  - T8.2.3 Jira/Linear issue creation adapters (stub with dry-run flag).
- AC:
  - Creating issues in dry-run prints payload with correct fields.

---

## Epic 9: CLI and Developer Experience

### Story 9.1: CLI Commands
- Tasks:
  - T9.1.1 `scan` command with target URL, categories, config, and output flags.
  - T9.1.2 `sessions list|get|resume` subcommands.
  - T9.1.3 `report` subcommand to regenerate/export.
- AC:
  - `agentic-scanner scan https://juice-shop` runs end-to-end in demo mode.

### Story 9.2: Profiles and Safety Toggles
- Tasks:
  - T9.2.1 Profiles: fast/balanced/deep impacting depth, concurrency, AI usage.
  - T9.2.2 `--respect-robots`, `--authorized`, `--dry-run` flags.
  - T9.2.3 Circuit breaker thresholds configurable via CLI.
- AC:
  - Safety flags visibly change behavior in logs and metrics.

---

## Epic 10: Security and Compliance

### Story 10.1: Data Protection
- Tasks:
  - T10.1.1 Redaction of secrets in evidence; configurable patterns.
  - T10.1.2 Optional at-rest encryption for SQLite file.
  - T10.1.3 Retention policy with purge command.
- AC:
  - `purge --older-than 30d` removes sessions and artifacts.

### Story 10.2: Auditability
- Tasks:
  - T10.2.1 Activity audit log (append-only) with signatures.
  - T10.2.2 Session replay metadata (without sensitive bodies).
  - T10.2.3 Export audit trail to JSONL.
- AC:
  - Audit file verifies no tampering (hash chain test).

---

## Epic 11: Performance and Cost Controls

### Story 11.1: AI Cost Guardrails
- Tasks:
  - T11.1.1 Global max tokens/minute and daily cap; fail-safe behavior.
  - T11.1.2 Cache identical analysis calls by content hash.
  - T11.1.3 Sampling: skip repetitive endpoints after N similar results.
- AC:
  - Cost estimator shows reduced tokens after caching enabled.

### Story 11.2: Load and Soak Tests
- Tasks:
  - T11.2.1 Simulate 10 parallel scans; capture latency and errors.
  - T11.2.2 Long-running scan stability test (2h) with circuit breaker events.
  - T11.2.3 Document tuning guidelines.
- AC:
  - No memory leaks; throughput degrades < 20% under load.

---

## Cross-Cutting: Documentation and Samples

### Story D.1: Developer Docs
- Tasks:
  - TD1.1 Architecture guide with diagrams.
  - TD1.2 Agent authoring cookbook (create new category/custom agent).
  - TD1.3 Prompt design guide and safety policy doc.
- AC:
  - Docs pass link check; examples run as shown.

### Story D.2: Samples and Fixtures
- Tasks:
  - TD2.1 Synthetic vulnerable endpoints and mock servers.
  - TD2.2 Golden test corpora (responses, logs, reports).
  - TD2.3 Example CI pipelines (GitHub Actions, GitLab, Jenkinsfile).
- AC:
  - New contributors can run samples end-to-end in < 20 minutes.

---

## Definition of Done (Global)
- Code: typed, formatted, linted; unit and integration tests added; coverage ≥ 80% where applicable.
- Docs: updated for user-facing and internal modules; changelog entry created.
- Security: secrets scrubbed; bandit clean; SBOM generated (stub allowed for v1).
- CI/CD: pipeline green; artifacts produced for tagged builds.

---

## Backlog Mapping to PRD Sections
- FR-1..FR-7: Epics 3–9, 10.
- NFR-1..NFR-5: Epics 2, 6, 7, 11.
- Safety: Epics 3, 4, 5, 9, 10.
- Reporting & Integrations: Epic 8.

---

## Milestone Slices
- M1: Epics 0–4 (subset), 5.2, 5.4, 8.1, 9.1 (demo mode).
- M2: Complete Epic 5; Epics 6–8; start 11.1.
- M3: Epics 9–11 finalized; polish and enterprise stubs.

---

This backlog is a living document. Convert stories/tasks into GitHub issues with labels: `epic`, `story`, `task`, `good-first-issue`, `security`, `ai`, `discovery`, `reporting`, `cli`, `performance`, `compliance`.
