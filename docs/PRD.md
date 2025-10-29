# Product Requirements Document (PRD)

Title: Agentic OWASP Security Scanner (AOSS)
Version: 0.1 (Initial Draft)
Owner: Shayan Banerjee (@streetquant)
Status: Draft
Last Updated: 2025-10-29

## 1. Executive Summary

Agentic OWASP Security Scanner (AOSS) is an autonomous, agentic-AI powered web application security testing system that orchestrates reconnaissance, vulnerability testing, AI reasoning, and reporting against the OWASP Top 10 categories. AOSS leverages Google Gemini Flash for advanced reasoning and payload generation, a multi-agent architecture for specialized testing, and adaptive learning to improve detection accuracy with each scan. The goal is to deliver a reliable, scalable, and extensible platform that integrates seamlessly into modern DevSecOps workflows while maintaining strict safety, authorization, and compliance controls.

## 2. Objectives and Success Criteria

### 2.1 Objectives
- Provide automated end-to-end OWASP Top 10 assessments for web applications.
- Utilize agentic AI (planning, memory, reasoning, and execution) for high-quality vulnerability detection.
- Minimize false positives via AI-enhanced triage and corroboration workflows.
- Integrate with CI/CD pipelines, SIEM, and issue trackers for actionable remediation.
- Offer a modular, extensible architecture for custom agents and enterprise features.

### 2.2 Success Metrics (KPIs)
- Detection Coverage: ≥ 90% coverage of OWASP Top 10 testing heuristics per category.
- False Positive Rate: ≤ 10% at P95 across benchmark targets with ground truth.
- Mean Time to Result (MTR): ≤ 60 minutes for a medium application (≤ 500 endpoints).
- Scalability: Parallel scans across ≥ 10 targets with no >20% latency overhead compared to sequential runs.
- Usability: < 20 min setup time; > 80% positive developer satisfaction in trial feedback.
- Integration: CI usage on ≥ 3 major CI providers; tickets auto-created in Jira/Linear.

## 3. Scope

### 3.1 In Scope (v0.1 – v1.0)
- OWASP Top 10 (2021) category coverage via specialized agents (A01–A10).
- Agentic components: planning, memory, reasoning (Gemini Flash), and execution.
- Web discovery, endpoint enumeration, parameter analysis, auth flow analysis.
- AI-assisted payload generation and result triage.
- Report generation (HTML, JSON) with evidence, CVE/CWE mapping, and remediation.
- Integrations: CLI, basic CI hooks, basic issue tracker sync, Redis + SQLite for state.
- Safety framework: rate limiting, target health checks, bounded payloads, authorization requirements.

### 3.2 Out of Scope (initial)
- Destructive testing (e.g., DoS, stress testing beyond safety thresholds).
- Mobile-specific testing (covered by separate projects like OWASP Mobile Top 10).
- Enterprise SSO/RBAC, multi-tenant SaaS hosting (planned for enterprise edition).

## 4. Users and Personas

- AppSec Engineer: Requires comprehensive, reproducible, low-noise assessments and exportable artifacts.
- Dev Lead: Needs prioritized findings with developer-friendly remediation guidance.
- SRE/SecOps: Wants telemetry, SIEM ingestion, and non-disruptive scanning controls.
- Compliance Officer: Needs evidence, audit trails, and compliance mappings.

## 5. System Overview and Architecture

AOSS follows a modular agentic architecture:
- Orchestrator: Coordinates phases and agents, enforces policies, manages resources.
- Planning: Converts high-level goals into dependency-ordered task DAGs.
- Discovery: Crawling, tech fingerprinting, auth analysis, parameter enumeration.
- Reasoning: Gemini Flash-driven analysis, payload generation, and learning.
- Agents: Specialized modules per OWASP category with shared utilities.
- Memory: Redis cache + SQLite/SQLAlchemy persistence; knowledge base of payloads/patterns.
- Reporting: Evidence-based HTML/JSON reports with links, code snippets, and CVE/CWE references.

Key non-functional requirements: observability, safety, idempotency, and resilience.

## 6. Detailed Requirements

### 6.1 Functional Requirements

FR-1 Orchestrated Scan Lifecycle
- FR-1.1: Initialize scan session with unique ID, config, and policy context.
- FR-1.2: Perform discovery (tech stack, endpoints, auth flows, parameters).
- FR-1.3: Plan execution DAG for OWASP agents based on discovered context.
- FR-1.4: Run agents concurrently with bounded concurrency and rate limits.
- FR-1.5: Collect findings, triage via AI, and deduplicate/correlate results.
- FR-1.6: Generate reports and export to configured sinks (filesystem, API, CI artifact).

FR-2 Discovery and Reconnaissance
- FR-2.1: Crawl within domain, respect robots.txt unless explicitly overridden.
- FR-2.2: Identify frameworks, server software, CDN, TLS configuration, cookies, headers.
- FR-2.3: Enumerate inputs (query params, forms, JSON bodies), and API endpoints (OpenAPI, GraphQL introspection if permitted).
- FR-2.4: Analyze auth flows (login, MFA presence, token handling) when credentials provided.

FR-3 OWASP Agents (A01–A10)
- FR-3.x: Each agent must implement category-specific heuristics, payloads, and AI-assisted analysis.
- FR-3.x: Each agent must produce structured findings with severity, status, evidence, remediation, CWE/CVSS where applicable.
- FR-3.x: Agents should exploit reusable utilities (HTTP, payloads, parsers) and contribute to payload learning.

FR-4 AI Reasoning and Learning
- FR-4.1: Use Gemini Flash for content analysis and payload generation with constrained prompts.
- FR-4.2: Extract JSON-only outputs robustly; fallback to conservative defaults on parse failure.
- FR-4.3: Update payload knowledge with effectiveness signals (confidence, corroboration).
- FR-4.4: Support pattern learning: refine indicators, filters, and rules from scan history.

FR-5 Reporting
- FR-5.1: Produce HTML and JSON reports with index, filters, and details pages.
- FR-5.2: Include PoC evidence, HTTP traces, impacted endpoints, and reproducible steps.
- FR-5.3: Map to CWE, optionally CVE for component vulnerabilities; include CVSS v3.1.
- FR-5.4: Provide executive summary and developer-focused remediation guidance.

FR-6 Integrations
- FR-6.1: CLI interface with commands: scan, list-sessions, resume, report, export.
- FR-6.2: CI templates (GitHub Actions, GitLab CI, Jenkins) for gated builds.
- FR-6.3: Issue tracker integration (Jira/Linear) via webhook/API adapters.
- FR-6.4: SIEM export via JSONL/CEF and optional syslog.

FR-7 Safety, Authorization, and Compliance
- FR-7.1: Require explicit authorization flags for non-local targets.
- FR-7.2: Enforce rate limits, target health checks, circuit breakers, and safe payload sets.
- FR-7.3: Record consent metadata and audit logs for every activity.
- FR-7.4: PII minimization and secure data handling (encryption at rest and in transit).

### 6.2 Non-Functional Requirements (NFRs)

NFR-1 Performance
- Crawl throughput ≥ 30 req/sec per target with backoff; AI calls batched and limited.
- Report generation completes in < 3 minutes for 1k findings.

NFR-2 Reliability
- Recoverable from agent failures; partial results preserved; resumable scans.
- Exactly-once reporting; idempotent exports.

NFR-3 Security
- Secrets in env vars or vault; no plaintext in logs; token scoping for least privilege.
- Encrypted storage for session data; configurable retention policies.

NFR-4 Observability
- Structured logs, metrics (Prometheus), distributed tracing hooks.
- Per-agent dashboards for throughput, errors, and effectiveness.

NFR-5 Extensibility
- Plugin interfaces for new agents, payload packs, and enrichers.
- Stable internal APIs; semantic versioning; migration guides.

## 7. Detailed Design

### 7.1 Module Breakdown

- Core
  - config.py: Validated configuration schemas; env/yaml loaders.
  - scanner.py: Orchestrator; lifecycle; progress; summary panels.
  - planning.py: Task DAG, dependency management, resource semaphores.
  - memory.py: Redis cache, SQLite persistence, knowledge base.
  - reasoning.py: Gemini Flash adapters; prompts; JSON parsing; rate limiting.

- Agents
  - base.py: Abstract base; HTTP helpers; payload injection; AI integration; results.
  - a01..a10: Category-specific logic, payloads, analyzers, heuristics, and safeguards.

- Utilities
  - discovery.py: Crawl, fingerprint, parameter enumeration, auth analysis.
  - http_client.py: Shared HTTP wrapper (retry, backoff, cookies, TLS options).
  - payloads.py: Canonical payload library + templating.
  - parsing.py: HTML/JSON/XML parsers, signature extraction.
  - reporting.py: HTML/JSON renderers, assets, export.

- CLI
  - cli.py: Typer-based CLI; commands and options; progress rendering.

### 7.2 Data Models

- Session: id, target_url, timestamps, status, config, findings_count.
- VulnerabilityFinding: id, category, severity, status, url, method, parameter, payload, evidence, remediation, cwe_id, cvss.
- KnowledgePattern: id, category, type (payload, signature, filter), effectiveness, usage_count, metadata.

### 7.3 Workflow

1. Initialize config and session.
2. Discovery phase: crawl, fingerprint, auth and parameter analysis.
3. Planning creates DAG over A01–A10 agents with dependencies and priorities.
4. Execution: concurrent agents with semaphores; per-endpoint tests; AI analysis per response; results stored.
5. Learning: update payload effectiveness; derive refined indicators and filters.
6. Reporting: generate HTML/JSON; export to sinks; create tickets if enabled.

### 7.4 Prompting Strategy (Gemini Flash)

- Use low temperature for deterministic triage.
- Strict JSON schemas; defensive parsing with regex and fallback defaults.
- Provide category patterns and target context for grounding.
- Limit response body excerpts (≤ 2k chars) to control token usage.
- Separate prompts for payload generation, triage, and learning.

### 7.5 Safety Controls

- Global and per-agent rate limiting; randomized jitter between requests.
- Circuit breaker: abort on persistent 5xx or elevated error rates.
- Do-not-touch list for destructive endpoints (admin destructive ops).
- Robots.txt respect by default; explicit override flag for authorized pentests.
- Bounded payloads library; no destructive payloads; no data exfiltration.

### 7.6 False Positive Reduction

- Multi-signal corroboration: header anomalies + timing + content signatures.
- Cross-check with replayed requests and variant payloads.
- Heuristic filters for known benign patterns; configurable whitelist.
- Confidence scoring from AI + rule-based features.

### 7.7 Performance and Cost Controls

- Batch AI requests where possible; reuse context; cache model responses.
- Adaptive sampling: reduce tests on stable/duplicate endpoints.
- Prioritized scanning: critical paths first based on business URLs and auth depth.

## 8. Roadmap and Milestones

- M1 (2 weeks): Core + Discovery + A01/A03 agents + HTML report + CLI scan.
- M2 (4 weeks): Remaining agents A02/A04/A05 + CI templates + JSON export.
- M3 (6 weeks): A06/A07/A08 + Issue tracker integration + SIEM export.
- M4 (8 weeks): A09/A10 + Advanced learning + Dashboard + Plugin SDK.
- M5 (10 weeks): Enterprise hardening (RBAC, SSO, org policies), Helm charts.

## 9. Acceptance Criteria

- Can scan a demo app (e.g., OWASP Juice Shop) end-to-end with reproducible findings.
- Reports contain PoC evidence and remediation for each confirmed/probable finding.
- False positive rate ≤ 10% on internal benchmark suite.
- CI pipeline blocks merge on CRITICAL/HIGH per policy; tickets auto-created.

## 10. Dependencies and Risks

- Dependencies: Google Gemini API access; Redis; Python 3.10+; SQLite (default) or Postgres (optional), network access.
- Risks: AI hallucinations; rate limits; target instability; legal/ethical constraints; cost control.
- Mitigations: strict prompting, JSON-only parsing, rate limiting, safety policies, dry-run mode.

## 11. Privacy, Security, and Compliance

- Data Handling: Store only necessary metadata and evidence; redact secrets and PII.
- Encryption: TLS in transit; optional at-rest encryption for DB and artifacts.
- Access Control: API keys via env vars or secret managers; principle of least privilege.
- Auditability: Tamper-evident logs; session replay with redactions.
- Compliance: CWE/CVSS mapping; optional PCI-DSS and SOC2 alignment notes.

## 12. UX and Reporting

- Console UX: Rich progress, per-category summaries, error surfacing.
- HTML Report: Filters by severity/category; detail views with collapsible evidence.
- JSON Report: Machine-friendly for SIEM and pipelines.
- Accessibility: Semantic HTML, high-contrast theme, copy-to-clipboard artifacts.

## 13. APIs and Integrations (Future)

- REST API: Start/stop scans, fetch sessions, download reports, push findings.
- Webhooks: Scan complete, threshold exceeded, new critical finding.
- Adapters: Jira/Linear, ServiceNow, Slack/Teams notifications.

## 14. Telemetry and Analytics

- Metrics: Requests per second, AI calls, cache hit ratio, findings per category, FP rate.
- Traces: Per-agent spans; external call timings; retry counts.
- Logs: Structured JSON logs; correlation IDs; redaction filters.

## 15. Testing Strategy

- Unit: Config validation, HTTP utilities, parsers, prompt builders, JSON parsing.
- Integration: Agent end-to-end against mock servers; replay harness.
- Regression: Corpus of known vulnerable pages; golden reports.
- Performance: Load tests for crawler and agent concurrency.
- Security: Static analysis; secret scanning; SBOM.

## 16. Operational Playbooks

- Onboarding: API keys, environment setup, auth configuration.
- Running Scans: CLI flags, profiles (fast, balanced, deep), safety toggles.
- Incident Response: Circuit breaker triggers, kill-switch, target restore checks.
- Data Retention: Default 30 days, configurable; purge scripts.

## 17. Open Questions

- Should we add a lightweight web UI in v1.0 or v1.1?
- Which SBOM tooling to standardize on for A06 (CycloneDX vs SPDX)?
- Add Postgres as first-class DB option for enterprise scale?

## 18. Glossary

- AOSS: Agentic OWASP Security Scanner
- FP: False Positive
- CVSS: Common Vulnerability Scoring System
- CWE: Common Weakness Enumeration
- SCA: Software Composition Analysis

---

This PRD is a living document and will be continuously refined as implementation progresses and user feedback is incorporated.
