# Production Gap Analysis — Local LLM Security Engine

**Status**: Development-ready. Not production-ready.  
**Purpose**: This document describes what is deliberately missing from the current MVP and what must be added before this service can be run in a real production SOC environment.

---

## Current State

The service is safe and clean enough for:
- Local development and experimentation
- Integration with a SOC backend **over a development tunnel** (e.g. Cloudflare Tunnel)
- Evaluating LLM classification quality on real event data
- Testing the integration contract before committing to a full deployment

The service is **not ready** for:
- Unattended production operation
- High-volume event streams
- Multi-tenant access
- Regulated environments requiring audit trails or data residency

---

## Gap 1 — Authentication and Identity

**Current**: Optional single shared API key (`X-API-Key` header). If not configured, auth is off.  
**Missing**:
- Per-caller API key management (rotate, revoke, scope)
- JWT bearer token authentication for service-to-service calls
- mTLS for machine-to-machine production traffic
- Key storage in a secrets manager (not plaintext `.env` files)
- Request signing / HMAC verification

**Impact**: A shared static key is a single point of failure. One leaked key = full access.  
**Effort**: Medium (1-3 days depending on chosen auth layer)

---

## Gap 2 — Persistence and Audit Trail

**Current**: No storage of any kind. Every request is stateless and unlogged to disk.  
**Missing**:
- Persistent request/response log (PostgreSQL, SQLite, or ClickHouse)
- Every analysis event should be stored: input, output, model used, timestamp, fallback used, request ID
- Audit queries: "show all high-risk events in the last 7 days", "show all fallbacks"
- Data retention policy enforcement

**Impact**: No forensics possible after the fact. SOC compliance almost always requires audit logs.  
**Effort**: Medium (2-5 days for schema + async write + query API)

---

## Gap 3 — Asynchronous Job Processing

**Current**: Synchronous HTTP. The caller blocks until Ollama finishes (up to 60 seconds).  
**Missing**:
- Job queue (Celery + Redis, or RQ, or simple asyncio queue)
- POST /analyze-event → returns job ID immediately
- GET /jobs/{id} → poll for result
- Webhook callback option for SOC backends that cannot long-poll
- Dead letter queue for jobs that exhausted retries

**Impact**: A single slow inference blocks the caller. Under any meaningful volume, this becomes unacceptable.  
**Effort**: Medium-High (3-7 days for full async pipeline)

---

## Gap 4 — Observability and Metrics

**Current**: Structured JSON logs to stdout. No metrics emitted.  
**Missing**:
- Prometheus metrics: request count, request duration (p50/p95/p99), fallback rate, Ollama error rate
- Grafana dashboard (or equivalent)
- Health alerting: if `fallback_used` rate exceeds threshold, alert
- Distributed tracing (OpenTelemetry)
- Log aggregation integration (Loki, Elasticsearch, Splunk)

**Impact**: No visibility into whether the service is performing well or degrading silently.  
**Effort**: Low-Medium (1-3 days for Prometheus + basic dashboard)

---

## Gap 5 — TLS and Network Security

**Current**: Plain HTTP on localhost. Cloudflare Tunnel adds TLS for development tunnels.  
**Missing**:
- TLS termination on the service itself (not relying on a tunnel proxy)
- Certificate management (Let's Encrypt / internal CA)
- HTTPS enforcement with HSTS headers
- mTLS for service-to-service communication
- Network policy / firewall rules for production environments

**Impact**: Plain HTTP exposes the API key and event data in transit.  
**Effort**: Low (1-2 days if using a reverse proxy like nginx or Caddy)

---

## Gap 6 — Model Lifecycle Management

**Current**: Model is configured once via `OLLAMA_MODEL` env var. No runtime control.  
**Missing**:
- Runtime model switching without service restart
- Model warm-up on startup (pre-load the model into VRAM to eliminate cold-start latency)
- Model health checks (detect if model crashed or is unresponsive)
- Multiple models (route high-severity events to a larger model)
- Model versioning (track which model version produced each result)
- Fallback model (if primary model fails, try secondary model before returning fallback result)

**Impact**: First request after a cold start can be very slow. Single model failure = all requests fail.  
**Effort**: Medium (2-4 days)

---

## Gap 7 — Input Sanitization and Security

**Current**: Basic Pydantic length limits. Content is passed directly to the LLM prompt.  
**Missing**:
- Prompt injection detection (malicious input trying to override the system prompt)
- Strip or escape control characters from input fields
- Content filtering on the output (detect if the model was jailbroken into returning non-security content)
- Request size limits on the HTTP body level (not just field-level Pydantic validation)

**Impact**: Adversarial input could manipulate the model's response, producing false classifications.  
**Effort**: Low-Medium (1-3 days)

---

## Gap 8 — Scalability and High Availability

**Current**: Single process, single Ollama instance, no load balancing.  
**Missing**:
- Horizontal scaling (multiple service instances behind a load balancer)
- Multiple Ollama instances (each service instance has its own GPU-backed Ollama)
- Graceful shutdown (drain in-flight requests before shutdown)
- Health-check-aware deployment (rolling updates, liveness + readiness probes)
- Request queuing to prevent thundering herd

**Impact**: Single point of failure. Cannot handle more load than one Ollama instance can process.  
**Effort**: High (depends on infrastructure; 1+ week with Kubernetes or Docker Swarm)

---

## Gap 9 — Rate Limiting in Production

**Current**: Simple in-memory sliding window per process. Resets on restart. Not shared across instances.  
**Missing**:
- Distributed rate limiter (Redis-backed) to share limits across multiple service instances
- Per-API-key limits (not just per-IP)
- Abuse detection and automatic blocking
- Rate limit dashboard

**Impact**: In-memory limiter is process-local — ineffective when running multiple instances.  
**Effort**: Low (1 day to swap in Redis-backed rate limiter)

---

## Gap 10 — Testing

**Current**: 83 unit tests covering parsing, validation, prompt building, client mocking, and schema.  
**Missing**:
- Integration tests against a real (test) Ollama instance
- Load/stress tests (what happens with 100 concurrent requests?)
- Adversarial input tests (prompt injection, extremely long inputs, Unicode edge cases)
- Contract tests (verify the response schema hasn't changed between versions)
- CI/CD pipeline running tests on every commit

**Effort**: Medium (2-4 days for integration + load tests; CI setup depends on toolchain)

---

## Summary — Priority Order for Production Readiness

| Priority | Gap                           | Risk if Skipped                              |
|----------|-------------------------------|----------------------------------------------|
| P0       | TLS                           | Credentials and data exposed in transit      |
| P0       | Persistent audit logging      | No forensics, compliance failure             |
| P1       | Proper authentication         | Shared key is one breach away from full access |
| P1       | Async job processing          | Blocking model calls are a reliability risk  |
| P1       | Distributed rate limiting     | In-memory limiter breaks under multiple instances |
| P2       | Observability / metrics       | Silent degradation goes undetected           |
| P2       | Model lifecycle management    | Cold starts and single-model failures        |
| P2       | Input sanitization            | Prompt injection risk                        |
| P3       | Horizontal scaling            | Single instance is a ceiling and a SPOF      |
| P3       | Integration + load tests      | Unknown behavior under real traffic          |

---

## Development-to-Production Path

A reasonable incremental path:

1. **Week 1**: Add TLS (Caddy reverse proxy), audit log to SQLite, replace static key with per-caller key table  
2. **Week 2**: Add async job queue (RQ + Redis), Prometheus metrics, Grafana dashboard  
3. **Week 3**: Add model warm-up, fallback model, prompt injection detection  
4. **Week 4**: Load test, fix bottlenecks, add CI, write runbooks  
5. **Month 2+**: Kubernetes deployment, distributed rate limiting, full HA setup
