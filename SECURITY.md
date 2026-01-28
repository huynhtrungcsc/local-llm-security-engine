# Security Policy

## Supported Versions

Only the latest version on the `main` branch receives security fixes.

| Version | Supported |
|---------|-----------|
| `main` (latest) | Yes |
| Older tags | No |

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a security issue privately:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability** to open a private advisory.
3. Provide a clear description of the issue, steps to reproduce it, and the potential impact.

You will receive an acknowledgement within **72 hours**. If the vulnerability is confirmed, a fix will be prepared and a coordinated disclosure timeline agreed upon with you before any public announcement.

---

## Scope

This project is an **inference module** — it is not designed for direct public internet exposure. The following considerations apply:

### In scope

- Authentication bypass in the `X-API-Key` middleware.
- Rate limiter bypass that enables denial-of-service against the local Ollama instance.
- Prompt injection attacks that cause the engine to leak system configuration via the LLM response.
- Input validation bypasses that allow oversized payloads to reach Ollama.
- Sensitive data leakage in structured log output (e.g., API keys appearing in logs).

### Out of scope

- Vulnerabilities in Ollama itself — report those to the [Ollama project](https://github.com/ollama/ollama/security).
- Vulnerabilities in third-party Python or Node.js packages — report those to the relevant maintainers.
- Issues that require physical access to the machine running the service.
- The service being exposed directly to the internet without a reverse proxy or authentication — this is explicitly discouraged in the documentation.

---

## Security Hardening Recommendations

Before deploying in any environment reachable from a network:

1. **Set `LOCAL_LLM_API_KEY`** to a strong, randomly generated value.
2. **Use a reverse proxy** (nginx, Caddy, Cloudflare Tunnel) — do not expose port 8000 directly.
3. **Enable rate limiting** (`RATE_LIMIT_ENABLED=true`, the default).
4. **Restrict Ollama** to `localhost` only — Ollama should not be reachable from the network.
5. **Review logs** — structured JSON logs include request IDs and IP addresses; ensure log storage complies with your data-handling requirements.

See [`llm-security-engine/docs/production_gap.md`](llm-security-engine/docs/production_gap.md) for a full list of gaps before production deployment.
