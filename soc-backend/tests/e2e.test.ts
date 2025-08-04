/**
 * End-to-end integration test.
 *
 * Architecture under test:
 *
 *   Test client  (real HTTP)
 *       │
 *       ▼  POST /api/analyze
 *   SOC API Server  (Express, real HTTP server on random port)
 *       │
 *       ▼  POST /analyze-event  (real HTTP — no fetch mocking at all)
 *   Mock Python Engine  (minimal HTTP server on random port, in-process)
 *       │
 *       ▼  returns canonical AnalysisResult JSON
 *
 * No globalThis.fetch replacement is used in this file.
 * All three components communicate over real TCP sockets.
 *
 * The test verifies:
 *   1. A full happy-path analysis round-trip returns all contract fields.
 *   2. Inbound SOC_API_KEY auth is enforced when configured.
 *   3. Rate limiting triggers 429 and the Retry-After header is set.
 */

import { describe, test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import app from "../src/app.js";
import { resetConfig } from "../src/lib/config.js";
import { resetLocalEngineClient } from "../src/providers/localSecurityEngine.js";
import { resetRateLimiter } from "../src/middleware/rateLimiter.js";

// ── Canonical engine response ─────────────────────────────────────────────────

const MOCK_ENGINE_RESPONSE = {
  attack_classification: "credential_access",
  false_positive_likelihood: 0.05,
  risk_score: 91,
  reason: "57 failed SSH logins then one success from a flagged external IP.",
  fallback_used: false,
  model_used: "phi4-mini",
  provider: "ollama",
  raw_parse_success: true,
  parse_strategy: "direct",
  ollama_error: null,
  request_id: "engine-e2e-id",
};

// ── Mock Python engine server ─────────────────────────────────────────────────

interface MockEngine {
  baseUrl: string;
  close: () => Promise<void>;
  lastRequestBody: () => Record<string, unknown>;
  lastRequestHeaders: () => Record<string, string>;
}

function startMockEngine(): Promise<MockEngine> {
  let _lastBody: Record<string, unknown> = {};
  let _lastHeaders: Record<string, string> = {};

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    _lastHeaders = req.headers as Record<string, string>;

    if (req.url === "/health" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          config: { ollama_model: "phi4-mini" },
          ollama: { reachable: true },
        }),
      );
      return;
    }

    if (req.url === "/analyze-event" && req.method === "POST") {
      let raw = "";
      req.on("data", (chunk: Buffer) => { raw += chunk.toString(); });
      req.on("end", () => {
        try { _lastBody = JSON.parse(raw); } catch { _lastBody = {}; }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(MOCK_ENGINE_RESPONSE));
      });
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ detail: "Not found" }));
  });

  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        close: () => new Promise((r, e) => server.close((err) => (err ? e(err) : r()))),
        lastRequestBody: () => _lastBody,
        lastRequestHeaders: () => _lastHeaders,
      });
    });
  });
}

// ── SOC backend server ────────────────────────────────────────────────────────

interface SocServer {
  baseUrl: string;
  close: () => Promise<void>;
}

function startSocServer(): Promise<SocServer> {
  return new Promise((resolve, reject) => {
    const server = createServer(app);
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        close: () => new Promise((r, e) => server.close((err) => (err ? e(err) : r()))),
      });
    });
  });
}

// ── Shared servers (started once for the whole suite) ─────────────────────────

let engine: MockEngine;
let soc: SocServer;

before(async () => {
  // Save env
  engine = await startMockEngine();

  // Point SOC backend at the mock engine
  process.env["LOCAL_LLM_ENGINE_BASE_URL"] = engine.baseUrl;
  delete process.env["SOC_API_KEY"];
  resetConfig();
  resetLocalEngineClient();
  resetRateLimiter();

  soc = await startSocServer();
});

after(async () => {
  await soc.close();
  await engine.close();
  delete process.env["LOCAL_LLM_ENGINE_BASE_URL"];
  delete process.env["SOC_API_KEY"];
  resetConfig();
  resetLocalEngineClient();
  resetRateLimiter();
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("E2E: happy path — full round-trip through mock Python engine", () => {
  test("POST /api/analyze returns 200 with all required contract fields", async () => {
    const res = await fetch(`${soc.baseUrl}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Request-ID": "e2e-trace-001",
      },
      body: JSON.stringify({
        description: "57 failed SSH logins then one successful login from 185.220.101.1.",
        source_ip: "185.220.101.1",
        destination_ip: "10.0.0.5",
        event_type: "authentication_failure",
        severity: "high",
        timestamp: "2024-01-15T10:00:00Z",
        additional_context: "Source IP is on threat intel blocklist.",
      }),
    });

    assert.equal(res.status, 200, "Expected HTTP 200");

    const body = await res.json() as Record<string, unknown>;

    // Core classification fields
    assert.equal(body["attack_classification"], "credential_access");
    assert.equal(body["risk_score"], 91);
    assert.equal(body["false_positive_likelihood"], 0.05);
    assert.ok(typeof body["reason"] === "string" && body["reason"].length > 0);

    // Transparency fields
    assert.equal(body["fallback_used"], false);
    assert.equal(body["engine_reachable"], true);
    assert.equal(body["contract_validation_failed"], false);

    // Provider metadata
    assert.equal(body["soc_provider_mode"], "local_security_engine");
    assert.equal(body["model_used"], "phi4-mini");
    assert.equal(body["provider"], "ollama");

    // Tracing
    assert.ok(typeof body["request_id"] === "string");
    assert.equal(res.headers.get("x-request-id"), "e2e-trace-001");

    // Latency measured
    assert.ok(typeof body["latency_ms"] === "number" && (body["latency_ms"] as number) >= 0);
  });

  test("engine receives the correctly shaped SecurityEvent request body", async () => {
    await fetch(`${soc.baseUrl}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Request-ID": "e2e-body-check",
      },
      body: JSON.stringify({
        description: "Outbound traffic to known C2 domain.",
        source_ip: "10.0.0.12",
        event_type: "dns_lookup",
        severity: "critical",
      }),
    });

    const sent = engine.lastRequestBody();
    assert.equal(sent["description"], "Outbound traffic to known C2 domain.");
    assert.equal(sent["source_ip"], "10.0.0.12");
    assert.equal(sent["event_type"], "dns_lookup");
    assert.equal(sent["severity"], "critical");
  });

  test("engine receives X-Request-ID header forwarded from the caller", async () => {
    await fetch(`${soc.baseUrl}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Request-ID": "e2e-forward-id",
      },
      body: JSON.stringify({ description: "Test propagation." }),
    });

    const headers = engine.lastRequestHeaders();
    assert.equal(
      (headers["x-request-id"] ?? "").toLowerCase(),
      "e2e-forward-id",
    );
  });

  test("GET /api/provider-health probes mock engine and reports reachable", async () => {
    const res = await fetch(`${soc.baseUrl}/api/provider-health`);
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, unknown>;

    assert.equal(body["provider_mode"], "local_security_engine");
    assert.equal(body["engine_reachable"], true);
    assert.equal(body["engine_status"], "ok");
    assert.equal(body["model_name"], "phi4-mini");
    assert.equal(body["auth_configured"], false);
    assert.equal(body["engine_error"], null);
    assert.ok(typeof body["configured_base_url"] === "string");
  });
});

describe("E2E: inbound API key auth on /api/analyze", () => {
  before(() => {
    process.env["SOC_API_KEY"] = "e2e-secret-key";
  });

  after(() => {
    delete process.env["SOC_API_KEY"];
    resetRateLimiter();
  });

  test("request without X-API-Key is rejected with 401", async () => {
    const res = await fetch(`${soc.baseUrl}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description: "test" }),
    });
    assert.equal(res.status, 401);
    const body = await res.json() as Record<string, unknown>;
    assert.equal(body["error"], "unauthorized");
    assert.ok((body["detail"] as string).toLowerCase().includes("x-api-key"));
  });

  test("request with wrong X-API-Key is rejected with 401", async () => {
    const res = await fetch(`${soc.baseUrl}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": "wrong-key",
      },
      body: JSON.stringify({ description: "test" }),
    });
    assert.equal(res.status, 401);
    const body = await res.json() as Record<string, unknown>;
    assert.equal(body["error"], "unauthorized");
  });

  test("request with correct X-API-Key succeeds", async () => {
    const res = await fetch(`${soc.baseUrl}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": "e2e-secret-key",
      },
      body: JSON.stringify({ description: "SSH brute force detected." }),
    });
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, unknown>;
    assert.equal(body["fallback_used"], false);
  });

  test("GET /api/healthz is not protected by auth (public monitoring endpoint)", async () => {
    const res = await fetch(`${soc.baseUrl}/api/healthz`);
    assert.equal(res.status, 200);
  });

  test("GET /api/provider-health is not protected by auth (public monitoring endpoint)", async () => {
    const res = await fetch(`${soc.baseUrl}/api/provider-health`);
    assert.equal(res.status, 200);
  });
});

describe("E2E: rate limiting on /api/analyze", () => {
  before(() => {
    delete process.env["SOC_API_KEY"];
    process.env["RATE_LIMIT_MAX"] = "2";
    process.env["RATE_LIMIT_WINDOW_MS"] = "5000";
    resetRateLimiter();
  });

  after(() => {
    delete process.env["RATE_LIMIT_MAX"];
    delete process.env["RATE_LIMIT_WINDOW_MS"];
    resetRateLimiter();
  });

  test("third request within window is rejected with 429 and Retry-After header", async () => {
    const payload = JSON.stringify({ description: "rate limit test" });
    const opts = {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload,
    };

    // First two requests pass
    const r1 = await fetch(`${soc.baseUrl}/api/analyze`, opts);
    assert.equal(r1.status, 200, "First request should succeed");

    const r2 = await fetch(`${soc.baseUrl}/api/analyze`, opts);
    assert.equal(r2.status, 200, "Second request should succeed");

    // Third request should be rate limited
    const r3 = await fetch(`${soc.baseUrl}/api/analyze`, opts);
    assert.equal(r3.status, 429, "Third request should be rate limited");

    const body = await r3.json() as Record<string, unknown>;
    assert.equal(body["error"], "rate_limit_exceeded");
    assert.ok(typeof body["retry_after_seconds"] === "number");

    const retryAfter = r3.headers.get("retry-after");
    assert.ok(retryAfter !== null, "Retry-After header must be set");
    assert.ok(parseInt(retryAfter!) > 0, "Retry-After must be positive");
  });
});
