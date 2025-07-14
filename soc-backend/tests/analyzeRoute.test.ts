/**
 * Integration tests for the HTTP routes.
 *
 * Starts a real Express server on a random port and makes real HTTP requests,
 * verifying the full request/response lifecycle including headers,
 * status codes, and body shape.
 *
 * Fetch mocking strategy:
 * - `realFetch` is saved at module-load time (before any mocks).
 * - `engineFetch(behavior)` returns a fetch function that routes calls to the
 *   test server (127.0.0.1) through `realFetch`, and all other calls (to the
 *   engine) through the provided `behavior`. This prevents the mock from
 *   accidentally intercepting test-server requests.
 */

import { describe, test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import app from "../src/app.js";
import { resetConfig } from "../src/lib/config.js";
import { resetLocalEngineClient } from "../src/providers/localSecurityEngine.js";

// ── Real fetch saved before any test runs ────────────────────────────────────

const realFetch = globalThis.fetch;

// ── Helpers ───────────────────────────────────────────────────────────────────

type FetchFn = typeof globalThis.fetch;

interface TestServer {
  baseUrl: string;
  close: () => Promise<void>;
}

function startServer(): Promise<TestServer> {
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

/**
 * Creates a smart fetch mock:
 * - Calls to http://127.0.0.1:* (the test server) pass through to realFetch.
 * - All other calls (to the engine) use `engineBehavior`.
 */
function engineFetch(engineBehavior: FetchFn): FetchFn {
  return async (url, opts) => {
    if (String(url).startsWith("http://127.0.0.1:")) {
      return realFetch(url, opts);
    }
    return engineBehavior(url, opts);
  };
}

function makeEngineOk(body = VALID_ENGINE_RESPONSE): FetchFn {
  return async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
}

function makeEngineError(status: number): FetchFn {
  return async () =>
    new Response(JSON.stringify({ detail: "Error" }), {
      status,
      headers: { "Content-Type": "application/json" },
    });
}

function makeNetworkError(): FetchFn {
  return async () => {
    throw new Error("connect ECONNREFUSED");
  };
}

// ── Canonical valid engine response ──────────────────────────────────────────

const VALID_ENGINE_RESPONSE = {
  attack_classification: "reconnaissance",
  false_positive_likelihood: 0.1,
  risk_score: 75,
  reason: "Port scan detected from known malicious IP.",
  fallback_used: false,
  model_used: "phi4-mini",
  provider: "ollama",
  raw_parse_success: true,
  parse_strategy: "direct",
  ollama_error: null,
  request_id: "engine-req-id",
};

// ── Lifecycle ─────────────────────────────────────────────────────────────────

let savedEnvUrl: string | undefined;

beforeEach(() => {
  savedEnvUrl = process.env["LOCAL_LLM_ENGINE_BASE_URL"];
});

afterEach(() => {
  globalThis.fetch = realFetch;
  if (savedEnvUrl !== undefined) {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = savedEnvUrl;
  } else {
    delete process.env["LOCAL_LLM_ENGINE_BASE_URL"];
  }
  delete process.env["LOCAL_LLM_ENGINE_API_KEY"];
  resetConfig();
  resetLocalEngineClient();
});

// ── GET /api/healthz ──────────────────────────────────────────────────────────

describe("GET /api/healthz", () => {
  test("returns 200 {status: ok}", async () => {
    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/healthz`);
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;
      assert.equal(body["status"], "ok");
    } finally {
      await close();
    }
  });
});

// ── GET /api/provider-health ──────────────────────────────────────────────────

describe("GET /api/provider-health", () => {
  test("no provider configured — returns none mode with clear error", async () => {
    delete process.env["LOCAL_LLM_ENGINE_BASE_URL"];
    resetConfig();
    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/provider-health`);
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;

      assert.equal(body["provider_mode"], "none");
      assert.equal(body["engine_reachable"], false);
      assert.equal(body["auth_configured"], false);
      assert.equal(body["configured_base_url"], null);
      assert.ok(typeof body["engine_error"] === "string" && body["engine_error"].length > 0);
    } finally {
      await close();
    }
  });

  test("local_security_engine configured — reports correct fields including auth_configured", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    process.env["LOCAL_LLM_ENGINE_API_KEY"] = "test-key";
    resetConfig();
    resetLocalEngineClient();

    globalThis.fetch = engineFetch(async () =>
      new Response(
        JSON.stringify({
          status: "ok",
          config: { ollama_model: "phi4-mini" },
          ollama: { reachable: true },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/provider-health`);
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;

      assert.equal(body["provider_mode"], "local_security_engine");
      assert.equal(body["engine_reachable"], true);
      assert.equal(body["engine_status"], "ok");
      assert.equal(body["model_name"], "phi4-mini");
      assert.equal(body["auth_configured"], true);
      assert.equal(body["configured_base_url"], "http://engine-host:8000");
      assert.equal(body["engine_error"], null);
    } finally {
      await close();
    }
  });

  test("engine unreachable — returns engine_reachable: false without crashing", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "https://dead-tunnel.trycloudflare.com";
    resetConfig();
    resetLocalEngineClient();

    globalThis.fetch = engineFetch(makeNetworkError());

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/provider-health`);
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;

      assert.equal(body["provider_mode"], "local_security_engine");
      assert.equal(body["engine_reachable"], false);
      assert.ok(typeof body["engine_error"] === "string");
    } finally {
      await close();
    }
  });
});

// ── POST /api/analyze ─────────────────────────────────────────────────────────

describe("POST /api/analyze", () => {
  test("returns 503 when no provider configured", async () => {
    delete process.env["LOCAL_LLM_ENGINE_BASE_URL"];
    resetConfig();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "Port scan from 1.2.3.4" }),
      });
      assert.equal(res.status, 503);
      const body = await res.json() as Record<string, unknown>;
      assert.equal(body["error"], "no_provider_configured");
      assert.ok(typeof body["request_id"] === "string");
    } finally {
      await close();
    }
  });

  test("returns 422 when description is missing", async () => {
    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_ip: "1.2.3.4" }),
      });
      assert.equal(res.status, 422);
      const body = await res.json() as Record<string, unknown>;
      assert.equal(body["error"], "validation_error");
      assert.ok(Array.isArray(body["errors"]) && (body["errors"] as unknown[]).length > 0);
    } finally {
      await close();
    }
  });

  test("returns 422 when description exceeds 4000 chars", async () => {
    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "x".repeat(4001) }),
      });
      assert.equal(res.status, 422);
      const body = await res.json() as Record<string, unknown>;
      assert.equal(body["error"], "validation_error");
    } finally {
      await close();
    }
  });

  test("returns 422 when body is not a JSON object", async () => {
    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify([1, 2, 3]),
      });
      assert.equal(res.status, 422);
    } finally {
      await close();
    }
  });

  test("valid request — returns 200 with complete AnalysisResult shape", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    resetConfig();
    resetLocalEngineClient();
    globalThis.fetch = engineFetch(makeEngineOk());

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          description: "SSH brute force from external IP",
          source_ip: "185.220.101.1",
          event_type: "authentication_failure",
          severity: "high",
        }),
      });
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;

      assert.ok(typeof body["attack_classification"] === "string");
      assert.ok(typeof body["false_positive_likelihood"] === "number");
      assert.ok(typeof body["risk_score"] === "number");
      assert.ok(typeof body["reason"] === "string");
      assert.equal(typeof body["fallback_used"], "boolean");
      assert.equal(typeof body["engine_reachable"], "boolean");
      assert.equal(typeof body["contract_validation_failed"], "boolean");
      assert.equal(body["soc_provider_mode"], "local_security_engine");
      assert.ok(typeof body["request_id"] === "string");
    } finally {
      await close();
    }
  });

  test("engine unreachable — 200 with fallback_used: true, engine_reachable: false", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    resetConfig();
    resetLocalEngineClient();
    globalThis.fetch = engineFetch(makeNetworkError());

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "Alert: anomaly detected" }),
      });
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;

      assert.equal(body["fallback_used"], true);
      assert.equal(body["engine_reachable"], false);
      assert.equal(body["contract_validation_failed"], false);
      assert.ok(typeof body["engine_error"] === "string");
    } finally {
      await close();
    }
  });

  test("engine contract violation — 200 with contract_validation_failed: true", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    resetConfig();
    resetLocalEngineClient();
    globalThis.fetch = engineFetch(async () =>
      new Response(JSON.stringify({ bad: "schema" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;

      assert.equal(body["fallback_used"], true);
      assert.equal(body["contract_validation_failed"], true);
      assert.equal(body["engine_reachable"], true);
    } finally {
      await close();
    }
  });

  test("caller X-Request-ID propagated in response header and body", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    resetConfig();
    resetLocalEngineClient();
    globalThis.fetch = engineFetch(makeEngineOk());

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": "my-trace-id-abc-123",
        },
        body: JSON.stringify({ description: "test" }),
      });
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("x-request-id"), "my-trace-id-abc-123");
      const body = await res.json() as Record<string, unknown>;
      assert.ok(typeof body["request_id"] === "string");
    } finally {
      await close();
    }
  });

  test("X-Request-ID auto-generated when not supplied by caller", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    resetConfig();
    resetLocalEngineClient();
    globalThis.fetch = engineFetch(makeEngineOk());

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      const responseId = res.headers.get("x-request-id");
      const body = await res.json() as Record<string, unknown>;

      assert.ok(typeof responseId === "string" && responseId.length > 0);
      assert.ok(typeof body["request_id"] === "string" && (body["request_id"] as string).length > 0);
    } finally {
      await close();
    }
  });

  test("X-Request-ID forwarded to engine", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    resetConfig();
    resetLocalEngineClient();

    let engineHeaders: Record<string, string> = {};
    globalThis.fetch = engineFetch(async (_url, opts) => {
      engineHeaders = { ...(opts?.headers as Record<string, string>) };
      return new Response(JSON.stringify(VALID_ENGINE_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    const { baseUrl, close } = await startServer();
    try {
      await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": "forward-this-id",
        },
        body: JSON.stringify({ description: "test" }),
      });
      assert.equal(engineHeaders["X-Request-ID"], "forward-this-id");
    } finally {
      await close();
    }
  });

  test("fallback response includes all required transparency fields", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    resetConfig();
    resetLocalEngineClient();
    globalThis.fetch = engineFetch(makeNetworkError());

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      const body = await res.json() as Record<string, unknown>;

      assert.ok("fallback_used" in body, "fallback_used missing");
      assert.ok("engine_reachable" in body, "engine_reachable missing");
      assert.ok("engine_error" in body, "engine_error missing");
      assert.ok("soc_provider_mode" in body, "soc_provider_mode missing");
      assert.ok("request_id" in body, "request_id missing");
      assert.ok("contract_validation_failed" in body, "contract_validation_failed missing");
    } finally {
      await close();
    }
  });

  test("engine 401 — 200 with auth error in engine_error", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    resetConfig();
    resetLocalEngineClient();
    globalThis.fetch = engineFetch(makeEngineError(401));

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;
      assert.equal(body["fallback_used"], true);
      assert.ok((body["engine_error"] as string).includes("X-API-Key missing"));
    } finally {
      await close();
    }
  });

  test("engine 429 — 200 with rate limit message", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    resetConfig();
    resetLocalEngineClient();
    globalThis.fetch = engineFetch(async () =>
      new Response(JSON.stringify({ detail: "rate limited" }), {
        status: 429,
        headers: { "Content-Type": "application/json", "Retry-After": "60" },
      }),
    );

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;
      assert.equal(body["fallback_used"], true);
      assert.ok((body["engine_error"] as string).toLowerCase().includes("rate limited"));
    } finally {
      await close();
    }
  });

  test("engine 500 — 200 with HTTP 500 in engine_error", async () => {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
    resetConfig();
    resetLocalEngineClient();
    globalThis.fetch = engineFetch(makeEngineError(500));

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;
      assert.equal(body["fallback_used"], true);
      assert.ok((body["engine_error"] as string).includes("HTTP 500"));
    } finally {
      await close();
    }
  });
});
