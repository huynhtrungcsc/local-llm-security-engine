/**
 * Contract stability tests.
 *
 * Verify that:
 *   1. The request body the SOC backend sends to the Python engine exactly
 *      matches the documented SecurityEvent contract.
 *   2. The SOC backend's response schema remains stable across all paths
 *      (success, engine fallback, network failure, contract validation failure).
 *   3. All fallback paths return the same top-level field set.
 *
 * Fetch mocking strategy: see analyzeRoute.test.ts for explanation.
 * `engineFetch()` routes 127.0.0.1 calls to realFetch, other URLs to the mock.
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

function engineFetch(engineBehavior: FetchFn): FetchFn {
  return async (url, opts) => {
    if (String(url).startsWith("http://127.0.0.1:")) {
      return realFetch(url, opts);
    }
    return engineBehavior(url, opts);
  };
}

// ── Documented stable response fields ────────────────────────────────────────

const REQUIRED_RESPONSE_FIELDS = [
  "attack_classification",
  "false_positive_likelihood",
  "risk_score",
  "reason",
  "fallback_used",
  "model_used",
  "provider",
  "raw_parse_success",
  "parse_strategy",
  "ollama_error",
  "request_id",
  "engine_reachable",
  "engine_error",
  "latency_ms",
  "contract_validation_failed",
  "soc_provider_mode",
] as const;

const DOCUMENTED_ENGINE_REQUEST_FIELDS = [
  "description",
  "source_ip",
  "destination_ip",
  "event_type",
  "severity",
  "timestamp",
  "additional_context",
] as const;

// ── Valid engine response ─────────────────────────────────────────────────────

const VALID_ENGINE_RESPONSE = {
  attack_classification: "reconnaissance",
  false_positive_likelihood: 0.2,
  risk_score: 65,
  reason: "Port scan from external IP.",
  fallback_used: false,
  model_used: "phi4-mini",
  provider: "ollama",
  raw_parse_success: true,
  parse_strategy: "direct",
  ollama_error: null,
  request_id: "engine-123",
};

function assertAllRequiredFields(body: Record<string, unknown>, context: string): void {
  for (const field of REQUIRED_RESPONSE_FIELDS) {
    assert.ok(
      field in body,
      `[${context}] Required field "${field}" missing from response`,
    );
  }
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

let savedEnvUrl: string | undefined;

beforeEach(() => {
  savedEnvUrl = process.env["LOCAL_LLM_ENGINE_BASE_URL"];
  process.env["LOCAL_LLM_ENGINE_BASE_URL"] = "http://engine-host:8000";
  resetConfig();
});

afterEach(() => {
  globalThis.fetch = realFetch;
  if (savedEnvUrl !== undefined) {
    process.env["LOCAL_LLM_ENGINE_BASE_URL"] = savedEnvUrl;
  } else {
    delete process.env["LOCAL_LLM_ENGINE_BASE_URL"];
  }
  resetConfig();
  resetLocalEngineClient();
});

// ── Request contract ──────────────────────────────────────────────────────────

describe("Request contract: SOC backend → Python engine", () => {
  test("request body includes all documented SecurityEvent fields", async () => {
    let capturedBody: Record<string, unknown> = {};
    globalThis.fetch = engineFetch(async (_url, opts) => {
      capturedBody = JSON.parse(opts?.body as string);
      return new Response(JSON.stringify(VALID_ENGINE_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          description: "Test event",
          source_ip: "1.2.3.4",
          destination_ip: "10.0.0.1",
          event_type: "port_scan",
          severity: "medium",
          timestamp: "2024-01-15T10:00:00Z",
          additional_context: "extra info",
        }),
      });

      assert.equal(capturedBody["description"], "Test event");
      assert.equal(capturedBody["source_ip"], "1.2.3.4");
      assert.equal(capturedBody["destination_ip"], "10.0.0.1");
      assert.equal(capturedBody["event_type"], "port_scan");
      assert.equal(capturedBody["severity"], "medium");
      assert.equal(capturedBody["timestamp"], "2024-01-15T10:00:00Z");
      assert.equal(capturedBody["additional_context"], "extra info");
    } finally {
      await close();
    }
  });

  test("request body contains no undocumented fields", async () => {
    let capturedBody: Record<string, unknown> = {};
    globalThis.fetch = engineFetch(async (_url, opts) => {
      capturedBody = JSON.parse(opts?.body as string);
      return new Response(JSON.stringify(VALID_ENGINE_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "minimal event" }),
      });

      const sentFields = Object.keys(capturedBody);
      const undocumented = sentFields.filter(
        (f) => !(DOCUMENTED_ENGINE_REQUEST_FIELDS as readonly string[]).includes(f),
      );
      assert.deepEqual(undocumented, [], `Undocumented fields: ${undocumented.join(", ")}`);
    } finally {
      await close();
    }
  });

  test("POST method and /analyze-event path used", async () => {
    let capturedMethod = "";
    let capturedUrl = "";
    globalThis.fetch = engineFetch(async (url, opts) => {
      capturedMethod = opts?.method ?? "";
      capturedUrl = String(url);
      return new Response(JSON.stringify(VALID_ENGINE_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });

      assert.equal(capturedMethod, "POST");
      assert.ok(capturedUrl.endsWith("/analyze-event"), `URL was: ${capturedUrl}`);
    } finally {
      await close();
    }
  });

  test("Content-Type: application/json sent to engine", async () => {
    let capturedContentType = "";
    globalThis.fetch = engineFetch(async (_url, opts) => {
      const headers = opts?.headers as Record<string, string>;
      capturedContentType = headers["Content-Type"] ?? "";
      return new Response(JSON.stringify(VALID_ENGINE_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      assert.equal(capturedContentType, "application/json");
    } finally {
      await close();
    }
  });
});

// ── Response contract ─────────────────────────────────────────────────────────

describe("Response contract: SOC backend → downstream consumers", () => {
  test("success path — all required fields present with correct types", async () => {
    globalThis.fetch = engineFetch(async () =>
      new Response(JSON.stringify(VALID_ENGINE_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      assert.equal(res.status, 200);
      const body = await res.json() as Record<string, unknown>;

      assertAllRequiredFields(body, "success");
      assert.equal(body["fallback_used"], false);
      assert.equal(body["engine_reachable"], true);
      assert.equal(body["contract_validation_failed"], false);
      assert.equal(body["soc_provider_mode"], "local_security_engine");
      assert.ok(typeof body["attack_classification"] === "string");
      assert.ok(typeof body["false_positive_likelihood"] === "number");
      assert.ok(typeof body["risk_score"] === "number");
    } finally {
      await close();
    }
  });

  test("engine fallback path — all required fields present", async () => {
    const engineFallback = {
      ...VALID_ENGINE_RESPONSE,
      fallback_used: true,
      attack_classification: "unknown",
      risk_score: 50,
      model_used: "none",
      reason: "Ollama timeout.",
    };
    globalThis.fetch = engineFetch(async () =>
      new Response(JSON.stringify(engineFallback), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      const body = await res.json() as Record<string, unknown>;

      assertAllRequiredFields(body, "engine-fallback");
      assert.equal(body["fallback_used"], true);
      assert.equal(body["contract_validation_failed"], false);
    } finally {
      await close();
    }
  });

  test("network failure path — all required fields present", async () => {
    globalThis.fetch = engineFetch(async () => {
      throw new Error("ECONNREFUSED");
    });
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      const body = await res.json() as Record<string, unknown>;

      assertAllRequiredFields(body, "network-failure");
      assert.equal(body["fallback_used"], true);
      assert.equal(body["engine_reachable"], false);
      assert.equal(body["contract_validation_failed"], false);
    } finally {
      await close();
    }
  });

  test("contract validation failure path — all required fields present", async () => {
    globalThis.fetch = engineFetch(async () =>
      new Response(JSON.stringify({ unexpected: "schema" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      const body = await res.json() as Record<string, unknown>;

      assertAllRequiredFields(body, "contract-validation-failure");
      assert.equal(body["fallback_used"], true);
      assert.equal(body["engine_reachable"], true);
      assert.equal(body["contract_validation_failed"], true);
    } finally {
      await close();
    }
  });

  test("all fallback paths produce identical top-level field sets", async () => {
    const scenarios: Array<{ name: string; engineBehavior: FetchFn }> = [
      {
        name: "network_error",
        engineBehavior: async () => { throw new Error("ECONNREFUSED"); },
      },
      {
        name: "bad_json",
        engineBehavior: async () =>
          new Response("not-json", { status: 200, headers: { "Content-Type": "application/json" } }),
      },
      {
        name: "missing_fields",
        engineBehavior: async () =>
          new Response(JSON.stringify({ bad: "schema" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      },
      {
        name: "http_500",
        engineBehavior: async () =>
          new Response("error", { status: 500, headers: { "Content-Type": "application/json" } }),
      },
      {
        name: "http_401",
        engineBehavior: async () =>
          new Response("{}", { status: 401, headers: { "Content-Type": "application/json" } }),
      },
    ];

    const fieldSets: string[][] = [];
    const { baseUrl, close } = await startServer();

    try {
      for (const scenario of scenarios) {
        globalThis.fetch = engineFetch(scenario.engineBehavior);
        resetLocalEngineClient();

        const res = await realFetch(`${baseUrl}/api/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ description: "test" }),
        });
        const body = await res.json() as Record<string, unknown>;
        fieldSets.push(Object.keys(body).sort());
      }
    } finally {
      await close();
    }

    const referenceFields = fieldSets[0]!;
    for (let i = 1; i < fieldSets.length; i++) {
      assert.deepEqual(
        fieldSets[i],
        referenceFields,
        `Scenario "${scenarios[i]!.name}" fields differ from "${scenarios[0]!.name}"`,
      );
    }
  });

  test("attack_classification is always a valid enum value (including fallback)", async () => {
    globalThis.fetch = engineFetch(async () => { throw new Error("ECONNREFUSED"); });
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      const body = await res.json() as Record<string, unknown>;
      const validClasses = [
        "reconnaissance", "credential_access", "initial_access",
        "lateral_movement", "command_and_control", "benign", "unknown",
      ];
      assert.ok(
        validClasses.includes(body["attack_classification"] as string),
        `Got: ${body["attack_classification"]}`,
      );
    } finally {
      await close();
    }
  });

  test("risk_score is always a number in [0, 100] (including fallback)", async () => {
    globalThis.fetch = engineFetch(async () => { throw new Error("ECONNREFUSED"); });
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      const body = await res.json() as Record<string, unknown>;
      const rs = body["risk_score"] as number;
      assert.ok(typeof rs === "number" && rs >= 0 && rs <= 100, `risk_score = ${rs}`);
    } finally {
      await close();
    }
  });

  test("false_positive_likelihood is always a number in [0, 1] (including fallback)", async () => {
    globalThis.fetch = engineFetch(async () => { throw new Error("ECONNREFUSED"); });
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      const body = await res.json() as Record<string, unknown>;
      const fpl = body["false_positive_likelihood"] as number;
      assert.ok(typeof fpl === "number" && fpl >= 0 && fpl <= 1, `false_positive_likelihood = ${fpl}`);
    } finally {
      await close();
    }
  });
});

// ── Request ID contract ───────────────────────────────────────────────────────

describe("Request ID contract", () => {
  test("caller-supplied X-Request-ID flows to response body and header", async () => {
    globalThis.fetch = engineFetch(async () =>
      new Response(JSON.stringify(VALID_ENGINE_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": "contract-test-id-abc",
        },
        body: JSON.stringify({ description: "test" }),
      });
      const body = await res.json() as Record<string, unknown>;

      assert.equal(res.headers.get("x-request-id"), "contract-test-id-abc");
      assert.ok(typeof body["request_id"] === "string");
    } finally {
      await close();
    }
  });

  test("auto-generated ID is a UUID when caller supplies none", async () => {
    globalThis.fetch = engineFetch(async () =>
      new Response(JSON.stringify(VALID_ENGINE_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      const body = await res.json() as Record<string, unknown>;
      const id = res.headers.get("x-request-id") ?? "";
      const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      assert.ok(uuidPattern.test(id), `Auto-generated ID "${id}" is not a valid UUID v4`);
      assert.ok(typeof body["request_id"] === "string");
    } finally {
      await close();
    }
  });

  test("X-Request-ID forwarded to Python engine in request header", async () => {
    let engineRequestId = "";
    globalThis.fetch = engineFetch(async (_url, opts) => {
      const h = opts?.headers as Record<string, string>;
      engineRequestId = h["X-Request-ID"] ?? "";
      return new Response(JSON.stringify(VALID_ENGINE_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    resetLocalEngineClient();

    const { baseUrl, close } = await startServer();
    try {
      await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": "propagation-test",
        },
        body: JSON.stringify({ description: "test" }),
      });
      assert.equal(engineRequestId, "propagation-test");
    } finally {
      await close();
    }
  });

  test("request_id present in 422 validation error response", async () => {
    delete process.env["LOCAL_LLM_ENGINE_BASE_URL"];
    resetConfig();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      assert.equal(res.status, 422);
      const body = await res.json() as Record<string, unknown>;
      assert.ok(typeof body["request_id"] === "string");
    } finally {
      await close();
    }
  });

  test("request_id present in 503 no-provider response", async () => {
    delete process.env["LOCAL_LLM_ENGINE_BASE_URL"];
    resetConfig();

    const { baseUrl, close } = await startServer();
    try {
      const res = await realFetch(`${baseUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "test" }),
      });
      assert.equal(res.status, 503);
      const body = await res.json() as Record<string, unknown>;
      assert.ok(typeof body["request_id"] === "string");
    } finally {
      await close();
    }
  });
});
