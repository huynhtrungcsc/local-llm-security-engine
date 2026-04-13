/**
 * Provider: Local LLM Security Engine
 *
 * Calls the Local LLM Security Engine — a standalone Python FastAPI service
 * that runs Ollama locally (llm-security-engine/, default port 8000).
 *
 * Local development: both this server and the engine run on the same machine.
 * Set LOCAL_LLM_ENGINE_BASE_URL=http://localhost:8000. No tunnel required.
 *
 * Remote deployment: if this SOC backend runs on a cloud server and the engine
 * runs on a separate local machine, use a Cloudflare Tunnel to bridge them.
 *
 * Integration contract: see llm-security-engine/docs/integration_contract.md
 *
 * Guarantees:
 * - Never throws on Ollama-level failures — the engine itself returns a fallback.
 * - If the engine is unreachable (network error, DNS failure, tunnel down, timeout),
 *   returns a local fallback with engine_reachable: false.
 * - If the engine returns HTTP 200 but a structurally invalid body, returns a fallback
 *   with contract_validation_failed: true (engine_reachable stays true).
 * - Auth: X-API-Key header sent only when LOCAL_LLM_ENGINE_API_KEY is configured.
 * - Request ID: forwarded as X-Request-ID to engine, echoed in every response.
 */

import { logger } from "../lib/logger.js";

// ── Request schema (matches the Python engine's SecurityEvent model) ───────────

export interface SecurityEventRequest {
  description: string;
  source_ip?: string;
  destination_ip?: string;
  event_type?: string;
  severity?: string;
  timestamp?: string;
  additional_context?: string;
}

// ── Valid attack classifications (from integration contract) ──────────────────

export const VALID_CLASSIFICATIONS = new Set<string>([
  "reconnaissance",
  "credential_access",
  "initial_access",
  "lateral_movement",
  "command_and_control",
  "benign",
  "unknown",
]);

export type AttackClassification =
  | "reconnaissance"
  | "credential_access"
  | "initial_access"
  | "lateral_movement"
  | "command_and_control"
  | "benign"
  | "unknown";

// ── Stable response schema from the Python engine (integration_contract.md) ───

export interface EngineAnalysisResponse {
  attack_classification: AttackClassification;
  false_positive_likelihood: number;
  risk_score: number;
  reason: string;
  fallback_used: boolean;
  model_used: string;
  provider: string;
  raw_parse_success: boolean;
  parse_strategy: string | null;
  ollama_error: string | null;
  request_id: string | null;
}

// ── AnalysisResult: EngineAnalysisResponse + SOC-backend metadata ─────────────

export interface AnalysisResult extends EngineAnalysisResponse {
  engine_reachable: boolean;
  engine_error: string | null;
  latency_ms: number | null;
  /**
   * true when the engine returned HTTP 200 but the response body failed
   * runtime contract validation. Always false on network-level fallbacks.
   */
  contract_validation_failed: boolean;
}

// ── Health response ───────────────────────────────────────────────────────────

export interface EngineHealthStatus {
  engine_reachable: boolean;
  engine_base_url: string;
  engine_status: string | null;
  engine_model: string | null;
  engine_error: string | null;
  latency_ms: number | null;
  /** Whether an API key is configured on this client. */
  auth_configured: boolean;
}

// ── Runtime contract validation ───────────────────────────────────────────────

/**
 * Validates the raw JSON returned by the engine against the integration contract.
 * Checked fields: attack_classification, false_positive_likelihood, risk_score,
 * reason, fallback_used, request_id.
 */
export function validateEngineResponse(
  raw: unknown,
): { valid: true; data: EngineAnalysisResponse } | { valid: false; errors: string[] } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { valid: false, errors: ["Response body is not a JSON object"] };
  }

  const r = raw as Record<string, unknown>;
  const errors: string[] = [];

  if (!VALID_CLASSIFICATIONS.has(String(r["attack_classification"] ?? ""))) {
    errors.push(
      `attack_classification must be one of [${[...VALID_CLASSIFICATIONS].join(", ")}]; got "${r["attack_classification"]}"`,
    );
  }

  if (
    typeof r["false_positive_likelihood"] !== "number" ||
    r["false_positive_likelihood"] < 0 ||
    r["false_positive_likelihood"] > 1
  ) {
    errors.push(
      `false_positive_likelihood must be a number in [0, 1]; got ${JSON.stringify(r["false_positive_likelihood"])}`,
    );
  }

  if (
    typeof r["risk_score"] !== "number" ||
    r["risk_score"] < 0 ||
    r["risk_score"] > 100
  ) {
    errors.push(
      `risk_score must be a number in [0, 100]; got ${JSON.stringify(r["risk_score"])}`,
    );
  }

  if (typeof r["reason"] !== "string" || r["reason"].trim().length === 0) {
    errors.push("reason must be a non-empty string");
  }

  if (typeof r["fallback_used"] !== "boolean") {
    errors.push(
      `fallback_used must be a boolean; got ${JSON.stringify(r["fallback_used"])}`,
    );
  }

  if (
    r["request_id"] !== null &&
    r["request_id"] !== undefined &&
    typeof r["request_id"] !== "string"
  ) {
    errors.push(
      `request_id must be a string or null; got ${JSON.stringify(r["request_id"])}`,
    );
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return { valid: true, data: r as unknown as EngineAnalysisResponse };
}

// ── Fallback constructors ─────────────────────────────────────────────────────

/** Used when the engine is unreachable at the network level. */
function unreachableFallback(
  engineError: string,
  latencyMs: number | null,
  requestId?: string,
): AnalysisResult {
  return {
    attack_classification: "unknown",
    false_positive_likelihood: 0.5,
    risk_score: 50,
    reason: `Local LLM Security Engine unreachable: ${engineError}`,
    fallback_used: true,
    model_used: "none",
    provider: "local_security_engine",
    raw_parse_success: false,
    parse_strategy: null,
    ollama_error: null,
    request_id: requestId ?? null,
    engine_reachable: false,
    engine_error: engineError,
    latency_ms: latencyMs,
    contract_validation_failed: false,
  };
}

/**
 * Used when the engine returned HTTP 200 but the body failed contract validation.
 * engine_reachable is true (we got a response), engine_error is null (no network fault).
 */
function contractValidationFallback(
  errors: string[],
  latencyMs: number | null,
  requestId?: string,
): AnalysisResult {
  return {
    attack_classification: "unknown",
    false_positive_likelihood: 0.5,
    risk_score: 50,
    reason: `Engine response failed contract validation: ${errors.join("; ")}`,
    fallback_used: true,
    model_used: "none",
    provider: "local_security_engine",
    raw_parse_success: false,
    parse_strategy: null,
    ollama_error: null,
    request_id: requestId ?? null,
    engine_reachable: true,
    engine_error: null,
    latency_ms: latencyMs,
    contract_validation_failed: true,
  };
}

// ── Client ─────────────────────────────────────────────────────────────────────

export class LocalSecurityEngineClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | null;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, apiKey: string | null, timeoutMs = 90_000) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
  }

  private buildHeaders(requestId?: string): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }
    if (requestId) {
      headers["X-Request-ID"] = requestId;
    }
    return headers;
  }

  /**
   * Analyze a security event via the Local LLM Security Engine.
   *
   * Always returns a structured AnalysisResult — never throws. On failure:
   *   - Network/transport failure → engine_reachable: false, contract_validation_failed: false
   *   - Bad response body       → engine_reachable: true,  contract_validation_failed: true
   */
  async analyzeEvent(
    event: SecurityEventRequest,
    requestId?: string,
  ): Promise<AnalysisResult> {
    const url = `${this.baseUrl}/analyze-event`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const start = Date.now();

    logger.info(
      {
        request_id: requestId,
        engine_url: url,
        description_length: event.description.length,
      },
      "local_engine_call_start",
    );

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: this.buildHeaders(requestId),
        body: JSON.stringify(event),
        signal: controller.signal,
      });

      const latencyMs = Date.now() - start;

      // ── HTTP-level error handling ───────────────────────────────────────────

      if (response.status === 429) {
        const retryAfter = response.headers.get("Retry-After");
        const engineError = `Engine rate limited. Retry after ${retryAfter ?? "unknown"}s.`;
        logger.warn(
          { request_id: requestId, status: 429, retry_after: retryAfter, latency_ms: latencyMs },
          "local_engine_rate_limited",
        );
        return unreachableFallback(engineError, latencyMs, requestId);
      }

      if (response.status === 401) {
        const engineError = "Engine auth required (X-API-Key missing). Set LOCAL_LLM_ENGINE_API_KEY.";
        logger.error(
          { request_id: requestId, status: 401, latency_ms: latencyMs },
          "local_engine_auth_error",
        );
        return unreachableFallback(engineError, latencyMs, requestId);
      }

      if (response.status === 403) {
        const engineError = "Engine auth rejected (X-API-Key invalid). Check LOCAL_LLM_ENGINE_API_KEY.";
        logger.error(
          { request_id: requestId, status: 403, latency_ms: latencyMs },
          "local_engine_auth_error",
        );
        return unreachableFallback(engineError, latencyMs, requestId);
      }

      if (!response.ok) {
        const body = await response.text().catch(() => "");
        const engineError = `Engine returned HTTP ${response.status}: ${body.slice(0, 200)}`;
        logger.error(
          { request_id: requestId, status: response.status, latency_ms: latencyMs },
          "local_engine_http_error",
        );
        return unreachableFallback(engineError, latencyMs, requestId);
      }

      // ── Parse JSON ─────────────────────────────────────────────────────────

      let rawData: unknown;
      try {
        rawData = await response.json();
      } catch {
        logger.error(
          { request_id: requestId, latency_ms: latencyMs },
          "local_engine_json_parse_failed",
        );
        return contractValidationFallback(
          ["Engine response is not valid JSON"],
          latencyMs,
          requestId,
        );
      }

      // ── Contract validation ────────────────────────────────────────────────

      const validation = validateEngineResponse(rawData);
      if (!validation.valid) {
        logger.error(
          {
            request_id: requestId,
            validation_errors: validation.errors,
            latency_ms: latencyMs,
          },
          "local_engine_contract_validation_failed",
        );
        return contractValidationFallback(validation.errors, latencyMs, requestId);
      }

      const data = validation.data;

      logger.info(
        {
          request_id: requestId,
          attack_classification: data.attack_classification,
          risk_score: data.risk_score,
          false_positive_likelihood: data.false_positive_likelihood,
          fallback_used: data.fallback_used,
          parse_strategy: data.parse_strategy,
          model_used: data.model_used,
          latency_ms: latencyMs,
        },
        "local_engine_call_complete",
      );

      return {
        ...data,
        engine_reachable: true,
        engine_error: null,
        latency_ms: latencyMs,
        contract_validation_failed: false,
      };
    } catch (err: unknown) {
      const latencyMs = Date.now() - start;
      const isTimeout = err instanceof Error && err.name === "AbortError";
      const engineError = isTimeout
        ? `Engine request timed out after ${this.timeoutMs}ms`
        : `Engine unreachable: ${err instanceof Error ? err.message : String(err)}`;

      logger.error(
        {
          request_id: requestId,
          err,
          is_timeout: isTimeout,
          latency_ms: latencyMs,
        },
        "local_engine_call_failed",
      );

      return unreachableFallback(engineError, latencyMs, requestId);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Check connectivity and model availability of the Local LLM Security Engine.
   * Calls GET /health on the engine. Never throws.
   */
  async checkHealth(): Promise<EngineHealthStatus> {
    const url = `${this.baseUrl}/health`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    const start = Date.now();

    logger.debug(
      { engine_url: url, auth_configured: this.apiKey !== null },
      "local_engine_health_probe",
    );

    try {
      const response = await fetch(url, {
        method: "GET",
        headers: this.buildHeaders(),
        signal: controller.signal,
      });

      const latencyMs = Date.now() - start;

      if (!response.ok) {
        logger.warn(
          { status: response.status, latency_ms: latencyMs },
          "local_engine_health_non_ok",
        );
        return {
          engine_reachable: false,
          engine_base_url: this.baseUrl,
          engine_status: null,
          engine_model: null,
          engine_error: `Health check returned HTTP ${response.status}`,
          latency_ms: latencyMs,
          auth_configured: this.apiKey !== null,
        };
      }

      const data = (await response.json()) as {
        status?: string;
        config?: { ollama_model?: string };
        ollama?: { reachable?: boolean; error?: string };
      };

      const ollamaError =
        data.ollama?.reachable === false
          ? (data.ollama?.error ?? "Ollama unreachable")
          : null;

      logger.debug(
        { engine_status: data.status, engine_model: data.config?.ollama_model, ollama_error: ollamaError, latency_ms: latencyMs },
        "local_engine_health_complete",
      );

      return {
        engine_reachable: true,
        engine_base_url: this.baseUrl,
        engine_status: data.status ?? null,
        engine_model: data.config?.ollama_model ?? null,
        engine_error: ollamaError,
        latency_ms: latencyMs,
        auth_configured: this.apiKey !== null,
      };
    } catch (err: unknown) {
      const latencyMs = Date.now() - start;
      const isTimeout = err instanceof Error && err.name === "AbortError";
      const engineError = isTimeout
        ? "Health check timed out"
        : `Engine unreachable: ${err instanceof Error ? err.message : String(err)}`;

      logger.warn({ err, is_timeout: isTimeout, latency_ms: latencyMs }, "local_engine_health_failed");

      return {
        engine_reachable: false,
        engine_base_url: this.baseUrl,
        engine_status: null,
        engine_model: null,
        engine_error: engineError,
        latency_ms: latencyMs,
        auth_configured: this.apiKey !== null,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

// ── Singleton factory ─────────────────────────────────────────────────────────

let _client: LocalSecurityEngineClient | null = null;

export function getLocalEngineClient(
  baseUrl: string,
  apiKey: string | null,
  timeoutMs: number,
): LocalSecurityEngineClient {
  if (!_client) {
    _client = new LocalSecurityEngineClient(baseUrl, apiKey, timeoutMs);
  }
  return _client;
}

export function resetLocalEngineClient(): void {
  _client = null;
}
