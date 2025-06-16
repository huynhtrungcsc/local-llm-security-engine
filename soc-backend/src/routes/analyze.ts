/**
 * POST /api/analyze
 *
 * Accepts a normalized security alert and returns a structured threat analysis.
 * Delegates to the configured LLM provider (currently: local_security_engine).
 *
 * HTTP status codes:
 *   200  — analysis result (always present; check fallback_used before automating)
 *   422  — request body failed validation
 *   503  — no LLM provider is configured
 *
 * The endpoint never returns 5xx for provider-level failures — those surface
 * as fallback_used: true in the 200 response body.
 */

import { Router, type IRouter, type Request, type Response } from "express";
import { getConfig } from "../lib/config.js";
import { getLocalEngineClient } from "../providers/localSecurityEngine.js";
import { logger } from "../lib/logger.js";
import { apiKeyAuth } from "../middleware/apiKeyAuth.js";
import { analyzeRateLimiter } from "../middleware/rateLimiter.js";

const router: IRouter = Router();

// ── Input validation ──────────────────────────────────────────────────────────

const MAX_DESCRIPTION = 4000;
const MAX_CONTEXT = 4000;
const MAX_FIELD = 500;

interface SocAlertInput {
  description: string;
  source_ip?: string;
  destination_ip?: string;
  event_type?: string;
  severity?: string;
  timestamp?: string;
  additional_context?: string;
}

function validateRequest(
  body: unknown,
): { valid: true; data: SocAlertInput } | { valid: false; errors: string[] } {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { valid: false, errors: ["Request body must be a JSON object."] };
  }

  const b = body as Record<string, unknown>;
  const errors: string[] = [];

  if (typeof b["description"] !== "string" || b["description"].trim().length === 0) {
    errors.push("description is required and must be a non-empty string.");
  } else if (b["description"].length > MAX_DESCRIPTION) {
    errors.push(`description must not exceed ${MAX_DESCRIPTION} characters.`);
  }

  const optFields = [
    "source_ip",
    "destination_ip",
    "event_type",
    "severity",
    "timestamp",
  ] as const;
  for (const field of optFields) {
    if (b[field] !== undefined && b[field] !== null) {
      if (typeof b[field] !== "string") {
        errors.push(`${field} must be a string if provided.`);
      } else if ((b[field] as string).length > MAX_FIELD) {
        errors.push(`${field} must not exceed ${MAX_FIELD} characters.`);
      }
    }
  }

  if (b["additional_context"] !== undefined && b["additional_context"] !== null) {
    if (typeof b["additional_context"] !== "string") {
      errors.push("additional_context must be a string if provided.");
    } else if ((b["additional_context"] as string).length > MAX_CONTEXT) {
      errors.push(`additional_context must not exceed ${MAX_CONTEXT} characters.`);
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    data: {
      description: (b["description"] as string).trim(),
      source_ip: typeof b["source_ip"] === "string" ? b["source_ip"] : undefined,
      destination_ip:
        typeof b["destination_ip"] === "string" ? b["destination_ip"] : undefined,
      event_type: typeof b["event_type"] === "string" ? b["event_type"] : undefined,
      severity: typeof b["severity"] === "string" ? b["severity"] : undefined,
      timestamp: typeof b["timestamp"] === "string" ? b["timestamp"] : undefined,
      additional_context:
        typeof b["additional_context"] === "string"
          ? b["additional_context"]
          : undefined,
    },
  };
}

// ── Route ─────────────────────────────────────────────────────────────────────

router.post("/analyze", apiKeyAuth, analyzeRateLimiter, async (req: Request, res: Response) => {
  // Request ID: honour caller-supplied ID or generate a fresh one
  const requestId =
    (req.headers["x-request-id"] as string | undefined) ?? crypto.randomUUID();

  logger.info(
    { request_id: requestId, method: "POST", path: "/api/analyze" },
    "analyze_request_start",
  );

  // ── Input validation ──────────────────────────────────────────────────────
  const validation = validateRequest(req.body);
  if (!validation.valid) {
    logger.warn(
      { request_id: requestId, errors: validation.errors },
      "analyze_input_validation_failed",
    );
    res.status(422).json({
      error: "validation_error",
      detail: "Request body failed validation.",
      errors: validation.errors,
      request_id: requestId,
    });
    return;
  }

  // ── Provider guard ────────────────────────────────────────────────────────
  const config = getConfig();

  if (config.providerMode === "none") {
    logger.warn(
      { request_id: requestId, provider_mode: "none" },
      "analyze_no_provider_configured",
    );
    res.status(503).json({
      error: "no_provider_configured",
      detail:
        "No LLM provider is configured. Set LOCAL_LLM_ENGINE_BASE_URL to enable the local_security_engine provider.",
      request_id: requestId,
    });
    return;
  }

  // ── Call provider ─────────────────────────────────────────────────────────
  const { baseUrl, apiKey, timeoutMs } = config.localEngine;
  const client = getLocalEngineClient(baseUrl!, apiKey, timeoutMs);

  logger.info(
    {
      request_id: requestId,
      provider_mode: config.providerMode,
      engine_url: baseUrl,
      description_length: validation.data.description.length,
    },
    "analyze_provider_call_start",
  );

  const result = await client.analyzeEvent(validation.data, requestId);

  // ── Observability: log fallback / contract failure ────────────────────────
  if (result.contract_validation_failed) {
    logger.error(
      {
        request_id: requestId,
        provider_mode: config.providerMode,
        engine_reachable: result.engine_reachable,
        reason: result.reason,
      },
      "analyze_contract_validation_failed",
    );
  } else if (result.fallback_used) {
    logger.warn(
      {
        request_id: requestId,
        provider_mode: config.providerMode,
        engine_reachable: result.engine_reachable,
        engine_error: result.engine_error,
      },
      "analyze_fallback_triggered",
    );
  } else {
    logger.info(
      {
        request_id: requestId,
        provider_mode: config.providerMode,
        attack_classification: result.attack_classification,
        risk_score: result.risk_score,
        fallback_used: result.fallback_used,
        latency_ms: result.latency_ms,
      },
      "analyze_complete",
    );
  }

  // ── Response ──────────────────────────────────────────────────────────────
  res.setHeader("X-Request-ID", requestId);
  res.json({
    ...result,
    soc_provider_mode: config.providerMode,
    // Ensure the caller's request_id is always present in the body, even if
    // the engine returned its own (engine's request_id is in the spread above).
    request_id: result.request_id ?? requestId,
  });
});

export default router;
