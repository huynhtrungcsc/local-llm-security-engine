import { Router, type IRouter, type Request } from "express";
import { HealthCheckResponse } from "@workspace/api-zod";
import { getConfig } from "../lib/config.js";
import { getLocalEngineClient } from "../providers/localSecurityEngine.js";
import { logger } from "../lib/logger.js";

const router: IRouter = Router();

/**
 * GET /api/healthz
 *
 * Lightweight liveness check. Always returns 200 with {status: "ok"}.
 * Use /api/provider-health for detailed provider connectivity status.
 */
router.get("/healthz", (_req, res) => {
  const data = HealthCheckResponse.parse({ status: "ok" });
  res.json(data);
});

/**
 * GET /api/provider-health
 *
 * Probes the configured LLM provider and returns connectivity status.
 * Never returns an error status — always 200 with reachability details.
 *
 * Response fields:
 *   provider_mode        — active mode ("local_security_engine" | "none")
 *   configured_base_url  — raw value of LOCAL_LLM_ENGINE_BASE_URL (null if unset)
 *   engine_reachable     — true if the engine responded to the health probe
 *   engine_status        — engine's self-reported status ("ok" | "degraded" | null)
 *   model_name           — Ollama model configured in the engine (null if unknown)
 *   latency_ms           — round-trip latency to engine's /health endpoint (null if not probed)
 *   auth_configured      — true if LOCAL_LLM_ENGINE_API_KEY is set
 *   engine_error         — error message if unreachable (null if healthy)
 */
router.get("/provider-health", async (req: Request, res) => {
  const requestId = (req.headers["x-request-id"] as string | undefined) ?? crypto.randomUUID();
  const config = getConfig();

  if (config.providerMode === "none") {
    logger.info({ request_id: requestId, provider_mode: "none" }, "provider_health_no_config");
    res.json({
      provider_mode: "none",
      configured_base_url: null,
      engine_reachable: false,
      engine_status: null,
      model_name: null,
      latency_ms: null,
      auth_configured: false,
      engine_error: "No provider configured. Set LOCAL_LLM_ENGINE_BASE_URL.",
    });
    return;
  }

  const { baseUrl, apiKey, timeoutMs } = config.localEngine;
  const client = getLocalEngineClient(baseUrl!, apiKey, timeoutMs);

  logger.debug({ request_id: requestId, engine_url: baseUrl }, "provider_health_probe");

  const health = await client.checkHealth();

  logger.info(
    {
      request_id: requestId,
      engine_reachable: health.engine_reachable,
      engine_status: health.engine_status,
      engine_model: health.engine_model,
      latency_ms: health.latency_ms,
    },
    "provider_health_result",
  );

  res.json({
    provider_mode: config.providerMode,
    configured_base_url: baseUrl,
    engine_reachable: health.engine_reachable,
    engine_status: health.engine_status,
    model_name: health.engine_model,
    latency_ms: health.latency_ms,
    auth_configured: health.auth_configured,
    engine_error: health.engine_error,
  });
});

export default router;
