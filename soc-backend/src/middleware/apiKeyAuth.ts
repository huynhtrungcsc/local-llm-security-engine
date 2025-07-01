/**
 * Inbound API key authentication middleware for the SOC backend.
 *
 * Behaviour:
 *   - If SOC_API_KEY is not set in the environment, authentication is
 *     disabled and every request passes through. This allows the server
 *     to run unauthenticated in development without any extra setup.
 *   - If SOC_API_KEY is set, the caller must supply a matching
 *     "X-API-Key" header; otherwise the request is rejected with 401.
 *
 * Applied only to /api/analyze. The /api/healthz and /api/provider-health
 * endpoints are public monitoring endpoints and are intentionally exempt.
 */

import { type Request, type Response, type NextFunction } from "express";
import { logger } from "../lib/logger.js";

export function apiKeyAuth(req: Request, res: Response, next: NextFunction): void {
  const configuredKey = process.env["SOC_API_KEY"]?.trim() || null;

  // Auth disabled — pass through.
  if (!configuredKey) {
    next();
    return;
  }

  const requestId =
    (req.headers["x-request-id"] as string | undefined)?.trim() ||
    "unknown";

  const provided = (req.headers["x-api-key"] as string | undefined)?.trim();

  if (!provided) {
    logger.warn({ request_id: requestId }, "auth_missing_api_key");
    res.status(401).json({
      error: "unauthorized",
      detail: "X-API-Key header is required.",
      request_id: requestId,
    });
    return;
  }

  if (provided !== configuredKey) {
    logger.warn({ request_id: requestId }, "auth_invalid_api_key");
    res.status(401).json({
      error: "unauthorized",
      detail: "Invalid API key.",
      request_id: requestId,
    });
    return;
  }

  next();
}
