/**
 * Lightweight in-memory fixed-window rate limiter for /api/analyze.
 *
 * Configuration (read from environment at request time):
 *   RATE_LIMIT_MAX         — max requests per window per IP (default: 60)
 *   RATE_LIMIT_WINDOW_MS   — window duration in milliseconds (default: 60000)
 *
 * Each unique client IP gets its own fixed window. When the window expires
 * the counter resets automatically on the next request.
 *
 * Returns 429 with a Retry-After header when the limit is exceeded.
 *
 * Call resetRateLimiter() between tests to clear the in-memory state.
 */

import { type Request, type Response, type NextFunction } from "express";
import { logger } from "../lib/logger.js";

interface WindowState {
  count: number;
  windowStart: number;
}

// Module-level store — reset between tests via resetRateLimiter().
let store = new Map<string, WindowState>();

export function resetRateLimiter(): void {
  store = new Map();
}

function getClientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0]!.trim();
  return req.socket?.remoteAddress ?? "unknown";
}

export function analyzeRateLimiter(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const maxRequests = parseInt(process.env["RATE_LIMIT_MAX"] ?? "60", 10);
  const windowMs = parseInt(process.env["RATE_LIMIT_WINDOW_MS"] ?? "60000", 10);

  const ip = getClientIp(req);
  const now = Date.now();
  const existing = store.get(ip);

  if (!existing || now - existing.windowStart >= windowMs) {
    store.set(ip, { count: 1, windowStart: now });
    next();
    return;
  }

  if (existing.count >= maxRequests) {
    const retryAfterMs = windowMs - (now - existing.windowStart);
    const retryAfterSec = Math.ceil(retryAfterMs / 1000);
    logger.warn(
      { ip, count: existing.count, retry_after_sec: retryAfterSec },
      "rate_limit_exceeded",
    );
    res.setHeader("Retry-After", String(retryAfterSec));
    res.status(429).json({
      error: "rate_limit_exceeded",
      detail: `Too many requests. Limit is ${maxRequests} per ${windowMs / 1000}s. Try again in ${retryAfterSec}s.`,
      retry_after_seconds: retryAfterSec,
    });
    return;
  }

  existing.count++;
  next();
}
