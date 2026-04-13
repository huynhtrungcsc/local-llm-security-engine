/**
 * Configuration for the SOC API Server.
 *
 * Provider modes:
 *   local_security_engine  — forward analysis requests to a Local LLM Security Engine.
 *                            Local development: LOCAL_LLM_ENGINE_BASE_URL=http://localhost:8000
 *                            (no tunnel needed when both services run on the same machine).
 *                            Remote deployment: use a Cloudflare Tunnel URL so the
 *                            remote server can reach the local engine.
 *   none                   — no LLM provider configured; /api/analyze returns 503
 *
 * The active mode is determined automatically:
 *   - If LOCAL_LLM_ENGINE_BASE_URL is set → local_security_engine
 *   - Otherwise                           → none
 *
 * Set PROVIDER_MODE explicitly to override this detection.
 */

export type ProviderMode = "local_security_engine" | "none";

export interface Config {
  providerMode: ProviderMode;
  localEngine: {
    baseUrl: string | null;
    apiKey: string | null;
    timeoutMs: number;
  };
}

function resolveProviderMode(baseUrl: string | null): ProviderMode {
  const explicit = process.env["PROVIDER_MODE"]?.trim().toLowerCase();
  if (explicit === "local_security_engine") return "local_security_engine";
  if (explicit === "none") return "none";
  // Auto-detect: if the URL is set, assume local_security_engine
  return baseUrl ? "local_security_engine" : "none";
}

export function loadConfig(): Config {
  const baseUrl = process.env["LOCAL_LLM_ENGINE_BASE_URL"]?.trim().replace(/\/$/, "") || null;
  const apiKey = process.env["LOCAL_LLM_ENGINE_API_KEY"]?.trim() || null;
  const timeoutMs = parseInt(process.env["LOCAL_LLM_ENGINE_TIMEOUT_MS"] ?? "90000", 10);

  const providerMode = resolveProviderMode(baseUrl);

  if (providerMode === "local_security_engine" && !baseUrl) {
    throw new Error(
      "PROVIDER_MODE=local_security_engine requires LOCAL_LLM_ENGINE_BASE_URL to be set.",
    );
  }

  return {
    providerMode,
    localEngine: {
      baseUrl,
      apiKey,
      timeoutMs: isNaN(timeoutMs) ? 90000 : timeoutMs,
    },
  };
}

// Singleton — loaded once at startup, shared across the process
let _config: Config | null = null;

export function getConfig(): Config {
  if (!_config) {
    _config = loadConfig();
  }
  return _config;
}

/** Reset the singleton (for testing). */
export function resetConfig(): void {
  _config = null;
}
