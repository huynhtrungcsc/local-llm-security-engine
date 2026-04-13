/**
 * Environment variable loader — MUST be the first import in src/index.ts.
 *
 * Loads .env.local first (development), then .env (production convenience).
 * Variables already present in process.env are NOT overridden — so env vars
 * set by the OS, systemd, or NSSM always take priority over .env files.
 *
 * For production deployments: set PORT and all other env vars through the
 * OS / service manager. You do not need .env files in production.
 */
import { config } from "dotenv";
import { fileURLToPath } from "url";
import { resolve, dirname } from "path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
config({ path: resolve(root, ".env.local") });
config({ path: resolve(root, ".env") });
