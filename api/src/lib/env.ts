// ──────────────────────────────────────────────────────────────
// VulnCenter API — Environment Configuration
// ──────────────────────────────────────────────────────────────

import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.coerce.number().default(8000),
  HOST: z.string().default("0.0.0.0"),

  // Database
  DATABASE_URL: z.string().url(),

  // Redis / Queue
  REDIS_URL: z.string(),

  // Auth
  JWT_SECRET: z.string().min(32),
  JWT_EXPIRY: z.string().default("24h"),

  // CORS - require explicit origins in production
  CORS_ORIGIN: env.NODE_ENV === "production" 
    ? z.string().refine(s => s !== "*", "CORS_ORIGIN cannot be '*' in production")
    : z.string().default("*"),

  // Rate Limiting
  RATE_LIMIT_MAX: z.coerce.number().default(100),

  // Logging
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),
});

function validateEnv() {
  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    console.error("❌ Invalid environment variables:", result.error.flatten().fieldErrors);
    process.exit(1);
  }
  return result.data;
}

export const env = validateEnv();
export type Env = z.infer<typeof envSchema>;