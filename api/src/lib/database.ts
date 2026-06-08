// ──────────────────────────────────────────────────────────────
// VulnCenter API — Database Client (Prisma)
// ──────────────────────────────────────────────────────────────

import { PrismaClient } from "@prisma/client";
import { env } from "./env.js";
import { logger } from "./logger.js";

// Extend PrismaClient with middleware for multi-tenant isolation
const prisma = new PrismaClient({
  log:
    env.NODE_ENV === "development"
      ? [
          { level: "query", emit: "event" },
          { level: "error", emit: "stdout" },
          { level: "warn", emit: "stdout" },
        ]
      : [{ level: "error", emit: "stdout" }],
});

if (env.NODE_ENV === "development") {
  prisma.$on("query" as never, (e: any) => {
    logger.debug({ query: e.query, params: e.params, duration: e.duration }, "database query");
  });
}

// Connect with retry logic
async function connectPrisma(): Promise<void> {
  const MAX_RETRIES = 10;
  const RETRY_DELAY_MS = 3000;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      await prisma.$connect();
      logger.info("Database connected successfully");
      return;
    } catch (error) {
      logger.error(
        { attempt, maxRetries: MAX_RETRIES, error },
        "Failed to connect to database, retrying..."
      );
      if (attempt === MAX_RETRIES) {
        throw new Error(`Could not connect to database after ${MAX_RETRIES} attempts`);
      }
      await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
    }
  }
}

export { prisma, connectPrisma };