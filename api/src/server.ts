// ──────────────────────────────────────────────────────────────
// VulnCenter API — Server Entry Point
// ──────────────────────────────────────────────────────────────

import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { env } from "./lib/env.js";
import { logger } from "./lib/logger.js";
import { connectPrisma, prisma } from "./lib/database.js";
import { redis } from "./lib/queue.js";
import { authPlugin } from "./lib/auth.js";
import { scanRoutes } from "./routes/scans.js";

async function buildServer() {
  const fastify = Fastify({
    logger: env.NODE_ENV !== "production" ? logger : true,
    trustProxy: true,
    bodyLimit: 5 * 1024 * 1024, // 5MB body limit
    requestTimeout: 30000,
  });

  // ─── Plugins ──────────────────────────────────────────

  // Helmet for security headers
  await fastify.register(helmet, {
    contentSecurityPolicy: false, // Allow frontend to load resources
    crossOriginResourcePolicy: { policy: "same-site" },
  });

  // CORS
  await fastify.register(cors, {
    origin: env.CORS_ORIGIN.split(",").map((o) => o.trim()),
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    maxAge: 86400,
  });

  // Rate Limiting
  await fastify.register(rateLimit, {
    max: env.RATE_LIMIT_MAX,
    timeWindow: "1 minute",
    keyGenerator: (request) => {
      return request.ip;
    },
    errorResponseBuilder: () => ({
      success: false,
      error: "Too many requests. Please try again later.",
    }),
  });

  // Auth plugin (JWT)
  await fastify.register(authPlugin);

  // ─── Health Check ─────────────────────────────────────

  fastify.get("/health", async (_request, _reply) => {
    const dbStatus = await prisma
      .$queryRaw`SELECT 1 AS ok`
      .then(() => "healthy" as const)
      .catch(() => "unhealthy" as const);

    const redisStatus = redis.status === "ready" ? ("healthy" as const) : ("unhealthy" as const);

    const healthy = dbStatus === "healthy" && redisStatus === "healthy";

    return {
      status: healthy ? "healthy" : "degraded",
      timestamp: new Date().toISOString(),
      version: "1.0.0",
      services: {
        database: dbStatus,
        redis: redisStatus,
      },
    };
  });

  // API Root
  fastify.get("/api/v1", async () => ({
    name: "VulnCenter API",
    version: "1.0.0",
    endpoints: {
      health: "/health",
      scans: "/api/v1/scans",
      targets: "/api/v1/targets",
      clients: "/api/v1/clients",
      auth: "/api/v1/auth",
    },
  }));

  // ─── Routes ───────────────────────────────────────────

  await fastify.register(scanRoutes);

  // ─── Error Handler ────────────────────────────────────

  fastify.setErrorHandler((error, request, reply) => {
    logger.error(
      {
        err: error,
        method: request.method,
        url: request.url,
        statusCode: error.statusCode ?? 500,
      },
      "Unhandled error"
    );

    // Zod validation errors
    if (error.validation) {
      return reply.status(400).send({
        success: false,
        error: "Validation error",
        details: error.validation.map((v) => v.message),
      });
    }

    // Rate limit errors
    if (error.statusCode === 429) {
      return reply.status(429).send({
        success: false,
        error: "Too many requests",
      });
    }

    // Default error
    const statusCode = error.statusCode ?? 500;
    return reply.status(statusCode).send({
      success: false,
      error:
        statusCode === 500 && env.NODE_ENV === "production"
          ? "Internal server error"
          : error.message,
    });
  });

  // ─── Graceful Shutdown ────────────────────────────────

  const signals: NodeJS.Signals[] = ["SIGINT", "SIGTERM"];
  for (const signal of signals) {
    process.on(signal, async () => {
      logger.info(`Received ${signal}, shutting down gracefully...`);
      await fastify.close();
      await prisma.$disconnect();
      redis.disconnect();
      process.exit(0);
    });
  }

  return fastify;
}

// ─── Start ──────────────────────────────────────────────

async function start() {
  try {
    // Connect to database with retry
    await connectPrisma();

    const server = await buildServer();
    const address = await server.listen({
      port: env.PORT,
      host: env.HOST,
    });

    logger.info(`VulnCenter API running at ${address}`);
    logger.info(`Health check: ${address}/health`);
  } catch (error) {
    logger.fatal({ error }, "Failed to start API server");
    await prisma.$disconnect().catch(() => {});
    process.exit(1);
  }
}

start();