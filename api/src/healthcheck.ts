// ──────────────────────────────────────────────────────────────
// VulnCenter API — Health Check Server
// Persistent HTTP server for Docker health checks
// ──────────────────────────────────────────────────────────────

import http from "node:http";
import { prisma } from "./database.js";
import { redis } from "./queue.js";
import { logger } from "./logger.js";

const PORT = parseInt(process.env.HEALTH_PORT ?? "8080", 10);
const HOST = "0.0.0.0";

const server = http.createServer(async (_req, res) => {
  try {
    // Check database
    const dbStatus = await prisma
      .$queryRaw`SELECT 1 AS ok`
      .then(() => "healthy" as const)
      .catch(() => "unhealthy" as const);

    // Check Redis
    const redisStatus = redis.status === "ready" ? "healthy" : "unhealthy";

    const isHealthy = dbStatus === "healthy" && redisStatus === "healthy";
    const statusCode = isHealthy ? 200 : 503;

    res.writeHead(statusCode, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: isHealthy ? "healthy" : "degraded",
        timestamp: new Date().toISOString(),
        services: {
          database: dbStatus,
          redis: redisStatus,
        },
      })
    );
  } catch (error) {
    logger.error({ error }, "Health check failed");
    res.writeHead(503, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: "unhealthy",
        timestamp: new Date().toISOString(),
        error: "Health check failed",
      })
    );
  }
});

server.listen(PORT, HOST, () => {
  logger.info(`Health check server listening on ${HOST}:${PORT}`);
});

// Handle shutdown gracefully
process.on("SIGTERM", () => {
  logger.info("Health check server received SIGTERM, shutting down");
  server.close(() => {
    logger.info("Health check server closed");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  logger.info("Health check server received SIGINT, shutting down");
  server.close(() => {
    logger.info("Health check server closed");
    process.exit(0);
  });
});