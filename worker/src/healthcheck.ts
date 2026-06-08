// ──────────────────────────────────────────────────────────────
// VulnCenter Worker — Health Check Server
// Persistent HTTP server for Docker health checks
// ──────────────────────────────────────────────────────────────

import http from "node:http";
import { logger } from "./lib/logger.js";
import { verifyTools } from "./lib/executor.js";

const PORT = parseInt(process.env.HEALTH_PORT ?? "8080", 10);
const HOST = "0.0.0.0";

const server = http.createServer((_req, res) => {
  try {
    const toolStatus = verifyTools();
    const allToolsReady = Object.values(toolStatus).every((status) => status);
    const statusCode = allToolsReady ? 200 : 503;

    res.writeHead(statusCode, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: allToolsReady ? "healthy" : "degraded",
        timestamp: new Date().toISOString(),
        tools: toolStatus,
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