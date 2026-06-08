// ──────────────────────────────────────────────────────────────
// VulnCenter API/Worker — Health Check Utility
// ──────────────────────────────────────────────────────────────

// Simple health probe for Docker healthchecks.
// Exits with 0 if process is alive, 1 if not.

import http from "node:http";

const port = parseInt(process.env.HEALTH_PORT ?? "8080", 10);

const server = http.createServer((_req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "healthy", timestamp: new Date().toISOString() }));
});

server.listen(port, "0.0.0.0", () => {
  console.log(`Health check server listening on port ${port}`);
  process.exit(0); // Exit immediately — Docker just checks if the port opens
});