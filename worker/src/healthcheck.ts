// ──────────────────────────────────────────────────────────────
// VulnCenter Worker — Health Check
// ──────────────────────────────────────────────────────────────

import http from "node:http";

const port = parseInt(process.env.HEALTH_PORT ?? "8080", 10);

const server = http.createServer((_req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "healthy", timestamp: new Date().toISOString() }));
});

server.listen(port, "0.0.0.0", () => {
  console.log("Health check OK");
  process.exit(0);
});