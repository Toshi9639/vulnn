// ──────────────────────────────────────────────────────────────
// VulnCenter Scan Worker — Entry Point (Worker Process)
// Listens to BullMQ queue and executes scans
// ──────────────────────────────────────────────────────────────

import { Worker } from "bullmq";
import { PrismaClient } from "@prisma/client";
import Redis from "ioredis";
import { executeScan } from "./lib/engine.js";
import { logger } from "./lib/logger.js";
import { verifyTools, WORKER_CONFIG } from "./lib/executor.js";
import type { ScanJobData, ScanJobResult } from "./lib/queue.js";

// ─── Database ─────────────────────────────────────────────

const prisma = new PrismaClient();

async function connectDatabase(): Promise<void> {
  for (let attempt = 1; attempt <= 10; attempt++) {
    try {
      await prisma.$connect();
      logger.info("Worker database connected");
      return;
    } catch (error) {
      logger.error({ attempt, error }, "Failed to connect to database, retrying...");
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  throw new Error("Could not connect to database after 10 attempts");
}

// ─── Redis ────────────────────────────────────────────────

const redisUrl = process.env.REDIS_URL ?? "redis://localhost:6379";

function createRedisConnection(): Redis {
  return new Redis(redisUrl, {
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
    retryStrategy: (times: number) => {
      if (times > 10) return null;
      return Math.min(times * 200, 2000);
    },
  });
}

// ─── Health Check Server ──────────────────────────────────

import http from "node:http";

function startHealthServer(): void {
  const port = parseInt(process.env.HEALTH_PORT ?? "8080", 10);
  const server = http.createServer((_req, res) => {
    const healthy = redis.status === "ready";
    res.writeHead(healthy ? 200 : 503, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: healthy ? "healthy" : "degraded",
      timestamp: new Date().toISOString(),
      tools: toolStatus,
    }));
  });
  server.listen(port, "0.0.0.0", () => {
    logger.info(`Health server listening on port ${port}`);
  });
}

// ─── Tool Verification ────────────────────────────────────

let toolStatus: Record<string, boolean> = {};

// ─── Main ─────────────────────────────────────────────────

async function main() {
  logger.info("VulnCenter Scan Worker starting...");

  // Connect database
  await connectDatabase();

  // Verify security tools are available
  toolStatus = verifyTools();
  const missingTools = Object.entries(toolStatus)
    .filter(([, available]) => !available)
    .map(([name]) => name);

  if (missingTools.length > 0) {
    logger.warn({ missingTools }, "Some scanning tools are not available");
  } else {
    logger.info("All scanning tools verified and available");
  }

  // Start health check
  startHealthServer();

  // Create Redis connection for worker
  const connection = createRedisConnection();

  // Create BullMQ Worker
  const worker = new Worker<ScanJobData, ScanJobResult>(
    "scan:queue",
    async (job) => {
      const { data } = job;
      logger.info(
        {
          scanId: data.scanId,
          scanType: data.scanType,
          target: data.targetValue,
          jobId: job.id,
        },
        "Worker processing scan job"
      );

      // Update scan status to RUNNING
      await prisma.scan.update({
        where: { id: data.scanId },
        data: { status: "RUNNING", startedAt: new Date() },
      });

      // Execute the scan
      const result = await executeScan(data);

      logger.info(
        {
          scanId: data.scanId,
          findingCount: result.findings.length,
          status: result.status,
        },
        "Scan execution completed"
      );

      // Persist results to database
      await persistResults(data, result);

      return result;
    },
    {
      connection,
      concurrency: WORKER_CONFIG.maxConcurrentScans,
      lockDuration: WORKER_CONFIG.scanTimeoutMs,
      stalledInterval: 30000,
      maxStalledCount: 3,
      autorun: true,
    }
  );

  worker.on("completed", (job, result) => {
    logger.info(
      { jobId: job.id, scanId: job.data.scanId, findings: result.findings.length },
      "Job completed successfully"
    );
  });

  worker.on("failed", (job, error) => {
    logger.error(
      { jobId: job?.id, scanId: job?.data.scanId, error: error.message },
      "Job failed"
    );

    if (job) {
      // Mark scan as failed in database
      prisma.scan
        .update({
          where: { id: job.data.scanId },
          data: {
            status: "FAILED",
            completedAt: new Date(),
            errorMessage: error.message,
          },
        })
        .catch((dbError) => {
          logger.error({ dbError, scanId: job.data.scanId }, "Failed to update scan status");
        });
    }
  });

  worker.on("error", (error) => {
    logger.error({ error }, "Worker encountered an error");
  });

  // Handle process signals
  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal}, shutting down worker...`);
    await worker.close();
    await prisma.$disconnect();
    connection.disconnect();
    process.exit(0);
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  logger.info(
    {
      concurrency: WORKER_CONFIG.maxConcurrentScans,
      timeoutMs: WORKER_CONFIG.scanTimeoutMs,
    },
    "Scan Worker is ready and listening for jobs"
  );
}

// ─── Persist Results ──────────────────────────────────────

async function persistResults(data: ScanJobData, result: ScanJobResult): Promise<void> {
  try {
    const { findings } = result;
    const severityCounts = {
      criticalFindings: 0,
      highFindings: 0,
      mediumFindings: 0,
      lowFindings: 0,
      infoFindings: 0,
    };

    // Create finding records in batches
    const BATCH_SIZE = 100;
    for (let i = 0; i < findings.length; i += BATCH_SIZE) {
      const batch = findings.slice(i, i + BATCH_SIZE);

      await prisma.finding.createMany({
        data: batch.map((f) => {
          // Track severity counts
          switch (f.severity) {
            case "CRITICAL": severityCounts.criticalFindings++; break;
            case "HIGH": severityCounts.highFindings++; break;
            case "MEDIUM": severityCounts.mediumFindings++; break;
            case "LOW": severityCounts.lowFindings++; break;
            default: severityCounts.infoFindings++; break;
          }

          return {
            scanId: data.scanId,
            clientId: data.clientId,
            source: f.source,
            findingType: f.findingType,
            severity: f.severity,
            title: f.title,
            description: f.description?.slice(0, 10000) ?? null,
            port: f.port ?? null,
            protocol: f.protocol ?? null,
            host: f.host ?? null,
            path: f.path ?? null,
            cveId: f.cveId ?? null,
            cvssScore: f.cvssScore ?? null,
            cvssVector: f.cvssVector ?? null,
            evidence: f.evidence?.slice(0, 50000) ?? null,
            remediation: f.remediation?.slice(0, 5000) ?? null,
            references: f.references ?? null,
            status: "OPEN",
          };
        }),
      });
    }

    // Update scan record
    await prisma.scan.update({
      where: { id: data.scanId },
      data: {
        status: result.status === "FAILED" ? "FAILED" : "COMPLETED",
        completedAt: new Date(),
        totalFindings: findings.length,
        ...severityCounts,
        errorMessage: result.errorMessage ?? null,
        rawOutput: result.rawOutput?.slice(0, 50000) ?? null,
      },
    });

    logger.info(
      {
        scanId: data.scanId,
        findingsCreated: findings.length,
        ...severityCounts,
      },
      "Scan results persisted to database"
    );

    // Create notifications for critical/high findings
    const criticalOrHigh = findings.filter(
      (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
    );

    if (criticalOrHigh.length > 0) {
      await prisma.notification.create({
        data: {
          clientId: data.clientId,
          userId: data.scanId, // Will be replaced with actual user lookup
          title: `Critical findings detected in scan`,
          message: `Scan found ${criticalOrHigh.length} critical/high severity vulnerabilities.`,
          type: "critical_finding",
          link: `/scans/${data.scanId}`,
        },
      });
    }
  } catch (error) {
    logger.error({ error, scanId: data.scanId }, "Failed to persist scan results");
    throw error;
  }
}

// ─── Startup ──────────────────────────────────────────────

main().catch((error) => {
  logger.fatal({ error }, "Worker failed to start");
  process.exit(1);
});