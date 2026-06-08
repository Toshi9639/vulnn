// ──────────────────────────────────────────────────────────────
// VulnCenter API — Redis / Queue Connection
// ──────────────────────────────────────────────────────────────

import Redis from "ioredis";
import { Queue, Worker, type QueueOptions, type WorkerOptions } from "bullmq";
import { env } from "./env.js";
import { logger } from "./logger.js";

const connectionUrl = new URL(env.REDIS_URL);

// Redis connection for general use
export const redis = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck: true,
  retryStrategy: (times: number) => {
    if (times > 10) {
      logger.error("Redis max retries reached");
      return null;
    }
    return Math.min(times * 200, 2000);
  },
});

redis.on("connect", () => logger.info("Redis connected"));
redis.on("error", (err) => logger.error({ err }, "Redis error"));

// BullMQ queue connection options
const queueConnection = {
  connection: new Redis(env.REDIS_URL, {
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
  }),
} satisfies QueueOptions;

// ─── Scan Queue ───────────────────────────────────────────
export const scanQueue = new Queue("scan:queue", {
  ...queueConnection,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: "exponential",
      delay: 10000,
    },
    removeOnComplete: {
      age: 3600 * 24 * 7, // Keep completed jobs for 7 days
      count: 1000,
    },
    removeOnFail: {
      age: 3600 * 24 * 30, // Keep failed jobs for 30 days
      count: 5000,
    },
  },
});

// ─── Job Types ────────────────────────────────────────────

export type ScanJobData = {
  scanId: string;
  clientId: string;
  targetId: string;
  targetValue: string;
  targetType: "IP" | "CIDR" | "FQDN" | "URL";
  scanType: "NMAP_QUICK" | "NMAP_FULL" | "NUCLEI_CVE" | "NUCLEI_WEB" | "NIKTO_WEB" | "TESTSSL";
  config: Record<string, unknown>;
  ports?: string;
};

export type ScanJobResult = {
  scanId: string;
  status: "COMPLETED" | "FAILED" | "PARTIAL";
  findings: Array<{
    source: string;
    findingType: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
    title: string;
    description?: string;
    port?: number;
    protocol?: string;
    host?: string;
    path?: string;
    cveId?: string;
    cvssScore?: number;
    cvssVector?: string;
    evidence?: string;
    remediation?: string;
    references?: string[];
  }>;
  errorMessage?: string;
  rawOutput?: string;
};

// ─── Helper Functions ────────────────────────────────────

export async function enqueueScan(jobData: ScanJobData): Promise<string> {
  const job = await scanQueue.add("nmap-scan", jobData, {
    jobId: `scan:${jobData.scanId}`,
    priority: getPriority(jobData.scanType),
  });
  logger.info({ scanId: jobData.scanId, scanType: jobData.scanType }, "Scan job enqueued");
  return job.id as string;
}

function getPriority(scanType: ScanJobData["scanType"]): number {
  // Lower number = higher priority
  switch (scanType) {
    case "NMAP_QUICK":
      return 1;
    case "NUCLEI_CVE":
      return 2;
    case "NMAP_FULL":
      return 3;
    case "NIKTO_WEB":
      return 4;
    case "TESTSSL":
      return 4;
    default:
      return 5;
  }
}

export async function getQueueMetrics() {
  const [waiting, active, completed, failed, delayed] = await Promise.all([
    scanQueue.getWaitingCount(),
    scanQueue.getActiveCount(),
    scanQueue.getCompletedCount(),
    scanQueue.getFailedCount(),
    scanQueue.getDelayedCount(),
  ]);
  return { waiting, active, completed, failed, delayed };
}