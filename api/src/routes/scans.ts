// ──────────────────────────────────────────────────────────────
// VulnCenter API — Route: v1/scans
// Scan management endpoints
// ──────────────────────────────────────────────────────────────

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { prisma } from "../lib/database.js";
import { scanQueue, enqueueScan } from "../lib/queue.js";
import { logger } from "../lib/logger.js";
import {
  getTenantScope,
  hasRole,
  requireRole,
  type UserRole,
} from "../lib/auth.js";
import { validateTarget, VALID_SCAN_TYPES } from "../lib/types.js";
import type { ScanJobData } from "../lib/queue.js";

// ─── Schemas ──────────────────────────────────────────────

const createScanSchema = z.object({
  targetId: z.string().min(1, "Target ID is required"),
  scanType: z.enum(VALID_SCAN_TYPES),
  config: z.record(z.unknown()).optional(),
});

export async function scanRoutes(fastify: FastifyInstance) {
  // ════════════════════════════════════════════════════════
  // POST /api/v1/scans — Trigger a new scan
  // ════════════════════════════════════════════════════════
  fastify.post(
    "/api/v1/scans",
    {
      preHandler: [fastify.authenticate],
      schema: {
        description: "Trigger a new vulnerability scan against a target",
        tags: ["scans"],
        body: {
          type: "object",
          required: ["targetId", "scanType"],
          properties: {
            targetId: { type: "string" },
            scanType: { type: "string", enum: VALID_SCAN_TYPES },
            config: { type: "object" },
          },
        },
        response: {
          201: {
            type: "object",
            properties: {
              success: { type: "boolean" },
              data: { type: "object" },
              message: { type: "string" },
            },
          },
          400: {
            type: "object",
            properties: {
              success: { type: "boolean" },
              error: { type: "string" },
            },
          },
          403: { type: "object", properties: { error: { type: "string" } } },
          404: { type: "object", properties: { error: { type: "string" } } },
        },
      },
    },
    async (request, reply) => {
      const user = request.user;
      if (!user) {
        return reply.status(401).send({ error: "Unauthorized" });
      }

      // Parse and validate request body
      const parseResult = createScanSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          success: false,
          error: parseResult.error.issues.map((i) => i.message).join("; "),
        });
      }

      const { targetId, scanType, config } = parseResult.data;

      // Get tenant scope
      const scope = getTenantScope(user);

      // Fetch and verify target exists within tenant scope
      const target = await prisma.target.findFirst({
        where: {
          id: targetId,
          client: {
            mspTenantId: scope.mspTenantId,
            ...(scope.clientId ? { id: scope.clientId } : {}),
          },
        },
      });

      if (!target) {
        return reply.status(404).send({
          success: false,
          error: "Target not found or not accessible in your tenant scope",
        });
      }

      // Verify target is in a scannable state
      if (target.status === "DISABLED") {
        return reply.status(400).send({
          success: false,
          error: "Target is disabled. Enable it before scanning.",
        });
      }

      if (target.status === "UNVERIFIED") {
        return reply.status(400).send({
          success: false,
          error:
            "Target must be verified before scanning. Accept the ownership disclaimer first.",
        });
      }

      // Validate target value for scan (safety check)
      const targetValidation = validateTarget(target.type, target.value);
      if (!targetValidation.valid) {
        return reply.status(400).send({
          success: false,
          error: `Target validation failed: ${targetValidation.error}`,
        });
      }

      // Create scan record in database
      const scan = await prisma.scan.create({
        data: {
          clientId: target.clientId,
          targetId: target.id,
          scanType,
          status: "PENDING",
          config: config ?? {},
          triggeredBy: user.id,
        },
      });

      logger.info(
        {
          scanId: scan.id,
          targetId: target.id,
          targetValue: target.value,
          scanType,
          triggeredBy: user.id,
          clientId: target.clientId,
        },
        "Scan created, enqueuing job"
      );

      // Enqueue the scan job to Redis/BullMQ
      const jobData: ScanJobData = {
        scanId: scan.id,
        clientId: target.clientId,
        targetId: target.id,
        targetValue: target.value,
        targetType: target.type,
        scanType,
        config: config ?? {},
        ports: target.ports ?? undefined,
      };

      try {
        const jobId = await enqueueScan(jobData);

        // Update scan status to QUEUED
        await prisma.scan.update({
          where: { id: scan.id },
          data: { status: "QUEUED" },
        });

        return reply.status(201).send({
          success: true,
          data: {
            scanId: scan.id,
            jobId,
            status: "QUEUED",
            target: target.value,
            scanType,
            createdAt: scan.createdAt,
          },
          message: "Scan queued successfully",
        });
      } catch (error) {
        logger.error({ error, scanId: scan.id }, "Failed to enqueue scan job");

        // Mark scan as failed
        await prisma.scan.update({
          where: { id: scan.id },
          data: {
            status: "FAILED",
            errorMessage: "Failed to queue scan job",
          },
        });

        return reply.status(500).send({
          success: false,
          error: "Failed to queue scan. Please try again.",
        });
      }
    }
  );

  // ════════════════════════════════════════════════════════
  // GET /api/v1/scans — List scans for tenant
  // ════════════════════════════════════════════════════════
  fastify.get(
    "/api/v1/scans",
    {
      preHandler: [fastify.authenticate],
      schema: {
        description: "List scans for the authenticated tenant",
        tags: ["scans"],
        querystring: {
          type: "object",
          properties: {
            status: { type: "string" },
            scanType: { type: "string" },
            targetId: { type: "string" },
            page: { type: "integer", default: 1 },
            limit: { type: "integer", default: 20 },
          },
        },
      },
    },
    async (request, reply) => {
      const user = request.user;
      if (!user) return reply.status(401).send({ error: "Unauthorized" });

      const scope = getTenantScope(user);
      const query = request.query as {
        status?: string;
        scanType?: string;
        targetId?: string;
        page?: number;
        limit?: number;
      };

      const page = Math.max(1, query.page ?? 1);
      const limit = Math.min(100, Math.max(1, query.limit ?? 20));
      const skip = (page - 1) * limit;

      const where: Record<string, unknown> = {
        client: {
          mspTenantId: scope.mspTenantId,
          ...(scope.clientId ? { id: scope.clientId } : {}),
        },
      };

      if (query.status) where.status = query.status;
      if (query.scanType) where.scanType = query.scanType;
      if (query.targetId) where.targetId = query.targetId;

      const [scans, total] = await Promise.all([
        prisma.scan.findMany({
          where,
          include: {
            target: {
              select: { value: true, type: true, label: true },
            },
          },
          orderBy: { createdAt: "desc" },
          skip,
          take: limit,
        }),
        prisma.scan.count({ where }),
      ]);

      return reply.send({
        success: true,
        data: scans,
        meta: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
        },
      });
    }
  );

  // ════════════════════════════════════════════════════════
  // GET /api/v1/scans/:id — Get scan details with findings
  // ════════════════════════════════════════════════════════
  fastify.get(
    "/api/v1/scans/:id",
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      const user = request.user;
      if (!user) return reply.status(401).send({ error: "Unauthorized" });

      const { id } = request.params as { id: string };
      const scope = getTenantScope(user);

      const scan = await prisma.scan.findFirst({
        where: {
          id,
          client: {
            mspTenantId: scope.mspTenantId,
            ...(scope.clientId ? { id: scope.clientId } : {}),
          },
        },
        include: {
          target: true,
          findings: {
            orderBy: [
              { severity: "asc" },
              { createdAt: "desc" },
            ],
          },
        },
      });

      if (!scan) {
        return reply.status(404).send({
          success: false,
          error: "Scan not found",
        });
      }

      return reply.send({
        success: true,
        data: scan,
      });
    }
  );

  // ════════════════════════════════════════════════════════
  // POST /api/v1/scans/:id/cancel — Cancel a running scan
  // ════════════════════════════════════════════════════════
  fastify.post(
    "/api/v1/scans/:id/cancel",
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      const user = request.user;
      if (!user) return reply.status(401).send({ error: "Unauthorized" });

      const { id } = request.params as { id: string };
      const scope = getTenantScope(user);

      const scan = await prisma.scan.findFirst({
        where: {
          id,
          client: {
            mspTenantId: scope.mspTenantId,
            ...(scope.clientId ? { id: scope.clientId } : {}),
          },
        },
      });

      if (!scan) {
        return reply.status(404).send({ error: "Scan not found" });
      }

      if (!["PENDING", "QUEUED", "RUNNING"].includes(scan.status)) {
        return reply.status(400).send({
          error: `Cannot cancel scan in '${scan.status}' state`,
        });
      }

      // Remove from BullMQ queue if pending
      try {
        const job = await scanQueue.getJob(`scan:${scan.id}`);
        if (job && (await job.isWaiting() || await job.isActive())) {
          await job.remove();
        }
      } catch (err) {
        logger.warn({ err, scanId: scan.id }, "Error removing BullMQ job");
      }

      // Update database
      await prisma.scan.update({
        where: { id },
        data: { status: "CANCELLED" },
      });

      logger.info({ scanId: scan.id, cancelledBy: user.id }, "Scan cancelled");

      return reply.send({
        success: true,
        message: "Scan cancelled successfully",
      });
    }
  );
}