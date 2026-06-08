// ──────────────────────────────────────────────────────────────
// VulnCenter API — Route: v1/reports
// Report generation endpoints
// ──────────────────────────────────────────────────────────────

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { prisma } from "../lib/database.js";
import { logger } from "../lib/logger.js";
import { getTenantScope } from "../lib/auth.js";

const generateReportSchema = z.object({
  scanId: z.string().optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  format: z.enum(["pdf", "json"]).default("json"),
});

export async function reportRoutes(fastify: FastifyInstance) {
  // GET /api/v1/reports — List reports
  fastify.get(
    "/api/v1/reports",
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      const user = request.user!;
      const scope = getTenantScope(user);
      const query = request.query as {
        page?: number;
        limit?: number;
        status?: string;
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

      const [reports, total] = await Promise.all([
        prisma.report.findMany({
          where,
          include: {
            scan: {
              select: { id: true, scanType: true, status: true, createdAt: true },
            },
            client: { select: { name: true } },
          },
          orderBy: { createdAt: "desc" },
          skip,
          take: limit,
        }),
        prisma.report.count({ where }),
      ]);

      return reply.send({
        success: true,
        data: reports,
        meta: { page, limit, total, totalPages: Math.ceil(total / limit) },
      });
    }
  );

  // POST /api/v1/reports/generate — Generate new report
  fastify.post(
    "/api/v1/reports/generate",
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      const user = request.user!;
      const scope = getTenantScope(user);
      const parse = generateReportSchema.safeParse(request.body);
      if (!parse.success) {
        return reply.status(400).send({
          success: false,
          error: parse.error.issues.map((i) => i.message).join("; "),
        });
      }

      const { scanId, startDate, endDate, format } = parse.data;

      // Create report record
      const report = await prisma.report.create({
        data: {
          clientId: user.clientId ?? scope.clientId!,
          scanId,
          title: scanId
            ? `Scan Report - ${scanId.slice(0, 8)}...`
            : `Client Summary - ${new Date().toISOString().slice(0, 10)}`,
          reportType: scanId ? "SCAN_SUMMARY" : "CLIENT_MONTHLY",
          status: "GENERATING",
          config: { startDate, endDate, format },
          generatedBy: user.id,
        },
      });

      // TODO: Enqueue PDF generation job to a separate queue
      // For now, we'll just return the report ID
      logger.info(
        { reportId: report.id, scanId, format },
        "Report generation started (async)"
      );

      return reply.status(202).send({
        success: true,
        data: { reportId: report.id, status: "GENERATING" },
        message: "Report generation started. Poll /api/v1/reports/:id for status.",
      });
    }
  );

  // GET /api/v1/reports/:id
  fastify.get(
    "/api/v1/reports/:id",
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      const user = request.user!;
      const { id } = request.params as { id: string };

      const report = await prisma.report.findFirst({
        where: {
          id,
          client: {
            mspTenantId: user.mspTenantId,
            ...(user.clientId ? { id: user.clientId } : {}),
          },
        },
        include: {
          scan: {
            select: { id: true, status: true, totalFindings: true },
          },
        },
      });

      if (!report) {
        return reply.status(404).send({ error: "Report not found" });
      }

      return reply.send({ success: true, data: report });
    }
  );

  // GET /api/v1/reports/:id/download
  fastify.get(
    "/api/v1/reports/:id/download",
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      const user = request.user!;
      const { id } = request.params as { id: string };

      const report = await prisma.report.findFirst({
        where: {
          id,
          client: {
            mspTenantId: user.mspTenantId,
            ...(user.clientId ? { id: user.clientId } : {}),
          },
        },
      });

      if (!report) {
        return reply.status(404).send({ error: "Report not found" });
      }

      if (report.status !== "READY" || !report.pdfPath) {
        return reply.status(400).send({
          error: "Report not ready for download. Check status first.",
        });
      }

      // TODO: actually read and stream the PDF file
      return reply.code(501).send({
        error: "PDF storage/download not implemented in MVP",
      });
    }
  );
}