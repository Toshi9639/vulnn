// ──────────────────────────────────────────────────────────────
// VulnCenter API — Route: v1/targets
// Target management endpoints
// ──────────────────────────────────────────────────────────────

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { prisma } from "../lib/database.js";
import { logger } from "../lib/logger.js";
import { getTenantScope, requireRole } from "../lib/auth.js";
import { validateTarget, type ValidTargetType } from "../lib/types.js";

const createTargetSchema = z.object({
  type: z.enum(["IP", "CIDR", "FQDN", "URL"]),
  value: z.string().min(1),
  label: z.string().max(255).optional(),
  ports: z.string().max(255).optional(),
  tags: z.array(z.string()).optional(),
  notes: z.string().optional(),
});

export async function targetRoutes(fastify: FastifyInstance) {
  // POST /api/v1/targets — Create target
  fastify.post(
    "/api/v1/targets",
    {
      preHandler: [fastify.authenticate],
      schema: {
        description: "Create a new scan target",
        body: {
          type: "object",
          required: ["type", "value"],
          properties: {
            type: { type: "string", enum: ["IP", "CIDR", "FQDN", "URL"] },
            value: { type: "string" },
            label: { type: "string" },
            ports: { type: "string" },
            tags: { type: "array", items: { type: "string" } },
            notes: { type: "string" },
          },
        },
      },
    },
    async (request, reply) => {
      const user = request.user;
      if (!user) return reply.status(401).send({ error: "Unauthorized" });

      const parse = createTargetSchema.safeParse(request.body);
      if (!parse.success) {
        return reply.status(400).send({
          success: false,
          error: parse.error.issues.map((i) => i.message).join("; "),
        });
      }

      const { type, value, label, ports, tags, notes } = parse.data;
      const validation = validateTarget(type, value);
      if (!validation.valid) {
        return reply.status(400).send({
          success: false,
          error: validation.error,
        });
      }

      // SUPER_ADMIN must select a client; CLIENT roles use own clientId
      const scope = getTenantScope(user, undefined);
      if (user.role === "SUPER_ADMIN") {
        return reply.status(400).send({
          success: false,
          error: "Super admins must specify clientId to create targets",
        });
      }

      // Check for duplicate target within same client
      const existing = await prisma.target.findFirst({
        where: {
          clientId: user.clientId!,
          value: validation.sanitized,
        },
      });
      if (existing) {
        return reply.status(409).send({
          success: false,
          error: "Target already exists for this client",
        });
      }

      const target = await prisma.target.create({
        data: {
          clientId: user.clientId!,
          type,
          value: validation.sanitized,
          label,
          ports,
          tags,
          notes,
          status: "UNVERIFIED",
          createdBy: user.id,
        },
      });

      logger.info(
        { targetId: target.id, clientId: user.clientId, target: validation.sanitized },
        "Target created"
      );

      return reply.status(201).send({ success: true, data: target });
    }
  );

  // GET /api/v1/targets — List targets
  fastify.get(
    "/api/v1/targets",
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      const user = request.user;
      if (!user) return reply.status(401).send({ error: "Unauthorized" });

      const scope = getTenantScope(user);
      const query = request.query as {
        status?: string;
        type?: string;
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
      if (query.type) where.type = query.type;

      const [targets, total] = await Promise.all([
        prisma.target.findMany({
          where,
          include: {
            client: { select: { name: true, slug: true } },
            _count: { select: { scans: true } },
          },
          orderBy: { createdAt: "desc" },
          skip,
          take: limit,
        }),
        prisma.target.count({ where }),
      ]);

      return reply.send({
        success: true,
        data: targets,
        meta: { page, limit, total, totalPages: Math.ceil(total / limit) },
      });
    }
  );

  // PUT /api/v1/targets/:id — Verify/accept disclaimer
  fastify.put(
    "/api/v1/targets/:id/verify",
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      const user = request.user;
      if (!user) return reply.status(401).send({ error: "Unauthorized" });

      const { id } = request.params as { id: string };
      const scope = getTenantScope(user);

      const target = await prisma.target.findFirst({
        where: {
          id,
          client: {
            mspTenantId: scope.mspTenantId,
            ...(scope.clientId ? { id: scope.clientId } : {}),
          },
        },
      });

      if (!target) {
        return reply.status(404).send({ error: "Target not found" });
      }

      if (target.status !== "UNVERIFIED") {
        return reply.status(400).send({
          error: `Target is already ${target.status}. Only UNVERIFIED targets can be verified.`,
        });
      }

      // Mark as verified (ownership/scope disclaimer accepted)
      const updated = await prisma.target.update({
        where: { id },
        data: {
          status: "VERIFIED",
          verifiedAt: new Date(),
          verifiedBy: user.id,
          disclaimerAcceptedAt: new Date(),
        },
      });

      logger.info({ targetId: id, verifiedBy: user.id }, "Target verified");

      return reply.send({ success: true, data: updated });
    }
  );

  // DELETE /api/v1/targets/:id
  fastify.delete(
    "/api/v1/targets/:id",
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      const user = request.user;
      if (!user) return reply.status(401).send({ error: "Unauthorized" });

      const { id } = request.params as { id: string };
      const scope = getTenantScope(user);

      const target = await prisma.target.findFirst({
        where: {
          id,
          client: {
            mspTenantId: scope.mspTenantId,
            ...(scope.clientId ? { id: scope.clientId } : {}),
          },
        },
      });

      if (!target) {
        return reply.status(404).send({ error: "Target not found" });
      }

      // Prevent deletion if active scans exist
      const activeScans = await prisma.scan.count({
        where: {
          targetId: id,
          status: { in: ["PENDING", "QUEUED", "RUNNING"] },
        },
      });

      if (activeScans > 0) {
        return reply.status(400).send({
          error: "Cannot delete target with active scans. Cancel scans first.",
        });
      }

      await prisma.target.delete({ where: { id } });
      logger.info({ targetId: id, deletedBy: user.id }, "Target deleted");

      return reply.send({ success: true, message: "Target deleted" });
    }
  );
}