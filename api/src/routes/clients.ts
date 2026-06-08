// ──────────────────────────────────────────────────────────────
// VulnCenter API — Route: v1/clients
// Client management (for SUPER_ADMIN only)
// ──────────────────────────────────────────────────────────────

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { prisma } from "../lib/database.js";
import { logger } from "../lib/logger.js";
import { requireRole, type UserRole } from "../lib/auth.js";

const createClientSchema = z.object({
  name: z.string().min(1).max(255),
  slug: z.string().regex(/^[a-z0-9-]+$/).max(100),
  contactName: z.string().max(255).optional(),
  contactEmail: z.string().email().optional(),
  contactPhone: z.string().max(50).optional(),
});

export async function clientRoutes(fastify: FastifyInstance) {
  // All client endpoints require SUPER_ADMIN role

  // GET /api/v1/clients — List all clients for MSP
  fastify.get(
    "/api/v1/clients",
    {
      preHandler: [fastify.authenticate, requireRole("SUPER_ADMIN")],
    },
    async (request, reply) => {
      const user = request.user!;
      const query = request.query as { page?: number; limit?: number; isActive?: string };

      const page = Math.max(1, query.page ?? 1);
      const limit = Math.min(100, Math.max(1, query.limit ?? 20));
      const skip = (page - 1) * limit;

      const where: Record<string, unknown> = {
        mspTenantId: user.mspTenantId,
      };

      if (query.isActive !== undefined) {
        where.isActive = query.isActive === "true";
      }

      const [clients, total] = await Promise.all([
        prisma.client.findMany({
          where,
          include: {
            _count: { select: { users: true, targets: true, scans: true } },
          },
          orderBy: { createdAt: "desc" },
          skip,
          take: limit,
        }),
        prisma.client.count({ where }),
      ]);

      return reply.send({
        success: true,
        data: clients,
        meta: { page, limit, total, totalPages: Math.ceil(total / limit) },
      });
    }
  );

  // POST /api/v1/clients — Create new client
  fastify.post(
    "/api/v1/clients",
    {
      preHandler: [fastify.authenticate, requireRole("SUPER_ADMIN")],
    },
    async (request, reply) => {
      const user = request.user!;

      const parse = createClientSchema.safeParse(request.body);
      if (!parse.success) {
        return reply.status(400).send({
          success: false,
          error: parse.error.issues.map((i) => i.message).join("; "),
        });
      }

      const { name, slug, contactName, contactEmail, contactPhone } = parse.data;

      // Ensure slug uniqueness within MSP
      const existing = await prisma.client.findFirst({
        where: { mspTenantId: user.mspTenantId, slug },
      });
      if (existing) {
        return reply.status(409).send({ error: "Client with this slug already exists" });
      }

      const client = await prisma.client.create({
        data: {
          mspTenantId: user.mspTenantId,
          name,
          slug,
          contactName,
          contactEmail,
          contactPhone,
        },
      });

      logger.info(
        { clientId: client.id, name, slug, createdBy: user.id },
        "Client created"
      );

      return reply.status(201).send({ success: true, data: client });
    }
  );

  // GET /api/v1/clients/:id
  fastify.get(
    "/api/v1/clients/:id",
    {
      preHandler: [fastify.authenticate, requireRole("SUPER_ADMIN")],
    },
    async (request, reply) => {
      const user = request.user!;
      const { id } = request.params as { id: string };

      const client = await prisma.client.findFirst({
        where: {
          id,
          mspTenantId: user.mspTenantId,
        },
        include: {
          _count: { select: { users: true, targets: true, scans: true } },
          targets: { take: 5, orderBy: { createdAt: "desc" } },
        },
      });

      if (!client) {
        return reply.status(404).send({ error: "Client not found" });
      }

      return reply.send({ success: true, data: client });
    }
  );

  // PUT /api/v1/clients/:id
  fastify.put(
    "/api/v1/clients/:id",
    {
      preHandler: [fastify.authenticate, requireRole("SUPER_ADMIN")],
    },
    async (request, reply) => {
      const user = request.user!;
      const { id } = request.params as { id: string };

      const existing = await prisma.client.findFirst({
        where: {
          id,
          mspTenantId: user.mspTenantId,
        },
      });

      if (!existing) {
        return reply.status(404).send({ error: "Client not found" });
      }

      const parse = createClientSchema.partial().safeParse(request.body);
      if (!parse.success) {
        return reply.status(400).send({
          success: false,
          error: parse.error.issues.map((i) => i.message).join("; "),
        });
      }

      const client = await prisma.client.update({
        where: { id },
        data: parse.data,
      });

      logger.info({ clientId: id, updatedBy: user.id }, "Client updated");
      return reply.send({ success: true, data: client });
    }
  );

  // DELETE /api/v1/clients/:id
  fastify.delete(
    "/api/v1/clients/:id",
    {
      preHandler: [fastify.authenticate, requireRole("SUPER_ADMIN")],
    },
    async (request, reply) => {
      const user = request.user!;
      const { id } = request.params as { id: string };

      // Prevent deletion if there are scans
      const scanCount = await prisma.scan.count({
        where: { clientId: id },
      });

      if (scanCount > 0) {
        return reply.status(400).send({
          error: "Cannot delete client with existing scans",
        });
      }

      await prisma.client.delete({
        where: {
          id,
          mspTenantId: user.mspTenantId,
        },
      });

      logger.info({ clientId: id, deletedBy: user.id }, "Client deleted");
      return reply.send({ success: true, message: "Client deleted" });
    }
  );
}