// ──────────────────────────────────────────────────────────────
// VulnCenter API — Auth / JWT Utilities
// ──────────────────────────────────────────────────────────────

import type { FastifyInstance, FastifyRequest } from "fastify";
import type { JWT } from "@fastify/jwt";
import { env } from "./env.js";

// Extend Fastify type to include authenticate decorator
declare module "fastify" {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

// Extend FastifyRequest for user context
declare module "@fastify/jwt" {
  interface FastifyJWT {
    user: {
      id: string;
      email: string;
      role: "SUPER_ADMIN" | "CLIENT_ADMIN" | "CLIENT_VIEWER";
      mspTenantId: string;
      clientId?: string | null;
    };
  }
}

// ─── Auth Plugin ──────────────────────────────────────────

import fp from "fastify-plugin";
import fjwt from "@fastify/jwt";
import type { FastifyReply } from "./types.js";

export const authPlugin = fp(async (fastify: FastifyInstance) => {
  Validate CORS_ORIGIN in production
  if (process.env.NODE_ENV === "production" && process.env.CORS_ORIGIN === "*") {
    throw new Error("CORS_ORIGIN cannot be '*' in production. Set explicit origins.");
  }

  // Register JWT
  await fastify.register(fjwt, {
    secret: env.JWT_SECRET,
    sign: {
      expiresIn: env.JWT_EXPIRY,
    },
    verify: {
      extractToken: (request) => {
        // Check Authorization header first
        const authHeader = request.headers.authorization;
        if (authHeader?.startsWith("Bearer ")) {
          return authHeader.slice(7);
        }
        // Then check cookie
        const token = request.cookies?.token;
        return token ?? null;
      },
    },
  });

  // Decorate authenticate
  fastify.decorate(
    "authenticate",
    async function (request: FastifyRequest, reply: FastifyReply) {
      try {
        await request.jwtVerify();
      } catch (err) {
        reply.status(401).send({
          error: "Unauthorized",
          message: "Invalid or expired token",
        });
      }
    }
  );
});

// ─── RBAC Authorization Helpers ───────────────────────────

export type UserRole = "SUPER_ADMIN" | "CLIENT_ADMIN" | "CLIENT_VIEWER";

const roleHierarchy: Record<UserRole, number> = {
  SUPER_ADMIN: 100,
  CLIENT_ADMIN: 50,
  CLIENT_VIEWER: 10,
};

export function hasRole(userRole: UserRole, requiredRole: UserRole): boolean {
  return roleHierarchy[userRole] >= roleHierarchy[requiredRole];
}

export function requireRole(requiredRole: UserRole) {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const user = request.user;
    if (!user || !hasRole(user.role, requiredRole)) {
      reply.status(403).send({
        error: "Forbidden",
        message: `Requires at least ${requiredRole} role`,
      });
    }
  };
}

// ─── Tenant Scoping Helper ────────────────────────────────

export function getTenantScope(
  user: { role: UserRole; mspTenantId: string; clientId?: string | null },
  requestedClientId?: string
): { mspTenantId: string; clientId?: string } {
  // SUPER_ADMIN can see all clients in their MSP
  if (user.role === "SUPER_ADMIN") {
    return {
      mspTenantId: user.mspTenantId,
      clientId: requestedClientId,
    };
  }

  // CLIENT_ADMIN and CLIENT_VIEWER are scoped to their client
  return {
    mspTenantId: user.mspTenantId,
    clientId: user.clientId ?? undefined,
  };
}