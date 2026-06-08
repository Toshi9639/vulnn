// ──────────────────────────────────────────────────────────────
// VulnCenter API — Shared Types
// ──────────────────────────────────────────────────────────────

import type { FastifyReply as FR, FastifyRequest as FReq } from "fastify";

export type FastifyReply = FR;
export type FastifyRequest = FReq;

// ─── API Response Wrappers ───────────────────────────────

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  meta?: {
    page?: number;
    limit?: number;
    total?: number;
    totalPages?: number;
  };
}

export function successResponse<T>(data: T, message?: string): ApiResponse<T> {
  return { success: true, data, message };
}

export function errorResponse(error: string): ApiResponse {
  return { success: false, error };
}

// ─── Scan Types ──────────────────────────────────────────

export const VALID_SCAN_TYPES = [
  "NMAP_QUICK",
  "NMAP_FULL",
  "NUCLEI_CVE",
  "NUCLEI_WEB",
  "NIKTO_WEB",
  "TESTSSL",
] as const;

export type ValidScanType = (typeof VALID_SCAN_TYPES)[number];

export const TARGET_TYPES = ["IP", "CIDR", "FQDN", "URL"] as const;
export type ValidTargetType = (typeof TARGET_TYPES)[number];

// ─── Target Validation ───────────────────────────────────

export function validateTarget(
  type: ValidTargetType,
  value: string
): { valid: boolean; sanitized: string; error?: string } {
  const sanitized = value.trim().toLowerCase();

  switch (type) {
    case "IP": {
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (!ipv4Regex.test(sanitized)) {
        return { valid: false, sanitized, error: "Invalid IPv4 address format" };
      }
      const parts = sanitized.split(".").map(Number);
      if (parts.some((p) => p > 255)) {
        return { valid: false, sanitized, error: "IP octet exceeds 255" };
      }
      // Block private/reserved IPs from being scanned (unless overridden)
      if (
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) ||
        (parts[0] === 192 && parts[1] === 168) ||
        parts[0] === 127 ||
        parts[0] === 0
      ) {
        return { valid: false, sanitized, error: "Private/reserved IP cannot be scanned" };
      }
      return { valid: true, sanitized };
    }

    case "CIDR": {
      const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
      if (!cidrRegex.test(sanitized)) {
        return { valid: false, sanitized, error: "Invalid CIDR notation (e.g., 8.8.8.0/24)" };
      }
      const prefix = parseInt(sanitized.split("/")[1]!);
      if (prefix < 8 || prefix > 32) {
        return { valid: false, sanitized, error: "CIDR prefix must be between 8 and 32" };
      }
      return { valid: true, sanitized };
    }

    case "FQDN": {
      const fqdnRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
      if (!fqdnRegex.test(sanitized)) {
        return { valid: false, sanitized, error: "Invalid FQDN format" };
      }
      return { valid: true, sanitized };
    }

    case "URL": {
      try {
        const url = new URL(sanitized.startsWith("http") ? sanitized : `https://${sanitized}`);
        if (!["http:", "https:"].includes(url.protocol)) {
          return { valid: false, sanitized, error: "URL must use HTTP or HTTPS protocol" };
        }
        return { valid: true, sanitized: url.origin };
      } catch {
        return { valid: false, sanitized, error: "Invalid URL format" };
      }
    }

    default:
      return { valid: false, sanitized, error: "Unknown target type" };
  }
}