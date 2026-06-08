// ──────────────────────────────────────────────────────────────
// VulnCenter Scan Worker — Scan Engine
// Executes security tools and parses results into Findings
// ──────────────────────────────────────────────────────────────

import { executeCommand, WORKER_CONFIG, createTempFile, safeRemoveFile } from "./executor.js";
import { logger } from "./logger.js";
import type { ScanJobData, ScanJobResult } from "./queue.js";

// ─── Finding Types ────────────────────────────────────────

export interface RawFinding {
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
  metadata?: Record<string, unknown>;
}

// ════════════════════════════════════════════════════════════
// SCAN ROUTER
// ════════════════════════════════════════════════════════════

export async function executeScan(jobData: ScanJobData): Promise<ScanJobResult> {
  logger.info(
    {
      scanId: jobData.scanId,
      scanType: jobData.scanType,
      target: jobData.targetValue,
    },
    "Starting scan execution"
  );

  try {
    switch (jobData.scanType) {
      case "NMAP_QUICK":
        return await runNmapQuick(jobData);
      case "NMAP_FULL":
        return await runNmapFull(jobData);
      case "NUCLEI_CVE":
        return await runNucleiCve(jobData);
      case "NUCLEI_WEB":
        return await runNucleiWeb(jobData);
      case "NIKTO_WEB":
        return await runNikto(jobData);
      case "TESTSSL":
        return await runTestssl(jobData);
      default:
        return {
          scanId: jobData.scanId,
          status: "FAILED",
          findings: [],
          errorMessage: `Unknown scan type: ${jobData.scanType}`,
        };
    }
  } catch (error) {
    logger.error({ error, scanId: jobData.scanId }, "Scan execution failed");
    return {
      scanId: jobData.scanId,
      status: "FAILED",
      findings: [],
      errorMessage: error instanceof Error ? error.message : "Unknown scan error",
    };
  }
}

// ════════════════════════════════════════════════════════════
// NMAP — Network & Port Scanning
// ════════════════════════════════════════════════════════════

async function runNmapQuick(jobData: ScanJobData): Promise<ScanJobResult> {
  const ports = jobData.ports ?? "80,443,22,21,25,53,110,143,993,995,3306,3389,5432,6379,8080,8443,9090";
  const outputFile = createTempFile("nmap-quick");

  try {
    const target = determineTargetArg(jobData);
    const result = executeCommand("nmap", [
      "-sS",        // SYN stealth scan
      "-sV",        // Service version detection
      "-O",         // OS detection
      "-T4",        // Timing aggressive
      "--top-ports", "100",
      "-oJ", outputFile,  // JSON output
      target,
    ], {
      timeout: WORKER_CONFIG.scanTimeoutMs,
    });

    if (result.exitCode !== 0 && result.exitCode !== -1) {
      logger.warn({ scanId: jobData.scanId, exitCode: result.exitCode }, "Nmap quick scan warning");
    }

    const findings = parseNmapOutput(outputFile, jobData);
    return {
      scanId: jobData.scanId,
      status: "COMPLETED",
      findings,
      rawOutput: result.stdout,
    };
  } finally {
    safeRemoveFile(outputFile);
  }
}

async function runNmapFull(jobData: ScanJobData): Promise<ScanJobResult> {
  const ports = jobData.ports ?? "1-65535";
  const outputFile = createTempFile("nmap-full");

  try {
    const target = determineTargetArg(jobData);
    const result = executeCommand("nmap", [
      "-sS", "-sV", "-O", "-sC",   // Full scan: SYN, version, OS, default scripts
      "-T4",
      "-p", ports,
      "-oJ", outputFile,
      "--stats-every", "30s",
      target,
    ], {
      timeout: WORKER_CONFIG.scanTimeoutMs,
    });

    const findings = parseNmapOutput(outputFile, jobData);
    return {
      scanId: jobData.scanId,
      status: "COMPLETED",
      findings,
      rawOutput: result.stdout,
    };
  } finally {
    safeRemoveFile(outputFile);
  }
}

function parseNmapOutput(outputFile: string, jobData: ScanJobData): RawFinding[] {
  const nmapData = readNmapJson(outputFile);
  if (!nmapData) return [];

  const findings: RawFinding[] = [];
  const hosts = Array.isArray(nmapData) ? nmapData : [nmapData];

  for (const host of hosts) {
    const hostname = host.hostnames?.[0]?.name ?? host.ip ?? jobData.targetValue;
    const osMatches = host.osmatch ?? [];

    // Add OS detection finding
    if (osMatches.length > 0) {
      const osName = osMatches[0]?.name ?? "Unknown";
      findings.push({
        source: "nmap",
        findingType: "OS_DETECTION",
        severity: "INFO",
        title: `OS Detection: ${osName}`,
        description: `Operating system detected on ${hostname}: ${osName}`,
        host: hostname,
        evidence: JSON.stringify(osMatches.slice(0, 3)),
      });
    }

    // Parse open ports
    const ports = host.ports ?? [];
    for (const port of ports) {
      if (port.state?.state !== "open") continue;

      const service = port.service ?? {};
      const product = service.product ?? "";
      const version = service.version ?? "";
      const serviceName = service.name ?? "unknown";

      findings.push({
        source: "nmap",
        findingType: "OPEN_PORT",
        severity: portIsSensitive(port.portid) ? "MEDIUM" : "INFO",
        title: `Open Port: ${port.portid}/${port.protocol} — ${serviceName}`,
        description: `Port ${port.portid}/${port.protocol} is open. Service: ${serviceName}${product ? ` (${product} ${version})`.trim() : ""}`,
        port: parseInt(port.portid, 10),
        protocol: port.protocol,
        host: hostname,
        evidence: JSON.stringify(port),
      });
    }
  }

  return findings;
}

function portIsSensitive(portId: string): boolean {
  const sensitive = ["3306", "5432", "6379", "27017", "3389", "22", "23", "21"];
  return sensitive.includes(portId);
}

function readNmapJson(filePath: string): any {
  try {
    import fs from "node:fs";
    const content = fs.readFileSync(filePath, "utf-8");
    // Nmap JSON output has `nmaprun` as root key
    const parsed = JSON.parse(content);
    return parsed?.nmaprun?.host ?? [];
  } catch {
    return null;
  }
}

// ════════════════════════════════════════════════════════════
// NUCLEI — Vulnerability Scanning (CVE Detection)
// ════════════════════════════════════════════════════════════

async function runNucleiCve(jobData: ScanJobData): Promise<ScanJobResult> {
  const target = determineTargetArg(jobData);
  const outputFile = createTempFile("nuclei-cve");

  try {
    const result = executeCommand("nuclei", [
      "-target", target,
      "-json", "-o", outputFile,
      "-severity", "critical,high,medium,low",
      "-templates", `${WORKER_CONFIG.nucleiTemplatesPath}/cves/`,
      "-rate-limit", "150",
      "-concurrency", "50",
      "-timeout", "10",
      "-retries", "2",
    ], {
      timeout: WORKER_CONFIG.scanTimeoutMs,
    });

    const findings = parseNucleiOutput(outputFile, jobData);
    return {
      scanId: jobData.scanId,
      status: "COMPLETED",
      findings,
      rawOutput: result.stdout,
    };
  } finally {
    safeRemoveFile(outputFile);
  }
}

async function runNucleiWeb(jobData: ScanJobData): Promise<ScanJobResult> {
  const target = determineTargetArg(jobData);
  const outputFile = createTempFile("nuclei-web");

  try {
    const result = executeCommand("nuclei", [
      "-target", target,
      "-json", "-o", outputFile,
      "-severity", "critical,high,medium,low,info",
      "-templates", `${WORKER_CONFIG.nucleiTemplatesPath}/technologies/,${WORKER_CONFIG.nucleiTemplatesPath}/exposures/,${WORKER_CONFIG.nucleiTemplatesPath}/misconfiguration/`,
      "-rate-limit", "150",
      "-concurrency", "50",
      "-timeout", "10",
      "-retries", "2",
    ], {
      timeout: WORKER_CONFIG.scanTimeoutMs,
    });

    const findings = parseNucleiOutput(outputFile, jobData);
    return {
      scanId: jobData.scanId,
      status: "COMPLETED",
      findings,
      rawOutput: result.stdout,
    };
  } finally {
    safeRemoveFile(outputFile);
  }
}

function parseNucleiOutput(outputFile: string, jobData: ScanJobData): RawFinding[] {
  try {
    import fs from "node:fs";
    const content = fs.readFileSync(outputFile, "utf-8");
    if (!content) return [];

    const lines = content.trim().split("\n");
    const findings: RawFinding[] = [];

    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        const severity: RawFinding["severity"] = normalizeSeverity(entry.info?.severity ?? entry.severity);

        findings.push({
          source: "nuclei",
          findingType: entry.info?.name ?? "NUCLEI_MATCH",
          severity,
          title: entry.info?.name ?? "Nuclei Template Match",
          description: entry.info?.description ?? entry.matcher_name ?? "",
          host: entry.host ?? entry.ip,
          path: entry.path ?? entry.matched_at,
          cveId: Array.isArray(entry.info?.classification?.cve_id)
            ? entry.info.classification.cve_id[0]
            : entry.info?.classification?.cve_id,
          cvssScore: entry.info?.classification?.cvss_score
            ? parseFloat(entry.info.classification.cvss_score)
            : undefined,
          cvssVector: entry.info?.classification?.cvss_vector,
          evidence: entry.matched ?? entry.extracted_results?.join(", "),
          remediation: entry.info?.remediation,
          references: entry.info?.reference
            ? (Array.isArray(entry.info.reference) ? entry.info.reference : [entry.info.reference])
            : undefined,
          metadata: {
            template_id: entry.template_id,
            template_url: entry.template_url,
          },
        });
      } catch {
        // Skip malformed lines
      }
    }

    return findings;
  } catch {
    return [];
  }
}

// ════════════════════════════════════════════════════════════
// NIKTO — Web Server Scanning
// ════════════════════════════════════════════════════════════

async function runNikto(jobData: ScanJobData): Promise<ScanJobResult> {
  const target = determineTargetArg(jobData);
  const outputFile = createTempFile("nikto");

  try {
    const result = executeCommand("nikto", [
      "-h", target,
      "-o", outputFile,
      "-Format", "json",
      "-Tuning", "123456789",  // All test types
      "-timeout", "10",
      "-nointeractive",
      "-Display", "V",  // Verbose
    ], {
      timeout: WORKER_CONFIG.scanTimeoutMs,
    });

    const findings = parseNiktoOutput(outputFile, jobData);
    return {
      scanId: jobData.scanId,
      status: "COMPLETED",
      findings,
      rawOutput: result.stdout,
    };
  } finally {
    safeRemoveFile(outputFile);
  }
}

function parseNiktoOutput(outputFile: string, jobData: ScanJobData): RawFinding[] {
  try {
    import fs from "node:fs";
    const content = fs.readFileSync(outputFile, "utf-8");
    if (!content) return [];

    const parsed = JSON.parse(content);
    const findings: RawFinding[] = [];
    const items = parsed?.nikto?.["@@"] ?? [];

    for (const item of items) {
      if (!item.OSVDB) continue; // Skip entries without findings

      const severity = mapNiktoSeverity(item.risk ?? 2);

      findings.push({
        source: "nikto",
        findingType: `NIKTO_${item.OSVDB}`,
        severity,
        title: item.msg ?? "Nikto Finding",
        description: item.msg ?? "",
        host: item.host ?? jobData.targetValue,
        path: item.uri,
        evidence: item.msg ?? "",
      });
    }

    return findings;
  } catch {
    return [];
  }
}

function mapNiktoSeverity(riskLevel: number): RawFinding["severity"] {
  switch (riskLevel) {
    case 0: return "INFO";
    case 1: return "LOW";
    case 2: return "MEDIUM";
    case 3: return "HIGH";
    default: return "UNKNOWN";
  }
}

// ════════════════════════════════════════════════════════════
// TESTSSL — SSL/TLS Analysis
// ════════════════════════════════════════════════════════════

async function runTestssl(jobData: ScanJobData): Promise<ScanJobResult> {
  const target = determineTargetArg(jobData);
  const outputFile = createTempFile("testssl");
  const jsonFile = `${outputFile}.json`;

  try {
    const result = executeCommand("testssl", [
      "--jsonfile", jsonFile,
      "--logfile", outputFile,
      "--quiet",
      "--color", "0",  // No color for parsing
      target,
    ], {
      timeout: WORKER_CONFIG.scanTimeoutMs,
    });

    const findings = parseTestsslOutput(jsonFile, jobData);
    return {
      scanId: jobData.scanId,
      status: "COMPLETED",
      findings,
      rawOutput: result.stdout,
    };
  } finally {
    safeRemoveFile(outputFile);
    safeRemoveFile(jsonFile);
  }
}

function parseTestsslOutput(jsonFile: string, jobData: ScanJobData): RawFinding[] {
  try {
    import fs from "node:fs";
    const content = fs.readFileSync(jsonFile, "utf-8");
    if (!content) return [];

    const lines = content.trim().split("\n");
    const findings: RawFinding[] = [];

    for (const line of lines) {
      try {
        const entry = JSON.parse(line);

        // Map testssl findings to our format
        if (entry.id && entry.severity && entry.finding) {
          const severity = mapTestsslSeverity(entry.severity);
          findings.push({
            source: "testssl",
            findingType: `SSL_${entry.id}`,
            severity,
            title: entry.finding ?? entry.id,
            description: entry.finding ?? "",
            host: entry.ip ?? entry.fqdn ?? jobData.targetValue,
            port: parseInt(entry.port, 10) || 443,
            evidence: JSON.stringify(entry),
          });
        }
      } catch {
        // Skip malformed lines
      }
    }

    return findings;
  } catch {
    return [];
  }
}

function mapTestsslSeverity(severe: string): RawFinding["severity"] {
  switch (severe.toUpperCase()) {
    case "CRITICAL": return "CRITICAL";
    case "HIGH": return "HIGH";
    case "MEDIUM": return "MEDIUM";
    case "LOW": return "LOW";
    case "INFO": return "INFO";
    default: return "UNKNOWN";
  }
}

// ════════════════════════════════════════════════════════════
// COMMON HELPERS
// ════════════════════════════════════════════════════════════

function determineTargetArg(jobData: ScanJobData): string {
  // Re-validate target value in worker (defense in depth)
  // The API should have already validated this, but we double-check here
  const value = jobData.targetValue.trim();
  
  // Basic sanity checks
  if (!value || value.length > 2048) {
    throw new Error("Invalid target value: must be non-empty and under 2048 characters");
  }
  
  // Reject shell metacharacters
  if (/[;&|`$(){}[\\]!#~<>*\n\r]/.test(value)) {
    throw new Error("Security: Target value contains invalid characters");
  }
  
  return value;
}

function normalizeSeverity(severity?: string): RawFinding["severity"] {
  if (!severity) return "UNKNOWN";
  const upper = severity.toUpperCase();
  if (upper.includes("CRITICAL")) return "CRITICAL";
  if (upper.includes("HIGH")) return "HIGH";
  if (upper.includes("MEDIUM")) return "MEDIUM";
  if (upper.includes("LOW")) return "LOW";
  if (upper.includes("INFO")) return "INFO";
  return "UNKNOWN";
}