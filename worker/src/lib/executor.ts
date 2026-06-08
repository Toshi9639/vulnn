// ──────────────────────────────────────────────────────────────
// VulnCenter Scan Worker — Command Execution Utilities
// ──────────────────────────────────────────────────────────────

import { execSync, execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { logger } from "./logger.js";

// ─── Worker Configuration ─────────────────────────────────

export const WORKER_CONFIG = {
  maxConcurrentScans: parseInt(process.env.MAX_CONCURRENT_SCANS ?? "5", 10),
  scanTimeoutMs: parseInt(process.env.SCAN_TIMEOUT_MS ?? "600000", 10), // 10 min default
  nucleiTemplatesPath: process.env.NUCLEI_TEMPLATES_PATH ?? "/opt/nuclei-templates",
  tempDir: path.join(os.tmpdir(), "vulncenter-scans"),
};

// Ensure temp directory exists
if (!fs.existsSync(WORKER_CONFIG.tempDir)) {
  fs.mkdirSync(WORKER_CONFIG.tempDir, { recursive: true });
}

// ─── Tool Location Constants ──────────────────────────────

const TOOLS = {
  nmap: "nmap",
  nuclei: "nuclei",
  nikto: "nikto",
  testssl: "testssl",
  masscan: "masscan",
} as const;

// ─── Check if tools are available ─────────────────────────

export function verifyTools(): Record<string, boolean> {
  const results: Record<string, boolean> = {};
  for (const [name, cmd] of Object.entries(TOOLS)) {
    try {
      execSync(`which ${cmd} 2>/dev/null || command -v ${cmd} 2>/dev/null`, {
        timeout: 5000,
        stdio: "pipe",
      });
      results[name] = true;
    } catch {
      results[name] = false;
    }
  }
  return results;
}

// ─── Safe Command Execution ───────────────────────────────

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Execute a command with timeout and proper error handling.
 * All user-provided values MUST be sanitized via the target validator
 * before reaching this function.
 */
export function executeCommand(
  command: string,
  args: string[],
  options: {
    timeout?: number;
    cwd?: string;
    maxBuffer?: number;
  } = {}
): ExecResult {
  const timeout = options.timeout ?? WORKER_CONFIG.scanTimeoutMs;

  // Sanitize: ensure args contain no shell metacharacters
  const sanitizedArgs = args.map((arg) => {
    if (typeof arg !== "string") return String(arg);
    // Reject args containing shell metacharacters
    if (/[;&|`$(){}[\]!#~<>*\n\r]/.test(arg)) {
      throw new Error(`Security: Argument contains shell metacharacters: ${arg.substring(0, 50)}`);
    }
    return arg;
  });

  logger.debug(
    { command, args: sanitizedArgs, timeout },
    "Executing command"
  );

  try {
    const result = execFile(command, sanitizedArgs, {
      timeout,
      maxBuffer: options.maxBuffer ?? 10 * 1024 * 1024, // 10MB default
      killSignal: "SIGTERM",
      env: {
        ...process.env,
        // Ensure tools are in PATH
        PATH: `/usr/local/bin:/usr/bin:/bin:${process.env.PATH ?? ""}`,
      },
    });

    const stdout = result.stdout ?? "";
    const stderr = result.stderr ?? "";
    const exitCode = result.status ?? -1;

    if (exitCode !== 0) {
      logger.warn(
        { command, exitCode, stderr: stderr.slice(0, 500) },
        "Command completed with non-zero exit code"
      );
    }

    return { stdout, stderr, exitCode };
  } catch (error: unknown) {
    const err = error as Error & { stdout?: string; stderr?: string; code?: string; signal?: string };
    const stdout = err.stdout ?? "";
    const stderr = err.stderr ?? "";
    const exitCode = err.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" ? -2 : -1;

    if (err.signal === "SIGTERM") {
      logger.warn({ command, timeout }, "Command timed out and was killed");
    } else {
      logger.error({ command, error: err.message }, "Command execution failed");
    }

    return { stdout, stderr, exitCode };
  }
}

// ─── Temp File Helpers ────────────────────────────────────

export function createTempFile(prefix: string, content?: string): string {
  const filePath = path.join(
    WORKER_CONFIG.tempDir,
    `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  );
  if (content) {
    fs.writeFileSync(filePath, content, "utf-8");
  }
  return filePath;
}

export function readJsonFile<T = unknown>(filePath: string): T | null {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(content) as T;
  } catch (error) {
    logger.error({ filePath, error }, "Failed to read/parse JSON file");
    return null;
  }
}

export function safeRemoveFile(filePath: string): void {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch {
    // Best effort cleanup
  }
}