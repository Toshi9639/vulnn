// ──────────────────────────────────────────────────────────────
// VulnCenter Worker — Queue Types (mirrors API types)
// Used by both the worker and for reference documentation
// ──────────────────────────────────────────────────────────────

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
    metadata?: Record<string, unknown>;
  }>;
  errorMessage?: string;
  rawOutput?: string;
};