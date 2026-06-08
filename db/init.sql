-- ──────────────────────────────────────────────────────────
-- VulnCenter — PostgreSQL Initialization
-- Extensions and base setup
-- ──────────────────────────────────────────────────────────

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Enable case-insensitive text
CREATE EXTENSION IF NOT EXISTS citext;

-- Enable performance monitoring
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Create enum types if not using Prisma migrations directly
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'UserRole') THEN
        CREATE TYPE "UserRole" AS ENUM ('SUPER_ADMIN', 'CLIENT_ADMIN', 'CLIENT_VIEWER');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'TargetType') THEN
        CREATE TYPE "TargetType" AS ENUM ('IP', 'CIDR', 'FQDN', 'URL');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'TargetStatus') THEN
        CREATE TYPE "TargetStatus" AS ENUM ('UNVERIFIED', 'VERIFIED', 'DISABLED', 'EXPIRED');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ScanType') THEN
        CREATE TYPE "ScanType" AS ENUM ('NMAP_QUICK', 'NMAP_FULL', 'NUCLEI_CVE', 'NUCLEI_WEB', 'NIKTO_WEB', 'TESTSSL', 'CUSTOM');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ScanStatus') THEN
        CREATE TYPE "ScanStatus" AS ENUM ('PENDING', 'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'PARTIAL');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'Severity') THEN
        CREATE TYPE "Severity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'FindingStatus') THEN
        CREATE TYPE "FindingStatus" AS ENUM ('OPEN', 'IN_PROGRESS', 'MITIGATED', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'REOPENED');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ReportStatus') THEN
        CREATE TYPE "ReportStatus" AS ENUM ('GENERATING', 'READY', 'FAILED');
    END IF;
END$$;

-- Create indexing maintenance function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;