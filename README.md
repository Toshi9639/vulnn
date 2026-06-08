# ──────────────────────────────────────────────────────────────
# VulnCenter
# Multi-Tenant Vulnerability Scanning Platform for MSPs
# ──────────────────────────────────────────────────────────────

> **Self-hosted, multi-tenant vulnerability scanning.** Manage Nmap, Nuclei,
> Nikto, and TestSSL scans for all your clients from a single dashboard.
> Deployed via Coolify with Docker Compose.

## Architecture Overview

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  User    │───▶│  API     │───▶│  Redis   │───▶│  Worker  │───▶│  Target  │
│ (Auth'd) │    │ Fastify  │    │  Queue   │    │  Pool    │    │  Network │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
```

## Tech Stack

| Layer      | Technology                                      |
|------------|-------------------------------------------------|
| Frontend   | Next.js 14 (App Router), Tailwind CSS, Shadcn/ui |
| API        | Node.js + Fastify + Prisma ORM                   |
| Queue      | Redis + BullMQ                                   |
| Workers    | Nmap, Nuclei, Nikto, TestSSL                    |
| Database   | PostgreSQL 16                                    |
| Deploy     | Coolify + Docker Compose                         |

## Quick Start

### Prerequisites
- Docker & Docker Compose v2
- Coolify instance (or any Docker host)

### 1. Clone & Configure

```bash
git clone <your-repo-url> vulncenter
cd vulncenter
cp .env.example .env
# Edit .env with your secrets
```

### 2. Environment Variables

Set these in Coolify or your `.env`:

| Variable            | Description                | Example                                |
|---------------------|----------------------------|----------------------------------------|
| `DATABASE_URL`      | PostgreSQL connection       | `postgresql://user:pass@postgres:5432/db` |
| `REDIS_PASSWORD`    | Redis auth password         | `your-strong-password`                 |
| `JWT_SECRET`        | JWT signing key (min 32ch) | `your-256-bit-secret-key-here-change-me` |
| `CORS_ORIGIN`       | Frontend URL for CORS       | `https://app.vulncenter.example.com`   |

### 3. Deploy with Coolify

1. Create a new **Docker Compose** resource in Coolify
2. Point it to your repository
3. Set all environment variables in Coolify's UI
4. Deploy!

### 4. Manual Deploy

```bash
# Run database migrations first
docker compose --profile setup run db-migrate

# Start all services
docker compose up -d

# Check health
curl http://localhost:8000/health
```

## Project Structure

```
vulncenter/
├── docker-compose.yml          # Multi-service Docker Compose
├── .env.example                # Environment variable template
├── api/                        # Fastify API Gateway
│   ├── Dockerfile
│   ├── src/
│   │   ├── server.ts           # Entry point
│   │   ├── routes/             # API route handlers
│   │   │   └── scans.ts        # Scan management routes
│   │   └── lib/                # Shared libraries
│   │       ├── auth.ts         # JWT + RBAC
│   │       ├── database.ts     # Prisma client
│   │       ├── queue.ts        # BullMQ queue
│   │       ├── types.ts        # Validation + types
│   │       └── env.ts          # Config validation
│   └── package.json
├── worker/                     # Scan Worker
│   ├── Dockerfile              # Pre-installs nmap, nuclei, nikto, testssl
│   ├── src/
│   │   ├── worker.ts           # BullMQ worker entry point
│   │   └── lib/
│   │       ├── engine.ts       # Scan execution engine
│   │       ├── executor.ts     # Secure command execution
│   │       └── queue.ts        # Queue types
│   └── package.json
├── web/                        # Next.js Frontend
│   ├── Dockerfile
│   ├── src/
│   │   ├── app/                # App Router pages
│   │   │   ├── page.tsx        # Landing page
│   │   │   └── layout.tsx      # Root layout
│   │   └── lib/
│   │       └── utils.ts        # Frontend utilities
│   └── package.json
├── db/                         # Database
│   ├── Dockerfile              # Migration runner
│   ├── schema.prisma           # Multi-tenant schema
│   └── init.sql                # Initial SQL setup
└── docs/
    └── ARCHITECTURE.md         # System architecture diagram
```

## API Endpoints

| Method | Path                    | Description                | Auth Required |
|--------|-------------------------|----------------------------|:-------------:|
| GET    | `/health`               | Health check               | No            |
| POST   | `/api/v1/scans`         | Trigger a new scan         | Yes           |
| GET    | `/api/v1/scans`         | List scans (tenant-scoped) | Yes           |
| GET    | `/api/v1/scans/:id`     | Scan details + findings    | Yes           |
| POST   | `/api/v1/scans/:id/cancel` | Cancel a running scan   | Yes           |

## Security

- **Multi-Tenant Isolation:** All DB queries scoped by `tenantId` + `clientId`
- **RBAC:** SUPER_ADMIN, CLIENT_ADMIN, CLIENT_VIEWER roles
- **Input Sanitization:** Target validation blocks private/reserved IPs
- **Command Injection Protection:** `execFile` (not shell), arg sanitization
- **Non-Root Containers:** All services run as non-root users
- **Capability Dropping:** Worker drops all Linux capabilities except NET_RAW/NET_ADMIN
- **Rate Limiting:** 100 req/min per IP on API gateway
- **Audit Logging:** All actions logged per tenant

## License

MIT — Built for the security community.