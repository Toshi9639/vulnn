# VulnCenter Architecture

## Multi-Tenant Vulnerability Scanning Platform for MSPs

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          INTERNET                                      │
│  ┌──────────┐    ┌──────────────┐               ┌───────────────────┐  │
│  │ MSP      │    │ Client A     │               │ Client B          │  │
│  │ Admins   │    │ Users        │               │ Users             │  │
│  └────┬─────┘    └──────┬───────┘               └───────┬───────────┘  │
│       │                 │                                │              │
└───────┼─────────────────┼────────────────────────────────┼──────────────┘
        │                 │                                │
        ▼                 ▼                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    COOLIFY DEPLOYMENT LAYER                              │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    REVERSE PROXY (Caddy/Nginx)                   │   │
│  │              api.vulncenter.example.com   app.vulncenter.com     │   │
│  └──────────────────────────────────┬───────────────────────────────┘   │
│                                      │                                   │
│  ┌──────────┐  ┌─────────────────────┼──────────┐  ┌────────────────┐  │
│  │          │  │                     │          │  │                │  │
│  ▼          ▼  ▼                     ▼          ▼  ▼                ▼  │
│ ┌─────────┐ ┌─────────────────────────────────────┐ ┌──────────────┐  │
│ │         │ │           DOCKER NETWORK             │ │              │  │
│ │ VOLUMES │ │  (vulncenter-internal)               │ │   COOLIFY    │  │
│ │         │ │                                      │ │   MANAGED    │  │
│ │ pgdata  │ │  ┌──────┐  ┌──────┐  ┌──────┐       │ │   ENV VARS   │  │
│ │ redis   │ │  │ WEB  │  │ API  │  │ NGNX │       │ │              │  │
│ │ nuclei  │ │  │(Next)│  │(Fast)│  │/Caddy│       │ │ DATABASE_URL  │  │
│ │         │ │  │ :3000 │  │:8000 │  │:443  │       │ │ REDIS_URL     │  │
│ └─────────┘ │  └──┬───┘  └──┬───┘  └──────┘       │ │ JWT_SECRET    │  │
│              │     │         │                     │ │ API_KEY       │  │
│              │     └─────────┘                     │ └──────────────┘  │
│              │           │                          │                  │
│              │           ▼                          │                  │
│              │  ┌──────────────────┐                │                  │
│              │  │  REDIS (BullMQ)  │                │                  │
│              │  │   ├─ Scan Queue  │                │                  │
│              │  │   ├─ Result Queue│                │                  │
│              │  │   └─ Rate Limit  │                │                  │
│              │  └────────┬─────────┘                │                  │
│              │           │                          │                  │
│              │           ▼                          │                  │
│              │  ┌─────────────────────────────┐     │                  │
│              │  │      SCAN WORKERS (Pool)    │     │                  │
│              │  │                             │     │                  │
│              │  │  ┌─────────┐ ┌──────────┐   │     │                  │
│              │  │  │ Nmap    │ │ Nuclei   │   │     │                  │
│              │  │  │ Worker  │ │ Worker   │   │     │                  │
│              │  │  └─────────┘ └──────────┘   │     │                  │
│              │  │  ┌─────────┐ ┌──────────┐   │     │                  │
│              │  │  │ Nikto   │ │ TestSSL  │   │     │                  │
│              │  │  │ Worker  │ │ Worker   │   │     │                  │
│              │  │  └─────────┘ └──────────┘   │     │                  │
│              │  └────────┬────────────────────┘     │                  │
│              │           │                          │                  │
│              │           ▼                          │                  │
│              │  ┌────────────────────┐              │                  │
│              │  │   POSTGRESQL DB   │              │                  │
│              │  │   (Prisma ORM)    │              │                  │
│              │  │                   │              │                  │
│              │  │  ┌─────────────┐  │              │                  │
│              │  │  │ msp_tenants │  │              │                  │
│              │  │  │ clients     │  │              │                  │
│              │  │  │ users       │  │              │                  │
│              │  │  │ targets     │  │              │                  │
│              │  │  │ scans       │  │              │                  │
│              │  │  │ findings    │  │              │                  │
│              │  │  └─────────────┘  │              │                  │
│              │  └───────────────────┘              │                  │
│              └─────────────────────────────────────┘                  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌──────────┐
│  User   │───▶│  API    │───▶│  Redis  │───▶│ Worker  │───▶│  Public  │
│ (Auth'd)│    │ Fastify │    │  Queue  │    │  Pool   │    │  Target  │
└─────────┘    └─────────┘    └─────────┘    └─────────┘    └──────────┘
     │              │              │              │               │
     │              │              │              │  ◄────────────┘
     │              │              │              │  (Scan Results)
     │              │              │              │
     │              │              │  ◄────────────┘
     │              │              │  (Job Complete)
     │              │              │
     │              │  ◄────────────┘
     │              │  (WebSocket/SSE)
     │              │
     │  ◄────────────┘
     │  (Polling/WS)
```

## Multi-Tenant Isolation Boundary

```
┌─────────────────────────────────────────────────────┐
│                  MSP_TENANTS ROOT                    │
│  ┌───────────────────────────────────────────────┐  │
│  │               TENANT ISOLATION                │  │
│  │                                               │  │
│  │  ┌─────────────────┐  ┌─────────────────┐    │  │
│  │  │   Client A      │  │   Client B      │    │  │
│  │  │                 │  │                 │    │  │
│  │  │  ┌───────┐      │  │  ┌───────┐      │    │  │
│  │  │  │Users  │      │  │  │Users  │      │    │  │
│  │  │  └───────┘      │  │  └───────┘      │    │  │
│  │  │  ┌───────┐      │  │  ┌───────┐      │    │  │
│  │  │  │Targets│      │  │  │Targets│      │    │  │
│  │  │  └───────┘      │  │  └───────┘      │    │  │
│  │  │  ┌───────┐      │  │  ┌───────┐      │    │  │
│  │  │  │Scans  │      │  │  │Scans  │      │    │  │
│  │  │  └───────┘      │  │  └───────┘      │    │  │
│  │  │  ┌───────┐      │  │  ┌───────┐      │    │  │
│  │  │  │Findings│     │  │  │Findings│     │    │  │
│  │  │  └───────┘      │  │  └───────┘      │    │  │
│  │  └─────────────────┘  └─────────────────┘    │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Component Breakdown

### Frontend (Next.js App Router)
- **Port:** 3000
- **Stack:** Next.js 14, Tailwind CSS, Shadcn/ui components
- **Features:** Dashboard, scan management, report viewer, admin panel
- **Auth:** JWT-based with middleware for route protection & RBAC

### API Gateway (Fastify)
- **Port:** 8000
- **Stack:** Node.js + Fastify + Prisma ORM
- **Roles:** Auth, RBAC enforcement, target validation, scan orchestration
- **Endpoints:** `/api/v1/scans`, `/api/v1/targets`, `/api/v1/clients`, `/api/v1/reports`
- **Tenant Isolation:** All queries scoped by `tenantId` extracted from JWT

### Task Queue (Redis + BullMQ)
- **Port:** 6379
- **Purpose:** Async job orchestration for long-running scans
- **Queues:** `scan:queue`, `result:queue`, `notification:queue`
- **Features:** Job retry, concurrency control, job progress reporting

### Scan Workers
- **Dedicated Containers:** One per scan tool type
- **Pre-installed Tools:** nmap, nuclei, nikto, testssl.sh
- **Process:** Dequeue job → execute scan → parse output → write results to DB
- **Security:** Non-root user, restricted capabilities, input sanitization

### Database (PostgreSQL)
- **Port:** 5432
- **ORM:** Prisma with strict multi-tenant schema
- **Key Tables:** `msp_tenants`, `clients`, `users`, `targets`, `scans`, `findings`, `reports`
- **Policy:** Row-Level Security via tenantId on all data tables

## Security Boundaries

```
 Layer              | Trust Level | Mitigation
────────────────────┼─────────────┼─────────────────────────────────────
 Internet           | Untrusted   | TLS, Rate limiting, WAF
 Reverse Proxy      | Semi-trusted| Request validation, CORS
 API Gateway        | Trusted     | JWT auth, RBAC, Input sanitization
 Queue/Redis        | Trusted     | Internal network only, Auth required
 Workers            | Trusted     | Non-root, No network except DB+Redis
 Database           | Trusted     | Encrypted at rest, RLS, Least privilege
 Scan Targets       | External    | Scope enforcement, Ownership verification
```

## Deployment Considerations (Coolify)

| Service  | Health Check          | Resource Limits          | Scaling           |
|----------|----------------------|--------------------------|-------------------|
| web      | /api/health → 200    | CPU: 1, RAM: 1GB         | Horizontal (k8s) |
| api      | /health → 200        | CPU: 1, RAM: 1GB         | Horizontal        |
| worker   | BullMQ job polling   | CPU: 2, RAM: 2GB         | Horizontal (pool) |
| postgres | pg_isready           | CPU: 2, RAM: 4GB         | Vertical          |
| redis    | redis-cli ping       | CPU: 1, RAM: 512MB       | Vertical          |