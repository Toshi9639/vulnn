# VulnCenter - Enterprise Vulnerability Scanning Platform for MSPs

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-latest-blue.svg)](https://hub.docker.com/r/vulncenter)
[![Coolify Compatible](https://img.shields.io/badge/Coolify-✔-green.svg)](https://coolify.io)

## Overview

VulnCenter is a **multi-tenant vulnerability scanning platform** designed for Managed Service Providers (MSPs). Manage security scans for all your clients from a single, self-hosted dashboard with complete data isolation.

### Key Features

- 🛡️ **Multi-Tenant Architecture** - Complete data isolation between clients with role-based access control
- 🔍 **Integrated Scanning Engines** - Nmap, Nuclei, Nikto, and TestSSL
- 📊 **Professional Reporting** - Generate PDF reports with severity breakdowns
- 🚀 **Coolify Ready** - One-click deployment with Coolify PaaS
- 🔐 **Enterprise Security** - JWT authentication, RBAC, audit logging

## Quick Start

### Prerequisites

- Docker 20.10+ and Docker Compose 2.0+
- OR Coolify 4.0+ installation
- 4GB RAM minimum (8GB recommended)
- 2 CPU cores minimum (4 cores recommended)

### Deploy with Coolify (Recommended)

1. **Prepare your Coolify instance**
   - Ensure Coolify is installed and running
   - Navigate to your project dashboard

2. **Add the repository**
   - Click "Add Resource" → "Git Repository"
   - Connect your GitHub/GitLab account
   - Select the vulnn repository

3. **Configure services**
   - Coolify will auto-detect `docker-compose.yml`
   - Set the following environment variables:
     ```bash
     DATABASE_URL=postgresql://vulncenter:YOUR_PASSWORD@postgres:5432/vulncenter
     REDIS_PASSWORD=YOUR_REDIS_PASSWORD
     JWT_SECRET=openssl rand -base64 32
     NEXT_PUBLIC_API_URL=https://api.yourdomain.com
     NEXT_PUBLIC_APP_URL=https://app.yourdomain.com
     ```

4. **Run database migrations**
   ```bash
   docker compose --profile setup run --rm db-migrate
   ```

5. **Deploy**
   - Click "Deploy" in Coolify
   - Wait for all services to become healthy
   - Access the dashboard at `https://app.yourdomain.com`

### Manual Deployment with Docker Compose

1. **Clone the repository**
   ```bash
   git clone https://github.com/vulncenter/vulnn.git
   cd vulnn
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your values
   nano .env
   ```

3. **Generate secrets**
   ```bash
   # JWT Secret (minimum 32 characters)
   openssl rand -base64 32
   
   # Database password
   openssl rand -base64 24
   ```

4. **Run migrations**
   ```bash
   docker compose --profile setup run --rm db-migrate
   ```

5. **Start services**
   ```bash
   docker compose up -d
   ```

6. **Verify deployment**
   ```bash
   docker compose ps
   # All services should show "healthy" status
   
   # Check logs
   docker compose logs -f api
   docker compose logs -f worker
   ```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | PostgreSQL connection string | - | ✅ |
| `REDIS_URL` | Redis connection string | - | ✅ |
| `JWT_SECRET` | JWT signing secret (min 32 chars) | - | ✅ |
| `JWT_EXPIRY` | JWT token expiration | `24h` | ❌ |
| `CORS_ORIGIN` | Allowed CORS origins (comma-separated) | `*` | ❌ |
| `ALLOW_PRIVATE_IPS` | Allow scanning private IPs | `false` | ❌ |
| `MAX_CONCURRENT_SCANS` | Worker concurrency | `5` | ❌ |
| `SCAN_TIMEOUT_MS` | Maximum scan duration | `1800000` | ❌ |
| `NUCLEI_TEMPLATES_PATH` | Nuclei templates directory | `/opt/nuclei-templates` | ❌ |

### Security Configuration

**Important**: Before deploying to production:

1. **Change default passwords** in `.env`
2. **Set `CORS_ORIGIN`** to your actual domain (not `*`)
3. **Generate strong JWT_SECRET** using `openssl rand -base64 32`
4. **Enable TLS/HTTPS** - Coolify handles this automatically
5. **Review `ALLOW_PRIVATE_IPS`** setting for internal scanning

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Reverse Proxy (Coolify)            │
│         (TLS Termination, Load Balancing)       │
└──────────────┬────────────────┬────────────────┘
               │                │
        ┌──────▼──────┐  ┌──────▼──────┐
        │  Web (3000) │  │  API (8000) │
        │   Next.js   │  │   Fastify   │
        └──────┬──────┘  └──────┬──────┘
               │                │
        ┌──────▼────────────────▼──────┐
        │       Redis (BullMQ)         │
        │    Scan Queue Management     │
        └──────┬────────────────┬──────┘
               │                │
        ┌──────▼──────┐  ┌──────▼──────┐
        │   Worker    │  │  PostgreSQL │
        │  Scan Pool  │  │   Database  │
        └─────────────┘  └─────────────┘
```

## Usage

### Creating Your First Scan

1. **Login** to the dashboard with admin credentials
2. **Add a client** organization under "Clients"
3. **Add a target** (IP, CIDR, FQDN, or URL)
4. **Verify ownership** by accepting the disclaimer
5. **Create a scan** and select scan type:
   - **NMAP_QUICK** - Fast port scan (top 100 ports)
   - **NMAP_FULL** - Comprehensive port scan (all 65535 ports)
   - **NUCLEI_CVE** - CVE vulnerability detection
   - **NUCLEI_WEB** - Web application scanning
   - **NIKTO_WEB** - Web server security checks
   - **TESTSSL** - SSL/TLS configuration analysis

### API Usage

```bash
# Authenticate
curl -X POST https://api.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"yourpassword"}'

# List scans
curl https://api.yourdomain.com/api/v1/scans \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Create a scan
curl -X POST https://api.yourdomain.com/api/v1/scans \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targetId": "target_id_here",
    "scanType": "NMAP_QUICK"
  }'
```

## Troubleshooting

### Common Issues

**Services won't start**
```bash
# Check database connectivity
docker compose exec postgres pg_isready

# View service logs
docker compose logs api
docker compose logs worker
```

**Migrations fail**
```bash
# Reset and re-run migrations
docker compose --profile setup run --rm db-migrate
```

**Worker scans timeout**
- Increase `SCAN_TIMEOUT_MS` in `.env`
- Check network connectivity to targets
- Verify scanning tools are installed: `docker compose exec worker which nmap nuclei nikto`

**CORS errors**
- Ensure `CORS_ORIGIN` matches your frontend domain exactly
- Include protocol: `https://app.example.com` (not `app.example.com`)

### Health Checks

```bash
# API health
curl https://api.yourdomain.com/health

# Worker health
curl http://localhost:8080 # from inside worker container

# Database readiness
docker compose exec postgres pg_isready
```

## Development

### Local Setup

```bash
# Install dependencies
cd api && npm install
cd ../worker && npm install
cd ../web && npm install

# Start database and Redis
docker compose up -d postgres redis

# Run migrations
cd api && npx prisma migrate dev

# Start development servers
cd api && npm run dev
cd ../worker && npm run dev
cd ../web && npm run dev
```

### Adding New Scan Types

1. Add scan type to `ScanType` enum in `db/schema.prisma`
2. Implement scanner in `worker/src/lib/engine.ts`
3. Add route in `api/src/routes/scans.ts`
4. Update frontend scan selector

## Security Considerations

⚠️ **Important**: This tool is for **authorized security testing only**.

- Only scan systems you own or have explicit permission to test
- The platform includes ownership verification mechanisms
- All scan activity is logged for audit purposes
- Private IP scanning is disabled by default (can be enabled via `ALLOW_PRIVATE_IPS=true`)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.vulncenter.io
- Issues: https://github.com/vulncenter/vulnn/issues
- Discord: https://discord.gg/vulncenter

## Acknowledgments

Built with:
- [Fastify](https://fastify.io/) - API framework
- [Next.js](https://nextjs.org/) - Frontend framework
- [Prisma](https://prisma.io/) - Database ORM
- [BullMQ](https://bullmq.io/) - Job queues
- [Nmap](https://nmap.org/), [Nuclei](https://nuclei.projectdiscovery.io/), [Nikto](https://cirt.net/nikto), [testssl.sh](https://testssl.sh/)

---

© 2024 VulnCenter. Built for MSPs, by MSPs.