# VulnCenter Deployment Checklist

## Pre-Deployment Preparation

### 1. Environment Setup

- [ ] Docker 20.10+ installed and running
- [ ] Docker Compose 2.0+ installed
- [ ] OR Coolify 4.0+ instance deployed
- [ ] Git repository cloned and accessible
- [ ] Domain names configured (if using custom domains)

### 2. Security Configuration

- [ ] Generate strong JWT_SECRET (min 32 chars)
  ```bash
  openssl rand -base64 32
  ```
  
- [ ] Generate PostgreSQL password
  ```bash
  openssl rand -base64 24
  ```

- [ ] Generate Redis password
  ```bash
  openssl rand -base64 24
  ```

- [ ] Set `CORS_ORIGIN` to specific domain(s), NOT `*`
  - Production: `https://app.yourdomain.com`
  - Multiple origins: `https://app.domain.com,https://admin.domain.com`

- [ ] Review `ALLOW_PRIVATE_IPS` setting
  - Default: `false` (recommended for production)
  - Set to `true` only if scanning internal networks

### 3. Database Preparation

- [ ] PostgreSQL 16+ available
- [ ] Database created and accessible
- [ ] User has CREATE/ALTER permissions for migrations
- [ ] Connection string tested

### 4. Redis Preparation

- [ ] Redis 7+ available  
- [ ] Password authentication enabled
- [ ] Connection URL formatted correctly

## Coolify Deployment Steps

### 1. Repository Setup

- [ ] Connect Git provider (GitHub/GitLab)
- [ ] Grant repository access to Coolify
- [ ] Verify `docker-compose.yml` auto-detected

### 2. Service Configuration

- [ ] Set resource limits per service:
  ```yaml
  web:    1 CPU, 1GB RAM
  api:    1 CPU, 1GB RAM  
  worker: 2 CPU, 2GB RAM
  postgres: 2 CPU, 4GB RAM
  redis:  0.5 CPU, 512MB RAM
  ```

- [ ] Configure persistent volumes:
  - [ ] `vulncenter-pgdata` → PostgreSQL data
  - [ ] `vulncenter-redis` → Redis data
  - [ ] `vulncenter-nuclei-templates` → Nuclei templates

### 3. Environment Variables

Create these in Coolify's environment UI:

```bash
# Required
DATABASE_URL=postgresql://vulncenter:<password>@postgres:5432/vulncenter
REDIS_URL=redis://:<password>@redis:6379
REDIS_PASSWORD=<strong_password>
JWT_SECRET=<32+_char_random_string>

# Recommended
NODE_ENV=production
CORS_ORIGIN=https://app.yourdomain.com
NEXT_PUBLIC_API_URL=https://api.yourdomain.com
NEXT_PUBLIC_APP_URL=https://app.yourdomain.com
API_INTERNAL_URL=http://api:8000

# Optional
LOG_LEVEL=info
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT_MS=1800000
ALLOW_PRIVATE_IPS=false
NUCLEI_TEMPLATES_PATH=/opt/nuclei-templates
```

### 4. Network Configuration

- [ ] Create internal network `vulncenter-internal` if not using Coolify auto-network
- [ ] Configure reverse proxy domains:
  - `app.yourdomain.com` → web service (port 3000)
  - `api.yourdomain.com` → api service (port 8000)
- [ ] Enable automatic HTTPS/TLS certificates

### 5. Database Migrations

```bash
# From Coolify terminal or SSH
docker compose --profile setup run --rm db-migrate
```

Verify output: `✔ Migration applied successfully`

### 6. Deploy Services

- [ ] Deploy postgres first, wait for healthy
- [ ] Deploy redis, wait for healthy
- [ ] Deploy api and worker
- [ ] Deploy web last

### 7. Health Check Verification

```bash
# Check all services
docker compose ps

# Expected:
# vulncenter-web       healthy
# vulncenter-api       healthy
# vulncenter-worker    healthy
# vulncenter-postgres  healthy
# vulncenter-redis     healthy
```

Manually test endpoints:
```bash
# API health
curl https://api.yourdomain.com/health

# Expected response:
# {"status":"healthy","timestamp":"...","services":{"database":"healthy","redis":"healthy"}}
```

## Manual Docker Compose Deployment

### 1. Repository Clone

```bash
git clone https://github.com/vulncenter/vulnn.git
cd vulnn
```

### 2. Environment Configuration

```bash
cp .env.example .env
nano .env  # Edit with your values
```

### 3. Run Migrations

```bash
docker compose --profile setup run --rm db-migrate
```

### 4. Start Services

```bash
# Start all services
docker compose up -d

# Watch startup
docker compose logs -f
```

### 5. Verify Deployment

```bash
# Service status
docker compose ps

# Individual service logs
docker compose logs api
docker compose logs worker
docker compose logs web

# Test API
curl http://localhost:8000/health

# Test Web
curl http://localhost:3000
```

## Post-Deployment Tasks

### 1. Create Admin User

First-time setup requires creating an admin user:

```bash
# Option 1: Via API (if seed script exists)
curl -X POST https://api.yourdomain.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourdomain.com",
    "password": "changeme_strong_password",
    "name": "Admin User",
    "role": "SUPER_ADMIN"
  }'

# Option 2: Direct database (advanced)
docker compose exec postgres psql -U vulncenter -d vulncenter \
  -c "INSERT INTO \"User\" (id, email, \"passwordHash\", name, role, \"mspTenantId\", \"createdAt\") VALUES (...);"
```

### 2. Configure TLS/HTTPS

If not using Coolify's automatic TLS:

```bash
# Install Caddy or Nginx Proxy Manager
# Configure domains
# Obtain Let's Encrypt certificates
# Redirect HTTP → HTTPS
```

### 3. Setup Monitoring

- [ ] Configure log aggregation (e.g., Loki, ELK)
- [ ] Setup Prometheus metrics endpoint
- [ ] Configure alerting for failed health checks
- [ ] Setup database backup strategy

### 4. Security Hardening

- [ ] Enable firewall rules (only allow 80/443)
- [ ] Configure fail2ban for API rate limiting
- [ ] Review and restrict `ALLOW_PRIVATE_IPS`
- [ ] Enable database connection encryption
- [ ] Configure Redis AUTH if not already done
- [ ] Review worker container capabilities

### 5. Backup Configuration

```bash
# Create backup script
cat > /usr/local/bin/vulncenter-backup.sh << 'EOF'
#!/bin/bash
docker compose exec postgres pg_dump -U vulncenter vulncenter | gzip > /backups/vulncenter-$(date +%Y%m%d-%H%M%S).sql.gz
docker compose exec redis redis-cli SAVE
cp -r /var/lib/docker/volumes/vulncenter-* /backups/
EOF

chmod +x /usr/local/bin/vulncenter-backup.sh

# Add to crontab
echo "0 2 * * * /usr/local/bin/vulncenter-backup.sh" | crontab -
```

## Troubleshooting

### Services Won't Start

1. Check database connectivity:
   ```bash
   docker compose exec postgres pg_isready
   ```

2. Verify Redis connection:
   ```bash
   docker compose exec redis redis-cli ping
   ```

3. Review logs:
   ```bash
   docker compose logs api | tail -100
   docker compose logs worker | tail -100
   ```

### Migrations Fail

```bash
# Reset failed migration
docker compose --profile setup run --rm db-migrate --force-reset

# Or manual reset (DANGER: deletes data)
docker compose exec postgres psql -U vulncenter -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
docker compose --profile setup run --rm db-migrate
```

### CORS Errors

- Verify `CORS_ORIGIN` exactly matches frontend URL
- Include protocol: `https://` not just domain
- No trailing slashes

### Worker Scans Timeout

1. Check network connectivity:
   ```bash
   docker compose exec worker ping 8.8.8.8
   ```

2. Verify tools installed:
   ```bash
   docker compose exec worker which nmap nuclei nikto testssl
   ```

3. Increase timeout in `.env`:
   ```
   SCAN_TIMEOUT_MS=3600000  # 60 minutes
   ```

## Rollback Procedure

If deployment fails:

```bash
# Stop new deployment
docker compose down

# Restore database from backup
gunzip -c /backups/vulncenter-YYYYMMDD.sql.gz | docker compose exec -T postgres psql -U vulncenter

# Restart old version
docker compose up -d
```

## Maintenance

### Routine Tasks

**Weekly:**
- [ ] Review scan logs for errors
- [ ] Check disk space usage
- [ ] Verify backup integrity

**Monthly:**
- [ ] Update Nuclei templates
- [ ] Review user access logs
- [ ] Rotate JWT secrets (requires user re-auth)
- [ ] Check for security updates

**Quarterly:**
- [ ] Full platform update
- [ ] Penetration test the platform itself
- [ ] Review and update firewall rules
- [ ] Disaster recovery drill

## Support Contacts

- Documentation: https://docs.vulncenter.io
- GitHub Issues: https://github.com/vulncenter/vulnn/issues
- Emergency: [Your contact info]

---

**Last Updated:** 2024-01-01  
**Version:** 1.0.0