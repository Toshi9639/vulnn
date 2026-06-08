# ──────────────────────────────────────────────────────────────
# VulnCenter API Dockerfile
# Fastify Backend API Gateway
# ──────────────────────────────────────────────────────────────

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (need dev for Prisma generation)
RUN npm ci

# Copy Prisma schema from db folder and generate client
COPY ../db/schema.prisma ./prisma/schema.prisma
RUN npx prisma generate

# Build the TypeScript code
RUN npm run build

# Stage 2: Production
FROM node:20-alpine

ARG UID=1001
ARG GID=1001
ARG USER=api

# Create non-root user
RUN addgroup -g ${GID} -S ${USER} \
    && adduser -u ${UID} -S ${USER} -G ${USER} -h /home/${USER}

WORKDIR /app

# Copy built artifacts
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
COPY --from=builder /app/prisma/ ./prisma/

# Ensure non-root
RUN chown -R ${USER}:${USER} /app

USER ${USER}

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD node /app/dist/healthcheck.js 2>/dev/null || exit 1

LABEL maintainer="vulncenter@nousresearch.com"
LABEL org.opencontainers.image.title="VulnCenter API"
LABEL org.opencontainers.image.description="Fastify API Gateway for VulnCenter platform"
LABEL org.opencontainers.image.vendor="Nous Research"

CMD ["node", "/app/dist/server.js"]