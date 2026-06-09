# ──────────────────────────────────────────────────────────────
# VulnCenter Web Dockerfile
# Next.js Frontend
# ──────────────────────────────────────────────────────────────

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./
COPY next.config.js ./
COPY tailwind.config.ts ./
COPY postcss.config.js ./
COPY components.json ./

RUN npm install --production --no-audit --no-fund

COPY . .

RUN npm run build

# Stage 2: Production
FROM node:20-alpine AS runner

ARG UID=1001
ARG GID=1001
ARG USER=web

# Create non-root user
RUN addgroup -g ${GID} -S ${USER} \
    && adduser -u ${UID} -S ${USER} -G ${USER} -h /home/${USER}

WORKDIR /app

ENV NODE_ENV=production

# Copy production build
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

# Ensure non-root
RUN chown -R ${USER}:${USER} /app

USER ${USER}

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

LABEL maintainer="vulncenter@nousresearch.com"
LABEL org.opencontainers.image.title="VulnCenter Web"
LABEL org.opencontainers.image.description="Next.js Frontend for VulnCenter platform"
LABEL org.opencontainers.image.vendor="Nous Research"

CMD ["node", "server.js"]