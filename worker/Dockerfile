# ──────────────────────────────────────────────────────────────
# VulnCenter Scan Worker Image
# Multi-tool Security Scanning Worker
# Contains: Node.js runtime + Nmap + Nuclei + Nikto + testssl.sh
# ──────────────────────────────────────────────────────────────

# Stage 1: Build dependencies
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++ git

# Copy all source files first
COPY package*.json ./
COPY tsconfig.json ./
COPY src/ ./src/

# Install ALL dependencies (including dev for TypeScript build)
RUN npm ci

# Verify source files are present
RUN ls -la src/ && ls -la src/lib/

# Build the TypeScript code
RUN npm run build

# Verify build output
RUN ls -la dist/

# Stage 2: Runtime image with security tools
FROM node:20-alpine

# Prevent container from running as root
ARG UID=1001
ARG GID=1001
ARG USER=scanworker

# ─── Install Security Scanning Tools ────────────────────────
# We install the latest versions from official sources
RUN apk add --no-cache \
    # Base tools
    bash \
    curl \
    wget \
    ca-certificates \
    jq \
    coreutils \
    findutils \
    grep \
    gzip \
    tar \
    xz \
    openssl \
    bind-tools \
    iputils \
    # Nmap for network scanning
    nmap \
    nmap-scripts \
    nmap-ncat \
    # Nikto for web scanning
    perl \
    perl-net-ssleay \
    perl-utils \
    # TestSSL dependencies
    socat \
    procps \
    util-linux \
    # General
    git \
    && rm -rf /var/cache/apk/*

# ─── Install Nuclei (ProjectDiscovery) ──────────────────────
RUN TARGETARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') && \
    curl -fsSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.x_linux_${TARGETARCH}.tar.gz \
    | tar xz -C /usr/local/bin/ nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && nuclei -version

# ─── Install Nikto ─────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && nikto -Version 2>/dev/null || true

# ─── Install testssl.sh ────────────────────────────────────
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && chmod +x /opt/testssl/testssl.sh \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

# ─── Download Nuclei Templates ─────────────────────────────
ENV NUCLEI_TEMPLATES_PATH=/opt/nuclei-templates
RUN mkdir -p /opt/nuclei-templates \
    && nuclei -update-templates \
    && nuclei -silent -ut -ud /opt/nuclei-templates 2>/dev/null || true

# ─── Create non-root user ──────────────────────────────────
RUN addgroup -g ${GID} -S ${USER} \
    && adduser -u ${UID} -S ${USER} -G ${USER} -h /home/${USER} \
    && mkdir -p /home/${USER}/.nuclei \
    && chown -R ${USER}:${USER} /home/${USER} \
    && chown -R ${USER}:${USER} /opt/nuclei-templates 2>/dev/null || true

# ─── Application Setup ─────────────────────────────────────
WORKDIR /app

# Copy runtime dependencies from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Copy compiled worker code
COPY dist/ ./dist/

# Ensure non-root ownership
RUN chown -R ${USER}:${USER} /app

# Drop all root capabilities
USER ${USER}

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD node /app/dist/healthcheck.js 2>/dev/null || exit 1

# Security labels
LABEL maintainer="vulncenter@nousresearch.com"
LABEL org.opencontainers.image.title="VulnCenter Scan Worker"
LABEL org.opencontainers.image.description="Multi-tool security scanning worker for VulnCenter platform"
LABEL org.opencontainers.image.vendor="Nous Research"
LABEL org.opencontainers.image.version="1.0.0"

# Run with non-root user
ENTRYPOINT ["node", "/app/dist/worker.js"]