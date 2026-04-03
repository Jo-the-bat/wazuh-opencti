#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================"
echo "  Wazuh + OpenCTI Docker Setup (HTTPS)"
echo "============================================"
echo

# ------------------------------------------
# 1. Check prerequisites
# ------------------------------------------
echo "[1/7] Checking prerequisites..."

if ! command -v docker &>/dev/null; then
    echo "ERROR: docker is not installed." >&2
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo "ERROR: docker compose plugin is not installed." >&2
    exit 1
fi

echo "  Docker and Docker Compose are available."

# ------------------------------------------
# 2. Set kernel parameters
# ------------------------------------------
echo "[2/7] Setting kernel parameters..."

CURRENT_MAP_COUNT=$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)
MIN_MAP_COUNT=262144
RECOMMENDED_MAP_COUNT=1048575

if [ "$CURRENT_MAP_COUNT" -lt "$MIN_MAP_COUNT" ]; then
    echo "  ERROR: vm.max_map_count=$CURRENT_MAP_COUNT is too low (minimum: $MIN_MAP_COUNT)."
    echo "  Run: sudo sysctl -w vm.max_map_count=$RECOMMENDED_MAP_COUNT"
    exit 1
elif [ "$CURRENT_MAP_COUNT" -lt "$RECOMMENDED_MAP_COUNT" ]; then
    echo "  vm.max_map_count=$CURRENT_MAP_COUNT (meets minimum $MIN_MAP_COUNT)."
    echo "  Recommended: sudo sysctl -w vm.max_map_count=$RECOMMENDED_MAP_COUNT"
else
    echo "  vm.max_map_count=$CURRENT_MAP_COUNT (OK)."
fi

# ------------------------------------------
# 3. Generate .env file
# ------------------------------------------
echo "[3/7] Generating .env file..."

generate_uuid() {
    python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null \
        || cat /proc/sys/kernel/random/uuid 2>/dev/null \
        || uuidgen
}

generate_password() {
    local len=${1:-24}
    head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c "$len"
}

if [ -f .env ]; then
    echo "  .env already exists, skipping generation."
    echo "  To regenerate, delete .env and re-run this script."
else
    OPENCTI_ADMIN_TOKEN=$(generate_uuid)
    OPENCTI_ADMIN_PASSWORD=$(generate_password 20)
    MINIO_ROOT_PASSWORD=$(generate_password 20)
    RABBITMQ_DEFAULT_PASS=$(generate_password 20)

    cat > .env << ENVEOF
# ============================================
# Wazuh + OpenCTI Environment Configuration
# ============================================

# --- Wazuh Versions ---
WAZUH_VERSION=4.9.2
WAZUH_CERTS_GENERATOR_VERSION=0.0.2

# --- Wazuh Passwords ---
WAZUH_INDEXER_PASSWORD=SecretPassword
WAZUH_API_PASSWORD=MyS3cr37P450r.*-

# --- OpenCTI Version ---
OPENCTI_VERSION=6.4.5

# --- OpenCTI Platform ---
OPENCTI_BASE_URL=https://localhost:8443
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=${OPENCTI_ADMIN_PASSWORD}
OPENCTI_ADMIN_TOKEN=${OPENCTI_ADMIN_TOKEN}
OPENCTI_PORT=8443

# --- Elasticsearch (for OpenCTI) ---
ELASTICSEARCH_VERSION=8.15.3
ELASTIC_MEMORY_SIZE=4G

# --- Redis ---
REDIS_VERSION=7.4

# --- RabbitMQ ---
RABBITMQ_VERSION=3.13-management
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=${RABBITMQ_DEFAULT_PASS}

# --- MinIO ---
MINIO_VERSION=RELEASE.2024-05-28T17-19-04Z
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}

# --- OpenCTI Connector IDs (UUIDs) ---
CONNECTOR_EXPORT_FILE_STIX_ID=$(generate_uuid)
CONNECTOR_EXPORT_FILE_CSV_ID=$(generate_uuid)
CONNECTOR_IMPORT_FILE_STIX_ID=$(generate_uuid)
CONNECTOR_IMPORT_DOCUMENT_ID=$(generate_uuid)

# --- Wazuh-OpenCTI Connector ---
WAZUH_CONNECTOR_VERSION=0.3.0
CONNECTOR_WAZUH_ID=$(generate_uuid)

# --- SMTP (optional) ---
SMTP_HOSTNAME=localhost
ENVEOF

    echo "  .env generated with random passwords and UUIDs."
fi

# ------------------------------------------
# 4. Generate Wazuh TLS certificates
# ------------------------------------------
echo "[4/7] Generating Wazuh TLS certificates..."

if [ -f config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
    echo "  Wazuh certificates already exist, skipping."
else
    docker compose -f generate-indexer-certs.yml run --rm generator

    # Ensure root-ca-manager.pem exists (some generator versions don't create it)
    if [ ! -f config/wazuh_indexer_ssl_certs/root-ca-manager.pem ]; then
        cp config/wazuh_indexer_ssl_certs/root-ca.pem config/wazuh_indexer_ssl_certs/root-ca-manager.pem
    fi

    echo "  Wazuh certificates generated."
fi

# ------------------------------------------
# 5. Generate self-signed TLS certs for Nginx (OpenCTI HTTPS)
# ------------------------------------------
echo "[5/7] Generating Nginx self-signed TLS certificates..."

if [ -f config/nginx/ssl/opencti.crt ]; then
    echo "  Nginx certificates already exist, skipping."
else
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout config/nginx/ssl/opencti.key \
        -out config/nginx/ssl/opencti.crt \
        -subj "/C=US/ST=Local/L=Local/O=OpenCTI/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:opencti,IP:127.0.0.1" \
        2>/dev/null

    echo "  Nginx self-signed certificate generated."
fi

# ------------------------------------------
# 6. Fix file permissions
# ------------------------------------------
echo "[6/7] Fixing file permissions..."

# Wazuh indexer needs specific perms on cert files
chmod -R 660 config/wazuh_indexer_ssl_certs/ 2>/dev/null || true
chmod 770 config/wazuh_indexer_ssl_certs/ 2>/dev/null || true

echo "  Permissions set."

# ------------------------------------------
# 7. Start services
# ------------------------------------------
echo "[7/7] Starting all services..."
echo

docker compose up -d

echo
echo "============================================"
echo "  Deployment complete!"
echo "============================================"
echo
echo "  Wazuh Dashboard (HTTPS):  https://localhost:9443"
echo "    Username: admin"
echo "    Password: SecretPassword"
echo
echo "  OpenCTI Platform (HTTPS): https://localhost:8443"
echo "    Email:    admin@opencti.io"
echo "    Password: $(grep OPENCTI_ADMIN_PASSWORD .env | head -1 | cut -d= -f2)"
echo
echo "  Wazuh Agent Ports:"
echo "    Events:     1514/tcp"
echo "    Enrollment: 1515/tcp"
echo "    Syslog:     514/udp"
echo "    API:        55000/tcp"
echo
echo "  NOTE: Self-signed certificates are used."
echo "  Your browser will show a security warning — this is expected."
echo
echo "  To check status:  docker compose ps"
echo "  To view logs:     docker compose logs -f"
echo "  To stop:          docker compose down"
echo "============================================"
