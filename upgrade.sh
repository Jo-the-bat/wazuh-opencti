#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================"
echo "  Wazuh + OpenCTI + Shuffle Upgrade"
echo "============================================"
echo

if [ ! -f .env ]; then
    echo "ERROR: .env not found. Run setup.sh first." >&2
    exit 1
fi

set -a; source .env; set +a

echo "  Current versions:"
echo "    Wazuh:         ${WAZUH_VERSION}"
echo "    OpenCTI:       ${OPENCTI_VERSION}"
echo "    Elasticsearch: ${ELASTICSEARCH_VERSION}"
echo "    Shuffle:       ${SHUFFLE_VERSION}"
echo

# --- Pre-flight checks ---
echo "[1/5] Pre-flight checks..."
command -v docker &>/dev/null || { echo "ERROR: docker not found." >&2; exit 1; }
docker compose version &>/dev/null || { echo "ERROR: docker compose not found." >&2; exit 1; }

RUNNING=$(docker compose ps --status running -q 2>/dev/null | wc -l)
echo "  ${RUNNING} containers currently running."

# --- Backup before upgrade ---
echo "[2/5] Creating pre-upgrade backup..."
BACKUP_DIR="./backups/pre-upgrade-$(date +%Y%m%d-%H%M%S)"
bash backup.sh "$BACKUP_DIR"
echo "  Backup saved to: ${BACKUP_DIR}"

# --- Pull new images ---
echo "[3/5] Pulling latest images for configured versions..."
docker compose pull 2>&1 | tail -5
echo "  Done."

# --- Apply upgrade ---
echo "[4/5] Applying upgrade (rolling restart)..."
# Infrastructure services first (order matters)
echo "  Restarting infrastructure..."
for svc in elasticsearch redis rabbitmq minio wazuh.indexer shuffle-opensearch; do
    if docker compose ps "$svc" --status running -q 2>/dev/null | grep -q .; then
        docker compose up -d --no-deps "$svc" 2>/dev/null
        echo "    ${svc}: updated"
    fi
done

# Wait for infrastructure health
echo "  Waiting for infrastructure to be healthy..."
for i in $(seq 1 60); do
    UNHEALTHY=$(docker compose ps --format json 2>/dev/null | grep -c '"unhealthy"' || true)
    STARTING=$(docker compose ps --format json 2>/dev/null | grep -c '"starting"' || true)
    if [ "$UNHEALTHY" -eq 0 ] && [ "$STARTING" -eq 0 ]; then
        break
    fi
    sleep 5
done

# Application services
echo "  Restarting application services..."
for svc in opencti shuffle-backend wazuh.manager; do
    if docker compose ps "$svc" --status running -q 2>/dev/null | grep -q .; then
        docker compose up -d --no-deps "$svc" 2>/dev/null
        echo "    ${svc}: updated"
    fi
done

# Everything else
echo "  Restarting remaining services..."
docker compose up -d 2>/dev/null
echo "  Done."

# --- Verify ---
echo "[5/5] Verifying upgrade..."
sleep 10
docker compose ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null | head -30

echo
echo "============================================"
echo "  Upgrade complete!"
echo "============================================"
echo "  Pre-upgrade backup: ${BACKUP_DIR}"
echo
echo "  To rollback if something went wrong:"
echo "    bash restore.sh ${BACKUP_DIR}"
echo
echo "  To update versions, edit .env and re-run:"
echo "    bash upgrade.sh"
echo "============================================"
