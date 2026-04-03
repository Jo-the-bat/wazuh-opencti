#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BACKUP_DIR="${1:-./backups/$(date +%Y%m%d-%H%M%S)}"
COMPOSE_PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$SCRIPT_DIR")}"

echo "============================================"
echo "  Wazuh + OpenCTI + Shuffle Backup"
echo "============================================"
echo
echo "  Backup directory: ${BACKUP_DIR}"
echo

mkdir -p "$BACKUP_DIR"

# --- Back up .env and config files ---
echo "[1/4] Backing up configuration files..."
tar czf "${BACKUP_DIR}/config.tar.gz" \
    .env \
    config/wazuh_cluster/ \
    config/wazuh_indexer/internal_users.yml \
    config/wazuh_dashboard/wazuh.yml \
    config/wazuh_indexer_ssl_certs/ \
    config/nginx/ssl/ \
    2>/dev/null || true
echo "  Done."

# --- List volumes to back up ---
VOLUMES=(
    esdata
    redisdata
    amqpdata
    s3data
    wazuh-indexer-data
    wazuh_logs
    wazuh_queue
    wazuh_etc
    wazuh_api_configuration
    shuffle-opensearch-data
    shuffle-files
)

# --- Back up Elasticsearch via snapshot API (online, no downtime) ---
echo "[2/4] Backing up Elasticsearch data..."
set -a; source .env 2>/dev/null; set +a

# Try ES snapshot API first (online backup)
if docker compose exec -T elasticsearch curl -sf \
    -u "elastic:${ELASTIC_PASSWORD}" \
    -X PUT "http://localhost:9200/_snapshot/backup" \
    -H "Content-Type: application/json" \
    -d '{"type":"fs","settings":{"location":"/usr/share/elasticsearch/data/backup"}}' \
    2>/dev/null | grep -q "acknowledged"; then
    docker compose exec -T elasticsearch curl -sf \
        -u "elastic:${ELASTIC_PASSWORD}" \
        -X PUT "http://localhost:9200/_snapshot/backup/snap_$(date +%Y%m%d)?wait_for_completion=true" \
        2>/dev/null | grep -q "SUCCESS" && echo "  Elasticsearch snapshot created." || echo "  Elasticsearch snapshot failed, will use volume backup."
else
    echo "  Elasticsearch snapshot API unavailable, will use volume backup."
fi

# --- Back up Docker volumes ---
echo "[3/4] Backing up Docker volumes..."
for vol in "${VOLUMES[@]}"; do
    FULL_VOL="${COMPOSE_PROJECT}_${vol}"
    if docker volume inspect "$FULL_VOL" &>/dev/null; then
        echo "  Backing up ${vol}..."
        docker run --rm \
            -v "${FULL_VOL}:/source:ro" \
            -v "$(realpath "$BACKUP_DIR"):/backup" \
            alpine tar czf "/backup/vol_${vol}.tar.gz" -C /source . 2>/dev/null
    else
        echo "  Skipping ${vol} (not found)"
    fi
done
echo "  Done."

# --- Summary ---
echo "[4/4] Calculating backup size..."
TOTAL_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
FILE_COUNT=$(find "$BACKUP_DIR" -type f | wc -l)

echo
echo "============================================"
echo "  Backup complete!"
echo "============================================"
echo "  Location: ${BACKUP_DIR}"
echo "  Size:     ${TOTAL_SIZE}"
echo "  Files:    ${FILE_COUNT}"
echo
echo "  Restore with: bash restore.sh ${BACKUP_DIR}"
echo "============================================"
