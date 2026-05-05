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
    wazuh_var_multigroups
    wazuh_integrations
    wazuh_active_response
    wazuh_agentless
    wazuh_wodles
    filebeat_etc
    filebeat_var
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
# tar against a live Elasticsearch / OpenSearch data dir produces "No such
# file or directory" warnings as Lucene segments get merged/deleted mid-read.
# busybox tar exits 1 on those warnings (the archive is still valid). Exit 2
# is a real error. Treat 0 and 1 as success, anything else as failure.
echo "[3/4] Backing up Docker volumes..."
WARN_LOG="${BACKUP_DIR}/tar-warnings.log"
: >"$WARN_LOG"
for vol in "${VOLUMES[@]}"; do
    FULL_VOL="${COMPOSE_PROJECT}_${vol}"
    if docker volume inspect "$FULL_VOL" &>/dev/null; then
        echo "  Backing up ${vol}..."
        set +e
        docker run --rm \
            -v "${FULL_VOL}:/source:ro" \
            -v "$(realpath "$BACKUP_DIR"):/backup" \
            alpine tar czf "/backup/vol_${vol}.tar.gz" -C /source . \
            2>>"$WARN_LOG"
        RC=$?
        set -e
        if [ "$RC" -gt 1 ]; then
            echo "  FAIL: tar of ${vol} exited ${RC} (see ${WARN_LOG})" >&2
            exit "$RC"
        elif [ "$RC" -eq 1 ]; then
            echo "  (warnings on ${vol}: files changed during read — archive is still usable)"
        fi
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
