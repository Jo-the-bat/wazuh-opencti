#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BACKUP_DIR="${1:?Usage: bash restore.sh <backup-directory>}"
COMPOSE_PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$SCRIPT_DIR")}"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "ERROR: Backup directory not found: ${BACKUP_DIR}" >&2
    exit 1
fi

echo "============================================"
echo "  Wazuh + OpenCTI + Shuffle Restore"
echo "============================================"
echo
echo "  Backup source: ${BACKUP_DIR}"
echo
echo "  WARNING: This will stop all services and"
echo "  overwrite current data with backup data."
echo
read -p "  Continue? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "  Aborted."
    exit 0
fi

# --- Stop services ---
echo "[1/4] Stopping services..."
docker compose down 2>/dev/null || true
echo "  Done."

# --- Restore configuration ---
# Extract via a root container (matches backup.sh) so we can overwrite the
# root-owned files in config/wazuh_indexer_ssl_certs/ that setup.sh produced
# from a containerized cert generator. A plain `tar xzf` from the user shell
# fails with "file exists / operation not permitted" on those.
echo "[2/4] Restoring configuration files..."
if [ -f "${BACKUP_DIR}/config.tar.gz" ]; then
    docker run --rm \
        -v "$(realpath .):/target" \
        -v "$(realpath "${BACKUP_DIR}/config.tar.gz"):/backup.tar.gz:ro" \
        alpine sh -c "cd /target && tar xzf /backup.tar.gz --overwrite"
    echo "  Done."
else
    echo "  No config backup found, skipping."
fi

# --- Restore volumes ---
echo "[3/4] Restoring Docker volumes..."
for backup_file in "${BACKUP_DIR}"/vol_*.tar.gz; do
    [ -f "$backup_file" ] || continue
    vol_name=$(basename "$backup_file" | sed 's/^vol_//; s/\.tar\.gz$//')
    FULL_VOL="${COMPOSE_PROJECT}_${vol_name}"

    echo "  Restoring ${vol_name}..."
    # Create volume if it doesn't exist
    docker volume create "$FULL_VOL" &>/dev/null || true
    # Clear and restore
    docker run --rm \
        -v "${FULL_VOL}:/target" \
        -v "$(realpath "$backup_file"):/backup.tar.gz:ro" \
        alpine sh -c "rm -rf /target/* && tar xzf /backup.tar.gz -C /target"
done
echo "  Done."

# --- Restart services ---
echo "[4/4] Starting services..."
docker compose up -d
echo "  Done."

echo
echo "============================================"
echo "  Restore complete!"
echo "============================================"
echo "  Services are starting. Check status with:"
echo "    docker compose ps"
echo "============================================"
