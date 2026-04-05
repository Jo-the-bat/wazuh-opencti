#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================"
echo "  Wazuh + OpenCTI Docker Setup (HTTPS)"
echo "============================================"
echo

# --- Helpers ---
generate_uuid() {
    python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null \
        || cat /proc/sys/kernel/random/uuid 2>/dev/null \
        || uuidgen
}
generate_password() {
    head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c "${1:-24}"
}
# Wazuh 4.14+ requires passwords with upper, lower, digit, and special chars
generate_wazuh_password() {
    echo "$(generate_password 14)@Wz1!"
}

# ------------------------------------------
# 1. Prerequisites
# ------------------------------------------
echo "[1/9] Checking prerequisites..."
command -v docker &>/dev/null || { echo "ERROR: docker not found." >&2; exit 1; }
docker compose version &>/dev/null || { echo "ERROR: docker compose not found." >&2; exit 1; }
command -v openssl &>/dev/null || { echo "ERROR: openssl not found." >&2; exit 1; }
echo "  OK"

# ------------------------------------------
# 2. Kernel parameters
# ------------------------------------------
echo "[2/9] Checking kernel parameters..."
MAP_COUNT=$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)
if [ "$MAP_COUNT" -lt 262144 ]; then
    echo "  ERROR: vm.max_map_count=$MAP_COUNT (need >=262144)."
    echo "  Run: sudo sysctl -w vm.max_map_count=1048575"
    exit 1
fi
echo "  vm.max_map_count=$MAP_COUNT (OK)"

# ------------------------------------------
# 3. Generate .env
# ------------------------------------------
echo "[3/9] Generating .env..."
if [ -f .env ]; then
    echo "  .env exists, skipping. Delete it to regenerate."
else
    WAZUH_INDEXER_PASSWORD=$(generate_wazuh_password)
    WAZUH_API_PASSWORD=$(generate_wazuh_password)
    WAZUH_DASHBOARD_PASSWORD=$(generate_wazuh_password)
    OPENCTI_ADMIN_PASSWORD=$(generate_password 20)
    OPENCTI_ADMIN_TOKEN=$(generate_uuid)
    MINIO_ROOT_PASSWORD=$(generate_password 20)
    RABBITMQ_DEFAULT_PASS=$(generate_password 20)
    ELASTIC_PASSWORD=$(generate_password 20)
    REDIS_PASSWORD=$(generate_password 20)
    OPENCTI_HEALTH_KEY=$(generate_password 16)
    SHUFFLE_DEFAULT_PASSWORD=$(generate_password 20)
    SHUFFLE_DEFAULT_APIKEY=$(generate_uuid)
    SHUFFLE_ENCRYPTION_MODIFIER=$(generate_password 32)

    cat > .env << ENVEOF
# ==========================================
# Wazuh + OpenCTI Configuration
# ==========================================

# --- Wazuh ---
WAZUH_VERSION=4.14.4
WAZUH_CERTS_GENERATOR_VERSION=0.0.2
WAZUH_INDEXER_PASSWORD=${WAZUH_INDEXER_PASSWORD}
WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD}
WAZUH_DASHBOARD_PASSWORD=${WAZUH_DASHBOARD_PASSWORD}

# --- OpenCTI ---
OPENCTI_VERSION=6.9.28
OPENCTI_BASE_URL=https://localhost:8443
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=${OPENCTI_ADMIN_PASSWORD}
OPENCTI_ADMIN_TOKEN=${OPENCTI_ADMIN_TOKEN}
OPENCTI_PORT=8443
OPENCTI_HEALTH_KEY=${OPENCTI_HEALTH_KEY}

# --- Elasticsearch (for OpenCTI) ---
ELASTICSEARCH_VERSION=8.19.13
ELASTIC_MEMORY_SIZE=3G
ELASTIC_PASSWORD=${ELASTIC_PASSWORD}

# --- Redis ---
REDIS_VERSION=7.4
REDIS_PASSWORD=${REDIS_PASSWORD}

# --- RabbitMQ ---
RABBITMQ_VERSION=4.2.5-management
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=${RABBITMQ_DEFAULT_PASS}

# --- MinIO ---
MINIO_VERSION=RELEASE.2025-09-07T16-13-09Z
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}

# --- Internal Connector IDs ---
CONNECTOR_EXPORT_FILE_STIX_ID=$(generate_uuid)
CONNECTOR_EXPORT_FILE_CSV_ID=$(generate_uuid)
CONNECTOR_IMPORT_FILE_STIX_ID=$(generate_uuid)
CONNECTOR_IMPORT_DOCUMENT_ID=$(generate_uuid)

# --- Threat Intel Connector IDs (free, no API key) ---
CONNECTOR_MITRE_ID=$(generate_uuid)
CONNECTOR_OPENCTI_DATASETS_ID=$(generate_uuid)
CONNECTOR_URLHAUS_ID=$(generate_uuid)
CONNECTOR_CISA_KEV_ID=$(generate_uuid)
CONNECTOR_THREATFOX_ID=$(generate_uuid)
CONNECTOR_VXVAULT_ID=$(generate_uuid)
CONNECTOR_DISARM_ID=$(generate_uuid)

# --- Wazuh-OpenCTI Integration ---
WAZUH_CONNECTOR_VERSION=0.3.0
CONNECTOR_WAZUH_ID=$(generate_uuid)

# --- Optional: API-Key Connectors (uncomment and fill to enable) ---
# Start with: docker compose --profile alienvault --profile abuseipdb --profile cve up -d
#ALIENVAULT_API_KEY=
#CONNECTOR_ALIENVAULT_ID=$(generate_uuid)
#ABUSEIPDB_API_KEY=
#CONNECTOR_ABUSEIPDB_ID=$(generate_uuid)
#CVE_API_KEY=
#CONNECTOR_CVE_ID=$(generate_uuid)

# --- Shuffle SOAR ---
SHUFFLE_VERSION=v2.2.0
SHUFFLE_OPENSEARCH_VERSION=2.14.0
SHUFFLE_DEFAULT_USERNAME=admin
SHUFFLE_DEFAULT_PASSWORD=${SHUFFLE_DEFAULT_PASSWORD}
SHUFFLE_DEFAULT_APIKEY=${SHUFFLE_DEFAULT_APIKEY}
SHUFFLE_ENCRYPTION_MODIFIER=${SHUFFLE_ENCRYPTION_MODIFIER}
SHUFFLE_PORT=3443

# --- Monitoring (optional, activate with: docker compose --profile monitoring up -d) ---
PROMETHEUS_VERSION=v3.11.0
CADVISOR_VERSION=v0.56.2
GRAFANA_VERSION=12.4.2
GRAFANA_ADMIN_PASSWORD=$(generate_password 16)

# --- SMTP (optional) ---
SMTP_HOSTNAME=localhost  # Change to real SMTP server for email alerts

# --- Nginx hostname (used for self-signed cert CN and SAN) ---
OPENCTI_HOSTNAME=localhost
ENVEOF
    echo "  Generated with random passwords and UUIDs."
fi

# ------------------------------------------
# 4. Source .env and generate config files
# ------------------------------------------
echo "[4/9] Generating config files..."
set -a; source .env; set +a

# --- Generate bcrypt hashes for Wazuh indexer internal users ---
echo "  Generating bcrypt hashes (pulling indexer image if needed)..."
generate_hash() {
    docker run --rm "wazuh/wazuh-indexer:${WAZUH_VERSION}" \
        bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$1" 2>/dev/null \
        | grep '^\$2'
}
ADMIN_HASH=$(generate_hash "$WAZUH_INDEXER_PASSWORD")
DASHBOARD_HASH=$(generate_hash "$WAZUH_DASHBOARD_PASSWORD")

if [ -z "$ADMIN_HASH" ] || [ -z "$DASHBOARD_HASH" ]; then
    echo "  ERROR: Bcrypt hash generation failed." >&2
    echo "  Ensure Docker can pull wazuh/wazuh-indexer:${WAZUH_VERSION}" >&2
    exit 1
fi

# --- internal_users.yml ---
cat > config/wazuh_indexer/internal_users.yml << IUEOF
---
_meta:
  type: "internalusers"
  config_version: 2
admin:
  hash: "${ADMIN_HASH}"
  reserved: true
  backend_roles:
    - "admin"
  description: "Admin user"
kibanaserver:
  hash: "${DASHBOARD_HASH}"
  reserved: true
  description: "Wazuh dashboard user"
IUEOF

# --- wazuh.yml (dashboard plugin config) ---
cat > config/wazuh_dashboard/wazuh.yml << WYEOF
hosts:
  - default:
      url: https://wazuh.manager
      port: 55000
      username: wazuh-wui
      password: ${WAZUH_API_PASSWORD}
      run_as: false
WYEOF

# --- wazuh_manager.conf (with real OpenCTI token) ---
WAZUH_CLUSTER_KEY=$(openssl rand -hex 16)
cat > config/wazuh_cluster/wazuh_manager.conf << WMEOF
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
    <email_notification>no</email_notification>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
  </rootcheck>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
  </syscheck>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_dir>etc/rules</rule_dir>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
  </ruleset>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <rule_test>
    <enabled>yes</enabled>
    <threads>1</threads>
    <max_sessions>64</max_sessions>
    <session_timeout>15m</session_timeout>
  </rule_test>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>wazuh-manager</node_name>
    <node_type>master</node_type>
    <key>${WAZUH_CLUSTER_KEY}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>wazuh-manager</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

WMEOF

# Append the integration block with the real token (variable substitution)
cat >> config/wazuh_cluster/wazuh_manager.conf << WMEOF2
  <!-- Shuffle SOAR: uncomment after creating a webhook workflow in Shuffle -->
  <!-- <integration>
    <name>shuffle</name>
    <hook_url>SHUFFLE_WEBHOOK_URL</hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration> -->

  <integration>
    <name>custom-opencti</name>
    <group>sysmon_eid1_detections,sysmon_eid3_detections,sysmon_eid7_detections,sysmon_eid22_detections,syscheck_file,osquery_file,ids,sysmon_process-anomalies,audit_command</group>
    <alert_format>json</alert_format>
    <api_key>${OPENCTI_ADMIN_TOKEN}</api_key>
    <hook_url>http://opencti:8080/graphql</hook_url>
  </integration>
</ossec_config>
WMEOF2

echo "  Config files generated."

# ------------------------------------------
# 5. Generate Wazuh TLS certificates
# ------------------------------------------
echo "[5/9] Generating Wazuh TLS certificates..."
if [ -f config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
    echo "  Already exist, skipping."
else
    docker compose -f generate-indexer-certs.yml run --rm generator
    # Fix cert permissions immediately (generator runs as root, host user needs read access)
    docker run --rm -v "$(pwd)/config/wazuh_indexer_ssl_certs:/certs" alpine \
        sh -c "chmod 755 /certs && chmod 644 /certs/*"
    echo "  Done."
fi
# Ensure root-ca-manager.pem always exists (needed by Wazuh manager filebeat)
[ ! -f config/wazuh_indexer_ssl_certs/root-ca-manager.pem ] && \
    cp config/wazuh_indexer_ssl_certs/root-ca.pem config/wazuh_indexer_ssl_certs/root-ca-manager.pem

# ------------------------------------------
# 6. Generate Nginx self-signed TLS certificate
# ------------------------------------------
echo "[6/9] Generating Nginx TLS certificate..."
OPENCTI_HOSTNAME="${OPENCTI_HOSTNAME:-localhost}"
if [ -f config/nginx/ssl/opencti.crt ]; then
    echo "  Already exists, skipping."
else
    mkdir -p config/nginx/ssl
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout config/nginx/ssl/opencti.key \
        -out config/nginx/ssl/opencti.crt \
        -subj "/C=US/ST=Local/L=Local/O=OpenCTI/CN=${OPENCTI_HOSTNAME}" \
        -addext "subjectAltName=DNS:${OPENCTI_HOSTNAME},DNS:opencti,IP:127.0.0.1" \
        2>/dev/null
    echo "  Done (CN=${OPENCTI_HOSTNAME})."
fi

# ------------------------------------------
# 7. Fix permissions
# ------------------------------------------
echo "[7/9] Fixing permissions..."
# Certs must be world-readable (644/755) because containers run as different UIDs
chmod 755 config/wazuh_indexer_ssl_certs/ 2>/dev/null || true
chmod 644 config/wazuh_indexer_ssl_certs/* 2>/dev/null || true
# Integration scripts must be world-readable+executable because wazuh-integratord
# runs as UID 999 (wazuh) but bind-mounted files are owned by host UID
chmod 755 config/wazuh_integrations/custom-opencti config/wazuh_integrations/custom-opencti.py 2>/dev/null || true
echo "  Done."

# ------------------------------------------
# 8. Start services
# ------------------------------------------
echo "[8/9] Starting services..."
if ! docker compose up -d; then
    echo "  ERROR: docker compose up failed." >&2
    exit 1
fi
echo "  Containers started."

# ------------------------------------------
# 9. Initialize Wazuh indexer security
# ------------------------------------------
echo "[9/9] Waiting for Wazuh indexer to initialize..."
INDEXER_READY=false
for i in $(seq 1 30); do
    # Try custom password first (security may auto-initialize from bind-mounted internal_users.yml),
    # then fall back to default admin:admin for pre-initialization state
    if docker compose exec -T wazuh.indexer bash -c \
        "curl -sku admin:${WAZUH_INDEXER_PASSWORD} https://localhost:9200/_cluster/health" 2>/dev/null | grep -q '"status"'; then
        INDEXER_READY=true
        break
    elif docker compose exec -T wazuh.indexer bash -c \
        "curl -sku admin:admin https://localhost:9200/_cluster/health" 2>/dev/null | grep -q '"status"'; then
        INDEXER_READY=true
        break
    fi
    sleep 5
done

if [ "$INDEXER_READY" != "true" ]; then
    echo "  ERROR: Wazuh indexer did not become ready within 150 seconds." >&2
    echo "  Check logs: docker compose logs wazuh.indexer" >&2
    exit 1
fi

echo "  Running security admin..."
if ! docker compose exec -T wazuh.indexer bash -c '
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd /usr/share/wazuh-indexer/config/opensearch-security/ \
    -nhnv \
    -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
    -cert /usr/share/wazuh-indexer/config/certs/admin.pem \
    -key /usr/share/wazuh-indexer/config/certs/admin-key.pem \
    -icl -h wazuh.indexer
' 2>&1 | tail -5; then
    echo "  WARNING: Security admin returned non-zero (may already be initialized)." >&2
fi

# Enable Filebeat archive forwarding before restarting (default image ships with archives: disabled)
echo "  Enabling Filebeat archive forwarding..."
docker compose exec -T wazuh.manager bash -c \
    'sed -i "/archives:/{n;s/enabled: false/enabled: true/}" /etc/filebeat/filebeat.yml'

# Restart manager and dashboard to pick up new indexer credentials + Filebeat config
docker compose restart wazuh.manager wazuh.dashboard 2>&1 | tail -2

echo
echo "============================================"
echo "  Deployment complete!"
echo "============================================"
echo
echo "  Wazuh Dashboard:  https://localhost:9443"
echo "    Username: admin"
echo "    Password: ${WAZUH_INDEXER_PASSWORD}"
echo
echo "  OpenCTI Platform: https://localhost:8443"
echo "    Email:    ${OPENCTI_ADMIN_EMAIL}"
echo "    Password: ${OPENCTI_ADMIN_PASSWORD}"
echo
echo "  Wazuh Agent Ports: 1514/tcp 1515/tcp 514/udp 55000/tcp"
echo
echo "  Threat intel connectors active:"
echo "    MITRE ATT&CK, URLhaus, CISA KEV, ThreatFox, OpenCTI Datasets"
echo
echo "  Optional connectors (need API keys in .env):"
echo "    docker compose --profile alienvault up -d"
echo "    docker compose --profile abuseipdb up -d"
echo "    docker compose --profile cve up -d"
echo
echo "  Shuffle SOAR:     https://localhost:${SHUFFLE_PORT:-3443}"
echo "    Username: ${SHUFFLE_DEFAULT_USERNAME:-admin}"
echo "    Password: ${SHUFFLE_DEFAULT_PASSWORD}"
echo "    To connect Wazuh alerts to Shuffle:"
echo "      1. Create a workflow in Shuffle with a Webhook trigger"
echo "      2. Copy the webhook URL"
echo "      3. Uncomment the Shuffle integration in ossec.conf"
echo "      4. Restart wazuh.manager"
echo
echo "  Self-signed certs — browser warnings expected."
echo "  Set OPENCTI_HOSTNAME in .env for custom CN."
echo
echo "  Web proxy: cp proxy.env.example proxy.env"
echo "    Then edit proxy.env and restart services."
echo "============================================"
