#!/usr/bin/env bash
# Smoke test to verify the deployment is fully operational.
# Run after setup.sh or anytime to check system health.
set -uo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
    echo "ERROR: .env not found. Run setup.sh first." >&2
    exit 1
fi
set -a; source .env; set +a

PASS=0
FAIL=0
WARN=0

check() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS  $label"
        ((PASS++))
    else
        echo "  FAIL  $label"
        ((FAIL++))
    fi
}

warn() {
    local label="$1"
    echo "  WARN  $label"
    ((WARN++))
}

echo "============================================"
echo "  Deployment Smoke Test"
echo "============================================"
echo ""

# --- 1. Container health ---
echo "--- Containers ---"
TOTAL=$(docker compose ps --format "{{.Status}}" 2>/dev/null | wc -l)
HEALTHY=$(docker compose ps --format "{{.Status}}" 2>/dev/null | grep -c "healthy" || true)
if [ "$HEALTHY" -eq "$TOTAL" ] && [ "$TOTAL" -ge 26 ]; then
    echo "  PASS  All $HEALTHY/$TOTAL containers healthy"
    ((PASS++))
else
    echo "  FAIL  Only $HEALTHY/$TOTAL containers healthy"
    ((FAIL++))
    docker compose ps --format "{{.Name}} {{.Status}}" 2>/dev/null | grep -v healthy | sed 's/^/         /'
fi

# --- 2. Wazuh indexer ---
echo "--- Wazuh Indexer ---"
check "Cluster health (green)" \
    docker compose exec -T wazuh.indexer curl -sf -u "admin:${WAZUH_INDEXER_PASSWORD}" \
    "https://localhost:9200/_cluster/health" -k

# --- 3. Wazuh manager API ---
echo "--- Wazuh Manager ---"
API_TOKEN=$(docker compose exec -T wazuh.manager curl -sk \
    -u "wazuh-wui:${WAZUH_API_PASSWORD}" \
    -X POST https://localhost:55000/security/user/authenticate?raw=true 2>/dev/null || true)
if [ -n "$API_TOKEN" ] && [ "$API_TOKEN" != "null" ]; then
    echo "  PASS  API authentication"
    ((PASS++))
else
    echo "  FAIL  API authentication"
    ((FAIL++))
fi

check "OpenCTI rules loaded" \
    docker compose exec -T wazuh.manager curl -sk \
    -H "Authorization: Bearer $API_TOKEN" \
    "https://localhost:55000/rules/files?search=opencti"

check "Integratord running" \
    docker compose exec -T wazuh.manager pgrep -f wazuh-integratord

check "Integration scripts executable" \
    docker compose exec -T wazuh.manager test -x /var/ossec/integrations/custom-opencti

# --- 4. Archive pipeline ---
echo "--- Archive Pipeline ---"
check "logall_json enabled" \
    docker compose exec -T wazuh.manager grep -q "logall_json>yes" /var/ossec/etc/ossec.conf

if docker compose exec -T wazuh.manager grep -A1 "archives:" /etc/filebeat/filebeat.yml 2>/dev/null | grep -q "enabled: true"; then
    echo "  PASS  Filebeat archives enabled"
    ((PASS++))
else
    echo "  FAIL  Filebeat archives enabled"
    ((FAIL++))
fi

ARCHIVE_COUNT=$(docker compose exec -T wazuh.indexer curl -sf -u "admin:${WAZUH_INDEXER_PASSWORD}" \
    "https://localhost:9200/wazuh-archives-*/_count" -k 2>/dev/null | \
    python3 -c "import sys,json;print(json.load(sys.stdin)['count'])" 2>/dev/null || echo 0)
if [ "$ARCHIVE_COUNT" -gt 0 ]; then
    echo "  PASS  Archive index has $ARCHIVE_COUNT docs"
    ((PASS++))
else
    warn "Archive index empty (normal on fresh deploy, data will appear after first events)"
fi

# --- 5. OpenCTI platform ---
echo "--- OpenCTI ---"
check "Platform reachable (HTTPS :8443)" \
    curl -sk -o /dev/null -w '%{http_code}' https://localhost:8443/ | grep -q "200"

INDICATOR_COUNT=$(curl -sk -X POST https://localhost:8443/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
    -d '{"query":"{ indicators(first:1) { pageInfo { globalCount } } }"}' 2>/dev/null | \
    python3 -c "import sys,json;print(json.load(sys.stdin)['data']['indicators']['pageInfo']['globalCount'])" 2>/dev/null || echo 0)
if [ "$INDICATOR_COUNT" -gt 0 ]; then
    echo "  PASS  Threat intel ingested ($INDICATOR_COUNT indicators)"
    ((PASS++))
else
    warn "No indicators yet (connectors may still be ingesting, check again in 5 minutes)"
fi

ACTIVE_CONNECTORS=$(curl -sk -X POST https://localhost:8443/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
    -d '{"query":"{ connectors { active connector_type } }"}' 2>/dev/null | \
    python3 -c "
import sys,json
c = json.load(sys.stdin)['data']['connectors']
ext = [x for x in c if x['connector_type'] == 'EXTERNAL_IMPORT' and x['active']]
print(len(ext))
" 2>/dev/null || echo 0)
check "Threat intel connectors active ($ACTIVE_CONNECTORS)" \
    test "$ACTIVE_CONNECTORS" -ge 5

# --- 6. Nginx proxy ---
echo "--- Nginx HTTPS ---"
check "OpenCTI proxy (:8443)" \
    curl -sk -o /dev/null https://localhost:8443/
check "Shuffle proxy (:3443)" \
    curl -sk -o /dev/null https://localhost:3443/
if curl -sk -I https://localhost:8443/ 2>/dev/null | grep -qi "strict-transport-security"; then
    echo "  PASS  HSTS header present"
    ((PASS++))
else
    echo "  FAIL  HSTS header present"
    ((FAIL++))
fi

# --- 7. Wazuh Dashboard ---
echo "--- Wazuh Dashboard ---"
check "Dashboard reachable (:9443)" \
    curl -sk -o /dev/null https://localhost:9443/

# --- 8. Integration test (optional, requires indicators) ---
echo "--- Integration Test ---"
if [ "$INDICATOR_COUNT" -gt 0 ]; then
    IOC=$(curl -sk -X POST https://localhost:8443/graphql \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
        -d '{"query":"{ indicators(first:1) { edges { node { name } } } }"}' 2>/dev/null | \
        python3 -c "import sys,json;print(json.load(sys.stdin)['data']['indicators']['edges'][0]['node']['name'])" 2>/dev/null || true)

    if [ -n "$IOC" ]; then
        docker compose exec -T wazuh.manager bash -c "cat > /tmp/smoke_test.json << ENDTEST
{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)\",\"rule\":{\"level\":3,\"id\":\"80792\",\"groups\":[\"audit\",\"audit_command\"],\"description\":\"Audit: smoke test\"},\"agent\":{\"id\":\"000\",\"name\":\"smoke-test\",\"ip\":\"127.0.0.1\"},\"data\":{\"audit\":{\"execve\":{\"a0\":\"curl\",\"a1\":\"$IOC\"}}},\"id\":\"smoke-test-$(date +%s)\"}
ENDTEST"
        docker compose exec -T wazuh.manager \
            /var/ossec/integrations/custom-opencti /tmp/smoke_test.json \
            "$OPENCTI_ADMIN_TOKEN" http://opencti:8080/graphql >/dev/null 2>&1

        sleep 5
        if docker compose exec -T wazuh.manager grep -q "smoke-test" /var/ossec/logs/alerts/alerts.json 2>/dev/null; then
            echo "  PASS  Wazuh->OpenCTI: malicious URL generated alert"
            ((PASS++))
        else
            echo "  FAIL  Wazuh->OpenCTI: no alert generated for known IOC"
            ((FAIL++))
        fi
    else
        warn "Could not fetch IOC for integration test"
    fi
else
    warn "Skipping integration test (no indicators loaded yet)"
fi

# --- Summary ---
echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed, $WARN warnings"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "  Troubleshoot failures with:"
    echo "    docker compose ps"
    echo "    docker compose logs <service-name> --tail 50"
    exit 1
fi
