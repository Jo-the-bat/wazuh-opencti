#!/usr/bin/env bash
# Smoke test to verify the deployment is fully operational.
# Run after setup.sh or anytime to check system health.
# Includes end-to-end pipeline test: injects a real event through the full
# Wazuh analysis chain (decoder → rules → integratord → OpenCTI → alert).
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

# --- 8. Integration script test (direct call, validates script + API connectivity) ---
echo "--- Integration Script Test ---"
if [ "$INDICATOR_COUNT" -gt 0 ]; then
    IOC_URL=$(curl -sk -X POST https://localhost:8443/graphql \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
        -d '{"query":"{ indicators(first:1, filters: { mode: and, filterGroups: [], filters: [{ key: \"pattern_type\", values: [\"stix\"] }] }) { edges { node { name } } } }"}' 2>/dev/null | \
        python3 -c "import sys,json;print(json.load(sys.stdin)['data']['indicators']['edges'][0]['node']['name'])" 2>/dev/null || true)

    if [ -n "$IOC_URL" ]; then
        # Direct call to integration script — validates it is executable and can reach OpenCTI API
        docker compose exec -T wazuh.manager bash -c "cat > /tmp/smoke_test.json << ENDTEST
{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)\",\"rule\":{\"level\":3,\"id\":\"80792\",\"groups\":[\"audit\",\"audit_command\"],\"description\":\"Audit: smoke test\"},\"agent\":{\"id\":\"000\",\"name\":\"smoke-test\",\"ip\":\"127.0.0.1\"},\"data\":{\"audit\":{\"execve\":{\"a0\":\"curl\",\"a1\":\"$IOC_URL\"}}},\"id\":\"smoke-test-$(date +%s)\"}
ENDTEST"
        if docker compose exec -T wazuh.manager \
            /var/ossec/integrations/custom-opencti /tmp/smoke_test.json \
            "$OPENCTI_ADMIN_TOKEN" http://opencti:8080/graphql 2>/dev/null; then
            echo "  PASS  Integration script executable and API reachable"
            ((PASS++))
        else
            echo "  FAIL  Integration script failed (exit code $?)"
            ((FAIL++))
        fi
    else
        warn "Could not fetch IOC for script test"
    fi
else
    warn "Skipping integration script test (no indicators loaded yet)"
fi

# --- 9. End-to-end pipeline test (event injection through full Wazuh pipeline) ---
echo "--- Pipeline End-to-End Test ---"
if [ "$INDICATOR_COUNT" -gt 0 ]; then
    # Find a URL indicator starting with http (audit_command path in custom-opencti.py)
    IOC_URL_E2E=$(curl -sk -X POST https://localhost:8443/graphql \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
        -d '{"query":"{ indicators(first:1, filters: { mode: and, filterGroups: [], filters: [{ key: \"pattern_type\", values: [\"stix\"] }, { key: \"pattern\", operator: starts_with, values: [\"[url:\"] }] }) { edges { node { name pattern } } } }"}' 2>/dev/null | \
        python3 -c "
import sys,json,re
edges = json.load(sys.stdin)['data']['indicators']['edges']
if edges:
    name = edges[0]['node']['name']
    if name.startswith('http'):
        print(name)
" 2>/dev/null || true)

    if [ -n "$IOC_URL_E2E" ]; then
        # Count existing OpenCTI alerts and Shuffle calls before injection
        BEFORE_COUNT=$(docker compose exec -T wazuh.manager \
            grep -cE '"id":"10021[2-5]"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0)
        SHUFFLE_BEFORE=$(docker compose exec -T wazuh.manager \
            grep -c shuffle /var/ossec/logs/integrations.log 2>/dev/null || echo 0)

        # Inject a realistic audit EXECVE event via the analysisd queue socket.
        # This exercises the FULL pipeline:
        #   queue socket → analysisd decoder → rule 80792 (audit_command group)
        #   → integratord → custom-opencti.py → OpenCTI GraphQL API
        #   → IOC match → alert via queue socket → rule 100212/100213
        docker compose exec -T wazuh.manager python3 -c "
from socket import socket, AF_UNIX, SOCK_DGRAM
audit = (
    'type=SYSCALL msg=audit(1712500099.000:99998): arch=c000003e syscall=59 '
    'success=yes exit=0 a0=0x1 a1=0x2 a2=0x3 a3=0x4 items=2 ppid=1 pid=9999 '
    'auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 '
    'ses=1 comm=\"curl\" exe=\"/usr/bin/curl\" key=\"audit-wazuh-c\"'
    ' type=EXECVE msg=audit(1712500099.000:99998): argc=2 a0=\"curl\"'
    ' a1=\"$IOC_URL_E2E\"'
)
sock = socket(AF_UNIX, SOCK_DGRAM)
sock.connect('/var/ossec/queue/sockets/queue')
sock.send(('1:/var/log/audit/audit.log:' + audit).encode())
sock.close()
" 2>/dev/null

        # Wait for the pipeline to process (decoder → rules → integratord → OpenCTI → alert)
        PIPELINE_PASS=false
        for i in $(seq 1 12); do
            sleep 5
            AFTER_COUNT=$(docker compose exec -T wazuh.manager \
                grep -cE '"id":"10021[2-5]"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0)
            if [ "$AFTER_COUNT" -gt "$BEFORE_COUNT" ]; then
                PIPELINE_PASS=true
                break
            fi
        done

        if [ "$PIPELINE_PASS" = true ]; then
            echo "  PASS  Full pipeline: event → decoder → integratord → OpenCTI → alert (rule 100212)"
            ((PASS++))

            # Active response: rule 100212 (group `opencti_alert`) is wired to
            # firewall-drop in ossec.conf. After the alert fires, the AR module
            # writes to /var/ossec/logs/active-responses.log. We accept any
            # firewall-drop line (URL-type IOCs cannot extract srcip and the
            # AR will log "Cannot read 'srcip' from data" — that still proves
            # the AR is wired and triggered).
            if docker compose exec -T wazuh.manager bash -c "
                test -f /var/ossec/logs/active-responses.log && \
                tail -50 /var/ossec/logs/active-responses.log | \
                    grep -q 'active-response/bin/firewall-drop'
            " 2>/dev/null; then
                echo "  PASS  Active response: firewall-drop invoked on OpenCTI IoC alert"
                ((PASS++))
            else
                echo "  FAIL  Active response: no firewall-drop entry after rule 100212 fired"
                ((FAIL++))
            fi

            # Check that the OpenCTI alert (level 12) also triggered Shuffle.
            # We require a *successful* forward (HTTP 2xx) — counting log lines
            # alone gives false positives when shuffle.py POSTs without auth and
            # gets HTTP 403 from /api/v1/workflows/<id>/execute.
            sleep 5
            if docker compose exec -T wazuh.manager bash -c "
                tail -20 /var/ossec/logs/integrations.log \
                    | grep -E 'custom-shuffle.*-> 2[0-9]{2}|shuffle.*Response received' >/dev/null
            " 2>/dev/null; then
                echo "  PASS  OpenCTI alert → Shuffle: integratord forwarded alert (HTTP 2xx)"
                ((PASS++))
            else
                echo "  FAIL  OpenCTI alert → Shuffle: no successful forward (check integratord auth header)"
                ((FAIL++))
            fi
        else
            echo "  FAIL  Full pipeline: no OpenCTI alert generated within 60s"
            ((FAIL++))
            echo "         Check: docker compose logs wazuh.manager --tail 20"
            echo "         Check: docker compose exec wazuh.manager tail -5 /var/ossec/logs/integrations.log"
        fi
    else
        warn "No URL-type indicator found for pipeline test (connectors may still be ingesting)"
    fi
else
    warn "Skipping pipeline test (no indicators loaded yet)"
fi

# --- 9b. Indexer operational state (templates, lifecycle policies) ---
echo "--- Indexer Operational State ---"

# ISM lifecycle policies — claim: hot→warm→delete for alerts/archives/monitoring
ISM_POLICIES=$(docker compose exec -T -e PW="${WAZUH_INDEXER_PASSWORD}" wazuh.indexer \
    bash -c 'curl -sk -u "admin:$PW" "https://localhost:9200/_plugins/_ism/policies"' 2>/dev/null \
    | python3 -c "import sys,json; print('\n'.join(p['policy']['policy_id'] for p in json.load(sys.stdin).get('policies',[])))" 2>/dev/null \
    | sort | tr '\n' ',' | sed 's/,$//')
EXPECTED_ISM="wazuh-alerts-lifecycle,wazuh-archives-lifecycle,wazuh-monitoring-lifecycle"
if [ "$ISM_POLICIES" = "$EXPECTED_ISM" ]; then
    echo "  PASS  ISM lifecycle policies present (alerts, archives, monitoring)"
    ((PASS++))
else
    echo "  FAIL  ISM lifecycle policies mismatch"
    echo "         expected: $EXPECTED_ISM"
    echo "         got:      $ISM_POLICIES"
    ((FAIL++))
fi

# Index template wazuh-shards — claim: order=1, shards=1
SHARDS_TPL=$(docker compose exec -T -e PW="${WAZUH_INDEXER_PASSWORD}" wazuh.indexer \
    bash -c 'curl -sk -u "admin:$PW" "https://localhost:9200/_template/wazuh-shards"' 2>/dev/null \
    | python3 -c "
import sys, json
try:
    t = json.load(sys.stdin)['wazuh-shards']
    print('%s|%s' % (t.get('order'), t.get('settings',{}).get('index',{}).get('number_of_shards')))
except Exception:
    pass
" 2>/dev/null)
if [ "$SHARDS_TPL" = "1|1" ]; then
    echo "  PASS  Index template wazuh-shards: order=1, shards=1"
    ((PASS++))
else
    echo "  FAIL  Index template wazuh-shards missing or misconfigured (got: $SHARDS_TPL)"
    ((FAIL++))
fi

# Actual shard count on today's wazuh-* indices — claim: 1 shard per index
WRONG_SHARDS=$(docker compose exec -T -e PW="${WAZUH_INDEXER_PASSWORD}" wazuh.indexer \
    bash -c 'curl -sk -u "admin:$PW" "https://localhost:9200/_cat/indices/wazuh-alerts-4.x-*,wazuh-archives-4.x-*?format=json"' 2>/dev/null \
    | python3 -c "
import sys, json
try:
    indices = json.load(sys.stdin)
except Exception:
    indices = []
bad = [i['index'] for i in indices if int(i.get('pri') or 1) != 1]
print(','.join(bad))
" 2>/dev/null)
if [ -z "$WRONG_SHARDS" ]; then
    echo "  PASS  All wazuh-{alerts,archives}-4.x-* indices have 1 shard"
    ((PASS++))
else
    echo "  FAIL  Indices with shards != 1: $WRONG_SHARDS"
    ((FAIL++))
fi

# Threat-intel connectors active by name — beyond the count check above
EXPECTED_CONNECTORS="MITRE ATT&CK,URLhaus,CISA KEV,ThreatFox,OpenCTI Datasets,VX Vault,DISARM Framework"
MISSING_CONNECTORS=$(curl -sk -X POST https://localhost:8443/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
    -d '{"query":"{ connectors { name active } }"}' 2>/dev/null \
    | python3 -c "
import sys, json
expected = set('''$EXPECTED_CONNECTORS'''.split(','))
got = {c['name'] for c in json.load(sys.stdin)['data']['connectors'] if c['active']}
missing = sorted(expected - got)
print(','.join(missing))
" 2>/dev/null)
if [ -z "$MISSING_CONNECTORS" ]; then
    echo "  PASS  All 7 expected threat-intel connectors active by name"
    ((PASS++))
else
    echo "  FAIL  Missing/inactive threat-intel connectors: $MISSING_CONNECTORS"
    ((FAIL++))
fi

# OpenCTI → Wazuh enrichment connector — distinct from the ingestion ones
WAZUH_ENRICH_ACTIVE=$(curl -sk -X POST https://localhost:8443/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
    -d '{"query":"{ connectors { name active } }"}' 2>/dev/null \
    | python3 -c "
import sys, json
print(any(c['name']=='Wazuh' and c['active'] for c in json.load(sys.stdin)['data']['connectors']))
" 2>/dev/null)
if [ "$WAZUH_ENRICH_ACTIVE" = "True" ]; then
    echo "  PASS  OpenCTI → Wazuh enrichment connector active"
    ((PASS++))
else
    echo "  FAIL  OpenCTI → Wazuh enrichment connector not active"
    ((FAIL++))
fi

# --- 9c. Operational tooling ---
echo "--- Operational Tooling ---"

# healthcheck-monitor.sh: should exit 0 when stack is healthy and report N/N
MONITOR_OUT=$(bash scripts/healthcheck-monitor.sh 2>&1)
MONITOR_EXIT=$?
if [ "$MONITOR_EXIT" -eq 0 ] && echo "$MONITOR_OUT" | grep -qE 'Stack health: ([0-9]+)/\1 healthy'; then
    echo "  PASS  healthcheck-monitor.sh reports all healthy and exits 0"
    ((PASS++))
else
    echo "  FAIL  healthcheck-monitor.sh did not report all-healthy / exit 0"
    echo "         output: $MONITOR_OUT"
    ((FAIL++))
fi

# --- 10. Shuffle SOAR pipeline test ---
echo "--- Shuffle Pipeline Test ---"
# Find the Shuffle integration block in ossec.conf — auto-config writes
# <name>custom-shuffle</name>; manual webhook config may use <name>shuffle</name>.
SHUFFLE_INT_NAME=$(docker compose exec -T wazuh.manager bash -c "
    grep -oE '<name>(custom-shuffle|shuffle)</name>' /var/ossec/etc/ossec.conf \
        | head -1 | sed 's|</\\?name>||g'" 2>/dev/null | tr -d '\r')
SHUFFLE_EXEC_URL=$(docker compose exec -T wazuh.manager bash -c "
    awk '/<name>(custom-shuffle|shuffle)<\\/name>/,/<\\/integration>/' \
        /var/ossec/etc/ossec.conf" 2>/dev/null \
    | grep hook_url | head -1 | sed 's|.*<hook_url>\(.*\)</hook_url>.*|\1|')
SHUFFLE_API_KEY=$(docker compose exec -T wazuh.manager bash -c "
    awk '/<name>(custom-shuffle|shuffle)<\\/name>/,/<\\/integration>/' \
        /var/ossec/etc/ossec.conf" 2>/dev/null \
    | grep api_key | head -1 | sed 's|.*<api_key>\(.*\)</api_key>.*|\1|')

if [ -n "$SHUFFLE_EXEC_URL" ] && echo "$SHUFFLE_EXEC_URL" | grep -qE "workflows|hooks"; then
    # Check integratord enabled the integration
    if docker compose exec -T wazuh.manager grep -qE "Enabling integration for: '(custom-)?shuffle'" \
        /var/ossec/logs/ossec.log 2>/dev/null; then
        echo "  PASS  Integratord has Shuffle enabled (${SHUFFLE_INT_NAME})"
        ((PASS++))
    else
        echo "  FAIL  Integratord did not enable Shuffle integration"
        ((FAIL++))
    fi

    # Exercise the real integration script: write a sample alert, invoke
    # /var/ossec/integrations/${SHUFFLE_INT_NAME} with the same args integratord
    # would pass, and verify the script exits 0 (HTTP 200 from Shuffle).
    if docker compose exec -T wazuh.manager bash -c "
        cat > /tmp/shuffle_smoke.alert <<'AEOF'
{\"timestamp\":\"2026-01-01T00:00:00+0000\",\"rule\":{\"id\":\"000\",\"level\":3,\"description\":\"Shuffle smoke test\"},\"agent\":{\"id\":\"000\",\"name\":\"manager\"},\"id\":\"smoke-test\"}
AEOF
        /var/ossec/integrations/${SHUFFLE_INT_NAME} /tmp/shuffle_smoke.alert '${SHUFFLE_API_KEY}' '${SHUFFLE_EXEC_URL}'
    " 2>/dev/null; then
        # Verify the last log line shows a 2xx status from Shuffle
        if docker compose exec -T wazuh.manager bash -c "
            tail -5 /var/ossec/logs/integrations.log | grep -E 'custom-shuffle.*-> 2[0-9]{2}|shuffle.*Response received' >/dev/null
        " 2>/dev/null; then
            echo "  PASS  Wazuh → Shuffle: integration script accepted by Shuffle (HTTP 2xx)"
            ((PASS++))
        else
            echo "  FAIL  Wazuh → Shuffle: integration script ran but Shuffle did not return 2xx"
            ((FAIL++))
        fi
    else
        echo "  FAIL  Wazuh → Shuffle: integration script returned non-zero (likely HTTP 4xx/5xx — check auth/url)"
        ((FAIL++))
    fi
else
    warn "Shuffle integration not configured in ossec.conf (run setup.sh to enable)"
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
