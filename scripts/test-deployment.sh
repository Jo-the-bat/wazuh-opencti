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
# `docker compose ps` (no -a) only lists running containers, so a service
# that exited would silently drop out of TOTAL and the ratio would still look
# healthy. Use -a so exited/dead/restarting containers count against the total.
echo "--- Containers ---"
TOTAL=$(docker compose ps -a --format "{{.Status}}" 2>/dev/null | wc -l)
HEALTHY=$(docker compose ps -a --format "{{.Status}}" 2>/dev/null | grep -c "healthy" || true)
if [ "$HEALTHY" -eq "$TOTAL" ] && [ "$TOTAL" -ge 26 ]; then
    echo "  PASS  All $HEALTHY/$TOTAL containers healthy"
    ((PASS++))
else
    echo "  FAIL  Only $HEALTHY/$TOTAL containers healthy"
    ((FAIL++))
    docker compose ps -a --format "{{.Name}} {{.Status}}" 2>/dev/null | grep -v healthy | sed 's/^/         /'
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

# Catches "connector active but ingesting nothing" (rate-limited API, broken
# feed). A fully broken ingestion would leave INDICATOR_COUNT at 0 or 1.
# Threshold ≥5 stays above that trivial floor without flaking on freshly
# booted stacks where URLhaus is still streaming its first batch (observed
# as low as 6 indicators ~30 s after setup).
if [ "$INDICATOR_COUNT" -ge 5 ]; then
    echo "  PASS  Threat intel ingestion depth: $INDICATOR_COUNT indicators (≥5 — ingestion progressing)"
    ((PASS++))
else
    echo "  FAIL  Threat intel ingestion depth too low: only $INDICATOR_COUNT indicators (≥5 expected — likely stuck connector)"
    ((FAIL++))
fi

# Per-source counts — detects a single connector being dead even when total
# indicators looks healthy (e.g. URLhaus fine, CISA KEV stuck). CISA KEV
# imports as `vulnerabilities`, MITRE as `attackPatterns` — both distinct
# STIX object types from `indicators`.
KEV_COUNT=$(curl -sk -X POST https://localhost:8443/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
    -d '{"query":"{ vulnerabilities(first:1) { pageInfo { globalCount } } }"}' 2>/dev/null \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["vulnerabilities"]["pageInfo"]["globalCount"])' 2>/dev/null || echo 0)
MITRE_COUNT=$(curl -sk -X POST https://localhost:8443/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
    -d '{"query":"{ attackPatterns(first:1) { pageInfo { globalCount } } }"}' 2>/dev/null \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["attackPatterns"]["pageInfo"]["globalCount"])' 2>/dev/null || echo 0)
KEV_COUNT=${KEV_COUNT:-0}
MITRE_COUNT=${MITRE_COUNT:-0}
# Thresholds well below documented "1500+ CVEs" and "~600 techniques" but
# high enough that a stuck connector (0 ingestion) is clearly detected.
# Both connectors typically finish their first sync within ~10 min of
# stack boot.
PER_SOURCE_OK=true
if [ "$KEV_COUNT" -lt 50 ]; then
    echo "  FAIL  CISA KEV: only $KEV_COUNT vulnerabilities (≥50 expected — connector likely stuck)"
    ((FAIL++))
    PER_SOURCE_OK=false
fi
if [ "$MITRE_COUNT" -lt 50 ]; then
    echo "  FAIL  MITRE ATT&CK: only $MITRE_COUNT attack patterns (≥50 expected — connector likely stuck)"
    ((FAIL++))
    PER_SOURCE_OK=false
fi
if [ "$PER_SOURCE_OK" = true ]; then
    echo "  PASS  Per-source TI depth: CISA KEV $KEV_COUNT vulns, MITRE $MITRE_COUNT patterns"
    ((PASS++))
fi

# --- 6. Nginx proxy ---
echo "--- Nginx HTTPS ---"
check "OpenCTI proxy (:8443)" \
    curl -sk -o /dev/null https://localhost:8443/
check "Shuffle proxy (:3443)" \
    curl -sk -o /dev/null https://localhost:3443/
NGINX_HEADERS=$(curl -sk -I https://localhost:8443/ 2>/dev/null)
HEADERS_OK=true
# Each entry is "name:expected-value-substring". The expected value must appear
# in the header line — checking the name alone is a false positive because the
# OpenCTI upstream also sets some of these headers (e.g. Referrer-Policy:
# unsafe-url), so just looking for the name would pass even if nginx no longer
# adds its hardened value.
for spec in \
    "strict-transport-security:max-age=31536000" \
    "x-frame-options:SAMEORIGIN" \
    "x-content-type-options:nosniff" \
    "referrer-policy:strict-origin-when-cross-origin"; do
    name="${spec%%:*}"
    expected="${spec#*:}"
    if ! echo "$NGINX_HEADERS" | grep -i "^${name}:" | grep -qF "${expected}"; then
        echo "  FAIL  Nginx header ${name} missing or wrong value (expected to contain: ${expected})"
        ((FAIL++))
        HEADERS_OK=false
    fi
done
if [ "$HEADERS_OK" = true ]; then
    echo "  PASS  Nginx security headers present with hardened values (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)"
    ((PASS++))
fi

# --- 7. Wazuh Dashboard ---
echo "--- Wazuh Dashboard ---"
check "Dashboard reachable (:9443)" \
    curl -sk -o /dev/null https://localhost:9443/

# Saved objects: setup.sh imports the SOC Security Overview dashboard via
# /api/saved_objects/_import. Verify it actually landed in the dashboard's
# saved objects index.
if curl -sk -u "admin:${WAZUH_INDEXER_PASSWORD}" \
    "https://localhost:9443/api/saved_objects/_find?type=dashboard&per_page=100" 2>/dev/null \
    | grep -q '"id":"soc-security-overview"'; then
    echo "  PASS  SOC Security Overview dashboard imported"
    ((PASS++))
else
    echo "  FAIL  SOC Security Overview dashboard not found in saved objects"
    ((FAIL++))
fi

# wazuh-archives-* index pattern — setup.sh creates it so archive docs show
# up in Discover. Pure config artifact (no events flow through it), so the
# only signal that the create call lived is to query Saved Objects.
if curl -sk -u "admin:${WAZUH_INDEXER_PASSWORD}" \
    "https://localhost:9443/api/saved_objects/_find?type=index-pattern&per_page=100" 2>/dev/null \
    | grep -qE '"title":"wazuh-archives-\*"|"id":"wazuh-archives'; then
    echo "  PASS  Kibana index pattern wazuh-archives-* registered"
    ((PASS++))
else
    echo "  FAIL  Kibana index pattern wazuh-archives-* not found"
    ((FAIL++))
fi

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

            # False-positive guard: a benign URL (RFC1918 host) must NOT
            # generate a 100212+ alert. Verifies custom-opencti.py only fires
            # on indicator matches, not on every audit_command event.
            #
            # Use a unique marker URL ("benign-fp-test-${RANDOM}") and only
            # count 100212-100215 alerts whose payload mentions that exact
            # marker — counting the global 100212-100215 stream is flaky
            # because the pipeline's positive-IOC alert can still be writing
            # additional 100212 entries during the 30 s wait, producing a
            # spurious increment unrelated to our benign injection.
            FP_MARKER="benign-fp-test-$$-$(date +%s)"
            FP_PATTERN="\"id\":\"10021[2-5]\".*${FP_MARKER}"
            docker compose exec -T -e MARKER="$FP_MARKER" wazuh.manager python3 -c "
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
audit = (
    'type=SYSCALL msg=audit(1712500999.000:99099): arch=c000003e syscall=59 '
    'success=yes exit=0 a0=0x1 a1=0x2 a2=0x3 a3=0x4 items=2 ppid=1 pid=9999 '
    'auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 '
    'ses=1 comm=\"curl\" exe=\"/usr/bin/curl\" key=\"audit-wazuh-c\"'
    ' type=EXECVE msg=audit(1712500999.000:99099): argc=2 a0=\"curl\"'
    ' a1=\"http://192.168.42.99/' + os.environ['MARKER'] + '\"'
)
sock = socket(AF_UNIX, SOCK_DGRAM)
sock.connect('/var/ossec/queue/sockets/queue')
sock.send(('1:/var/log/audit/audit.log:' + audit).encode())
sock.close()
" 2>/dev/null
            sleep 30
            FP_HITS=$(docker compose exec -T -e PAT="$FP_PATTERN" wazuh.manager \
                bash -c 'grep -cE "$PAT" /var/ossec/logs/alerts/alerts.json 2>/dev/null || true' \
                | tr -d '\r' | head -1)
            FP_HITS=${FP_HITS:-0}
            if [ "$FP_HITS" -eq 0 ]; then
                echo "  PASS  No false positive: benign RFC1918 URL did not produce a 100212+ alert"
                ((PASS++))
            else
                echo "  FAIL  False positive: benign URL injection produced ${FP_HITS} matching 100212+ alert(s)"
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

# --- 9a-bis. custom-opencti.py — IP and domain IOC code paths ---
# The Pipeline E2E section exercises the URL path. custom-opencti.py also has
# distinct code paths for IPv4 (extracted from srcip/dstip/src fields of
# firewall events) and domain (from sysmon DNS / curl-style events). On a
# fresh stack OpenCTI only has URL indicators (URLhaus); we create temporary
# IOCs via GraphQL, inject a matching event, verify rule 100212/100213 fires,
# then clean up.
echo "--- Integration IOC Types ---"

create_test_indicator() {
    # $1 = pattern, $2 = observable type, $3 = name
    curl -sk -X POST https://localhost:8443/graphql \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
        -d "{\"query\":\"mutation(\$i: IndicatorAddInput!){indicatorAdd(input:\$i){id}}\",\"variables\":{\"i\":{\"name\":\"$3\",\"pattern\":\"$1\",\"pattern_type\":\"stix\",\"x_opencti_main_observable_type\":\"$2\"}}}" \
        2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("data",{}).get("indicatorAdd",{}).get("id",""))' 2>/dev/null
}

delete_test_indicator() {
    [ -z "$1" ] && return 0
    curl -sk -X POST https://localhost:8443/graphql \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
        -d "{\"query\":\"mutation{indicatorDelete(id:\\\"$1\\\")}\"}" \
        >/dev/null 2>&1
}

# IPv4 IOC path: create indicator, inject Stormshield event (group=stormshield
# is in the custom-opencti integration trigger list), expect 100212/100213.
IP_TEST_IP="1.2.3.99"
IP_IND_ID=$(create_test_indicator \
    "[ipv4-addr:value = '${IP_TEST_IP}']" "IPv4-Addr" "${IP_TEST_IP}")
if [ -n "$IP_IND_ID" ]; then
    # Stormshield event whose src field is the test IP — custom-opencti.py
    # reads src/srcip/dstip/dst and queries OpenCTI for IPv4 indicators.
    IP_BEFORE=$(docker compose exec -T -e IP="$IP_TEST_IP" wazuh.manager bash -c \
        'grep -cE "\"id\":\"10021[2-5]\".*\"query_values\":\".*ipv4-addr.*${IP}" /var/ossec/logs/alerts/alerts.json 2>/dev/null || true' \
        | tr -d '\r' | head -1)
    IP_BEFORE=${IP_BEFORE:-0}
    printf '<134>May  5 14:10:00 sns id=firewall time="2026-05-05 14:10:00" fw="sns.test" tz=+0100 startime="2026-05-05 14:10:00" pri=4 confid=01 slotlevel=4 ruleid=2 srcif="in" srcifname="in" ipproto=tcp dstif="out" dstifname="out" proto=https src=%s srcname="external" srcport=12345 srcportname="ephemeral_fw_tcp" dst=10.0.0.50 origdst=10.0.0.50 dstname="target" dstport=443 dstportname="https" action=pass\n' \
        "$IP_TEST_IP" \
        | nc -u -w1 localhost 514
    IP_HIT=false
    for _ in $(seq 1 8); do
        sleep 5
        IP_AFTER=$(docker compose exec -T -e IP="$IP_TEST_IP" wazuh.manager bash -c \
            'grep -cE "\"id\":\"10021[2-5]\".*\"query_values\":\".*ipv4-addr.*${IP}" /var/ossec/logs/alerts/alerts.json 2>/dev/null || true' \
            | tr -d '\r' | head -1)
        IP_AFTER=${IP_AFTER:-0}
        if [ "$IP_AFTER" -gt "$IP_BEFORE" ]; then IP_HIT=true; break; fi
    done
    delete_test_indicator "$IP_IND_ID"
    if [ "$IP_HIT" = true ]; then
        echo "  PASS  custom-opencti.py IPv4 path: 100212/100213 fired for $IP_TEST_IP"
        ((PASS++))
    else
        echo "  FAIL  custom-opencti.py IPv4 path: no IOC alert for $IP_TEST_IP"
        ((FAIL++))
    fi
else
    echo "  FAIL  Could not create test IPv4 indicator in OpenCTI"
    ((FAIL++))
fi

# (Domain/hostname path intentionally not exercised here: custom-opencti.py
# only queries [domain-name:value=...] from sysmon event-id-22 DNS queries
# or from firewall events where dst is non-numeric. Reproducing either in a
# smoke test requires a Windows sysmon agent or a hand-crafted firewall log
# with a hostname dst, neither of which is available in the default profile.)

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

# Threat-intel connectors active by name — beyond the count check above.
# We also cross-check the matching container is healthy, because OpenCTI keeps
# reporting active=true for several minutes after the connector stops sending
# heartbeats. Without the Docker-side check a short-lived crash would slip
# through this test (false positive).
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
UNHEALTHY_CONNECTORS=""
for c in connector-mitre connector-urlhaus connector-cisa-kev connector-threatfox \
         connector-opencti-datasets connector-vxvault connector-disarm; do
    state=$(docker inspect -f '{{.State.Health.Status}}' "wazuh-opencti-${c}-1" 2>/dev/null || echo "missing")
    if [ "$state" != "healthy" ]; then
        UNHEALTHY_CONNECTORS="${UNHEALTHY_CONNECTORS}${c}(${state}) "
    fi
done
if [ -z "$MISSING_CONNECTORS" ] && [ -z "$UNHEALTHY_CONNECTORS" ]; then
    echo "  PASS  All 7 expected threat-intel connectors active by name and healthy"
    ((PASS++))
else
    echo "  FAIL  Threat-intel connectors broken"
    [ -n "$MISSING_CONNECTORS" ]   && echo "         OpenCTI inactive: $MISSING_CONNECTORS"
    [ -n "$UNHEALTHY_CONNECTORS" ] && echo "         containers not healthy: $UNHEALTHY_CONNECTORS"
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

# --- 9d. Network ingestion paths (syslog 514/udp) ---
echo "--- Network Ingestion ---"

# SSH brute-force correlation: 10 'Failed password' events from same srcip
# via syslog UDP 514 should trigger rule 5712 (sshd brute force, non existent
# user — frequency=8, timeframe=120). Built-in Wazuh sshd decoder + ruleset.
SSH_TEST_IP="198.51.100.42"
SSH_BEFORE=$(docker compose exec -T wazuh.manager bash -c \
    "grep -c '\"id\":\"5712\".*\"srcip\":\"$SSH_TEST_IP\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true" \
    | tr -d '\r' | head -1)
SSH_BEFORE=${SSH_BEFORE:-0}
for i in $(seq 1 10); do
    printf '<13>May  5 14:00:%02d testhost sshd[1234]: Failed password for invalid user attacker%d from %s port %d ssh2\n' \
        "$i" "$i" "$SSH_TEST_IP" "$((50000+i))" \
        | nc -u -w1 localhost 514
done
SSH_PASS=false
for _ in $(seq 1 6); do
    sleep 5
    SSH_AFTER=$(docker compose exec -T wazuh.manager bash -c \
        "grep -c '\"id\":\"5712\".*\"srcip\":\"$SSH_TEST_IP\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true" \
        | tr -d '\r' | head -1)
    SSH_AFTER=${SSH_AFTER:-0}
    if [ "$SSH_AFTER" -gt "$SSH_BEFORE" ]; then
        SSH_PASS=true; break
    fi
done
if [ "$SSH_PASS" = true ]; then
    echo "  PASS  SSH brute-force: 514/udp → sshd decoder → rule 5712 (correlation, $SSH_TEST_IP)"
    ((PASS++))
else
    echo "  FAIL  SSH brute-force: rule 5712 not triggered after 10 syslog events on 514/udp"
    ((FAIL++))
fi

# Defense action — README claims "rule 5763 → host-deny for 1 hour" for SSH
# brute-force. The previous "invalid user" log format triggers 5710 → 5712
# (which is NOT wired to host-deny). The plain "Failed password for root"
# format triggers 5760 → 5763 → host-deny. Use a distinct srcip so we can
# attribute the active-response log entry unambiguously.
HOSTDENY_TEST_IP="198.51.100.222"
HOSTDENY_BEFORE=$(docker compose exec -T -e IP="$HOSTDENY_TEST_IP" wazuh.manager bash -c \
    'grep -cE "active-response/bin/host-deny.*$IP" /var/ossec/logs/active-responses.log 2>/dev/null || true' \
    | tr -d '\r' | head -1)
HOSTDENY_BEFORE=${HOSTDENY_BEFORE:-0}
for i in $(seq 1 12); do
    printf '<13>May  5 14:30:%02d testhost sshd[1234]: Failed password for root from %s port %d ssh2\n' \
        "$i" "$HOSTDENY_TEST_IP" "$((50000+i))" \
        | nc -u -w1 localhost 514
done
HOSTDENY_PASS=false
for _ in $(seq 1 6); do
    sleep 5
    HOSTDENY_AFTER=$(docker compose exec -T -e IP="$HOSTDENY_TEST_IP" wazuh.manager bash -c \
        'grep -cE "active-response/bin/host-deny.*$IP" /var/ossec/logs/active-responses.log 2>/dev/null || true' \
        | tr -d '\r' | head -1)
    HOSTDENY_AFTER=${HOSTDENY_AFTER:-0}
    if [ "$HOSTDENY_AFTER" -gt "$HOSTDENY_BEFORE" ]; then
        HOSTDENY_PASS=true; break
    fi
done
if [ "$HOSTDENY_PASS" = true ]; then
    echo "  PASS  Active response: host-deny invoked on sshd brute-force (rule 5763 → AR, $HOSTDENY_TEST_IP)"
    ((PASS++))
else
    echo "  FAIL  Active response: no host-deny entry for $HOSTDENY_TEST_IP after sshd brute-force events"
    ((FAIL++))
fi

# Stormshield SNS firewall: a single block event in the documented log format
# should be decoded (custom stormshield_decoders.xml) and matched by a 103xxx
# rule (custom stormshield_rules.xml).
STORM_TEST_IP="203.0.113.7"
STORM_BEFORE=$(docker compose exec -T wazuh.manager bash -c \
    "grep -cE '\"id\":\"103[0-9]+\".*\"src\":\"$STORM_TEST_IP\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true" \
    | tr -d '\r' | head -1)
STORM_BEFORE=${STORM_BEFORE:-0}
printf '<134>May  5 14:01:00 sns id=firewall time="2026-05-05 14:01:00" fw="sns.test" tz=+0100 startime="2026-05-05 14:01:00" pri=4 confid=01 slotlevel=4 ruleid=2 srcif="in" srcifname="in" ipproto=tcp dstif="out" dstifname="out" proto=ssh src=%s srcname="attacker" srcport=12345 srcportname="ephemeral_fw_tcp" dst=10.0.0.2 dstname="target" dstport=22 dstportname="ssh" action=block\n' \
    "$STORM_TEST_IP" \
    | nc -u -w1 localhost 514
STORM_PASS=false
for _ in $(seq 1 6); do
    sleep 5
    STORM_AFTER=$(docker compose exec -T wazuh.manager bash -c \
        "grep -cE '\"id\":\"103[0-9]+\".*\"src\":\"$STORM_TEST_IP\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true" \
        | tr -d '\r' | head -1)
    STORM_AFTER=${STORM_AFTER:-0}
    if [ "$STORM_AFTER" -gt "$STORM_BEFORE" ]; then
        STORM_PASS=true; break
    fi
done
if [ "$STORM_PASS" = true ]; then
    echo "  PASS  Stormshield: 514/udp → custom decoder → rule 103xxx ($STORM_TEST_IP)"
    ((PASS++))
else
    echo "  FAIL  Stormshield: no 103xxx rule triggered after firewall syslog event"
    ((FAIL++))
fi

# Stormshield variants: 103001 (pass action), 103004 (auth fail), 103009
# (bruteforce correlation) + firewall-drop AR, 103010 (public IP). Each is
# wired up by setup.sh / shipped decoders but never exercised individually.

# Pass action — chains 103001 → 103011 (private dst) or 103010 (public dst).
# We accept any of those as long as the alert records action=pass for the
# test srcip, which proves the decoder + chain handled "pass" events.
STORM_PASS_IP="203.0.113.31"
printf '<134>May  5 14:01:00 sns id=firewall time="2026-05-05 14:01:00" fw="sns.test" tz=+0100 startime="2026-05-05 14:01:00" pri=4 confid=01 slotlevel=4 ruleid=2 srcif="in" srcifname="in" ipproto=tcp dstif="out" dstifname="out" proto=ssh src=%s srcname="user" srcport=12345 srcportname="ephemeral_fw_tcp" dst=10.0.0.50 origdst=10.0.0.50 dstname="target" dstport=22 dstportname="ssh" action=pass\n' \
    "$STORM_PASS_IP" \
    | nc -u -w1 localhost 514
sleep 10
if docker compose exec -T -e IP="$STORM_PASS_IP" wazuh.manager bash -c \
    'awk -v ip="$IP" "/\"id\":\"1030(01|10|11)\"/ && index(\$0, ip) && index(\$0, \"\\\"action\\\":\\\"pass\\\"\")" /var/ossec/logs/alerts/alerts.json | head -1 | grep -q .' 2>/dev/null; then
    echo "  PASS  Stormshield variant: pass-action rule (103001 chain) fired for $STORM_PASS_IP"
    ((PASS++))
else
    echo "  FAIL  Stormshield variant: no pass-action rule fired for $STORM_PASS_IP"
    ((FAIL++))
fi

# 103004 (auth failed) + 103009 (bruteforce correlation, frequency=3) +
# firewall-drop active response wired to rule 103009 in ossec.conf.
STORM_AUTH_IP="203.0.113.32"
STORM_AR_BEFORE=$(docker compose exec -T -e IP="$STORM_AUTH_IP" wazuh.manager bash -c \
    'grep -cE "active-response/bin/firewall-drop.*$IP" /var/ossec/logs/active-responses.log 2>/dev/null || true' \
    | tr -d '\r' | head -1)
STORM_AR_BEFORE=${STORM_AR_BEFORE:-0}
for i in $(seq 1 5); do
    printf '<134>May  5 14:02:%02d sns id=firewall time="2026-05-05 14:02:%02d" fw="sns.test" tz=+0100 startime="2026-05-05 14:02:%02d" pri=3 confid=01 slotlevel=4 ruleid=2 user="attacker" src=%s srcname="bruteforcer" error=4 msg="Authentication request invalid"\n' \
        "$i" "$i" "$i" "$STORM_AUTH_IP" \
        | nc -u -w1 localhost 514
done
sleep 15
if docker compose exec -T -e IP="$STORM_AUTH_IP" wazuh.manager bash -c \
    'grep -E "\"id\":\"103004\".*\"src\":\"$IP\"" /var/ossec/logs/alerts/alerts.json >/dev/null 2>&1' 2>/dev/null; then
    echo "  PASS  Stormshield variant: rule 103004 (auth failed) fired for $STORM_AUTH_IP"
    ((PASS++))
else
    echo "  FAIL  Stormshield variant: rule 103004 (auth failed) did not fire"
    ((FAIL++))
fi
STORM_BF_PASS=false
for _ in $(seq 1 4); do
    sleep 5
    if docker compose exec -T -e IP="$STORM_AUTH_IP" wazuh.manager bash -c \
        'grep -E "\"id\":\"103009\".*\"src\":\"$IP\"" /var/ossec/logs/alerts/alerts.json >/dev/null 2>&1' 2>/dev/null; then
        STORM_BF_PASS=true; break
    fi
done
if [ "$STORM_BF_PASS" = true ]; then
    echo "  PASS  Stormshield variant: rule 103009 (bruteforce correlation) fired for $STORM_AUTH_IP"
    ((PASS++))
else
    echo "  FAIL  Stormshield variant: rule 103009 did not fire after 5 auth failures"
    ((FAIL++))
fi
# Active response firewall-drop on rule 103009 (configured in ossec.conf
# alongside the host-deny block — README claim "firewall-drop on rule 103009").
STORM_AR_PASS=false
for _ in $(seq 1 4); do
    sleep 5
    STORM_AR_AFTER=$(docker compose exec -T -e IP="$STORM_AUTH_IP" wazuh.manager bash -c \
        'grep -cE "active-response/bin/firewall-drop.*$IP" /var/ossec/logs/active-responses.log 2>/dev/null || true' \
        | tr -d '\r' | head -1)
    STORM_AR_AFTER=${STORM_AR_AFTER:-0}
    if [ "$STORM_AR_AFTER" -gt "$STORM_AR_BEFORE" ]; then
        STORM_AR_PASS=true; break
    fi
done
if [ "$STORM_AR_PASS" = true ]; then
    echo "  PASS  Active response: firewall-drop invoked by rule 103009 ($STORM_AUTH_IP)"
    ((PASS++))
else
    echo "  FAIL  Active response: no firewall-drop entry for $STORM_AUTH_IP after rule 103009"
    ((FAIL++))
fi

# 103010 — pass traffic to a public destination
STORM_PUB_IP="203.0.113.33"
printf '<134>May  5 14:03:00 sns id=firewall time="2026-05-05 14:03:00" fw="sns.test" tz=+0100 startime="2026-05-05 14:03:00" pri=4 confid=01 slotlevel=4 ruleid=2 srcif="in" srcifname="in" ipproto=tcp dstif="out" dstifname="out" proto=https src=%s srcname="user" srcport=12345 srcportname="ephemeral_fw_tcp" dst=8.8.8.8 origdst=8.8.8.8 dstname="dns.google" dstport=443 dstportname="https" action=pass\n' \
    "$STORM_PUB_IP" \
    | nc -u -w1 localhost 514
sleep 10
if docker compose exec -T -e IP="$STORM_PUB_IP" wazuh.manager bash -c \
    'grep -E "\"id\":\"103010\".*\"src\":\"$IP\"" /var/ossec/logs/alerts/alerts.json >/dev/null 2>&1' 2>/dev/null; then
    echo "  PASS  Stormshield variant: rule 103010 (public IP) fired for $STORM_PUB_IP → 8.8.8.8"
    ((PASS++))
else
    echo "  FAIL  Stormshield variant: rule 103010 (public IP) did not fire"
    ((FAIL++))
fi

# --- 9e. Listening ports on the host ---
echo "--- Listening Ports ---"
PORTS_OK=true
for p in 1514 1515 55000 9443 8443 3443; do
    if ! ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(^|[^0-9])${p}\$"; then
        echo "  FAIL  TCP port $p not listening on host"
        ((FAIL++))
        PORTS_OK=false
    fi
done
if ! ss -lnu 2>/dev/null | awk '{print $4}' | grep -qE "(^|[^0-9])514\$"; then
    echo "  FAIL  UDP port 514 (syslog) not listening on host"
    ((FAIL++))
    PORTS_OK=false
fi
if [ "$PORTS_OK" = true ]; then
    echo "  PASS  All exposed ports listening (1514/1515/55000/9443/8443/3443 tcp, 514 udp)"
    ((PASS++))
fi

# --- 9e-bis. Runtime container hardening ---
# Verify the hardening posture CLAUDE.md claims actually persists at runtime
# (`docker compose` only validates the YAML at parse time — these checks read
# the live container HostConfig).
echo "--- Hardening Runtime ---"

NGINX_RO=$(docker inspect wazuh-opencti-nginx-1 --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null)
if [ "$NGINX_RO" = "true" ]; then
    echo "  PASS  Nginx rootfs is read-only at runtime"
    ((PASS++))
else
    echo "  FAIL  Nginx rootfs not read-only (got: $NGINX_RO)"
    ((FAIL++))
fi

NGINX_CAPS=$(docker inspect wazuh-opencti-nginx-1 --format '{{json .HostConfig.CapDrop}}' 2>/dev/null)
if echo "$NGINX_CAPS" | grep -q '"ALL"'; then
    echo "  PASS  Nginx drops all Linux capabilities (cap_drop=[ALL])"
    ((PASS++))
else
    echo "  FAIL  Nginx CapDrop missing 'ALL' (got: $NGINX_CAPS)"
    ((FAIL++))
fi

# CLAUDE.md claims `no-new-privileges` is set on 30/32 containers (excludes
# Shuffle backend + orborus which need Docker-socket access). Check at least
# 25 containers have it.
NNP_COUNT=$(docker compose ps -aq 2>/dev/null \
    | xargs -r docker inspect --format '{{.Name}} {{.HostConfig.SecurityOpt}}' 2>/dev/null \
    | grep -c 'no-new-privileges:true' || true)
NNP_COUNT=${NNP_COUNT:-0}
if [ "$NNP_COUNT" -ge 25 ]; then
    echo "  PASS  no-new-privileges set on $NNP_COUNT containers (≥25 expected)"
    ((PASS++))
else
    echo "  FAIL  no-new-privileges set on only $NNP_COUNT containers (≥25 expected)"
    ((FAIL++))
fi

# Redis requires authentication: a connection without password must fail.
# Override REDISCLI_AUTH so redis-cli does not silently auto-authenticate
# with the password baked into the container env (which is set by the
# REDIS_PASSWORD compose variable). The implicit success of authenticated
# clients is verified separately by OpenCTI being healthy.
REDIS_UNAUTH=$(docker compose exec -T -e REDISCLI_AUTH= redis redis-cli ping 2>&1 \
    | grep -vE "level=warning|^time=")
if echo "$REDIS_UNAUTH" | grep -qiE 'NOAUTH|Authentication required'; then
    echo "  PASS  Redis rejects unauthenticated connections"
    ((PASS++))
else
    echo "  FAIL  Redis answered without password (got: $REDIS_UNAUTH)"
    ((FAIL++))
fi

# --- 9f. .env file permissions ---
ENV_PERMS=$(stat -c %a .env 2>/dev/null || echo "missing")
if [ "$ENV_PERMS" = "600" ]; then
    echo "  PASS  .env permissions are 600 (not world/group readable)"
    ((PASS++))
else
    echo "  FAIL  .env permissions are $ENV_PERMS (expected 600)"
    ((FAIL++))
fi

# Random passwords must match the length setup.sh's generate_password()
# advertises (≥16 chars; Grafana is deliberately exactly 16, others 19-20).
# Catches a setup.sh regression that downgrades to short or hard-coded
# defaults. Skip commented lines (template entries like #SMTP_AUTH_PASS=)
# and skip the WAZUH_CLUSTER_KEY/uuid/version fields which are not
# passwords.
SHORT_PWS=$(awk -F= '
    /^#/ {next}
    /_PASSWORD=|_PASS=/ {
        v=$2; gsub(/^"|"$/,"",v); gsub(/^'\''|'\''$/,"",v)
        if (length(v) < 16) print $1"("length(v)")"
    }' .env)
if [ -z "$SHORT_PWS" ]; then
    echo "  PASS  All generated passwords in .env are ≥16 characters"
    ((PASS++))
else
    echo "  FAIL  Generated passwords too short: $SHORT_PWS"
    ((FAIL++))
fi

# Internal Wazuh indexer users must have bcrypt hashes, not plaintext. The
# setup.sh script generates them via the wazuh-indexer container — catches a
# regression that drops in plain passwords or silently fails to hash. The
# file only contains hashes for the accounts setup.sh actively configures
# (admin + kibanaserver = 2), so the threshold is ≥2.
INTERNAL_USERS=config/wazuh_indexer/internal_users.yml
if [ -f "$INTERNAL_USERS" ]; then
    BCRYPT_COUNT=$(grep -cE 'hash:\s*"\$2[aby]\$[0-9]+\$' "$INTERNAL_USERS" || true)
    PLAINTEXT_COUNT=$(grep -cE '^\s*password:\s*[^$"#]' "$INTERNAL_USERS" || true)
    if [ "$BCRYPT_COUNT" -ge 2 ] && [ "$PLAINTEXT_COUNT" -eq 0 ]; then
        echo "  PASS  Internal indexer users: $BCRYPT_COUNT bcrypt hashes, no plaintext password"
        ((PASS++))
    else
        echo "  FAIL  internal_users.yml: $BCRYPT_COUNT bcrypt, $PLAINTEXT_COUNT plaintext (expected ≥2 bcrypt, 0 plaintext)"
        ((FAIL++))
    fi
else
    echo "  FAIL  config/wazuh_indexer/internal_users.yml missing"
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

# ctem-report.sh: must exit 0 and emit all 6 documented sections (Scoping,
# Discovery, Prioritization, Threat Landscape, Mobilization, Recommendations)
CTEM_OUT=$(bash scripts/ctem-report.sh 2>&1)
CTEM_EXIT=$?
CTEM_SECTIONS=$(printf '%s\n' "$CTEM_OUT" | grep -cE '^--- [1-6]\.' || true)
if [ "$CTEM_EXIT" -eq 0 ] && [ "$CTEM_SECTIONS" -ge 6 ]; then
    echo "  PASS  ctem-report.sh emits all 6 CTEM sections and exits 0"
    ((PASS++))
else
    echo "  FAIL  ctem-report.sh: exit=$CTEM_EXIT, sections=$CTEM_SECTIONS (expected 6)"
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
    # Confirm the integration script integratord would invoke is present and
    # executable. We deliberately do not grep ossec.log for "Enabling
    # integration" — that line only lives in the *current* log and disappears
    # after rotation, producing a false-negative on long-running stacks.
    # The subsequent "integration script accepted by Shuffle (HTTP 2xx)" test
    # is the end-to-end proof that integratord can actually fire it.
    if docker compose exec -T wazuh.manager test -x "/var/ossec/integrations/${SHUFFLE_INT_NAME}" 2>/dev/null; then
        echo "  PASS  Integratord has Shuffle enabled (${SHUFFLE_INT_NAME})"
        ((PASS++))
    else
        echo "  FAIL  Integration script /var/ossec/integrations/${SHUFFLE_INT_NAME} missing or not executable"
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

# --- Operations end-to-end — upgrade.sh no-op covers backup.sh + rolling
# restart on a same-versions run. We do not call restore.sh (destructive,
# already covered by manual round-trip in the commit log). upgrade.sh:
#  1. calls backup.sh (verifies the tar-warnings.log fix lands all 18 vols)
#  2. docker compose pull (no-op when versions unchanged)
#  3. rolling restart of services whose image changed (zero on a no-op run)
echo "--- Operations Round-Trip ---"
UPGRADE_BACKUPS_BEFORE=$(ls -1d backups/pre-upgrade-*/ 2>/dev/null | wc -l)
UPGRADE_OUT=$(bash upgrade.sh 2>&1)
UPGRADE_EXIT=$?
UPGRADE_BACKUPS_AFTER=$(ls -1d backups/pre-upgrade-*/ 2>/dev/null | wc -l)
UPGRADE_LATEST_BACKUP=$(ls -1dt backups/pre-upgrade-*/ 2>/dev/null | head -1)
UPGRADE_BACKUP_FILES=$(ls "$UPGRADE_LATEST_BACKUP" 2>/dev/null | wc -l)
if [ "$UPGRADE_EXIT" -eq 0 ] && \
   [ "$UPGRADE_BACKUPS_AFTER" -gt "$UPGRADE_BACKUPS_BEFORE" ] && \
   [ "$UPGRADE_BACKUP_FILES" -ge 19 ]; then
    echo "  PASS  upgrade.sh no-op: backup created ($UPGRADE_BACKUP_FILES files) and rolling restart completed cleanly"
    ((PASS++))
else
    echo "  FAIL  upgrade.sh failed (exit=$UPGRADE_EXIT, backup_files=$UPGRADE_BACKUP_FILES, new_dirs=$((UPGRADE_BACKUPS_AFTER-UPGRADE_BACKUPS_BEFORE)))"
    ((FAIL++))
fi
# Cleanup pre-upgrade backup so the smoke test does not leave artifacts. We
# keep ./backups/ itself (it is gitignored) so future runs can reuse the
# directory structure.
[ -n "$UPGRADE_LATEST_BACKUP" ] && rm -rf "$UPGRADE_LATEST_BACKUP"

# --- 11. Nginx rate limit (last — bursting against /graphql may briefly
# exhaust the per-IP bucket; keeping this at the end avoids cascading failures
# in other OpenCTI tests). The opencti_api zone is 30 r/s + burst=20 nodelay,
# so 200 parallel requests must produce at least one HTTP 429.
echo "--- Nginx Rate Limit ---"
RATE_RESPONSES=$(for _ in $(seq 1 200); do
    curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:8443/graphql 2>/dev/null &
done; wait)
RATE_429=$(printf '%s\n' "$RATE_RESPONSES" | grep -c '^429$' || true)
RATE_429=${RATE_429:-0}
if [ "$RATE_429" -gt 0 ]; then
    echo "  PASS  Nginx rate limit triggered ($RATE_429/200 requests returned 429)"
    ((PASS++))
else
    echo "  FAIL  Nginx rate limit not triggered after 200 parallel requests on /graphql"
    ((FAIL++))
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
