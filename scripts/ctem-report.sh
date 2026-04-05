#!/usr/bin/env bash
# CTEM Report — Continuous Threat Exposure Management
#
# Cross-references Wazuh vulnerability scan results against OpenCTI threat intel
# (CISA KEV, MITRE ATT&CK) to prioritize vulnerabilities by real-world exploitation.
#
# Usage: bash scripts/ctem-report.sh [--json]
#
# Requires: running Wazuh + OpenCTI stack, agents enrolled with vuln detection
set -uo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
    echo "ERROR: .env not found. Run setup.sh first." >&2
    exit 1
fi
set -a; source .env; set +a

JSON_OUTPUT=false
[ "${1:-}" = "--json" ] && JSON_OUTPUT=true

IDXPW=$(grep INDEXER_PASSWORD .env | cut -d= -f2)
API_PASS=$(grep WAZUH_API_PASSWORD .env | cut -d= -f2)

# Get Wazuh API token
TOKEN=$(docker compose exec -T wazuh.manager curl -sk \
    -u "wazuh-wui:${API_PASS}" \
    -X POST https://localhost:55000/security/user/authenticate?raw=true 2>/dev/null)

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "ERROR: Cannot authenticate to Wazuh API" >&2
    exit 1
fi

if [ "$JSON_OUTPUT" = false ]; then
    echo "================================================================"
    echo "  CTEM REPORT — $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "================================================================"
fi

# --- 1. Scoping: Get enrolled agents ---
AGENTS=$(docker compose exec -T wazuh.manager curl -sk \
    -H "Authorization: Bearer $TOKEN" \
    "https://localhost:55000/agents?limit=500&select=id,name,ip,os.name,os.version,status" 2>/dev/null)

AGENT_COUNT=$(echo "$AGENTS" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['total_affected_items'])" 2>/dev/null)

if [ "$JSON_OUTPUT" = false ]; then
    echo ""
    echo "--- 1. ATTACK SURFACE (Scoping) ---"
    echo "  Enrolled agents: $AGENT_COUNT"
    echo "$AGENTS" | python3 -c "
import sys,json
agents = json.load(sys.stdin)['data']['affected_items']
for a in agents:
    if a['id'] == '000': continue
    os_name = a.get('os',{}).get('name','?')
    os_ver = a.get('os',{}).get('version','')
    print(f'    {a[\"id\"]}: {a[\"name\"]} ({a[\"status\"]}) - {os_name} {os_ver} [{a.get(\"ip\",\"?\")}]')
" 2>/dev/null
fi

# --- 2. Discovery: Get vulnerabilities from Wazuh ---
VULNS=$(docker compose exec -T wazuh.manager curl -sk \
    -H "Authorization: Bearer $TOKEN" \
    "https://localhost:55000/vulnerability?limit=500&select=cve,name,severity,status,external_references,condition,version" 2>/dev/null)

VULN_COUNT=$(echo "$VULNS" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('data',{}).get('total_affected_items',0))" 2>/dev/null || echo "0")

# Also check vulnerability alerts in the indexer
VULN_ALERTS=$(docker compose exec -T wazuh.indexer curl -sk -u "admin:$IDXPW" \
    "https://localhost:9200/wazuh-alerts-*/_search" -H "Content-Type: application/json" -d '{
    "size": 0,
    "query": {"bool": {"should": [
        {"match": {"rule.groups": "vulnerability-detector"}},
        {"match": {"data.vulnerability.cve": {"query": "CVE", "operator": "and"}}}
    ]}},
    "aggs": {"cves": {"terms": {"field": "data.vulnerability.cve.keyword", "size": 500}}}
}' 2>/dev/null)

UNIQUE_CVES=$(echo "$VULN_ALERTS" | python3 -c "
import sys,json
d = json.load(sys.stdin)
buckets = d.get('aggregations',{}).get('cves',{}).get('buckets',[])
cves = [b['key'] for b in buckets]
for c in cves: print(c)
" 2>/dev/null)

CVE_LIST_COUNT=$(echo "$UNIQUE_CVES" | grep -c "CVE" || true)
CVE_LIST_COUNT=${CVE_LIST_COUNT:-0}

if [ "$JSON_OUTPUT" = false ]; then
    echo ""
    echo "--- 2. DISCOVERY (Vulnerabilities) ---"
    echo "  Unique CVEs detected by Wazuh: $CVE_LIST_COUNT"
    echo "  Vulnerability API results: $VULN_COUNT"
fi

# --- 3. Prioritization: Cross-reference with CISA KEV ---
if [ "$CVE_LIST_COUNT" -gt 0 ]; then
    # Query OpenCTI for each CVE to check if it's in CISA KEV
    ACTIVELY_EXPLOITED=$(echo "$UNIQUE_CVES" | python3 -c "
import sys, json, urllib.request

cves = [l.strip() for l in sys.stdin if l.strip().startswith('CVE')]
token = '$OPENCTI_ADMIN_TOKEN'
url = 'https://localhost:8443/graphql'

# Batch query: check which CVEs exist as vulnerabilities in OpenCTI
exploited = []
for cve in cves:
    try:
        query = json.dumps({
            'query': '''{ vulnerabilities(filters: {mode: and, filterGroups: [], filters: [{key: \"name\", values: [\"%s\"]}]}, first: 1) { edges { node { name description x_opencti_score } } } }''' % cve
        }).encode()
        req = urllib.request.Request(url, data=query, headers={
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        })
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        data = json.loads(resp.read())
        edges = data.get('data',{}).get('vulnerabilities',{}).get('edges',[])
        if edges:
            node = edges[0]['node']
            exploited.append({
                'cve': cve,
                'score': node.get('x_opencti_score', 0),
                'description': (node.get('description') or '')[:100]
            })
    except Exception as e:
        pass

# Sort by score descending
exploited.sort(key=lambda x: -x.get('score',0))
for e in exploited:
    print(json.dumps(e))
" 2>/dev/null)

    KEV_COUNT=$(echo "$ACTIVELY_EXPLOITED" | grep -c "cve" 2>/dev/null || echo "0")

    if [ "$JSON_OUTPUT" = false ]; then
        echo ""
        echo "--- 3. PRIORITIZATION (CISA KEV Cross-Reference) ---"
        echo "  CVEs found in CISA KEV (actively exploited): $KEV_COUNT / $CVE_LIST_COUNT"
        echo ""
        if [ "$KEV_COUNT" -gt 0 ]; then
            echo "  CRITICAL — Actively exploited vulnerabilities on your assets:"
            echo "  ─────────────────────────────────────────────────────────────"
            echo "$ACTIVELY_EXPLOITED" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        score = e.get('score', 0)
        severity = 'CRITICAL' if score >= 80 else 'HIGH' if score >= 60 else 'MEDIUM'
        print(f'    [{severity:8s}] {e[\"cve\"]:20s} score={score}')
        if e.get('description'):
            print(f'              {e[\"description\"][:80]}')
    except: pass
" 2>/dev/null
        else
            echo "  No actively exploited CVEs found on enrolled agents."
        fi
    fi
else
    if [ "$JSON_OUTPUT" = false ]; then
        echo ""
        echo "--- 3. PRIORITIZATION ---"
        echo "  No vulnerabilities detected yet."
        echo "  (Enroll agents with Wazuh vulnerability detection enabled)"
    fi
fi

# --- 4. OpenCTI Threat Landscape ---
THREAT_STATS=$(curl -sk -X POST https://localhost:8443/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENCTI_ADMIN_TOKEN" \
    -d '{"query":"{ vulnerabilities(first:1) { pageInfo { globalCount } } indicators(first:1) { pageInfo { globalCount } } attackPatterns(first:1) { pageInfo { globalCount } } }"}' 2>/dev/null)

if [ "$JSON_OUTPUT" = false ]; then
    echo ""
    echo "--- 4. THREAT LANDSCAPE (OpenCTI) ---"
    echo "$THREAT_STATS" | python3 -c "
import sys,json
d = json.load(sys.stdin)['data']
print(f'  CISA KEV CVEs:      {d[\"vulnerabilities\"][\"pageInfo\"][\"globalCount\"]}')
print(f'  IOC indicators:     {d[\"indicators\"][\"pageInfo\"][\"globalCount\"]}')
print(f'  ATT&CK techniques:  {d[\"attackPatterns\"][\"pageInfo\"][\"globalCount\"]}')
" 2>/dev/null

    # --- 5. Mobilization: Create remediation cases ---
    echo ""
    echo "--- 5. MOBILIZATION (Remediation Tracking) ---"

    if [ "${KEV_COUNT:-0}" -gt 0 ] 2>/dev/null; then
        echo "  Creating remediation cases in OpenCTI..."
        echo "$ACTIVELY_EXPLOITED" | python3 -c "
import sys, json, urllib.request, ssl, datetime

token = '$OPENCTI_ADMIN_TOKEN'
url = 'https://localhost:8443/graphql'
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
today = datetime.date.today().isoformat()
created = 0

for line in sys.stdin:
    try:
        e = json.loads(line)
        cve = e['cve']
        score = e.get('score', 0)
        severity = 'P1' if score >= 80 else 'P2' if score >= 60 else 'P3'
        desc = e.get('description','')

        # Check if case already exists for this CVE
        check_q = json.dumps({
            'query': '{ caseIncidents(first: 1, search: \"%s\") { edges { node { id name } } } }' % ('CTEM: ' + cve)
        }).encode()
        req = urllib.request.Request(url, data=check_q, headers={
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        })
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        existing = json.loads(resp.read())
        if existing['data']['caseIncidents']['edges']:
            print(f'    [EXISTS] {cve} — case already open')
            continue

        # Create remediation case
        case_name = 'CTEM: %s — actively exploited' % cve
        case_desc = 'Vulnerability %s detected on enrolled agents and confirmed actively exploited (CISA KEV).\\n\\nScore: %s\\nPriority: %s\\n\\n%s\\n\\nGenerated by CTEM report on %s' % (cve, score, severity, desc, today)
        create_q = json.dumps({
            'query': 'mutation { caseIncidentAdd(input: { name: \"%s\", description: \"%s\", severity: \"%s\", priority: \"%s\" }) { id name } }' % (case_name, case_desc, 'critical' if score >= 80 else 'high', severity)
        }).encode()
        req = urllib.request.Request(url, data=create_q, headers={
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        })
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        result = json.loads(resp.read())
        case_id = result['data']['caseIncidentAdd']['id']

        # Add remediation task
        task_q = json.dumps({
            'query': 'mutation { taskAdd(input: { name: \"Patch %s on affected assets\", description: \"Apply vendor security update to remediate %s. Verify with rescan after patching.\", objects: [\"%s\"] }) { id } }' % (cve, cve, case_id)
        }).encode()
        req = urllib.request.Request(url, data=task_q, headers={
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        })
        urllib.request.urlopen(req, context=ctx, timeout=10)

        created += 1
        print(f'    [CREATED] {cve} [{severity}] — case + remediation task')
    except Exception as ex:
        print(f'    [ERROR] {e.get(\"cve\",\"?\")}: {ex}')

if created > 0:
    print(f'  {created} new remediation case(s) created in OpenCTI')
else:
    print(f'  All CVEs already have open cases')
print(f'  Track at: https://localhost:8443/dashboard/cases/incidents')
" 2>/dev/null
    else
        echo "  No actively exploited CVEs to track."
    fi

    echo ""
    echo "--- 6. RECOMMENDATIONS ---"
    echo "  1. Enroll agents on all assets (servers, workstations, network devices)"
    echo "  2. Review CRITICAL/HIGH CVEs above and patch immediately"
    echo "  3. Track remediation in OpenCTI: https://localhost:8443/dashboard/cases/incidents"
    echo "  4. Schedule this report: crontab -e -> 0 6 * * 1 bash scripts/ctem-report.sh"
    echo ""
    echo "================================================================"
fi
