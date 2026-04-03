#!/bin/bash
# Stack health monitor - run via cron or systemd timer
# Checks all container healthchecks, alerts on failures
#
# Usage:
#   bash scripts/healthcheck-monitor.sh                    # Print status
#   bash scripts/healthcheck-monitor.sh --alert            # Alert on failures
#   ALERT_WEBHOOK_URL=http://... bash scripts/healthcheck-monitor.sh --alert
#
# Cron example (every 5 minutes):
#   */5 * * * * cd /path/to/wazuh-opencti && bash scripts/healthcheck-monitor.sh --alert >> /var/log/soc-monitor.log 2>&1
#
# Alert destinations (set via environment):
#   ALERT_WEBHOOK_URL  - POST JSON to this URL (works with Shuffle, Slack, Teams, etc.)
#   ALERT_EMAIL        - Send email (requires mailutils/sendmail)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

ALERT_MODE="${1:-}"
ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"
ALERT_EMAIL="${ALERT_EMAIL:-}"
HOSTNAME_LABEL="${HOSTNAME:-$(hostname)}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- Collect status ---
UNHEALTHY=()
STOPPED=()
HEALTHY=()

while IFS= read -r line; do
    NAME=$(echo "$line" | jq -r '.Name' 2>/dev/null) || continue
    STATUS=$(echo "$line" | jq -r '.Health' 2>/dev/null) || continue
    STATE=$(echo "$line" | jq -r '.State' 2>/dev/null) || continue

    if [ "$STATE" != "running" ]; then
        STOPPED+=("$NAME")
    elif [ "$STATUS" = "unhealthy" ]; then
        UNHEALTHY+=("$NAME")
    else
        HEALTHY+=("$NAME")
    fi
done < <(docker compose ps --format json 2>/dev/null)

TOTAL=$(( ${#HEALTHY[@]} + ${#UNHEALTHY[@]} + ${#STOPPED[@]} ))

# --- Print status ---
echo "[${TIMESTAMP}] Stack health: ${#HEALTHY[@]}/${TOTAL} healthy"

if [ ${#UNHEALTHY[@]} -gt 0 ]; then
    echo "  UNHEALTHY: ${UNHEALTHY[*]}"
fi
if [ ${#STOPPED[@]} -gt 0 ]; then
    echo "  STOPPED:   ${STOPPED[*]}"
fi

# --- Alert if needed ---
if [ "$ALERT_MODE" != "--alert" ]; then
    exit 0
fi

if [ ${#UNHEALTHY[@]} -eq 0 ] && [ ${#STOPPED[@]} -eq 0 ]; then
    exit 0
fi

ALERT_MSG="SOC Stack Alert on ${HOSTNAME_LABEL}: ${#UNHEALTHY[@]} unhealthy, ${#STOPPED[@]} stopped services"
ALERT_DETAIL="Unhealthy: ${UNHEALTHY[*]:-none}. Stopped: ${STOPPED[*]:-none}."

# Webhook alert (Shuffle, Slack, Teams, generic)
if [ -n "$ALERT_WEBHOOK_URL" ]; then
    PAYLOAD=$(jq -n \
        --arg text "$ALERT_MSG" \
        --arg detail "$ALERT_DETAIL" \
        --arg host "$HOSTNAME_LABEL" \
        --arg time "$TIMESTAMP" \
        --argjson unhealthy "$(printf '%s\n' "${UNHEALTHY[@]:-}" | jq -R . | jq -s .)" \
        --argjson stopped "$(printf '%s\n' "${STOPPED[@]:-}" | jq -R . | jq -s .)" \
        '{text: $text, detail: $detail, host: $host, timestamp: $time, unhealthy: $unhealthy, stopped: $stopped}')

    if curl -sf -X POST "$ALERT_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" -o /dev/null 2>/dev/null; then
        echo "  Alert sent to webhook."
    else
        echo "  WARNING: Failed to send webhook alert." >&2
    fi
fi

# Email alert
if [ -n "$ALERT_EMAIL" ] && command -v mail &>/dev/null; then
    echo "${ALERT_MSG}\n\n${ALERT_DETAIL}" | mail -s "$ALERT_MSG" "$ALERT_EMAIL" 2>/dev/null && \
        echo "  Alert sent to ${ALERT_EMAIL}." || \
        echo "  WARNING: Failed to send email alert." >&2
fi

# Exit non-zero so cron/monitoring can detect failures
exit 1
