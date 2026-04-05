#!/usr/bin/env bash
# Configure Wazuh to send alerts to a Shuffle webhook.
# Usage: bash scripts/configure-shuffle.sh <webhook-url>
#
# Steps before running this script:
#   1. Open Shuffle UI at https://localhost:3443
#   2. Create a workflow with a Webhook trigger
#   3. Click the trigger, copy the Webhook URL
#   4. Run this script with that URL
set -euo pipefail

WEBHOOK_URL="${1:-}"

if [ -z "$WEBHOOK_URL" ]; then
    echo "Usage: $0 <shuffle-webhook-url>"
    echo ""
    echo "Get the webhook URL from the Shuffle UI:"
    echo "  1. Login at https://localhost:3443"
    echo "  2. Create a workflow with a Webhook trigger"
    echo "  3. Click the trigger node, copy the URL"
    echo "  4. Convert external URL to internal: replace"
    echo "     'https://localhost:3443' with 'http://shuffle-backend:5001'"
    exit 1
fi

# Convert external URL to internal Docker network URL if needed
WEBHOOK_URL=$(echo "$WEBHOOK_URL" | sed 's|https://localhost:[0-9]*/|http://shuffle-backend:5001/|')
echo "Webhook URL: $WEBHOOK_URL"

# Update ossec.conf: uncomment the Shuffle integration and set the URL
echo "Configuring Wazuh manager..."
docker compose exec -T wazuh.manager bash -c "
# Uncomment the Shuffle integration block
sed -i '
    /<!-- <integration>/,/<\/integration> -->/{
        s/<!-- <integration>/<integration>/
        s/<\/integration> -->/<\/integration>/
    }
' /var/ossec/etc/ossec.conf

# Set the webhook URL
sed -i 's|<hook_url>SHUFFLE_WEBHOOK_URL</hook_url>|<hook_url>$WEBHOOK_URL</hook_url>|' /var/ossec/etc/ossec.conf
sed -i 's|<hook_url>http://shuffle-backend.*</hook_url>|<hook_url>$WEBHOOK_URL</hook_url>|' /var/ossec/etc/ossec.conf
"

# Verify
echo ""
echo "Integration config:"
docker compose exec -T wazuh.manager grep -A 5 "shuffle" /var/ossec/etc/ossec.conf | head -6

# Restart manager
echo ""
echo "Restarting Wazuh manager..."
docker compose restart wazuh.manager 2>&1 | tail -1

echo ""
echo "Done. Wazuh will now send level 3+ alerts to Shuffle."
echo "Check integration logs: docker compose exec wazuh.manager tail -f /var/ossec/logs/integrations.log"
