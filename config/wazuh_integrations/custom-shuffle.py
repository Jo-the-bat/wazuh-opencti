#!/usr/bin/env python3
# Wazuh integration that forwards alerts to a Shuffle workflow execution
# endpoint with a Bearer token. The vendor `shuffle` integration (shuffle.py)
# does not pass <api_key> as an Authorization header, so direct calls to
# /api/v1/workflows/<id>/execute are rejected with HTTP 403. This script
# closes that gap. It also works with /api/v1/hooks/<id> webhooks (the
# header is simply ignored there).
#
# Wazuh integratord argv layout:
#   argv[1] = alert file path (JSON)
#   argv[2] = <api_key>
#   argv[3] = <hook_url>

import json
import sys

try:
    import requests
except ModuleNotFoundError:
    sys.stderr.write("custom-shuffle: 'requests' module missing\n")
    sys.exit(1)

LOG_FILE = '/var/ossec/logs/integrations.log'


def log(line: str) -> None:
    try:
        with open(LOG_FILE, 'a') as fh:
            fh.write(line + '\n')
    except OSError:
        pass


def main(argv):
    if len(argv) < 4:
        log('# custom-shuffle ERROR: expected alert_file api_key hook_url, got: %s' % argv[1:])
        sys.exit(2)

    alert_file, api_key, url = argv[1], argv[2], argv[3]

    try:
        with open(alert_file) as fh:
            alert = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        log('# custom-shuffle ERROR reading %s: %s' % (alert_file, e))
        sys.exit(3)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + api_key,
    }
    payload = {'execution_argument': json.dumps(alert), 'start': ''}

    try:
        res = requests.post(url, json=payload, headers=headers, timeout=10)
    except requests.RequestException as e:
        log('# custom-shuffle POST %s failed: %s' % (url, e))
        sys.exit(5)

    body = res.text[:200].replace('\n', ' ')
    log('# custom-shuffle POST %s -> %d %s' % (url, res.status_code, body))
    if res.status_code >= 400:
        sys.exit(4)


if __name__ == '__main__':
    main(sys.argv)
