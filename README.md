# Wazuh + OpenCTI + Shuffle SOAR

Production-ready Docker Compose deployment of a complete security operations stack:

- **Wazuh 4.14.4** — SIEM/XDR with agent management, vulnerability detection, and file integrity monitoring
- **OpenCTI 6.9.28** — Cyber Threat Intelligence platform with automated threat feed ingestion
- **Shuffle** — Open-source SOAR for no-code security automation workflows
- **Bidirectional integration** — Wazuh alerts enriched with OpenCTI threat intel, OpenCTI sightings from Wazuh data

## Architecture

```
                    +-----------+
                    |   Nginx   |
                    | HTTPS TLS |
                    +-----+-----+
                    :8443 | :3443
              +-----------+-----------+
              |                       |
        +-----v-----+          +-----v-----+
        |  OpenCTI   |          |  Shuffle  |
        |  Platform  |          |   SOAR    |
        +-----+------+          +-----+-----+
              |                       |
    +---------+---------+     +-------+-------+
    |    |    |    |     |    |       |       |
   ES Redis RMQ MinIO Workers  OpenSearch Orborus
              |
        +-----v------+
        |   Wazuh     |
        |   Manager   |<--- agents (1514/tcp)
        +-----+-------+
              |
        +-----v------+
        |   Wazuh     |
        |   Indexer   |
        +-----+-------+
              |
        +-----v------+
        |   Wazuh     |
        |  Dashboard  |:9443
        +-------------+
```

**28 default containers** + 8 optional (3 API-key connectors + 3 monitoring + 2 Suricata IDS):

| Component | Services | Purpose |
|-----------|----------|---------|
| **Wazuh** | manager, indexer, dashboard | SIEM/XDR with mutual TLS |
| **OpenCTI** | platform, 3 workers, Elasticsearch, Redis, RabbitMQ, MinIO | Threat intelligence |
| **Shuffle** | backend, frontend, orborus, OpenSearch | Security automation |
| **Connectors** | MITRE, URLhaus, CISA KEV, ThreatFox, OpenCTI Datasets | Threat feeds (free) |
| **Integration** | wazuh-connector, custom-opencti scripts | Bidirectional enrichment |
| **Nginx** | reverse proxy | HTTPS termination |

## Quick Start

### Prerequisites

- Docker Engine 20.10+ with the `docker compose` plugin (Compose v2.x or later)
- Host tools: `bash`, `curl`, `openssl`, `jq` — used by `setup.sh`, the smoke test, and the healthcheck monitor (`apt install jq` / `brew install jq` if missing)
- 32 GB RAM minimum, ~40 GB recommended (the full stack reserves ~34 GB across containers — see [Resource Requirements](#resource-requirements))
- `vm.max_map_count >= 262144`:
  ```bash
  # Check current value
  cat /proc/sys/vm/max_map_count

  # Set it (requires root)
  sudo sysctl -w vm.max_map_count=1048575
  echo "vm.max_map_count=1048575" | sudo tee -a /etc/sysctl.conf
  ```
  > **Note**: On some systems, `sysctl` is in `/usr/sbin/` and may not be in your PATH. Use the full path `/usr/sbin/sysctl` or check the value via `/proc/sys/vm/max_map_count`.

### Deploy

```bash
git clone https://github.com/Jo-the-bat/wazuh-opencti.git
cd wazuh-opencti
bash setup.sh
```

`setup.sh` handles everything: generates random passwords, creates TLS certificates, starts all services, and initializes Wazuh security. It's idempotent — safe to re-run. On first run, credentials are printed at the end; on subsequent runs, existing secrets in `.env` are preserved.

> **Note**: Optional connector profiles (AlienVault, AbuseIPDB, CVE) will show warnings about unset API keys during startup — this is normal and can be ignored unless you plan to enable them.

> **Note**: `setup.sh` may print `WARNING: Could not update workflow` during the Shuffle step. This is cosmetic — the workflow is created and Wazuh→Shuffle forwarding works (verified by the smoke test); only the in-place workflow content update is skipped.

> **Important**: credentials are printed once at the end of `setup.sh`. Copy them, or retrieve them later with `grep -E 'PASSWORD|TOKEN|OPENCTI_ADMIN_EMAIL' .env`.

Verify the deployment is working. Wait until every container shows `(healthy)` — count on **2–3 minutes** after `setup.sh` returns (the Wazuh dashboard is the slowest to come up):

```bash
# Watch healthchecks settle
docker compose ps

# Run the smoke test once everything is healthy
bash scripts/test-deployment.sh
```

If the test reports a transient failure such as `wazuh.dashboard health: starting`, wait another minute and re-run it.

### Access

| Service | URL | Default Credentials |
|---------|-----|-------------------|
| Wazuh Dashboard | `https://localhost:9443` | admin / (from setup output) |
| OpenCTI | `https://localhost:8443` | admin@opencti.io / (from setup output) |
| Shuffle SOAR | `https://localhost:3443` | admin / (from setup output) |

All passwords are in `.env` (gitignored, generated per deployment). You can also view them with:

```bash
grep -E 'PASSWORD|TOKEN|OPENCTI_ADMIN_EMAIL' .env
```

## Integrations

### Wazuh <-> OpenCTI (automatic)

Bidirectional enrichment works out of the box:

1. **Wazuh -> OpenCTI**: When Wazuh detects an IP, hash, domain, or URL, the `custom-opencti` integration queries OpenCTI's GraphQL API. If it matches a known IOC, Wazuh generates a level 10-12 alert with full threat context.

2. **OpenCTI -> Wazuh**: The `wazuh-connector` enrichment connector searches Wazuh alerts when viewing indicators in OpenCTI, creating STIX sightings.

3. **Active Response**: When an IOC is confirmed by OpenCTI (level 12), Wazuh automatically blocks the source IP via `firewall-drop` for 30 minutes. Also auto-blocks brute-force attackers (1 hour) and high-severity IDS alerts (30 minutes). All blocks auto-expire.

### Wazuh -> Shuffle (automatic)

The Wazuh-to-Shuffle integration is **automatically configured** by `setup.sh`: it creates a "Wazuh Alert Triage" workflow and wires Wazuh integratord to send level 3+ alerts to Shuffle via direct workflow execution.

If automatic configuration fails (check setup output for warnings), you can configure it manually:

1. Log in to Shuffle at `https://localhost:3443`
2. Create a new workflow with a **Webhook** trigger
3. Save and **Start** the workflow
4. Copy the generated webhook URL
5. Run the helper script with the **external** URL shown in the Shuffle UI (e.g. `https://localhost:3443/api/v1/hooks/<id>`); the script rewrites it to the internal Docker URL automatically:
   ```bash
   bash scripts/configure-shuffle.sh <webhook-url>
   ```

### Shuffle <-> OpenCTI

Add the OpenCTI app in Shuffle to enrich alerts with threat intelligence:
- URL: `http://opencti:8080`
- API Token: `OPENCTI_ADMIN_TOKEN` from `.env`

Example workflow: Wazuh alert -> extract IOC -> query OpenCTI -> if malicious -> block IP / create ticket / send alert.

## Threat Intelligence Feeds

### Enabled by default (free, no API key)

| Connector | Data | Update Interval |
|-----------|------|-----------------|
| MITRE ATT&CK | Tactics, techniques, procedures | 7 days |
| OpenCTI Datasets | Marking definitions, identities, locations | 7 days |
| URLhaus | Malicious URLs | 3 days |
| CISA KEV | Known exploited vulnerabilities | 7 days |
| ThreatFox | IOCs (IPs, domains, hashes) | 3 days |
| VX Vault | Malware hosting URLs | 3 days |
| DISARM Framework | Disinformation techniques and tactics | 7 days |

### Optional (require API keys)

Enable by adding API keys to `.env` and starting with the profile:

```bash
# AlienVault OTX (free key at https://otx.alienvault.com)
docker compose --profile alienvault up -d

# AbuseIPDB (free key at https://www.abuseipdb.com)
docker compose --profile abuseipdb up -d

# NVD/CVE (free key at https://nvd.nist.gov/developers/request-an-api-key)
docker compose --profile cve up -d
```

## CTEM Report (Continuous Threat Exposure Management)

Generate a prioritized vulnerability report that cross-references Wazuh-detected CVEs against CISA KEV (actively exploited vulnerabilities) in OpenCTI:

```bash
bash scripts/ctem-report.sh
```

The report covers the 5 CTEM stages:
1. **Scoping** — enrolled agents and attack surface
2. **Discovery** — CVEs detected by Wazuh vulnerability scanning
3. **Prioritization** — cross-reference with CISA KEV to flag actively exploited CVEs
4. **Threat landscape** — IOC counts, ATT&CK coverage from OpenCTI
5. **Recommendations** — actionable next steps

Schedule weekly: `0 6 * * 1 cd /path/to/wazuh-opencti && bash scripts/ctem-report.sh >> /var/log/ctem-report.log`

## Network IDS (optional)

Enable Suricata for network traffic analysis — alerts feed directly into Wazuh:

```bash
docker compose --profile suricata up -d
```

Suricata monitors host network traffic with `network_mode: host`, detects intrusions, and forwards alerts to Wazuh via syslog. Wazuh IDS rules process Suricata alerts, and the OpenCTI integration enriches matched IPs against threat intel. Active response auto-blocks confirmed threats.

Edit the `SURICATA_OPTIONS` environment variable to change the monitored interface (default: `eth0`).

## Notifications

### Email (SMTP)

Edit `.env` to configure email alerts for level 12+ events:

```bash
SMTP_HOSTNAME=smtp.example.com
ALERT_EMAIL_FROM=wazuh@example.com
ALERT_EMAIL_TO=soc-team@example.com
```

Then restart the manager: `docker compose restart wazuh.manager`

### Slack

Set `SLACK_WEBHOOK_URL` in `.env` before running `setup.sh`, or add manually to ossec.conf:

```xml
<integration>
    <name>slack</name>
    <hook_url>https://hooks.slack.com/services/YOUR/WEBHOOK/URL</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
</integration>
```

## Monitoring (optional)

Enable Grafana + Prometheus + cAdvisor for container metrics:

```bash
docker compose --profile monitoring up -d
```

| Service | URL | Default Credentials |
|---------|-----|-------------------|
| Grafana | `https://localhost:4443` | admin / (from `.env`) |

Prometheus auto-discovers container metrics via cAdvisor. Import dashboard [193](https://grafana.com/grafana/dashboards/193-docker-monitoring/) in Grafana for pre-built Docker visualizations.

## Wazuh Agent Enrollment

### Linux

```bash
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.4-1_amd64.deb
sudo WAZUH_MANAGER='<your-server-ip>' WAZUH_REGISTRATION_SERVER='<your-server-ip>' dpkg -i wazuh-agent.deb
sudo systemctl enable --now wazuh-agent
```

### Windows (PowerShell as admin)

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.4-1.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='<your-server-ip>' WAZUH_REGISTRATION_SERVER='<your-server-ip>'
net start Wazuh
```

Replace `<your-server-ip>` with the host running this stack. Agents connect on ports **1514/tcp** (events) and **1515/tcp** (enrollment). For non-agent log sources (firewalls, network devices, syslog forwarders), forward syslog to **514/udp** instead.

## Let's Encrypt Certificates

To replace self-signed certs with Let's Encrypt:

```bash
# Install certbot
sudo apt install certbot

# Generate cert (requires port 80 temporarily open)
sudo certbot certonly --standalone -d your-domain.com

# Copy to nginx ssl dir
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem config/nginx/ssl/opencti.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem config/nginx/ssl/opencti.key

# Update hostname and restart
sed -i 's/OPENCTI_HOSTNAME=.*/OPENCTI_HOSTNAME=your-domain.com/' .env
docker compose restart nginx
```

Set up auto-renewal via cron:
```bash
0 3 * * * certbot renew --deploy-hook "cd /path/to/wazuh-opencti && cp /etc/letsencrypt/live/your-domain.com/fullchain.pem config/nginx/ssl/opencti.crt && cp /etc/letsencrypt/live/your-domain.com/privkey.pem config/nginx/ssl/opencti.key && docker compose restart nginx"
```

## Web Proxy Support

For deployments behind a corporate proxy:

```bash
cp proxy.env.example proxy.env
# Edit proxy.env with your proxy URLs:
#   HTTP_PROXY=http://proxy.corp:8080
#   HTTPS_PROXY=http://proxy.corp:8080
docker compose up -d
```

The proxy settings are applied to all internet-facing services (connectors, OpenCTI, Shuffle, Wazuh manager). Internal services are excluded via `NO_PROXY`. When `proxy.env` doesn't exist, proxy support is silently skipped.

## Security

All security features are enabled by default:

- **All passwords randomized** per deployment (Wazuh, OpenCTI, Elasticsearch, Redis, RabbitMQ, MinIO, Shuffle)
- **Wazuh mutual TLS** — indexer, manager, and dashboard communicate over TLS with generated certificates
- **Elasticsearch authentication** — `xpack.security.enabled: true`
- **Redis authentication** — `requirepass` enabled
- **Wazuh connector TLS verification** — CA cert mounted and verified
- **Randomized Wazuh cluster key** — `openssl rand -hex 16` per deployment
- **Nginx hardening** — HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, `server_tokens off`, modern cipher suite (ECDHE+AESGCM/CHACHA20-POLY1305), SSL session cache
- **Read-only config mounts** — all bind-mounted configs and certs use `:ro`
- **OpenCTI session timeout** — 30 minutes idle
- **Randomized health check key** — not hardcoded
- **Configurable TLS hostname** — set `OPENCTI_HOSTNAME` in `.env`

### Docker Socket

Shuffle requires `/var/run/docker.sock` mounted on `shuffle-backend` and `shuffle-orborus` to manage workflow worker containers. This grants those containers Docker daemon access. This is an inherent Shuffle design requirement.

## Reliability

- **Healthchecks** on every service (28 containers)
- **`depends_on` with conditions** — services wait for dependencies to be healthy before starting
- **Resource limits** — memory caps on all services; JVM heaps and Node.js `--max-old-space-size` sized to fit
- **Log rotation** — JSON file driver, 10 MB default (50 MB for Wazuh manager), 5 files per container
- **Archive logging** — all events archived to `wazuh-archives-*` indices via Filebeat for forensic analysis (enabled automatically by `setup.sh`)
- **Pinned image versions** — all images use explicit version tags from `.env`
- **Error handling in setup.sh** — `set -euo pipefail`, explicit checks on bcrypt hashing, Docker Compose startup, Wazuh indexer readiness, and security admin initialization

## Configuration

### Exposed Ports

| Port | Service | Protocol |
|------|---------|----------|
| 9443 | Wazuh Dashboard | HTTPS |
| 8443 | OpenCTI Platform | HTTPS |
| 3443 | Shuffle SOAR | HTTPS |
| 1514 | Wazuh agent events | TCP |
| 1515 | Wazuh agent enrollment | TCP |
| 514 | Syslog | UDP |
| 55000 | Wazuh REST API | HTTPS |

### Key Files

```
docker-compose.yml                  # All services with healthchecks, resource limits, log rotation
setup.sh                            # Automated setup: passwords, certs, config, deploy
generate-indexer-certs.yml          # Wazuh TLS cert generation
proxy.env.example                   # Web proxy template
config/
  certs.yml                         # Cert generator node definitions
  nginx/
    opencti.conf                    # OpenCTI HTTPS reverse proxy (port 8443)
    shuffle.conf                    # Shuffle HTTPS reverse proxy (port 3443)
  wazuh_indexer/
    wazuh.indexer.yml               # OpenSearch configuration
  wazuh_dashboard/
    opensearch_dashboards.yml       # Dashboard TLS configuration
  wazuh_integrations/
    custom-opencti                  # Shell wrapper for OpenCTI integration
    custom-opencti.py               # Python script: Wazuh->OpenCTI IOC lookup
  wazuh_rules/
    opencti_rules.xml               # Custom alert rules (100210-100215)
```

### Generated Files (gitignored)

Created by `setup.sh`, never committed:

- `.env` — all secrets, passwords, UUIDs, versions
- `proxy.env` — web proxy settings (optional, user-created)
- `config/wazuh_indexer/internal_users.yml` — bcrypt hashed passwords
- `config/wazuh_dashboard/wazuh.yml` — API credentials
- `config/wazuh_cluster/wazuh_manager.conf` — Wazuh manager config with tokens
- `config/wazuh_indexer_ssl_certs/` — Wazuh TLS certificates
- `config/nginx/ssl/` — Nginx self-signed certificates

### Custom TLS Certificates

`setup.sh` generates self-signed certificates with CN=`localhost` (the default value of `OPENCTI_HOSTNAME` in `.env`), which is fine for local use. To use your own certificates instead:

1. Place your cert and key at `config/nginx/ssl/opencti.crt` and `config/nginx/ssl/opencti.key`
2. Set `OPENCTI_HOSTNAME` in `.env` to match your certificate CN
3. Restart nginx: `docker compose restart nginx`

## Commands

```bash
# Full setup (idempotent)
bash setup.sh

# Start/stop
docker compose up -d
docker compose down

# Cleanup orphan Shuffle worker containers — orborus spawns these outside
# the compose project, so `docker compose down` does not remove them
docker ps -aq --filter name=worker- | xargs -r docker rm -f

# Enable optional connectors
docker compose --profile alienvault up -d
docker compose --profile abuseipdb up -d
docker compose --profile cve up -d

# View logs
docker compose logs -f wazuh.manager
docker compose logs -f opencti
docker compose logs -f shuffle-backend

# Restart a service
docker compose restart wazuh.manager

# Check service health
docker compose ps
```

## Operations

### Backup and Restore

```bash
# Full backup (config + all data volumes, ~online, no downtime)
bash backup.sh

# Backup to a specific directory
bash backup.sh ./backups/before-upgrade

# Restore from backup (stops services, overwrites data, restarts)
bash restore.sh ./backups/20260403-120000
```

Backups include:
- All configuration files and TLS certificates
- Elasticsearch data (OpenCTI threat intel)
- Wazuh indexer data (SIEM alerts, archives, and all indices)
- Redis, RabbitMQ, MinIO data
- Shuffle workflows and execution data

Schedule automatic daily backups via cron:
```bash
# Add to crontab -e:
0 2 * * * cd /path/to/wazuh-opencti && bash backup.sh >> /var/log/soc-backup.log 2>&1
```

### Upgrade

```bash
# Edit .env to set new versions, then:
bash upgrade.sh
```

The upgrade script:
1. Creates a pre-upgrade backup
2. Pulls new images for configured versions
3. Performs a rolling restart (infrastructure first, then applications)
4. Verifies all services are healthy
5. Prints rollback instructions if something goes wrong

### Monitoring

A built-in health monitor checks all container healthchecks and alerts on failures:

```bash
# Check stack health
bash scripts/healthcheck-monitor.sh

# Alert on failures (webhook, email, or both)
ALERT_WEBHOOK_URL=https://hooks.slack.com/... bash scripts/healthcheck-monitor.sh --alert

# Send alerts to a Shuffle workflow
ALERT_WEBHOOK_URL=http://shuffle-backend:5001/api/v1/hooks/YOUR_ID bash scripts/healthcheck-monitor.sh --alert
```

Schedule via cron for continuous monitoring:
```bash
# Every 5 minutes, alert on failures:
*/5 * * * * cd /path/to/wazuh-opencti && ALERT_WEBHOOK_URL=https://... bash scripts/healthcheck-monitor.sh --alert >> /var/log/soc-monitor.log 2>&1
```

### Nginx Rate Limiting

Rate limiting is enabled on all public endpoints to protect against brute-force attacks:

| Endpoint | Rate | Burst |
|----------|------|-------|
| OpenCTI GraphQL API | 30 req/s | 20 |
| OpenCTI general | 50 req/s | 30 |
| Shuffle login API | 5 req/s | 5 |
| Shuffle general | 50 req/s | 30 |

Requests exceeding the limit receive HTTP 429 (Too Many Requests).

## Resource Requirements

| Component | Memory Limit | Notes |
|-----------|-------------|-------|
| Wazuh Manager | 2 GB | Increased log rotation (50 MB) |
| Wazuh Indexer | 2 GB | JVM heap: 1 GB |
| Wazuh Dashboard | 2 GB | |
| Elasticsearch | 6 GB | JVM heap: 3 GB (for OpenCTI) |
| Redis | 1 GB | |
| RabbitMQ | 2 GB | |
| MinIO | 1 GB | |
| OpenCTI Platform | 4 GB | Node.js heap: 3 GB |
| OpenCTI Workers (x3) | 3 GB | 1 GB each |
| Shuffle OpenSearch | 2 GB | JVM heap: 1 GB |
| Shuffle Backend | 2 GB | |
| Shuffle Frontend | 512 MB | |
| Shuffle Orborus | 512 MB | |
| Connectors (x11) | 5.5 GB | 512 MB each |
| Nginx | 256 MB | |
| **Total** | **~34 GB** | Actual usage is typically lower |
| *+ Monitoring* | *+2 GB* | *Prometheus 1G, Grafana 512M, cAdvisor 512M* |

## Credits

- [Wazuh](https://wazuh.com/) — Open-source SIEM/XDR
- [OpenCTI](https://www.opencti.io/) — Open-source Cyber Threat Intelligence platform
- [Shuffle](https://shuffler.io/) — Open-source SOAR
- [misje/wazuh-opencti](https://github.com/misje/wazuh-opencti) — Wazuh-OpenCTI integration scripts
- [misje/opencti-wazuh-connector](https://github.com/misje/opencti-wazuh-connector) — OpenCTI enrichment connector for Wazuh

## License

This deployment configuration is provided as-is. Individual components are governed by their respective licenses (GPLv2 for Wazuh, Apache 2.0 for OpenCTI, AGPL for Shuffle).
