# CLAUDE.md

## Project Overview

Docker Compose deployment of **Wazuh** (SIEM/XDR) + **OpenCTI** (Cyber Threat Intelligence) with HTTPS and bidirectional threat intel integration.

## Architecture

17 Docker containers on a single `wazuh-opencti` bridge network:

- **Wazuh Stack**: manager (4.9.2), indexer (OpenSearch), dashboard — mutual TLS on all inter-component communication
- **OpenCTI Stack**: platform (6.4.5), 3 workers, Elasticsearch 8.15.3, Redis, RabbitMQ, MinIO
- **Connectors**: STIX/CSV export, STIX/document import, Wazuh enrichment connector
- **Nginx**: HTTPS reverse proxy for OpenCTI (port 8443)

## Integration (Bidirectional)

1. **Wazuh → OpenCTI** (`custom-opencti` integration inside wazuh.manager): When Wazuh sees an IP/hash/domain in an alert, it queries OpenCTI's GraphQL API. If the observable is a known IOC, a level 10-12 alert is generated. Uses the [misje/wazuh-opencti](https://github.com/misje/wazuh-opencti) fork (compatible with OpenCTI 6.x). Scripts live at `/var/ossec/integrations/custom-opencti{,.py}` inside the manager container, rules at `/var/ossec/etc/rules/opencti_rules.xml`.

2. **OpenCTI → Wazuh** (`ghcr.io/misje/opencti-wazuh-connector:0.3.0`): OpenCTI enrichment connector that searches Wazuh's indexed alerts when viewing indicators, creating STIX sightings.

## Key Files

```
.env                          # ALL secrets/passwords/tokens (gitignored)
docker-compose.yml            # All 17 services
setup.sh                      # Automated setup: certs, .env generation, deploy
generate-indexer-certs.yml    # Wazuh TLS cert generation (one-shot)
config/
  certs.yml                   # Node definitions for Wazuh cert generator
  wazuh_indexer/
    wazuh.indexer.yml          # OpenSearch config (single-node, TLS)
    internal_users.yml         # Indexer security users (bcrypt hashes)
  wazuh_cluster/
    wazuh_manager.conf         # ossec.conf with OpenCTI integration block
  wazuh_dashboard/
    opensearch_dashboards.yml  # Dashboard TLS + indexer connection
    wazuh.yml                  # Dashboard plugin → manager API connection
  nginx/
    opencti.conf               # HTTPS reverse proxy with WebSocket support
    ssl/                       # Self-signed certs for Nginx (gitignored)
  wazuh_indexer_ssl_certs/     # Generated Wazuh TLS certs (gitignored)
```

## Exposed Ports

| Port | Service |
|------|---------|
| 9443 | Wazuh Dashboard (HTTPS) |
| 8443 | OpenCTI Platform (HTTPS via Nginx) |
| 1514 | Wazuh agent events |
| 1515 | Wazuh agent enrollment |
| 514/udp | Syslog |
| 55000 | Wazuh REST API |

## Common Commands

```bash
bash setup.sh                    # Full setup (idempotent)
docker compose up -d             # Start all services
docker compose down              # Stop all services
docker compose logs -f <service> # Tail logs (e.g. opencti, wazuh.manager)
docker compose ps                # Check status
```

## Important Notes

- `.env` contains all secrets — never commit it. `setup.sh` generates it with random passwords/UUIDs.
- The `wazuh_manager.conf` on the host has a placeholder token (`OPENCTI_ADMIN_TOKEN_PLACEHOLDER`). The actual token is injected into the running container's ossec.conf. After `setup.sh`, update the host file with the real token from `.env` for full persistence.
- The Wazuh indexer requires `vm.max_map_count >= 262144` (recommended 1048575). `setup.sh` checks this.
- Self-signed TLS certificates are used everywhere. Browsers will show security warnings.
- The `custom-opencti` integration scripts and `opencti_rules.xml` are persisted in Docker named volumes (`wazuh_integrations`, `wazuh_etc`). They survive `docker compose restart` but NOT `docker compose down -v`.
- Port 443 was unavailable on this host, so Wazuh Dashboard uses 9443 instead of the default 443.
