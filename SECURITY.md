# Security Policy

## Supported Versions

This project tracks upstream component versions. Security updates are applied by updating the pinned image tags in `.env` and redeploying.

| Component | Version | Status |
|-----------|---------|--------|
| Wazuh | 4.14.4 | :white_check_mark: Supported |
| OpenCTI | 6.9.28 | :white_check_mark: Supported |
| Elasticsearch | 8.19.13 | :white_check_mark: Supported |
| RabbitMQ | 4.2.5 | :white_check_mark: Supported |
| Shuffle SOAR | v2.2.0 | :white_check_mark: Supported |
| Redis | 7.4 | :white_check_mark: Supported |

## Reporting a Vulnerability

If you discover a security vulnerability in this deployment project (docker-compose configuration, setup scripts, integration scripts, or custom rules), please report it responsibly:

1. **Do NOT open a public issue** for security vulnerabilities
2. Use [GitHub Security Advisories](https://github.com/Jo-the-bat/wazuh-opencti/security/advisories/new) to report privately
3. Alternatively, contact the maintainer directly via GitHub

You can expect:
- **Acknowledgment** within 48 hours
- **Assessment** within 1 week
- **Fix or mitigation** as soon as possible, depending on severity

## Security Architecture

This deployment implements the following security measures. See the [Security Hardening wiki page](https://github.com/Jo-the-bat/wazuh-opencti/wiki/Security-Hardening) for full details.

### Container Security
- **`no-new-privileges`** on 30/32 containers (CIS Docker Benchmark 5.25)
- **`cap_drop: ALL`** on 23/26 base services with minimal `cap_add` (ANSSI R8-)
- **CPU and memory limits** on all 34 services (ANSSI R10/R11)
- **Read-only root filesystem** on Nginx with tmpfs for writable paths (ANSSI R12)
- **Pinned image versions** — all images use explicit version tags, never `latest`

### Authentication & Secrets
- **All passwords randomized** at deployment time (Wazuh, OpenCTI, Elasticsearch, Redis, RabbitMQ, MinIO, Shuffle)
- **Wazuh password complexity** enforced: uppercase + lowercase + digit + special character
- **`.env` file permissions**: `chmod 600` (owner-only read/write)
- **OpenCTI session timeout**: 30 minutes idle
- **Randomized Wazuh cluster key** via `openssl rand -hex 16`
- **Randomized health check key** for OpenCTI

### Network & TLS
- **Mutual TLS** between Wazuh manager, indexer, and dashboard (auto-generated certificates)
- **HTTPS** on all web interfaces via Nginx reverse proxy
- **Modern cipher suite**: ECDHE+AESGCM/CHACHA20, TLSv1.2/1.3 only
- **Wazuh connector TLS verification** enabled with CA cert mounted
- **No internal services exposed** to the host (Elasticsearch, Redis, RabbitMQ, MinIO)

### HTTP Security Headers
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `server_tokens off` (Nginx version hidden)

### Rate Limiting
- Login endpoint: 5 req/s
- GraphQL API: 30 req/s (burst 20)
- General: 50 req/s (burst 30)

### Data Protection
- **Read-only config mounts** — all bind-mounted configs and certs use `:ro`
- **Log rotation** — JSON file driver with size limits prevents disk exhaustion
- **Index lifecycle** — 90-day retention on all Wazuh indices (auto-delete)
- **Elasticsearch authentication** — `xpack.security.enabled: true`
- **Redis authentication** — `requirepass` with randomized password

## Known Limitations

- **Self-signed certificates**: The deployment uses self-signed TLS certificates. For production, replace with certificates from a trusted CA.
- **Docker socket access**: Shuffle (orborus/backend) requires Docker socket access to spawn workflow workers. These containers do not have `no-new-privileges`.
- **Single-node deployment**: This is a single-server deployment. For high availability, additional configuration is needed.
- **Syslog (UDP 514)**: Syslog uses unencrypted UDP. For sensitive environments, consider agent-based collection over TLS (port 1514) instead.

## Security References

- [ANSSI-FT-082 — Docker Hardening Guide](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-au-deploiement-de-conteneurs-docker/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Wazuh Security Configuration](https://documentation.wazuh.com/current/user-manual/manager/security-configuration.html)
- [OpenCTI Security](https://docs.opencti.io/latest/deployment/configuration/#security)
