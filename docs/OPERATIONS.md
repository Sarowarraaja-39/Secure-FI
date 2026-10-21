# Operations

## Supported local profile

Use `python start.py [--demo]`. Its HTTP server listens on `127.0.0.1` and is intended for a private workstation. SQLite uses write-ahead logging and tenant write transactions. Run from the repository root so the default private `data/` directory is predictable. No paid services are required.

The token file contains hashed tokens and the pseudonymisation key. POSIX creation mode is `0600`; on Windows apply equivalent user-only file permissions. Tokens are not logged by request handlers, but first-run credentials are deliberately printed to your own terminal. Avoid screen recordings that show them.

Default CLI paths can be overridden before a subcommand:

```bash
python -m securefi app --db /private/workspace/platform.db --auth /private/workspace/access.json demo
python -m securefi app --db /private/workspace/platform.db --auth /private/workspace/access.json serve --port 8765
```

The older `securefi lab` alias remains for compatibility. The separate `python -m securefi --help` findings workbench retains SARIF, CycloneDX and finding-import tools; it uses a different database and is not silently merged into the current event pipeline.

## Backup and recovery

For the simplest consistent local backup, stop the application and workers, then copy the complete private data directory to an access-controlled backup location. Include the database, any SQLite sidecar files and matching `access.json`; preserve its file permissions. Restart only after copying completes. For online backup use SQLite's documented backup API, not a blind copy of the active main database file.

Test restoration into a separate directory. Start using explicit `--db`/`--auth`, verify audit integrity, event/case counts and one frozen report digest. Preserve any independently stored audit checkpoint. A local EVM has separate state: restoring SQL does not restore a chain. A chain failure must stay visible rather than being reported as successful verification.

Retention is available through the domain `retention` operation. It removes old events only when alerts do not reference them. The release does not schedule automatic retention, delete case/evidence records, implement legal holds or claim complete privacy-erasure automation.

## ASGI and Docker sandbox profile

Install `requirements-platform.txt`. Initialise credentials before starting the optional service:

```bash
python -m securefi app init
python -m uvicorn services.asgi:app --host 127.0.0.1 --port 8080 --no-proxy-headers
```

The service requires an existing access file, rather than generating invisible container credentials. Set `SECUREFI_AUTH_FILE`, `SECUREFI_DB`, `SECUREFI_DATABASE_URL` and `SECUREFI_ALLOWED_HOSTS` as appropriate. Authentication configuration is loaded at startup; restart after rotation.

Compose prerequisites: Docker Engine with Compose, available image registries and enough resources for PostgreSQL/RabbitMQ. Prepare the container-readable access-file copy inside its private host directory:

```bash
python -m securefi app init
python scripts/prepare_container_access.py
# Set fresh sandbox values in SECUREFI_POSTGRES_PASSWORD and SECUREFI_RABBIT_PASSWORD.
docker compose -f deploy/compose/compose.yaml up --build
```

Generate strong fresh values in your own environment. Use URL-safe values or percent-encode credentials correctly in service URLs. Compose API binds to `127.0.0.1:8080`; the internal data network is not published. Regenerate the container access copy and restart services after changing tokens. Host data directories are ignored by Git.

The default container is non-root, has a read-only root filesystem in Compose, drops capabilities and mounts credentials read-only. The PostgreSQL profile creates its operational tables on startup. `schemas/postgresql.sql` additionally documents constraints/indexes. If upgrading a previously constraint-initialised schema, extend the `records_kind_check` constraint to include `asset`, `draft` and `registry` before using version 2.1; an existing table is not migrated automatically.

## Kubernetes, Helm and Terraform

Kubernetes YAML and Helm are deployment starting points for a sandbox. They require a built `securefi:2.1.0` image loaded into the cluster, reachable PostgreSQL, `securefi-access` and `securefi-runtime` secrets, and CNI support for network policy. Review the outbound database selector/CIDR and namespace labels against your actual environment before applying policy. There is no automatic cloud or cluster creation.

The Terraform sandbox contains a private network module and an encrypted, versioned, public-access-blocked evidence bucket module. It requires your own sandbox account, region, availability zone, globally unique bucket name and KMS key ARN. Run `terraform init`, `fmt`, `validate` and review a plan. Cloud resources may incur costs; no apply was run for this release. These modules do not provision a complete managed Kubernetes, identity or SIEM environment.

## Hardening and operational limits

Before shared or internet-facing use, implement OIDC/MFA, managed secrets, revocation, TLS and trusted edge policy, bounded request streaming/rate limits, pagination, independently verified backups, central operational logs and alerting, database service isolation and a security review. ASGI `/healthz` is liveness only. The default HTTP handler suppresses access logs; the activity log records domain actions, not every denied request.

Full tenant-history scans bound the current practical scale. Avoid treating a short local fixture benchmark as sustained service capacity. Optional infrastructure deployments have not been exercised end to end in the release environment; syntax and adapter tests are identified separately in `TESTING.md`.
