# Birthday Memory — Application Security Assessment Report (Track B)

**Course:** CYBR 4550 — Threat Actors / Applied Security Assessment  
**Track:** Track B (Application Security)  
**Target Application:** Birthday Memory (React/Vite frontend, Express REST API, PostgreSQL 16 in Docker)  
**Branch:** `security-hardening-appsec`  
**Date:** November 21, 2026

---

## 1. Executive Summary

This assessment evaluated the *Birthday Memory* three-tier web application across three domains: the Express API, the PostgreSQL database layer, and the Docker container configuration. Before hardening, the application exposed all stored PII (names, birthdates, phone numbers, and email addresses) to any unauthenticated client, accepted cross-origin requests from any website, ran database queries as a Postgres superuser with hardcoded default credentials, and shipped with a Critical IP-spoofing flaw in `proxy-addr`.

All high-priority findings from the Phase B1 threat model (`security/threat-model.md`) were remediated in four sequenced commits, verified with paired before-and-after evidence in `security/baseline/` and `security/after/`, and tested end-to-end in the React UI. Both `server/` and `client/` dependency audits now report **0 vulnerabilities**, unauthenticated API access is blocked with `401 Unauthorized`, the database runtime runs under a least-privilege role (`bm_app`), and PostgreSQL is locked down to `127.0.0.1` inside a hardened container.

---

## 2. Scope & Methodology

1. **Baseline Capture:** Started the unmodified stack and recorded live evidence of open endpoints, exposed headers, Docker bindings, dependency CVEs, and SQL injection behavior in `security/baseline/`.
2. **Threat Modeling (Phase B1):** Built a Data Flow Diagram with trust boundaries, ran a STRIDE analysis across all three domains, verified false positives, and prioritized fixes in `security/threat-model.md`.
3. **Iterative Hardening (Phase B2):** Applied fixes in four isolated commits—dependencies, container/secrets, database least privilege, and API/client security—capturing matching verification artifacts in `security/after/` at each step.
4. **Functional Verification:** Confirmed the React UI at `http://localhost:5173` loads seeded data, creates and deletes records through the authenticated API, and writes PII-free audit logs to the server console.

---

## 3. Before vs. After Evidence Matrix

| Finding / Control | Before Hardening (`security/baseline/`) | After Hardening (`security/after/`) | Status |
| :--- | :--- | :--- | :--- |
| **Server Dependencies** | Critical `proxy-addr` IP spoofing (`GHSA-jqcg-44mw-7w3h`) + High/Moderate DoS CVEs (`npm_audit_server_before.txt`) | `found 0 vulnerabilities` (`npm_audit_server_after.txt`) | **Fixed** |
| **Client Dependencies** | High CVEs in `vite` and `source-map-js` (`npm_audit_client_before.txt`) | `found 0 vulnerabilities` (`npm_audit_client_after.txt`) | **Fixed** |
| **Container Exposure & Hardening** | Postgres bound to `0.0.0.0:5544->5432/tcp`, floating `postgres:16-alpine` tag, default creds, no caps/limits (`docker_ps_before.txt`) | Bound strictly to `127.0.0.1:5544->5432/tcp`, pinned by SHA256 digest, `cap_drop: [ALL]`, `read_only: true`, `no-new-privileges`, memory/CPU/PID caps, healthy (`docker_ps_after.txt`) | **Fixed** |
| **Database Least Privilege** | App connected as Postgres superuser (`birthday`) and executed DDL at startup | Runtime uses `bm_app` role (DML only); `SELECT` succeeds and `DROP TABLE birthdays;` fails with `must be owner of table birthdays` (`db_least_privilege_after.txt`) | **Fixed** |
| **API Authentication** | `GET /api/birthdays` returned `200 OK` with full PII dump without credentials (`api_birthdays_unauth_before.txt`) | Unauthenticated requests return `401 Unauthorized` (`api_birthdays_unauth_after.txt`); valid Bearer token returns `200 OK` (`api_birthdays_auth_after.txt`) | **Fixed** |
| **Bulk Exfiltration / Pagination** | Unbounded `SELECT` returned entire table in one request (`api_birthdays_unauth_before.txt`) | Bounded `LIMIT`/`OFFSET` (default 100, max 200) verified with `?limit=3` returning `X-Limit: 3` and 3 rows (`api_birthdays_auth_after.txt`) | **Fixed** |
| **CORS Policy** | Wide-open `cors()` allowed any origin | Explicit allowlist (`http://localhost:5173`); `Origin: https://evil.example` receives no `Access-Control-Allow-Origin` header (`cors_blocked_after.txt`) | **Fixed** |
| **Headers, Rate Limit & Health** | `/api/health` leaked DB name (`thebirthdates`), exposed `X-Powered-By: Express`, no security or rate-limit headers (`api_health_before.txt`) | Returns `{"status":"ok"}`, removes `X-Powered-By`, enforces `helmet` headers (`CSP`, `HSTS`, `nosniff`, `SAMEORIGIN`) and `RateLimit` (`100/15m`) (`health_after.txt`) | **Fixed** |
| **SQL Injection** | `GET /api/birthdays?q=' OR '1'='1` returned `200 OK` with `[]` (`sqli_test_before.txt`) | Parameterized queries (`$1`–`$6`) and `UUID_RE` checks preserved across all routes | **Not Vulnerable** |

---

## 4. Remediation Summary by Domain

### Domain 1: Express API & React Client
* **Authentication:** Added `requireAuth` middleware in `server/src/index.js` using `crypto.timingSafeEqual` for constant-time Bearer token validation against `API_KEY` (stored in untracked `server/.env`). Updated `client/src/lib/api.js` to attach the token from untracked `client/.env`.
* **Headers, CORS, and DoS Controls:** Added `helmet()`, disabled `x-powered-by`, locked CORS to `CORS_ORIGIN` (`http://localhost:5173`), capped JSON payloads at `16kb` (`express.json({ limit: '16kb' })`), bound Express to `127.0.0.1:4000`, and added `express-rate-limit` (`100` requests per 15 minutes).
* **Validation & Pagination:** Tightened `server/src/validate.js` to reject non-string types instead of coercing them with `String(...)` and capped `email` at 254 characters. Added bounded `LIMIT`/`OFFSET` pagination and `X-Limit`/`X-Offset` headers in `server/src/routes.js`.
* **Sanitized Health & Audit Logging:** Stripped the database name and raw error details from `/api/health`. Added structured JSON audit logs (`CREATE_BIRTHDAY`, `UPDATE_BIRTHDAY`, `DELETE_BIRTHDAY`) recording `recordId`, `timestamp`, `method`, `path`, and `ip` without logging PII.

### Domain 2: PostgreSQL Database
* **Role Separation:** Separated schema ownership (`bm_admin`) from runtime access (`bm_app`), revoking `PUBLIC` privileges on the database and schema and granting `bm_app` only `SELECT`, `INSERT`, `UPDATE`, and `DELETE` on `birthdays`.
* **Credential & TLS Hardening:** Removed hardcoded `birthday` fallbacks from `server/src/db.js` and `server/.env.example` so the API fails closed if credentials are missing. Changed `PGSSL=true` handling to enforce `rejectUnauthorized: true` (with optional `PGSSLROOTCERT`) and removed runtime DDL from `initSchema()`.

### Domain 3: Docker Container & Secrets
* **Container Lock-Down:** Pinned `docker-compose.yml` to the exact `postgres:16-alpine` SHA256 digest, bound port `5544` strictly to `127.0.0.1`, added `cap_drop: [ALL]` (restoring only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`), enabled `read_only: true` with `tmpfs` mounts for `/tmp` and `/var/run/postgresql`, added `no-new-privileges:true`, and set `mem_limit: 512m`, `cpus: 1.0`, and `pids_limit: 100`.
* **Secret Hygiene:** Replaced hardcoded Compose passwords with required `.env` variables (`:?` syntax), generated random passwords with `openssl`, restricted file permissions (`chmod 600`), and verified via `git status` that no `.env` files are tracked.

---

## 5. Residual Risks & Production Recommendations

Even after hardening the local stack, three architectural trade-offs remain and should be addressed before any internet-facing deployment:

1. **Shared API Key vs. Per-User Authentication:** A shared Bearer token blocks unauthenticated access and fits a single-user local app, but shipping `VITE_API_KEY` in a frontend bundle means any user with browser DevTools can read it. Production should use per-user authentication (OIDC/OAuth2 or `HttpOnly` session cookies) with per-user ownership checks.
2. **Transport Encryption (HTTPS & Postgres TLS):** Local traffic runs over loopback HTTP and `PGSSL=false`. Production should terminate TLS at a reverse proxy (Caddy/Nginx) and enable `PGSSL=true` with a CA-signed database certificate.
3. **PII Encryption at Rest:** Names, birthdates, phone numbers, and emails remain plaintext inside the Postgres volume. Production deployments handling real user PII should enable disk-level encryption and consider application-level or KMS-backed column encryption.
