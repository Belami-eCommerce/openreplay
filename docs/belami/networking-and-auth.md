# Networking and Auth — Belami's CF Access pattern

How Belami fronts internally-hosted tools (OpenReplay being the first) with Cloudflare Tunnel + Cloudflare Access, and how the app consumes the resulting identity to skip its own login flow.

## TL;DR

End-to-end auth for `replays-sandbox.belamiecommerce.com`:

```
User browser
    │  HTTPS, port 443 at the edge
    ▼
Cloudflare Edge   ──►  Cloudflare Access  ──►  Entra ID SSO
                       (issues signed JWT, sets CF_Authorization cookie,
                        adds Cf-Access-Authenticated-User-Email header)
    │
    ▼
Cloudflare Tunnel  (outbound-only daemon `cloudflared` running on the VM)
    │
    ▼
caddy on 127.0.0.1:9080  (HTTP, loopback only — no NSG path)
    │
    ▼
nginx (docker-internal)
    │
    ▼
chalice (FastAPI auth/admin service)
    │
    ▼
GET /api/cf-sso/login
    Reads Cf-Access-Authenticated-User-Email header
    Looks up user; auto-provisions as `member` if first time
    Mints OpenReplay's standard JWT + refresh-token cookies
```

## What runs where

| Layer | Hostname / Port | Bound to | What it does |
|---|---|---|---|
| Public hostname (prod) | `replays.belamiecommerce.com` | Cloudflare edge | Prod OpenReplay |
| Public hostname (sandbox) | `replays-sandbox.belamiecommerce.com` | Cloudflare edge | Sandbox OpenReplay (this branch) |
| SSH gateway | `ssh-replays.belamiecommerce.com` | Cloudflare edge | SSH to the VM, gated by CF Access |
| Tunnel daemon | `cloudflared` service | Outbound from VM | Maintains 2 connections to CF edge; no inbound |
| caddy (sandbox) | `127.0.0.1:9080` | Loopback only | HTTP origin for the sandbox |
| caddy (prod) | `0.0.0.0:80` / `0.0.0.0:443` | Host-bound | HTTP origin for prod |
| nginx, chalice, frontend, etc. | docker-internal | bridge network only | OpenReplay app services |

The two stacks share one VM but are completely isolated at every layer (separate docker projects, networks, volumes, container names).

## Identity flow

### At the edge: Cloudflare Access

When a request arrives for a hostname with an Access app attached:

1. CF checks for the `CF_Authorization` cookie on the user's browser. Missing → redirect to Entra SSO.
2. User completes Entra SSO. Entra returns a SAML assertion to CF.
3. CF validates the assertion against the Belami IdP federation (`idp.id = 4937ee4c-...`).
4. CF evaluates the **policy attached to the application**. Policy "Allow openreplay audience" includes by Azure-Group UUIDs:
   - `RG-SUP-DEFAULTROLE` = `dd9b4f14-f4d8-4072-ab57-d2d6f9b6d072`
   - `RG-DEV-DEFAULTROLE` = `34aedce2-8cde-4312-8b83-d4b6a3e268e5`
5. On allow, CF issues its own short-lived JWT, sets the `CF_Authorization` cookie, and forwards the request through the tunnel — adding two headers visible to the origin:
   - `Cf-Access-Authenticated-User-Email`
   - `Cf-Access-Jwt-Assertion`

### At the app: trusted-header SSO

OpenReplay's chalice service (Belami fork) exposes a new endpoint `GET /api/cf-sso/login` that:

1. Checks `CF_SSO_ENABLED` env var. If false, returns 404.
2. Reads `Cf-Access-Authenticated-User-Email`. If missing, returns 401.
3. Looks up the email in `public.users`. If found, mints OpenReplay's session JWT for that user.
4. If not found, calls `create_new_member()` with `role='member'` and `tenant_id=1` (single-tenant self-host), then mints the JWT.
5. Returns the same response shape as the existing email/password `/login` endpoint, including the `refreshToken` and `spotRefreshToken` httponly cookies.

The frontend can transparently call this on app mount and skip the login form entirely.

### Provisioning policy

| Trigger | Action |
|---|---|
| First user (manual) | Bootstrap via `/signup` wizard → becomes `owner` (creates the tenant) |
| Subsequent users via SSO | Auto-provision as `role=member` |
| Admin promotion | Manual, via OpenReplay admin UI |

No claim-mapping logic. Group-based admin elevation is a future option but not implemented — kept simple deliberately.

## Why "trust the proxy" instead of in-app SAML

OpenReplay CE (community edition) doesn't ship the SAML SSO code; that's an EE feature gated by license. Two viable Option-tree leaves remained:

| Option | Verdict |
|---|---|
| Pay for OpenReplay EE license | Works but doesn't help future tools |
| Patch chalice to consume `Cf-Access-Authenticated-User-Email` | ~80 LOC, works for any tool with login route to bypass |

We chose the patch path. The same pattern applies to any future tool we self-host behind CF Access: read the upstream email header, look up the local user, mint a session.

## Threat model

The patch trusts the upstream `Cf-Access-Authenticated-User-Email` header at face value. This is safe **only if** chalice is unreachable except via the tunnel path. Verify periodically that:

- caddy binds `127.0.0.1:9080`, not `0.0.0.0:9080` (`docker inspect caddy-sandbox | grep HostIp`)
- No NSG rule exposes 9080 on the VM's NIC
- chalice is in the docker-internal network only (no host port bindings)

If any of those drift — e.g. a future change rebinds caddy to all interfaces — the trust assumption breaks because anyone reaching the VM at the network layer could forge the email header.

**Hardening for v2:** verify `Cf-Access-Jwt-Assertion` against Cloudflare's JWKS endpoint (`https://belami-edge.cloudflareaccess.com/cdn-cgi/access/certs`). About 20 extra lines using `python-jose`. Pinned for a follow-up commit.

## What's where in the codebase

| Path | Purpose |
|---|---|
| `api/chalicelib/core/users.py` | `get_or_provision_sso_user()` and `authenticate_sso()` helpers |
| `api/routers/core_dynamic.py` | `GET /cf-sso/login` endpoint, near the existing `POST /login` |
| `scripts/docker-compose/docker-envs/chalice.env` | `CF_SSO_ENABLED=true` |
| `api/Dockerfile` | unchanged — same multi-stage Python 3.13 alpine build, just rebuilt as `belami/chalice:1.26.0-cfsso` |

## Cookies / session details

The endpoint sets the same cookies as the standard login flow:

| Cookie | Path | Max-Age | Purpose |
|---|---|---|---|
| `refreshToken` | `/api/refresh` | 7 days | Refresh the `jwt` |
| `spotRefreshToken` | `/api/spot/refresh` | 7 days | Refresh `spotJwt` (spot is the comments/screenshot product) |

Both are `HttpOnly`, `Secure`, `SameSite=lax`. Frontend never sees the refresh tokens — only the short-lived `jwt` and `spotJwt` in the response body.

## Operational gotchas

- **Email-domain mismatch (Daniel only):** Daniel's UPN is `daniel.williams@belamiecommerce.com`, while everyone else's UPN matches their `@belamiinc.com` mail attribute. CF Access sends the UPN. Daniel's owner account must be signed up with `@belamiecommerce.com` so SSO matches; everyone else SSO's in as `@belamiinc.com` with no quirk.
- **First signup must be manual.** SSO can't bootstrap an empty system because OpenReplay's `__process_authentication_response` fetches `scope.get_scope(-1)` from the tenants table, which 500s if no tenant exists.
- **Cleanup on failed test:** If the SSO endpoint provisions a user during a failed test (DB insert succeeded but response 500'd), there's an orphan row. Clean with `DELETE FROM basic_authentication WHERE user_id = X; DELETE FROM users WHERE user_id = X;`.

## Reference: applying this pattern to a new tool

For any future internally-hosted app behind CF Access:

1. Add the public hostname route on the existing tunnel `cft-vm-nc-openreplay` (or stand up a dedicated tunnel for blast-radius isolation).
2. Create a CF Access Application on the new hostname.
3. Attach an existing reusable policy (e.g. "allow openreplay audience" or whichever fits — never duplicate a policy with display-name strings; use Entra group **UUIDs**).
4. Bind the app's HTTP origin to `127.0.0.1:<some-port>` only — never `0.0.0.0`.
5. In the app code, add a route that reads `Cf-Access-Authenticated-User-Email`, gates on a `*_SSO_ENABLED` env, and bypasses the app's normal login.
6. Document the new app in this section.
