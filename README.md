# webhost 0.3

Universal single-file Go website hosting server (stdlib only, no module deps).

## Build (Linux)

```bash
cd /path/to/webhost
go build -o webhost main.go
# or run from source:
chmod +x main.go && ./main.go version
```

Requires Go 1.22+ (verified on Go 1.24). CGO is not needed — the binary is static.

## Quick start

```bash
# 1) Init data dir, config.json, local CA, demo site + admin token (printed once)
./webhost init -dir ~/webhost-data

# 2) Put your site files into the site root (demo uses sites/default/current)
cp -a /path/to/site/. ~/webhost-data/sites/default/current/

# 3) Optional health check of config / CA / binds
./webhost doctor -dir ~/webhost-data

# 4) Run (HTTP :8080 / HTTPS :8443 as non-root; :80/:443 if root)
./webhost run -config ~/webhost-data/config.json
```

Without arguments, `./webhost` does init-if-needed then run.

Admin token is generated on `init` and written to `config.json` (`admin.token`).  
Use: `Authorization: Bearer <token>` against `http://127.0.0.1:9080/`.

## HTTPS for a real domain

1. Point DNS A/AAAA of your domain to this machine.
2. Edit `config.json`:
   - site `domains`: your FQDN (not `*`)
   - `listen.http` / `listen.https`: `:80` / `:443` (needs root or CAP_NET_BIND_SERVICE)
   - site `tls.enabled: true`, `tls.acme: true`
   - top-level `acme.enabled: true`, `acme.email`, `acme.agree_tos: true`
3. Restart / `webhost reload`. ACME HTTP-01 uses port 80; certificates renew in the background.

Until ACME succeeds, SNI serves a local-CA / self-signed cert (`webhost ca` shows how to trust it).

## Site modes

Per-site `type` in `config.json`:

| type | behavior |
|------|----------|
| `static` | files from `root`, index, ETag/cache, gzip |
| `spa` | static + fallback to `index.html` |
| `proxy` | reverse proxy to `upstreams` (http/https), health checks, LB |
| `fastcgi` | PHP-FPM / FastCGI |
| `redirect` | HTTP redirect |

Also: ACL, basic auth, CORS, security headers, rate limit, body size limits, path traversal protection, custom error pages, maintenance mode, access/error rotating logs.

## Service install (systemd)

```bash
sudo ./webhost service -install -user webhost
# unit uses: webhost run -config <data>/config.json
```

Also supports OpenRC / rc.d / launchd / schtasks where available.

## Useful CLI

```bash
./webhost version
./webhost doctor -config ~/webhost-data/config.json
./webhost reload -config ~/webhost-data/config.json
./webhost deploy mysite ./dist -config ~/webhost-data/config.json
./webhost backup create -config ~/webhost-data/config.json
./webhost hash 'mypassword'          # for basic_auth in config
./webhost mail send -to you@example.com -subject 'Test' -text 'Hello' -config ~/webhost-data/config.json
./webhost service -uninstall
```

`mail send` needs `mail.enabled: true` and `mail.from`; the same is available as `POST /api/v1/mail/send` (Admin API, JSON: `to`, `subject`, `text` and/or `html`, optional `from`, `headers`).

## Notes

- **IP trust model:** Forwarding headers (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Forwarded-Port`) are honored only when the TCP peer is in `listen.trusted_proxies`. Otherwise they are ignored and stripped so they cannot spoof ACL/rate-limit or be smuggled upstream. Trusted peers: headers are walked right-to-left (skip trusted hops, chain cap, never leftmost blindly); several `X-Forwarded-For` lines are read as one chain. Rate-limit and ACL use the resolved IP from request context only.
- Default `trusted_proxies` is loopback only. Behind a real reverse proxy set LAN/CIDR **and** `listen.allow_wide_trusted_proxies: true` (fail-closed without the opt-in).
- Admin must bind to a specific address (default `127.0.0.1:9080`), not `0.0.0.0`.
- Default max body size: 64 MiB (raise in `limits.max_body_bytes_mb` if needed).
- `/metrics` and Admin API require Bearer token; `/healthz` is open on the admin listener.
- **Behind a TLS-terminating proxy:** from a trusted peer, `X-Forwarded-Proto` / `X-Forwarded-Host` are passed upstream as received; PHP gets `HTTPS`, `REQUEST_SCHEME`, `SERVER_PORT` and the client's address in `REMOTE_ADDR`; HSTS is sent; requests that reached the proxy over HTTPS are not redirected to HTTPS again.
- **TLS per site:** `tls.min_version` applies to its own site (chosen by SNI). Sites with `tls.enabled: false` are served over plain HTTP: no redirect to HTTPS and no certificate for their names.
- `proxy.strip_prefix` removes whole path segments only (`/api` leaves `/apiary` alone); encoded characters such as `%2F` reach the upstream unchanged.
- `fastcgi.static_extensions` (e.g. `[".css", ".js", ".png"]`): when set, only files with these extensions are served directly; any other file goes to the front controller, so `.env`, `*.sql` and the like are never handed out raw.
- `proxy.websocket` is ignored: WebSocket connections are always proxied.
- Roots imported with `webhost roots -import` are trusted by all outbound TLS (ACME, proxy upstreams and their health checks, mail). On Windows and macOS the OS certificate store is used.
- Changing `acme.directory_url` (for example staging → production) moves the previous account and certificates to `certs/acme/previous-<host>-<time>/`. ACME settings take effect after a restart.
- Direct MX delivery with `mail.starttls: "auto"` uses opportunistic TLS (encrypted when possible, plain if the MX's TLS is broken); the certificate of a `mail.relay` is still verified.
- `webhost service -install` refuses to install when the config is missing or invalid.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 supersfera
