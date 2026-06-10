# FreeWAF

FreeWAF is a lightweight WAF/reverse-proxy management system built with a Python backend and a React admin panel. The dashboard manages applications, SSL certificates, IP groups, access rules, users, logs, and Nginx configuration. Actual traffic enforcement is handled by Nginx.

FreeWAF does not copy SafeLine private binaries or modules. It mirrors the main SafeLine-style workflows using FreeWAF's own Python state, React UI, and native Nginx configuration.

## Supported Operating Systems

The installer supports:

- Debian 12
- Debian 13
- Ubuntu 24.04 LTS

A fresh VPS with root access is recommended. If the server already has custom Nginx sites, back up `/etc/nginx/` before installing.

## Components

- Python backend: stores state, serves the API, generates Nginx config, and can run `nginx -t` or reload Nginx.
- React dashboard: manages applications, certificates, IP groups, access rules, users, logs, and settings.
- Nginx: performs reverse proxy and WAF enforcement on public ports.
- systemd: runs the admin panel as the `freewaf` service.

Default install paths:

```text
/opt/freewaf
/etc/freewaf/freewaf.env
/etc/systemd/system/freewaf.service
/etc/nginx/conf.d/freewaf.conf
/opt/freewaf/nginx/generated/freewaf.conf
```

## Quick Install

Install directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/bnixvn/freewaf/main/install.sh -o install.sh
sudo FREEWAF_REPO_URL=https://github.com/bnixvn/freewaf.git bash install.sh
```

Or install from a cloned repository:

```bash
git clone https://github.com/bnixvn/freewaf.git
cd freewaf
sudo bash install.sh
```

The installer will:

- Install Nginx, certbot, Python 3, and Node.js 20+ when needed.
- Build the React dashboard.
- Copy the application to `/opt/freewaf`.
- Create the `freewaf` systemd service.
- Add an Nginx include file for the generated FreeWAF config.
- Start FreeWAF and reload Nginx.

After installation, open:

```text
http://SERVER_IP:7001
```

On first access, the panel will ask you to create the first admin user.

## Installer Options

Change the install directory or admin port:

```bash
sudo FREEWAF_APP_DIR=/opt/freewaf ADMIN_PORT=7001 bash install.sh
```

Install from a specific Git branch:

```bash
sudo FREEWAF_REPO_URL=https://github.com/bnixvn/freewaf.git FREEWAF_REPO_BRANCH=main bash install.sh
```

Allow installation on an unsupported OS:

```bash
sudo FREEWAF_ALLOW_UNSUPPORTED=true bash install.sh
```

## Operations

Check service status:

```bash
sudo systemctl status freewaf
```

Follow logs:

```bash
sudo journalctl -u freewaf -f
```

Restart the admin panel:

```bash
sudo systemctl restart freewaf
```

Test Nginx:

```bash
sudo nginx -t
```

Reload Nginx:

```bash
sudo systemctl reload nginx
```

## Basic Workflow

1. Open `http://SERVER_IP:7001`.
2. Create the first admin user.
3. Go to `Certs` and add an SSL certificate:
   - Paste cert: paste the certificate chain PEM and private key PEM.
   - Get free cert: request a Let's Encrypt certificate through certbot.
4. Go to `Applications` and click `Add Application`.
5. Enter the domain, HTTP/HTTPS listening ports, certificate, application type, and upstream.
6. Go to `Access` to create allow/deny rules.
7. Go to `Settings -> Nginx Config` and click `Write + Test` or `Test + Reload`.

## Applications

FreeWAF supports three application types:

- Reverse Proxy: proxies traffic to one or more `http://` or `https://` upstreams.
- Static Files: generates `root` and `try_files`.
- Redirect: generates `return <status> <address>$request_uri`.

Each application can configure:

- Domain/server names.
- SafeLine-style listening ports such as `80` and `443_ssl`.
- SSL certificate.
- HTTP to HTTPS redirect.
- HSTS, gzip, and Brotli.
- X-Forwarded-For reset behavior.
- Strict Host validation.
- Per-application access logs.
- HTTP Flood limit.
- Bot Protection.
- Auth flag.
- Attack rules.
- ACL/basic access limit.

## SSL and SNI

Client-side SNI into FreeWAF is handled by Nginx using `server_name` and the selected certificate for each application.

For HTTPS upstreams, FreeWAF emits:

```nginx
proxy_ssl_server_name on;
proxy_ssl_name $host;
```

By default, upstream SNI uses `$host`. If your origin requires a different SNI name than the public domain, add a dedicated upstream SNI field in the UI/generator.

## Certificates

The `Certs` page supports two certificate sources:

- Paste cert: paste the certificate chain PEM and private key PEM. The backend writes them under `nginx/certs`.
- Get free cert: enter a domain and email address; the backend calls certbot using HTTP-01.

For certbot, the default certificate paths are:

```text
/etc/letsencrypt/live/<domain>/fullchain.pem
/etc/letsencrypt/live/<domain>/privkey.pem
```

Certificate renewal is handled by certbot on the VPS:

```bash
sudo systemctl enable --now certbot.timer
```

## Panel Security

The `Settings` page includes:

- Panel SSL: select a certificate from `Certs` to run the admin panel over HTTPS.
- Users: create, edit, delete, enable, disable, and change passwords.
- Google Authenticator: enable 6-digit TOTP codes for each user.
- Nginx Config: preview, write, test, and reload generated Nginx configuration.

After enabling HTTPS for the admin panel, restart the service:

```bash
sudo systemctl restart freewaf
```

The first admin user is created on first panel access. FreeWAF prevents deleting the currently signed-in user and prevents removing the last enabled admin user.

## IP Groups

IP Groups can be entered manually or loaded from a `.txt` reference URL.

The backend automatically syncs reference URLs once per day. Each line may contain an IP address or CIDR block:

```text
192.0.2.10
198.51.100.0/24
203.0.113.0/24 # comment
```

## Access Rules

Access rules follow a SafeLine-style flow:

- Allow or Deny Rule.
- Insert Position: First or Last.
- Match Target: Source IP, URI, Host, User-Agent, or Method.
- Operator: Equals, CIDR, In IP Group, Fuzzy Match, Regex, and related operators.
- AND conditions inside one condition group.
- OR conditions between groups.

The Nginx generator emits `geo` maps for IP/CIDR/IP Group conditions and native `if` checks for URI, Host, User-Agent, and Method conditions.

## Detection Rules

Detection rules support these targets:

- all
- url
- headers
- body
- method
- ip

Native Nginx handles URI, method, IP, and common headers well. Deep request body inspection requires ModSecurity, Lua, or njs.

## Native Nginx Limits

FreeWAF currently enforces rules using native Nginx directives, so there are known limits:

- It does not include SafeLine CE detector/FVM/chaos modules.
- Deep POST body, multipart, and JSON payload parsing are not fully enforced.
- Basic Attack Limit and Basic Error Limit are stored in the model, but accurate counting requires a detector/state module.
- Brotli is emitted only when `NGINX_HAS_BROTLI=true` and your Nginx build includes the Brotli module.

For deeper WAF behavior, the next step is integrating ModSecurity + OWASP CRS, Lua, or njs.

## Environment Variables

The installer writes `/etc/freewaf/freewaf.env`. Important variables:

```text
ADMIN_PORT=7001
DEMO_ORIGIN_PORT=9090
ENABLE_DEMO_ORIGIN=true
DATA_FILE=/opt/freewaf/data/state.json
NGINX_OUTPUT_FILE=/opt/freewaf/nginx/generated/freewaf.conf
NGINX_ACCESS_LOG=/opt/freewaf/logs/freewaf_access.log
NGINX_SITE_LOG_DIR=/opt/freewaf/logs/freewaf
NGINX_CERT_DIR=/opt/freewaf/nginx/certs
NGINX_TEST_CMD="/usr/sbin/nginx -t"
NGINX_RELOAD_CMD="/usr/sbin/nginx -s reload"
NGINX_AUTO_WRITE=false
NGINX_STATIC_ROOT=/opt/freewaf/public/static
CERTBOT_CMD=/usr/bin/certbot
CERTBOT_AUTH_METHOD=nginx
CERTBOT_WEBROOT=/var/www/html
CERTBOT_LIVE_DIR=/etc/letsencrypt/live
IP_GROUP_AUTO_SYNC=true
IP_GROUP_SYNC_INTERVAL_SECONDS=86400
```

After changing environment variables:

```bash
sudo systemctl restart freewaf
```

## Backup

Back up these paths:

```text
/opt/freewaf/data/state.json
/opt/freewaf/nginx/certs/
/etc/freewaf/freewaf.env
```

If you use Let's Encrypt, also back up or be ready to reissue:

```text
/etc/letsencrypt/
```

## Update

Update from Git:

```bash
cd /opt/freewaf
sudo git pull
sudo npm --prefix frontend ci
sudo npm --prefix frontend run build
sudo systemctl restart freewaf
```

If installed with the installer, you can run it again:

```bash
sudo FREEWAF_REPO_URL=https://github.com/bnixvn/freewaf.git bash install.sh
```

The installer keeps local `data/state.json`, logs, and certificates.

## Development

Run the backend:

```bash
python3 backend/run.py
```

Run the frontend dev server:

```bash
npm --prefix frontend install
npm --prefix frontend run dev
```

Build the frontend so Python can serve the static files:

```bash
npm --prefix frontend run build
python3 backend/run.py
```

Run backend tests:

```bash
python3 -m unittest discover backend/tests
```

Build-test the frontend:

```bash
npm --prefix frontend run build
```

## SafeLine Mapping

FreeWAF mirrors key SafeLine concepts with its own model:

- Application: domains, ports, upstreams, redirect status, certificate, and ACL.
- Proxy config: gzip, HSTS, reset XFF, access logs, and strict host checks.
- SSL certificates: paste/upload-style PEM input or certbot.
- IP Groups: manual content or reference URL.
- ACL/access rules: allow/deny, source IP, IP group, URI, Host, User-Agent, and Method conditions.

SafeLine/Tengine-specific modules such as `t1k_intercept`, `tx_intercept`, detector/FVM, and chaos are not part of FreeWAF.
