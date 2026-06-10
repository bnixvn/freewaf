# FreeWAF

FreeWAF la ban MVP theo dung kien truc ban vua chot: Python + React lam trang quan tri, con Nginx la lop reverse proxy/WAF thuc su dung de chan request.

## Kien Truc

- Python backend: quan ly sites/rules, sinh config Nginx, goi `nginx -t` va reload neu duoc cau hinh.
- React dashboard: them site, SSL certificate, IP group, allow/deny access rule, bat/tat rule, xem log, preview/apply config Nginx.
- Nginx: nghe port public, match rule bang native directive, block/monitor request, proxy ve origin.
- Demo origin: Python co the chay mot origin local o `127.0.0.1:9090` de test.
- Da doi chieu VPS SafeLine that o `/data/safeline`: tengine doc `resources/nginx/sites-enabled/IF_backend_*`, state nam trong Postgres cac bang `mgt_website`, `mgt_proxy_config`, `mgt_ssl_cert`, `mgt_ip_group`, `mgt_acl_config_v3`.

## WSL hay VPS?

Dev/test local khong can VPS. Neu muon test Nginx that tren may Windows, nen dung WSL Ubuntu hoac cai Nginx Windows. May hien tai chua co Python va WSL chua cai distro Linux, nen can cai mot trong hai:

- Python tren Windows + Nginx Windows.
- Ubuntu WSL + Python + Nginx. Day la cach minh khuyen dung cho dev.

VPS chi can khi chay production ngoai internet voi domain, TLS, firewall, systemd, backup va log rotation.

## Cai Len VPS

Ho tro cai truc tiep tren:

- Debian 12
- Debian 13
- Ubuntu 24.04 LTS

Installer se cai `nginx`, `certbot`, Python 3, Node.js 20+ de build React, copy app vao `/opt/freewaf`, tao `/etc/freewaf/freewaf.env`, tao service `freewaf`, va include config Nginx tai `/etc/nginx/conf.d/freewaf.conf`.

Cai tu repo da clone:

```bash
sudo bash install.sh
```

Cai bang Git URL:

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/freewaf/main/install.sh -o install.sh
sudo FREEWAF_REPO_URL=https://github.com/<owner>/freewaf.git bash install.sh
```

Bien cai dat hay dung:

```bash
sudo FREEWAF_APP_DIR=/opt/freewaf ADMIN_PORT=7001 bash install.sh
```

Sau khi cai xong, mo:

```text
http://SERVER_IP:7001
```

Lan dau panel se bat tao admin user. Neu bat HTTPS cho panel trong Settings, can restart service de admin socket doi sang TLS:

```bash
sudo systemctl restart freewaf
```

Lenh quan tri:

```bash
sudo systemctl status freewaf
sudo journalctl -u freewaf -f
sudo nginx -t
```

## Chay Backend

Backend Python khong dung package ngoai.

```powershell
python backend/run.py
```

Mac/Linux/WSL:

```bash
python3 backend/run.py
```

Mac dinh:

- Admin API/static build: `http://localhost:7001`
- Demo origin: `http://localhost:9090`
- Nginx listen port mac dinh trong generated config: `8080`

Lan dau mo admin panel se hien man `Create admin account`. Sau khi tao user dau tien, cac API quan tri se yeu cau login bang session cookie. Neu bat Google Authenticator cho user, panel se hien secret/URI de them vao app Google Authenticator va lan dang nhap sau can ma 6 so.

## Chay React Dashboard

```powershell
npm.cmd --prefix frontend install
npm.cmd --prefix frontend run dev
```

React dev server chay o `http://localhost:5173` va proxy `/api` ve backend `http://localhost:7001`.

Build React de Python serve static:

```powershell
npm.cmd --prefix frontend run build
python backend/run.py
```

## Chay Nginx Local

Tu dashboard, vao Settings va bam `Write Config`. File duoc sinh tai:

```text
nginx/generated/freewaf.conf
```

Chay Nginx voi project root lam prefix:

```bash
nginx -p /path/to/freewaf/ -c nginx/nginx.conf.example
```

Test request bi chan:

```bash
curl "http://localhost:8080/?q=' OR 1=1 --"
```

Request binh thuong se proxy ve demo origin:

```bash
curl "http://localhost:8080/"
```

## Bien Moi Truong

```text
ADMIN_PORT=7001
DEMO_ORIGIN_PORT=9090
ENABLE_DEMO_ORIGIN=true
DATA_FILE=./data/state.json
NGINX_OUTPUT_FILE=./nginx/generated/freewaf.conf
NGINX_ACCESS_LOG=./logs/freewaf_access.log
NGINX_SITE_LOG_DIR=./logs/freewaf
NGINX_CERT_DIR=./nginx/certs
NGINX_TEST_CMD=nginx -t
NGINX_RELOAD_CMD=nginx -s reload
NGINX_AUTO_WRITE=false
NGINX_AUTH_FILE=
NGINX_HAS_BROTLI=false
NGINX_CHAOS_CHALLENGE_URL=
NGINX_FREEWAF_STATIC_DIR=
NGINX_STATIC_ROOT=./public/static
CERTBOT_CMD=certbot
CERTBOT_AUTH_METHOD=nginx
CERTBOT_WEBROOT=/var/www/html
CERTBOT_LIVE_DIR=/etc/letsencrypt/live
IP_GROUP_AUTO_SYNC=true
IP_GROUP_SYNC_INTERVAL_SECONDS=86400
IP_GROUP_SYNC_CHECK_SECONDS=3600
IP_GROUP_REFERENCE_TIMEOUT=20
IP_GROUP_REFERENCE_MAX_BYTES=1048576
```

Dashboard `Write + Test` va `Test + Reload` se dung `NGINX_TEST_CMD` / `NGINX_RELOAD_CMD`.

## SSL Certificates

Dashboard co 2 cach add cert:

- `Paste cert`: dan noi dung certificate chain PEM va private key PEM; backend luu thanh file trong `nginx/certs/`.
- `Get free cert`: nhap domain va email; backend goi certbot de lay Let's Encrypt certificate bang HTTP-01. Mac dinh dung `certbot certonly --nginx`; co the doi bang `CERTBOT_AUTH_METHOD=webroot` hoac `standalone`.

## Panel Security

Settings gom:

- Panel SSL: chon certificate da tao trong tab Certs de admin panel chay HTTPS. Sau khi save can restart `backend/run.py` de socket admin doi sang TLS.
- Users: tao/sua/xoa user, doi password, bat/tat Google Authenticator. Khong the xoa user dang dang nhap va khong the xoa admin enabled cuoi cung.
- Nginx Config: preview/write/test/reload config Nginx.

Voi certbot, record se tro toi:

```text
/etc/letsencrypt/live/<domain>/fullchain.pem
/etc/letsencrypt/live/<domain>/privkey.pem
```

Renew tu dong la nhiem vu cua certbot timer/cron tren VPS. UI hien chinh sach renew truoc 30 ngay theo flow SafeLine; de renew that, cai certbot timer nhu `systemctl enable --now certbot.timer`.

## Gioi Han Nginx Native

- Add Application theo flow SafeLine: Domain, Listening Port HTTP/HTTPS, SSL Cert, Reverse Proxy / Static Files / Redirect, Application Name.
- Application reverse proxy voi `server_names`, `ports` kieu SafeLine (`80`, `443_ssl`), mot hoac nhieu `upstreams`, upstream block rieng va per-site access/error log.
- Static Files sinh `root`/`try_files`; mac dinh root theo `NGINX_STATIC_ROOT/<site-id>`.
- Redirect sinh `return <status> <address>$request_uri`.
- SSL/TLS bang `ssl_certificate` va `ssl_certificate_key`.
- HTTP -> HTTPS redirect neu bat.
- Moi website/application co feature rieng: HTTP Flood, Bot Protection, Auth, Attacks, ACL/Limits, HSTS, gzip, Brotli, reset XFF, default server, strict host va proxy headers.
- SafeLine-like routes `/.safeline/forbidden_page`, `acl_page`, `offline_page`, `bad_gateway_page`, `gateway_timeout_page`, `challenge/v2/`, `static`.
- IP allow/deny list bang `geo`; IP Group co the nhap Content thu cong hoac Reference URL `.txt` va backend tu cap nhat moi ngay 1 lan.
- Access rule theo IP/CIDR, method, URI regex, host regex, User-Agent regex.
- Signature rule theo URI, method, IP va cac header pho bien nhu User-Agent/Referer/Content-Type.
- Basic Access Limit theo application bang `limit_req`. Basic Attack Limit va Basic Error Limit duoc luu theo model SafeLine; de enforce chuan can detector/module co state nhu SafeLine CE.

Neu can inspect body POST, multipart upload, JSON payload sau, nen tich hop ModSecurity + OWASP CRS, Lua, hoac njs. SafeLine that dung detector/FVM/Tengine rieng nen co kha nang sau hon Nginx native.

## Mapping voi SafeLine

SafeLine tren VPS dang chay Docker Compose voi `safeline-mgt`, `safeline-tengine`, `safeline-detector`, `safeline-chaos`, `safeline-luigi`, `safeline-pg`. Moi application trong Postgres gom `comment`, `server_names`, `ports`, `upstreams`, `redirect_status_code`, `cert_id`, `acl_enabled`; proxy setting nam o `mgt_proxy_config`; IP group co `comment`, `ip_text`, `reference`; ACL basic limit nam o `mgt_acl_config_v3`.

FreeWAF mirror cac phan do bang Python state + React UI + Nginx-native config. Nhung module rieng cua SafeLine/Tengine nhu `t1k_intercept`, `tx_intercept`, detector/FVM/chaos chi duoc mo phong bang native Nginx route/comment, khong copy private key hay binary tu VPS.

## Test

Khi co Python:

```bash
python -m unittest discover backend/tests
```

Frontend:

```bash
npm --prefix frontend run build
```
