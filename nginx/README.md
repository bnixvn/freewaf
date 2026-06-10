# Nginx Runtime

FreeWAF writes generated WAF config to:

```text
nginx/generated/freewaf.conf
```

The generated file must be included inside the Nginx `http {}` context.
Certificates pasted in the dashboard are written to:

```text
nginx/certs/
```

Free certificates requested from the dashboard are issued by `certbot`; Nginx then points to the generated `fullchain.pem` and `privkey.pem` under the configured Let's Encrypt live directory.

Per-application logs go under `./logs/freewaf/` by default. The generated config uses one upstream block per application, per-site `access_log` and `error_log`, and SafeLine-like internal routes such as `/.safeline/forbidden_page`, `acl_page`, `offline_page`, `bad_gateway_page`, `gateway_timeout_page`, `challenge/v2/`, and `static`.

For a local standalone test, write the config from the dashboard, then run Nginx with the project root as prefix:

```bash
nginx -p /path/to/freewaf/ -c nginx/nginx.conf.example
```

On a VPS, include the generated file from your normal Nginx config instead:

```nginx
http {
    include /data/freewaf/nginx/generated/freewaf.conf;
}
```

Native Nginx rules here cover site proxying, SSL, HTTP-to-HTTPS redirect, IP/CIDR allow-deny lists, URI/method/host/User-Agent access rules, signature rules, and rate limiting. Request-body WAF rules require ModSecurity, Lua, njs, or another Nginx module.

IP Groups can be managed manually or populated from a reference `.txt` URL. The backend refreshes referenced groups once per day and the generated `geo` maps use the latest stored content.

If you set `NGINX_HAS_BROTLI=true`, the generator will emit `brotli on;` when a site has Brotli enabled. `NGINX_CHAOS_CHALLENGE_URL` and `NGINX_FREEWAF_STATIC_DIR` let you wire the challenge and static assets to real paths when you have them.

Static Files applications use `NGINX_STATIC_ROOT/<site-id>` unless the site stores an explicit static root.
