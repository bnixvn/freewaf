import unittest
import tempfile
import os
import gzip
import json
import re
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf.defaults import BUILTIN_RULES, DEFAULT_SETTINGS, VERIFIED_AI_BOT_PROVIDERS, VERIFIED_BOT_PROVIDERS
from freewaf.nginx import generate_nginx_config, parse_nginx_logs, write_nginx_config


def make_state(**overrides):
    state = {
        "settings": DEFAULT_SETTINGS,
        "sites": [
            {
                "id": "site-demo",
                "name": "Demo",
                "hostnames": ["localhost"],
                "origin": "http://127.0.0.1:9090",
                "listen": 8080,
                "mode": "block",
                "enabled": True,
            }
        ],
        "rules": BUILTIN_RULES,
        "logs": [],
    }
    state.update(overrides)
    return state


def make_settings(proxy: dict | None = None, mod_security: dict | None = None) -> dict:
    settings = json.loads(json.dumps(DEFAULT_SETTINGS))
    if proxy:
        settings["applicationDefaults"]["proxy"].update(proxy)
    if mod_security:
        settings["applicationDefaults"]["modSecurity"].update(mod_security)
    return settings


class NginxGeneratorTests(unittest.TestCase):
    def test_generates_server_block_for_enabled_site(self):
        config = generate_nginx_config(make_state())

        self.assertIn("server {", config)
        self.assertIn("map $request_uri $sfl_verdict {", config)
        self.assertIn("map $request_uri $sfl_reason {", config)
        self.assertIn("upstream backend_site_demo", config)
        self.assertIn("listen 0.0.0.0:8080;", config)
        self.assertIn("server_name localhost;", config)
        self.assertIn("server 127.0.0.1:9090;", config)
        self.assertIn("proxy_pass http://backend_site_demo_localhost;", config)
        self.assertIn("location = /.safeline/forbidden_page", config)

    def test_generates_safe_http_defaults_without_sites(self):
        config = generate_nginx_config(make_state(sites=[]))

        self.assertIn("map $request_uri $sfl_verdict {", config)
        self.assertIn("map $request_uri $sfl_reason {", config)
        self.assertIn("# No enabled sites.", config)
        self.assertNotIn("unknown \"sfl_verdict\"", config)

    def test_nginx_log_parser_counts_edge_403_as_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            log_file = root_dir / "freewaf_access.log"
            log_file.write_text(
                json.dumps(
                    {
                        "time": "2026-06-10T12:00:00+00:00",
                        "remote_addr": "203.0.113.10",
                        "host": "example.test",
                        "method": "POST",
                        "uri": "/login",
                        "status": 403,
                        "bytes": 153,
                        "request_time": 0.01,
                        "upstream_status": "-",
                        "verdict": "allow",
                        "reason": "Allowed",
                        "user_agent": "Mozilla/5.0",
                        "referer": "",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with mock.patch.dict(os.environ, {"NGINX_ACCESS_LOG": str(log_file), "NGINX_SITE_LOG_DIR": str(root_dir / "sites")}, clear=False):
                entries = parse_nginx_logs(root_dir, 10)

        self.assertEqual(entries[0]["verdict"], "block")
        self.assertEqual(entries[0]["statusCode"], 403)
        self.assertEqual(entries[0]["matchedRules"][0]["name"], "Blocked by ModSecurity or Nginx edge policy")

    def test_writes_one_nginx_file_per_domain(self):
        state = make_state(
            sites=[
                {
                    "id": "site-shop",
                    "name": "Shop",
                    "hostnames": ["shop.example.test", "www.shop.example.test"],
                    "origin": "http://127.0.0.1:9090",
                    "ports": ["80"],
                    "mode": "block",
                    "enabled": True,
                }
            ]
        )

        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            with mock.patch.dict(os.environ, {"NGINX_OUTPUT_FILE": "nginx/generated/freewaf.conf"}, clear=False):
                output_file = write_nginx_config(root_dir, state)

            main_config = output_file.read_text(encoding="utf-8")
            site_files = sorted((output_file.parent / "sites").glob("*.conf"))

            self.assertIn("include ", main_config)
            self.assertIn("/nginx/generated/sites/*.conf;", main_config.replace("\\", "/"))
            self.assertEqual(len(site_files), 2)
            self.assertTrue(any("shop_example_test" in file.name for file in site_files))
            self.assertTrue(any("www_shop_example_test" in file.name for file in site_files))
            self.assertTrue(any("server_name shop.example.test;" in file.read_text(encoding="utf-8") for file in site_files))
            self.assertTrue(any("server_name www.shop.example.test;" in file.read_text(encoding="utf-8") for file in site_files))

    def test_exact_and_wildcard_domains_use_distinct_upstream_names(self):
        state = make_state(
            sites=[
                {
                    "id": "site-manguon",
                    "name": "Ma Nguon",
                    "hostnames": ["manguon.top", "*.manguon.top"],
                    "origin": "http://127.0.0.1:9090",
                    "ports": ["80"],
                    "mode": "block",
                    "enabled": True,
                }
            ]
        )

        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            with mock.patch.dict(os.environ, {"NGINX_OUTPUT_FILE": "nginx/generated/freewaf.conf"}, clear=False):
                output_file = write_nginx_config(root_dir, state)

            site_files = sorted((output_file.parent / "sites").glob("*.conf"))
            site_config = "\n".join(file.read_text(encoding="utf-8") for file in site_files)

        upstream_names = re.findall(r"^upstream\s+(\S+)\s+\{", site_config, re.MULTILINE)
        self.assertEqual(len(site_files), 2)
        self.assertEqual(len(upstream_names), 2)
        self.assertEqual(len(set(upstream_names)), 2)
        self.assertIn("upstream backend_site_manguon_manguon_top", site_config)
        self.assertIn("upstream backend_site_manguon_wildcard_manguon_top", site_config)
        self.assertIn("server_name *.manguon.top;", site_config)

    def test_writing_nginx_config_removes_stale_domain_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            with mock.patch.dict(os.environ, {"NGINX_OUTPUT_FILE": "nginx/generated/freewaf.conf"}, clear=False):
                output_file = write_nginx_config(root_dir, make_state())
                stale_file = output_file.parent / "sites" / "stale.example.conf"
                stale_file.write_text("server { server_name stale.example.test; }", encoding="utf-8")
                write_nginx_config(root_dir, make_state(sites=[]))

            self.assertFalse(stale_file.exists())
            self.assertIn("# No enabled sites.", output_file.read_text(encoding="utf-8"))

    def test_generates_blocking_rule_for_builtin_sqli(self):
        config = generate_nginx_config(make_state())

        self.assertIn("SQL injection probes", config)
        self.assertIn("set $sfl_block 1;", config)
        self.assertIn("return 460;", config)
        self.assertIn("if ($request_method ~*", config)
        self.assertIn("if ($request_uri ~*", config)
        self.assertNotIn("$request_method$request_uri", config)

    def test_application_builtin_rules_are_nginx_native(self):
        app_rule_ids = {
            "builtin-wordpress-sensitive-files",
            "builtin-wordpress-enumeration",
            "builtin-whmcs-sensitive-paths",
            "builtin-laravel-sensitive-files",
            "builtin-codeigniter-sensitive-paths",
            "builtin-hostbill-sensitive-paths",
            "builtin-php-vendor-test-exposure",
        }
        rules = {rule["id"]: rule for rule in BUILTIN_RULES}

        for rule_id in app_rule_ids:
            rule = rules[rule_id]
            self.assertNotEqual(rule["target"], "body")
            re.compile(rule["pattern"], re.IGNORECASE)

        laravel_rule = rules["builtin-laravel-sensitive-files"]
        self.assertRegex("/vendor/composer/installed.php", laravel_rule["pattern"])
        self.assertNotRegex("/wp-includes/js/dist/vendor/wp-polyfill.min.js?ver=3.15.0", laravel_rule["pattern"])

        config = generate_nginx_config(make_state())

        self.assertIn("[WordPress] Sensitive application files", config)
        self.assertIn("[WHMCS] Sensitive files and directories", config)
        self.assertIn("[Laravel] Env, logs, and framework internals", config)
        self.assertIn("[CodeIgniter] Protected framework paths", config)
        self.assertIn("[HostBill] Sensitive files and directories", config)

    def test_monitor_site_does_not_block_matching_rules(self):
        state = make_state(
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "monitor",
                    "enabled": True,
                }
            ]
        )
        config = generate_nginx_config(state)

        self.assertIn("set $sfl_verdict monitor;", config)
        self.assertIn("set $sfl_block 0;", config)

    def test_body_rules_are_documented_not_emitted_as_native_blocks(self):
        state = make_state(
            rules=[
                {
                    "id": "body-test",
                    "name": "Body secret",
                    "enabled": True,
                    "siteId": "*",
                    "matcher": "regex",
                    "target": "body",
                    "pattern": "password=",
                    "action": "block",
                    "severity": "high",
                }
            ]
        )
        config = generate_nginx_config(state)

        self.assertIn("Native Nginx cannot inspect request bodies", config)
        self.assertNotIn("password=", config)

    def test_allow_rules_set_precedence_variable(self):
        state = make_state(
            rules=[
                {
                    "id": "allow-health",
                    "name": "Allow health",
                    "enabled": True,
                    "siteId": "*",
                    "matcher": "contains",
                    "target": "url",
                    "pattern": "/health",
                    "action": "allow",
                    "severity": "low",
                },
                *BUILTIN_RULES,
            ]
        )
        config = generate_nginx_config(state)

        self.assertIn("set $sfl_allow 1;", config)
        self.assertIn("if ($sfl_allow = 1)", config)

    def test_generates_tls_directives_when_certificate_selected(self):
        state = make_state(
            settings=make_settings(proxy={"forceHttps": True}),
            certificates=[
                {
                    "id": "cert-demo",
                    "name": "Demo cert",
                    "certFile": "nginx/certs/demo.crt",
                    "keyFile": "nginx/certs/demo.key",
                }
            ],
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["example.test"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 443,
                    "tls": {
                        "enabled": True,
                        "certificateId": "cert-demo",
                        "redirectHttp": True,
                        "httpListen": 80,
                        "http2": True,
                    },
                    "mode": "block",
                    "enabled": True,
                }
            ],
        )
        config = generate_nginx_config(state)

        self.assertIn("listen 0.0.0.0:443 ssl http2;", config)
        self.assertIn("ssl_certificate nginx/certs/demo.crt;", config)
        self.assertIn("ssl_certificate_key nginx/certs/demo.key;", config)
        self.assertIn("return 301 https://$host:443$request_uri;", config)

    def test_uploaded_certificate_paths_use_configured_absolute_cert_directory(self):
        state = make_state(
            certificates=[
                {
                    "id": "cert-demo",
                    "name": "Demo cert",
                    "certFile": "nginx/certs/demo.crt",
                    "keyFile": "nginx/certs/demo.key",
                }
            ],
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["demo.example.test"],
                    "origin": "http://127.0.0.1:9090",
                    "ports": ["443_ssl"],
                    "tls": {"enabled": True, "certificateId": "cert-demo"},
                    "enabled": True,
                }
            ],
        )

        with mock.patch.dict(os.environ, {"NGINX_CERT_DIR": "/opt/freewaf/nginx/certs"}, clear=False):
            config = generate_nginx_config(state)

        self.assertIn("ssl_certificate /opt/freewaf/nginx/certs/demo.crt;", config)
        self.assertIn("ssl_certificate_key /opt/freewaf/nginx/certs/demo.key;", config)

    def test_force_https_redirect_server_enforces_waf_before_redirect(self):
        state = make_state(
            settings=make_settings(proxy={"forceHttps": True}),
            certificates=[
                {
                    "id": "cert-demo",
                    "name": "Demo cert",
                    "certFile": "nginx/certs/demo.crt",
                    "keyFile": "nginx/certs/demo.key",
                }
            ],
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["example.test"],
                    "origin": "http://127.0.0.1:9090",
                    "ports": ["80", "443_ssl"],
                    "listen": 443,
                    "tls": {
                        "enabled": True,
                        "certificateId": "cert-demo",
                        "redirectHttp": True,
                        "httpListen": 80,
                        "http2": True,
                    },
                    "proxy": {"forceHttps": True},
                    "mode": "block",
                    "enabled": True,
                }
            ],
        )
        config = generate_nginx_config(state)
        http_server = config[config.find("listen 0.0.0.0:80;") : config.find("listen 0.0.0.0:443")]

        self.assertIn("set $sfl_challenge 0;", http_server)
        self.assertIn("if ($sfl_bad_bot_ua = 1)", http_server)
        self.assertIn("if ($sfl_block = 1)", http_server)
        self.assertIn("if ($sfl_challenge = 1)", http_server)
        self.assertIn("limit_req zone=freewaf_rate", http_server)
        self.assertIn("return 301 https://$host:443$request_uri;", http_server)

    def test_generates_safeline_like_upstreams_and_proxy_options(self):
        state = make_state(
            settings=make_settings(proxy={"forceHttps": True, "hsts": True, "hstsMaxAge": "15768000", "resetXff": True, "gzip": True}),
            certificates=[
                {
                    "id": "cert-demo",
                    "name": "Demo cert",
                    "certFile": "nginx/certs/demo.crt",
                    "keyFile": "nginx/certs/demo.key",
                }
            ],
            sites=[
                {
                    "id": "site-shop",
                    "name": "Shop",
                    "hostnames": ["shop.example.test", "www.shop.example.test"],
                    "origin": "https://203.0.113.10:443",
                    "upstreams": ["https://203.0.113.10:443", "https://203.0.113.11:443"],
                    "ports": ["80", "443_ssl"],
                    "listen": 443,
                    "tls": {
                        "enabled": True,
                        "certificateId": "cert-demo",
                        "redirectHttp": True,
                        "httpListen": 80,
                        "http2": True,
                    },
                    "proxy": {
                        "forceHttps": True,
                        "hsts": True,
                        "hstsMaxAge": "15768000",
                        "resetXff": True,
                        "gzip": True,
                    },
                    "mode": "block",
                    "enabled": True,
                }
            ],
        )
        config = generate_nginx_config(state)

        self.assertIn("upstream backend_site_shop", config)
        self.assertIn("server 203.0.113.10:443;", config)
        self.assertIn("server 203.0.113.11:443;", config)
        self.assertIn("access_log ./logs/freewaf/accesslog_site_shop freewaf;", config)
        self.assertIn("add_header Strict-Transport-Security \"max-age=15768000;\" always;", config)
        self.assertIn("proxy_ssl_server_name on;", config)
        self.assertIn("proxy_pass https://backend_site_shop_shop_example_test;", config)
        self.assertIn("proxy_pass https://backend_site_shop_www_shop_example_test;", config)
        self.assertIn("location ~ ^/wp-content/cache/min/1/(.+)$", config)
        self.assertIn("rewrite ^/wp-content/cache/min/1/(.+)$ /$1 last;", config)

    def test_generates_modsecurity_and_explicit_forwarding_controls(self):
        state = make_state(
            settings=make_settings(
                proxy={
                    "modifyHostHeader": False,
                    "forwardedHeaders": True,
                    "resetXff": True,
                    "xForwardedHost": "$host",
                    "xForwardedProto": "https",
                },
                mod_security={
                    "enabled": True,
                    "mode": "on",
                    "ruleset": "comodo",
                    "requestBodyLimit": 8388608,
                },
            ),
            sites=[
                {
                    "id": "site-secure",
                    "name": "Secure",
                    "hostnames": ["secure.example.test"],
                    "origin": "http://127.0.0.1:9090",
                    "ports": ["80"],
                    "proxy": {
                        "modifyHostHeader": False,
                        "forwardedHeaders": True,
                        "resetXff": True,
                        "xForwardedHost": "$host",
                        "xForwardedProto": "https",
                    },
                    "modSecurity": {
                        "enabled": True,
                        "mode": "on",
                        "ruleset": "comodo",
                        "requestBodyLimit": 8388608,
                    },
                    "mode": "block",
                    "enabled": True,
                }
            ],
        )

        with mock.patch.dict(
            os.environ,
            {
                "NGINX_HAS_MODSECURITY": "true",
                "NGINX_MODSECURITY_COMODO_RULES_FILE": "/etc/freewaf/modsecurity/comodo.conf",
            },
            clear=False,
        ):
            config = generate_nginx_config(state)

        self.assertIn("modsecurity on;", config)
        self.assertIn("modsecurity_rules_file /etc/freewaf/modsecurity/comodo.conf;", config)
        self.assertIn("modsecurity_rules 'SecRuleEngine On';", config)
        self.assertIn("modsecurity_rules 'SecRequestBodyLimit 8388608';", config)
        self.assertNotIn("proxy_set_header Host $http_host;", config)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", config)
        self.assertIn("proxy_set_header X-Forwarded-Proto https;", config)
        self.assertIn("proxy_set_header X-Forwarded-Host $host;", config)

    def test_application_defaults_override_site_transport_and_modsecurity(self):
        settings = json.loads(json.dumps(DEFAULT_SETTINGS))
        settings["applicationDefaults"] = {
            "proxy": {
                "forceHttps": True,
                "hsts": True,
                "hstsMaxAge": 123,
                "gzip": True,
                "brotli": True,
                "http2": True,
                "resetXff": True,
                "modifyHostHeader": True,
                "forwardedHeaders": True,
                "hostHeader": "$host",
                "xForwardedProto": "https",
                "xForwardedHost": "$host",
                "proxySslServerName": True,
            },
            "modSecurity": {
                "enabled": True,
                "mode": "on",
                "ruleset": "owasp",
                "requestBodyLimit": 8388608,
            },
        }
        state = make_state(
            settings=settings,
            certificates=[
                {
                    "id": "cert-demo",
                    "name": "Demo cert",
                    "certFile": "/etc/ssl/demo/fullchain.pem",
                    "keyFile": "/etc/ssl/demo/privkey.pem",
                }
            ],
            sites=[
                {
                    "id": "site-secure",
                    "name": "Secure",
                    "hostnames": ["secure.example.test"],
                    "origin": "https://203.0.113.10:443",
                    "ports": ["80", "443_ssl"],
                    "tls": {"enabled": True, "certificateId": "cert-demo", "http2": False},
                    "proxy": {
                        "forceHttps": False,
                        "hsts": False,
                        "gzip": False,
                        "brotli": False,
                        "http2": False,
                        "resetXff": False,
                        "modifyHostHeader": False,
                        "forwardedHeaders": False,
                    },
                    "modSecurity": {
                        "enabled": False,
                    },
                    "mode": "block",
                    "enabled": True,
                }
            ],
        )

        with mock.patch.dict(
            os.environ,
            {
                "NGINX_HAS_MODSECURITY": "true",
                "NGINX_HAS_BROTLI": "true",
                "NGINX_MODSECURITY_OWASP_RULES_FILE": "/etc/freewaf/modsecurity/owasp-crs.conf",
            },
            clear=False,
        ):
            config = generate_nginx_config(state)

        self.assertIn("listen 0.0.0.0:443 ssl http2;", config)
        self.assertIn("return 301 https://$host:443$request_uri;", config)
        self.assertIn('add_header Strict-Transport-Security "max-age=123;" always;', config)
        self.assertIn("gzip on;", config)
        self.assertIn("brotli on;", config)
        self.assertIn("proxy_set_header Host $host;", config)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", config)
        self.assertIn("proxy_set_header X-Forwarded-Proto https;", config)
        self.assertIn("proxy_set_header X-Forwarded-Host $host;", config)
        self.assertIn("modsecurity on;", config)
        self.assertIn("modsecurity_rules_file /etc/freewaf/modsecurity/owasp-crs.conf;", config)
        self.assertIn("modsecurity_rules 'SecRequestBodyLimit 8388608';", config)

    def test_omits_forwarded_headers_when_disabled(self):
        state = make_state(
            settings=make_settings(proxy={"forwardedHeaders": False}),
            sites=[
                {
                    "id": "site-private",
                    "name": "Private",
                    "hostnames": ["private.example.test"],
                    "origin": "http://127.0.0.1:9090",
                    "ports": ["80"],
                    "proxy": {"forwardedHeaders": False},
                    "features": {"botProtection": False},
                    "acl": {"enabled": False},
                    "mode": "block",
                    "enabled": True,
                }
            ],
        )

        config = generate_nginx_config(state)

        self.assertNotIn("proxy_set_header X-Forwarded-For", config)
        self.assertNotIn("proxy_set_header X-Forwarded-Proto", config)
        self.assertNotIn("proxy_set_header X-Forwarded-Host", config)
        self.assertIn("proxy_set_header X-Real-IP $remote_addr;", config)

    def test_redirect_application_returns_configured_address(self):
        state = make_state(
            sites=[
                {
                    "id": "site-redirect",
                    "name": "Redirect",
                    "applicationType": "redirect",
                    "hostnames": ["old.example.test"],
                    "ports": ["80"],
                    "listen": 80,
                    "redirect": {"statusCode": 301, "address": "https://new.example.test"},
                    "mode": "block",
                    "enabled": True,
                }
            ],
        )
        config = generate_nginx_config(state)

        self.assertNotIn("upstream backend_site_redirect", config)
        self.assertIn("return 301 https://new.example.test$request_uri;", config)

    def test_static_application_uses_static_root(self):
        state = make_state(
            sites=[
                {
                    "id": "site-static",
                    "name": "Static",
                    "applicationType": "static_files",
                    "hostnames": ["static.example.test"],
                    "ports": ["80"],
                    "listen": 80,
                    "static": {"root": "/srv/static/site-static"},
                    "features": {"botProtection": False},
                    "acl": {"enabled": False},
                    "mode": "block",
                    "enabled": True,
                }
            ],
        )
        config = generate_nginx_config(state)

        self.assertNotIn("proxy_pass", config)
        self.assertIn("root /srv/static/site-static;", config)
        self.assertIn("try_files $uri $uri/ =404;", config)

    def test_generates_ip_access_rule_geo_map(self):
        state = make_state(
            ipGroups=[
                {
                    "id": "ipgroup-admin",
                    "name": "Admins",
                    "description": "",
                    "items": ["203.0.113.0/24"],
                    "enabled": True,
                }
            ],
            accessRules=[
                {
                    "id": "access-deny",
                    "name": "Deny test range",
                    "description": "",
                    "enabled": True,
                    "siteId": "*",
                    "action": "deny",
                    "ipGroupIds": ["ipgroup-admin"],
                    "ips": ["198.51.100.10"],
                    "methods": [],
                    "uriPatterns": [],
                    "hostPatterns": [],
                    "userAgentPatterns": [],
                }
            ],
        )
        config = generate_nginx_config(state)

        self.assertIn("geo $sfl_access_ip_1", config)
        self.assertIn("203.0.113.0/24 1;", config)
        self.assertIn("198.51.100.10 1;", config)
        self.assertIn("Deny test range", config)

    def test_access_rule_reads_external_ip_group_file(self):
        with tempfile.TemporaryDirectory() as directory:
            ip_file = Path(directory) / "feed.txt"
            ip_file.write_text("203.0.113.10\n198.51.100.0/24\n", encoding="utf-8")
            state = make_state(
                ipGroups=[
                    {
                        "id": "ipgroup-feed",
                        "name": "Feed",
                        "items": [],
                        "itemsFile": str(ip_file),
                        "itemsExternal": True,
                        "enabled": True,
                    }
                ],
                accessRules=[
                    {
                        "id": "access-feed",
                        "name": "Feed deny",
                        "enabled": True,
                        "siteId": "*",
                        "action": "deny",
                        "ipGroupIds": ["ipgroup-feed"],
                    }
                ],
            )

            config = generate_nginx_config(state)

        self.assertIn("203.0.113.10 1;", config)
        self.assertIn("198.51.100.0/24 1;", config)

    def test_generates_access_rule_condition_group(self):
        state = make_state(
            ipGroups=[
                {
                    "id": "ipgroup-admin",
                    "name": "Admins",
                    "description": "",
                    "items": ["203.0.113.0/24"],
                    "enabled": True,
                }
            ],
            accessRules=[
                {
                    "id": "access-admin",
                    "name": "Deny admin path",
                    "description": "",
                    "enabled": True,
                    "siteId": "*",
                    "action": "deny",
                    "conditionGroups": [
                        {
                            "conditions": [
                                {"target": "source_ip", "operator": "in_ip_group", "content": "ipgroup-admin"},
                                {"target": "uri", "operator": "contains", "content": "/admin"},
                            ]
                        }
                    ],
                }
            ],
        )
        config = generate_nginx_config(state)

        self.assertIn("geo $sfl_access_ip_1_1_1", config)
        self.assertIn("203.0.113.0/24 1;", config)
        self.assertIn('if ($request_uri ~* "/admin")', config)
        self.assertIn("set $sfl_access_1_group_1 1;", config)
        self.assertIn("Deny admin path", config)

    def test_bot_protection_emits_header_block_login_challenge_and_rate_rules(self):
        state = make_state(
            settings=make_settings(mod_security={"enabled": False}),
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {"botProtection": True},
                    "botProtection": {
                        "antiBotChallenge": True,
                        "verifiedSearchBots": {"enabled": False},
                        "rateChallenge": {
                            "enabled": True,
                            "windowSeconds": 10,
                            "challengeCount": 300,
                            "blockCount": 700,
                            "blockMinutes": 30,
                        },
                    },
                }
            ],
        )
        with mock.patch.dict(
            os.environ,
            {
                "NGINX_HAS_MODSECURITY": "true",
                "NGINX_MODSECURITY_BASE_RULES_FILE": "/etc/freewaf/modsecurity/base.conf",
            },
            clear=False,
        ):
            config = generate_nginx_config(state)

        self.assertIn("map $http_user_agent $sfl_bad_bot_ua", config)
        self.assertNotIn("map $http_user_agent $sfl_suspicious_ua", config)
        self.assertIn("secure_link \"$cookie_freewaf_challenge,$cookie_freewaf_challenge_expires\";", config)
        self.assertIn("set $sfl_bot_block 1;", config)
        self.assertIn("set $sfl_challenge 1;", config)
        self.assertIn("$request_uri ~*", config)
        self.assertIn("wp-login", config)
        self.assertIn("error_page 461 = @freewaf_challenge;", config)
        self.assertIn("location = /.freewaf/challenge/verify", config)
        self.assertNotIn("freewaf_challenge=passed", config)
        self.assertIn("Bot protection matched scanner headers", config)
        self.assertIn("Bot protection protected login path", config)
        self.assertIn("modsecurity_rules_file /etc/freewaf/modsecurity/base.conf;", config)
        self.assertIn("REQUEST_HEADERS:User-Agent", config)
        self.assertIn("REQUEST_HEADERS:Accept-Language", config)
        self.assertIn("initcol:global=freewaf_site_demo_bot_%{REMOTE_ADDR}_%{tx.freewaf_site_demo_bot_ua_hash}", config)
        self.assertIn('SecRule GLOBAL:freewaf_site_demo_bot_count "@gt 700"', config)
        self.assertIn("expirevar:global.freewaf_site_demo_bot_blocked=1800", config)
        self.assertIn('SecRule GLOBAL:freewaf_site_demo_bot_count "@gt 300"', config)
        self.assertNotIn('SecRule IP:freewaf_site_demo_bot_count', config)
        self.assertIn("status:461", config)
        self.assertIn('REQUEST_COOKIES:freewaf_challenge "@rx .+"', config)
        self.assertGreater(config.find("freewaf_site_demo_bot_count"), config.find("    location / {"))
        self.assertIn('limit_req_zone "$remote_addr|$request_method|$http_user_agent" zone=freewaf_rate_fingerprint', config)

    def test_verified_search_engine_bots_use_official_ip_and_user_agent_match(self):
        google = VERIFIED_BOT_PROVIDERS["google"]
        bing = VERIFIED_BOT_PROVIDERS["bing"]
        state = make_state(
            ipGroups=[
                {"id": google["id"], "name": google["name"], "items": ["66.249.64.0/27"], "enabled": True},
                {"id": bing["id"], "name": bing["name"], "items": ["40.77.167.0/24"], "enabled": True},
            ],
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {"httpFlood": True, "botProtection": True},
                    "underAttack": {"enabled": True},
                    "botProtection": {
                        "antiBotChallenge": True,
                        "verifiedSearchBots": {
                            "enabled": True,
                            "bypassChallenge": True,
                            "bypassRateLimit": True,
                        },
                        "rateChallenge": {
                            "enabled": True,
                            "windowSeconds": 10,
                            "challengeCount": 300,
                            "blockCount": 700,
                            "blockMinutes": 30,
                        },
                    },
                }
            ],
        )

        with mock.patch.dict(
            os.environ,
            {
                "NGINX_HAS_MODSECURITY": "true",
                "NGINX_MODSECURITY_BASE_RULES_FILE": "/etc/freewaf/modsecurity/base.conf",
            },
            clear=False,
        ):
            config = generate_nginx_config(state)

        self.assertIn("geo $sfl_verified_google_ip", config)
        self.assertIn("66.249.64.0/27 1;", config)
        self.assertIn('map "$sfl_verified_google_ip:$http_user_agent" $sfl_verified_google_bot {', config)
        self.assertIn("Googlebot|Google-InspectionTool|GoogleOther", config)
        self.assertIn("geo $sfl_verified_bing_ip", config)
        self.assertIn("40.77.167.0/24 1;", config)
        self.assertIn('map "$sfl_verified_google_bot|$sfl_verified_bing_bot" $sfl_verified_search_bot {', config)
        self.assertIn("map $sfl_verified_rate_bypass $sfl_global_rate_key", config)
        self.assertIn("set $sfl_verified_rate_bypass 1;", config)
        self.assertIn("limit_req_zone $sfl_global_rate_key zone=freewaf_rate:10m", config)
        self.assertIn("if ($sfl_verified_search_bot = 1)", config)
        self.assertIn("set $sfl_under_attack_challenge 0;", config)
        self.assertIn('SecRule REMOTE_ADDR "@ipMatch 66.249.64.0/27"', config)
        self.assertIn("skipAfter:FREEWAF_BOT_RATE_DONE_SITE_DEMO", config)

    def test_verified_ai_bots_are_site_scoped_and_off_by_default(self):
        openai = VERIFIED_AI_BOT_PROVIDERS["openai_user"]
        anthropic = VERIFIED_AI_BOT_PROVIDERS["anthropic_user"]
        state = make_state(
            ipGroups=[
                {"id": openai["id"], "name": openai["name"], "items": ["104.210.139.192/28"], "enabled": True},
                {"id": anthropic["id"], "name": anthropic["name"], "items": ["160.79.104.0/21"], "enabled": True},
            ],
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {"httpFlood": True, "botProtection": True},
                    "underAttack": {"enabled": True},
                    "botProtection": {
                        "antiBotChallenge": True,
                        "verifiedSearchBots": {"enabled": False},
                        "verifiedAIBots": {
                            "enabled": True,
                            "allowedProviders": ["openai_user", "anthropic_user"],
                            "bypassChallenge": True,
                            "bypassRateLimit": True,
                        },
                        "rateChallenge": {
                            "enabled": True,
                            "windowSeconds": 10,
                            "challengeCount": 300,
                            "blockCount": 700,
                            "blockMinutes": 30,
                        },
                    },
                }
            ],
        )

        with mock.patch.dict(
            os.environ,
            {
                "NGINX_HAS_MODSECURITY": "true",
                "NGINX_MODSECURITY_BASE_RULES_FILE": "/etc/freewaf/modsecurity/base.conf",
            },
            clear=False,
        ):
            config = generate_nginx_config(state)

        self.assertIn("geo $sfl_verified_ai_openai_user_ip", config)
        self.assertIn("104.210.139.192/28 1;", config)
        self.assertIn('map "$sfl_verified_ai_openai_user_ip:$http_user_agent" $sfl_verified_ai_openai_user_bot {', config)
        self.assertIn("ChatGPT-User", config)
        self.assertIn("geo $sfl_verified_ai_anthropic_user_ip", config)
        self.assertIn("160.79.104.0/21 1;", config)
        self.assertIn('map "$sfl_verified_ai_openai_user_bot|$sfl_verified_ai_anthropic_user_bot" $sfl_verified_ai_bot_site_demo {', config)
        self.assertIn("if ($sfl_verified_ai_bot_site_demo = 1)", config)
        self.assertIn("set $sfl_verified_rate_bypass 1;", config)
        self.assertIn("map $sfl_verified_rate_bypass $sfl_global_rate_key", config)
        self.assertIn('SecRule REMOTE_ADDR "@ipMatch 104.210.139.192/28"', config)
        self.assertIn("(?i:(?:ChatGPT-User))", config)
        self.assertNotIn("$sfl_verified_search_bot = 1", config)

    def test_http_flood_emits_temporary_block_cooldown_rules(self):
        state = make_state(
            settings=make_settings(mod_security={"enabled": False}),
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {"httpFlood": True, "botProtection": False},
                    "acl": {
                        "enabled": True,
                        "accessLimit": {
                            "enabled": True,
                            "period": 10,
                            "count": 200,
                            "blockCount": 500,
                            "action": "challenge_v1",
                            "blockMin": 60,
                        },
                    },
                }
            ],
        )
        with mock.patch.dict(
            os.environ,
            {
                "NGINX_HAS_MODSECURITY": "true",
                "NGINX_MODSECURITY_BASE_RULES_FILE": "/etc/freewaf/modsecurity/base.conf",
            },
            clear=False,
        ):
            config = generate_nginx_config(state)

        self.assertIn("modsecurity_rules_file /etc/freewaf/modsecurity/base.conf;", config)
        self.assertIn('SecRule IP:freewaf_site_demo_flood_count "@gt 500"', config)
        self.assertIn('SecRule IP:freewaf_site_demo_flood_blocked "@eq 1"', config)
        self.assertIn("expirevar:ip.freewaf_site_demo_flood_blocked=3600", config)
        self.assertIn("limit_req zone=sfl_acl_site_demo burst=200 nodelay;", config)

    def test_under_attack_uses_signed_challenge_cookie(self):
        state = make_state(
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["demo.example.test"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {"botProtection": False},
                    "underAttack": {"enabled": True},
                }
            ]
        )

        with mock.patch.dict(os.environ, {"FREEWAF_CHALLENGE_SECRET": "unit-test-secret", "ADMIN_PORT": "7001"}, clear=False):
            config = generate_nginx_config(state)

        self.assertIn("map \"$request_method:$uri\" $sfl_under_attack_bypass", config)
        self.assertIn("secure_link \"$cookie_freewaf_challenge,$cookie_freewaf_challenge_expires\";", config)
        self.assertIn("$secure_link_expires|$host|$remote_addr|$http_user_agent|unit-test-secret", config)
        self.assertIn("location @freewaf_challenge", config)
        self.assertIn("location = /.freewaf/challenge/verify", config)
        self.assertIn("proxy_set_header X-FreeWAF-Challenge-Site \"site-demo\";", config)
        self.assertIn("set $sfl_reason \"Under Attack Mode browser challenge\";", config)
        self.assertNotIn("$request_method$request_uri$http_user_agent", config)

    def test_social_crawler_user_agents_are_not_challenged_by_default(self):
        user_agent = "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)"
        config = generate_nginx_config(make_state())

        self.assertNotIn("sfl_suspicious_ua", config)
        self.assertNotIn("externalagent|facebookexternalhit", config)
        self.assertNotRegex(user_agent, r"sqlmap|nikto|acunetix|nessus|nuclei|wpscan")

    def test_bot_protection_options_gate_challenge_and_emit_replay(self):
        state = make_state(
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {"httpFlood": False, "botProtection": True},
                    "botProtection": {
                        "enabled": True,
                        "antiBotChallenge": False,
                        "dynamicProtection": {"enabled": True, "html": True, "js": False, "watermark": True},
                        "antiReplay": {"enabled": True},
                    },
                }
            ]
        )
        config = generate_nginx_config(state)

        self.assertNotIn("map $http_user_agent $sfl_bad_bot_ua", config)
        self.assertNotIn("Bot protection protected login path", config)
        self.assertNotIn("freewaf_site_demo_bot_count", config)
        self.assertIn('limit_req_zone "$binary_remote_addr|$request_method|$request_uri|$http_user_agent" zone=sfl_replay_site_demo:10m rate=1r/s;', config)
        self.assertIn("limit_req zone=sfl_replay_site_demo burst=1 nodelay;", config)
        self.assertIn('add_header X-FreeWAF-Dynamic-Protection "html,watermark" always;', config)

    def test_geo_block_emits_country_geo_map_and_block(self):
        with tempfile.TemporaryDirectory() as directory:
            geoip_file = Path(directory) / "dbip-country-lite.csv.gz"
            with gzip.open(geoip_file, "wt", encoding="utf-8", newline="") as target:
                target.write("8.8.8.0,8.8.8.255,US\n")
                target.write("1.1.1.0,1.1.1.255,AU\n")
            state = make_state(
                sites=[
                    {
                        "id": "site-demo",
                        "name": "Demo",
                        "hostnames": ["localhost"],
                        "origin": "http://127.0.0.1:9090",
                        "listen": 8080,
                        "mode": "block",
                        "enabled": True,
                        "features": {"geoBlock": True},
                        "geoBlock": {"enabled": True, "countries": ["US"], "action": "block"},
                    }
                ]
            )

            with mock.patch.dict(os.environ, {"GEOIP_DB_FILE": str(geoip_file)}, clear=False):
                config = generate_nginx_config(state)

        self.assertIn("geo $sfl_geo_block_site_demo", config)
        self.assertIn("8.8.8.0/24 1;", config)
        self.assertNotIn("1.1.1.0/24 1;", config)
        self.assertIn("if ($sfl_geo_block_site_demo = 1)", config)
        self.assertIn("Geo block matched country: US", config)

    def test_acl_challenge_rate_limit_uses_cookie_aware_keys(self):
        state = make_state(
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {"httpFlood": True, "botProtection": False},
                    "acl": {
                        "enabled": True,
                        "accessLimit": {
                            "enabled": True,
                            "period": 10,
                            "count": 200,
                            "action": "challenge_v1",
                            "blockMin": 60,
                        },
                    },
                }
            ]
        )
        config = generate_nginx_config(state)

        self.assertIn("map $cookie_freewaf_challenge $sfl_acl_key_site_demo", config)
        self.assertIn("map $cookie_freewaf_challenge $sfl_acl_key_site_demo_fp", config)
        self.assertIn("passed \"\";", config)
        self.assertIn("limit_req_zone $sfl_acl_key_site_demo zone=sfl_acl_site_demo:10m", config)
        self.assertIn("limit_req_zone $sfl_acl_key_site_demo_fp zone=sfl_acl_site_demo_fp:10m", config)
        self.assertIn("limit_req zone=sfl_acl_site_demo burst=200 nodelay;", config)
        self.assertIn("limit_req zone=sfl_acl_site_demo_fp burst=200 nodelay;", config)
        self.assertIn("error_page 429 = @freewaf_challenge;", config)

    def test_http_flood_global_mode_uses_global_rate_limit(self):
        state = make_state(
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {"httpFlood": True, "botProtection": False},
                    "acl": {
                        "enabled": True,
                        "rateLimitMode": "global",
                        "accessLimit": {
                            "enabled": True,
                            "period": 10,
                            "count": 200,
                            "action": "challenge_v1",
                            "blockMin": 60,
                        },
                    },
                }
            ]
        )
        config = generate_nginx_config(state)

        self.assertIn("limit_req_zone $binary_remote_addr zone=freewaf_rate:10m", config)
        self.assertIn("limit_req zone=freewaf_rate burst=120 nodelay;", config)
        self.assertNotIn("zone=sfl_acl_site_demo", config)

    def test_waiting_room_queues_without_nodelay(self):
        state = make_state(
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {"httpFlood": True, "botProtection": False},
                    "acl": {
                        "enabled": True,
                        "rateLimitMode": "custom",
                        "waitingRoom": True,
                        "accessLimit": {
                            "enabled": True,
                            "period": 10,
                            "count": 200,
                            "action": "challenge_v1",
                            "blockMin": 60,
                        },
                    },
                }
            ]
        )
        config = generate_nginx_config(state)

        self.assertIn("limit_req zone=sfl_acl_site_demo burst=200;", config)
        self.assertIn("limit_req zone=sfl_acl_site_demo_fp burst=200;", config)
        self.assertNotIn("limit_req zone=sfl_acl_site_demo burst=200 nodelay;", config)

    def test_legacy_site_feature_switches_are_ignored(self):
        state = make_state(
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {
                        "httpFlood": False,
                        "botProtection": False,
                        "auth": True,
                        "attacks": False,
                    },
                }
            ]
        )
        config = generate_nginx_config(state)

        self.assertNotIn("limit_req_zone", config)
        self.assertNotIn("limit_req zone=freewaf_rate", config)
        self.assertIn("SQL injection probes", config)
        self.assertNotIn("Scanner user agents", config)
        self.assertNotIn("Auth feature is enabled", config)
        self.assertNotIn("auth_basic", config)

    def _modsec_rate_state(self, access_rules: list[dict]) -> dict:
        return make_state(
            sites=[
                {
                    "id": "site-demo",
                    "name": "Demo",
                    "hostnames": ["localhost"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "mode": "block",
                    "enabled": True,
                    "features": {"httpFlood": True, "botProtection": True},
                    "botProtection": {
                        "antiBotChallenge": True,
                        "rateChallenge": {
                            "enabled": True,
                            "windowSeconds": 10,
                            "challengeCount": 30,
                            "blockCount": 60,
                            "blockMinutes": 10,
                        },
                    },
                    "acl": {
                        "enabled": True,
                        "rateLimitMode": "custom",
                        "accessLimit": {
                            "enabled": True,
                            "period": 10,
                            "count": 200,
                            "blockCount": 500,
                            "action": "challenge_v1",
                            "blockMin": 60,
                        },
                    },
                }
            ],
            accessRules=access_rules,
        )

    def test_access_allow_ip_skips_modsecurity_bot_rate_and_http_flood(self):
        state = self._modsec_rate_state(
            access_rules=[
                {
                    "id": "allow-office",
                    "name": "Allow office",
                    "enabled": True,
                    "siteId": "*",
                    "action": "allow",
                    "conditionGroups": [
                        {
                            "conditions": [
                                {"target": "source_ip", "operator": "cidr", "content": "203.0.113.7"},
                            ]
                        }
                    ],
                }
            ]
        )

        with mock.patch.dict(os.environ, {"NGINX_HAS_MODSECURITY": "true"}, clear=False):
            config = generate_nginx_config(state)

        self.assertIn('@ipMatch 203.0.113.7', config)
        self.assertRegex(config, r"@ipMatch 203\.0\.113\.7\".*skipAfter:FREEWAF_BOT_RATE_DONE_SITE_DEMO")
        self.assertRegex(config, r"@ipMatch 203\.0\.113\.7\".*skipAfter:FREEWAF_HTTP_FLOOD_DONE_SITE_DEMO")

    def test_access_allow_legacy_ips_skip_modsecurity_rate_rules(self):
        state = self._modsec_rate_state(
            access_rules=[
                {
                    "id": "allow-cdn",
                    "name": "Allow CDN",
                    "enabled": True,
                    "siteId": "site-demo",
                    "action": "allow",
                    "ips": ["198.51.100.5", "198.51.100.6"],
                }
            ]
        )

        with mock.patch.dict(os.environ, {"NGINX_HAS_MODSECURITY": "true"}, clear=False):
            config = generate_nginx_config(state)

        self.assertIn("198.51.100.5", config)
        self.assertIn("198.51.100.6", config)
        self.assertRegex(config, r"skipAfter:FREEWAF_BOT_RATE_DONE_SITE_DEMO")
        self.assertRegex(config, r"skipAfter:FREEWAF_HTTP_FLOOD_DONE_SITE_DEMO")

    def test_access_allow_with_non_ip_condition_does_not_emit_modsec_skip(self):
        state = self._modsec_rate_state(
            access_rules=[
                {
                    "id": "allow-path",
                    "name": "Allow path",
                    "enabled": True,
                    "siteId": "*",
                    "action": "allow",
                    "conditionGroups": [
                        {
                            "conditions": [
                                {"target": "source_ip", "operator": "cidr", "content": "203.0.113.9"},
                                {"target": "url", "operator": "contains", "content": "/health"},
                            ]
                        }
                    ],
                }
            ]
        )

        with mock.patch.dict(os.environ, {"NGINX_HAS_MODSECURITY": "true"}, clear=False):
            config = generate_nginx_config(state)

        self.assertNotRegex(config, r"@ipMatch 203\.0\.113\.9\".*skipAfter:FREEWAF_BOT_RATE_DONE_SITE_DEMO")

    def test_access_allow_continue_detect_does_not_skip_modsec(self):
        state = self._modsec_rate_state(
            access_rules=[
                {
                    "id": "allow-cd",
                    "name": "Allow continue",
                    "enabled": True,
                    "continueDetect": True,
                    "siteId": "*",
                    "action": "allow",
                    "ips": ["198.51.100.42"],
                }
            ]
        )

        with mock.patch.dict(os.environ, {"NGINX_HAS_MODSECURITY": "true"}, clear=False):
            config = generate_nginx_config(state)

        self.assertNotRegex(config, r"@ipMatch 198\.51\.100\.42\".*skipAfter:FREEWAF_BOT_RATE_DONE_SITE_DEMO")


if __name__ == "__main__":
    unittest.main()
