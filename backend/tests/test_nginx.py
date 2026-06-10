import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf.defaults import BUILTIN_RULES, DEFAULT_SETTINGS
from freewaf.nginx import generate_nginx_config


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


class NginxGeneratorTests(unittest.TestCase):
    def test_generates_server_block_for_enabled_site(self):
        config = generate_nginx_config(make_state())

        self.assertIn("server {", config)
        self.assertIn("upstream backend_site_demo", config)
        self.assertIn("listen 0.0.0.0:8080;", config)
        self.assertIn("server_name localhost;", config)
        self.assertIn("server 127.0.0.1:9090;", config)
        self.assertIn("proxy_pass http://backend_site_demo;", config)
        self.assertIn("location = /.safeline/forbidden_page", config)

    def test_generates_blocking_rule_for_builtin_sqli(self):
        config = generate_nginx_config(make_state())

        self.assertIn("SQL injection probes", config)
        self.assertIn("set $sfl_block 1;", config)
        self.assertIn("return 460;", config)

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

    def test_generates_safeline_like_upstreams_and_proxy_options(self):
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
        self.assertIn("proxy_pass https://backend_site_shop;", config)

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

    def test_site_features_gate_native_modules(self):
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
        self.assertNotIn("SQL injection probes", config)
        self.assertNotIn("Scanner user agents", config)
        self.assertIn("Auth feature is enabled", config)


if __name__ == "__main__":
    unittest.main()
