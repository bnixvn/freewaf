import unittest
import tempfile
import os
import gzip
import re
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf.defaults import BUILTIN_RULES, DEFAULT_SETTINGS
from freewaf.nginx import BOT_CHALLENGE_UA_PATTERN, generate_nginx_config, write_nginx_config


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

    def test_force_https_redirect_server_enforces_waf_before_redirect(self):
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

    def test_bot_protection_emits_header_block_and_challenge(self):
        config = generate_nginx_config(make_state())

        self.assertIn("map $http_user_agent $sfl_bad_bot_ua", config)
        self.assertIn("map $http_user_agent $sfl_suspicious_ua", config)
        self.assertIn("map $cookie_freewaf_challenge $sfl_challenge_passed", config)
        self.assertIn("set $sfl_bot_block 1;", config)
        self.assertIn("set $sfl_challenge 1;", config)
        self.assertIn("error_page 461 = @freewaf_challenge;", config)
        self.assertIn("document.cookie=\"freewaf_challenge=passed;", config)
        self.assertNotIn("add_header Set-Cookie \"freewaf_challenge=passed;", config)
        self.assertIn("Bot protection matched scanner headers", config)
        self.assertIn("Bot protection matched suspicious headers", config)
        self.assertIn('limit_req_zone "$remote_addr|$request_method|$http_user_agent" zone=freewaf_rate_fingerprint', config)
        self.assertNotIn("$request_method$request_uri$http_user_agent", config)

    def test_social_crawler_user_agents_are_challenged(self):
        user_agent = "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)"
        config = generate_nginx_config(make_state())
        suspicious_map = config[
            config.find("map $http_user_agent $sfl_suspicious_ua") :
            config.find("map $http_user_agent $sfl_missing_user_agent")
        ]

        self.assertRegex(user_agent, BOT_CHALLENGE_UA_PATTERN)
        self.assertIn("externalagent|facebookexternalhit", suspicious_map)
        self.assertNotRegex(suspicious_map, r"~\*.*externalagent.* 0;")

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
                    "features": {"httpFlood": False, "botProtection": True, "attacks": False},
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
        self.assertNotIn("Bot protection matched suspicious headers", config)
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
                    "features": {"httpFlood": True, "botProtection": False, "attacks": True},
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
                    "features": {"httpFlood": True, "botProtection": False, "attacks": True},
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
                    "features": {"httpFlood": True, "botProtection": False, "attacks": True},
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
