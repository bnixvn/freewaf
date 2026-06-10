import gzip
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf.store import Store, build_stats, country_for_ip, normalize_state


class StoreTests(unittest.TestCase):
    def test_stats_count_challenges_as_protected_events(self):
        with mock.patch("freewaf.store.country_for_ip", side_effect=lambda ip: {"code": "US", "name": "United States"}):
            stats = build_stats(
                {
                    "sites": [
                        {"id": "site-demo", "name": "Demo", "hostnames": ["demo.example.test"]},
                        {"id": "site-other", "name": "Other", "hostnames": ["*.other.test"]},
                    ],
                    "logs": [
                        {"verdict": "allow", "statusCode": 200, "siteName": "demo.example.test", "host": "demo.example.test", "ip": "203.0.113.1"},
                        {"verdict": "block", "statusCode": 403, "siteName": "demo.example.test", "host": "demo.example.test", "ip": "203.0.113.2", "matchedRules": [{"name": "Deny IP"}]},
                        {
                            "verdict": "challenge",
                            "statusCode": 200,
                            "siteName": "demo.example.test",
                            "host": "demo.example.test",
                            "ip": "203.0.113.3",
                            "userAgent": "meta-externalagent/1.1",
                            "matchedRules": [{"name": "Browser challenge required"}],
                        },
                        {"verdict": "monitor", "statusCode": 200, "siteName": "demo.example.test", "host": "demo.example.test", "ip": "203.0.113.4", "matchedRules": [{"name": "Monitor rule"}]},
                    ]
                }
            )

        self.assertEqual(stats["total"], 4)
        self.assertEqual(stats["blocked"], 1)
        self.assertEqual(stats["challenged"], 1)
        self.assertEqual(stats["protected"], 2)
        self.assertEqual(stats["monitored"], 1)
        self.assertEqual(stats["allowed"], 1)
        self.assertEqual(stats["blockRate"], 25.0)
        self.assertEqual(stats["protectedRate"], 50.0)
        meta_bot = next(item for item in stats["botTypes"] if item["name"] == "Meta/Facebook crawler")
        self.assertEqual(meta_bot["challenged"], 1)
        self.assertEqual(stats["topCountries"][0]["name"], "United States")
        self.assertEqual(stats["topCountries"][0]["protected"], 2)
        self.assertEqual(stats["blockedCountryCount"], 1)
        demo_stats = next(item for item in stats["siteStats"] if item["siteId"] == "site-demo")
        self.assertEqual(demo_stats["requests"], stats["total"])
        self.assertEqual(demo_stats["blocked"], stats["blocked"])
        self.assertEqual(demo_stats["protected"], stats["protected"])

    def test_site_stats_prefer_exact_domain_before_wildcard_and_catchall(self):
        stats = build_stats(
            {
                "sites": [
                    {"id": "site-catchall", "name": "Catchall", "hostnames": ["*"]},
                    {"id": "site-wildcard", "name": "Wildcard", "hostnames": ["*.example.test"]},
                    {"id": "site-exact", "name": "Exact", "hostnames": ["shop.example.test"]},
                ],
                "logs": [
                    {"host": "shop.example.test", "verdict": "block"},
                    {"host": "blog.example.test", "verdict": "challenge"},
                    {"host": "other.test", "verdict": "allow"},
                ],
            }
        )

        site_stats = {item["siteId"]: item for item in stats["siteStats"]}
        self.assertEqual(site_stats["site-exact"]["requests"], 1)
        self.assertEqual(site_stats["site-exact"]["blocked"], 1)
        self.assertEqual(site_stats["site-wildcard"]["requests"], 1)
        self.assertEqual(site_stats["site-wildcard"]["challenged"], 1)
        self.assertEqual(site_stats["site-catchall"]["requests"], 1)

    def test_dashboard_stats_exclude_logs_not_matching_current_applications(self):
        stats = build_stats(
            {
                "sites": [{"id": "site-current", "name": "Current", "hostnames": ["current.example.test"]}],
                "logs": [
                    {"host": "current.example.test", "verdict": "allow"},
                    {"host": "deleted.example.test", "verdict": "block"},
                    {"host": "203.0.113.10", "verdict": "challenge"},
                ],
            }
        )

        self.assertEqual(stats["scannedTotal"], 3)
        self.assertEqual(stats["unmatchedTotal"], 2)
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["protected"], 0)
        self.assertEqual(stats["siteStats"][0]["requests"], stats["total"])

    def test_geoip_country_csv_resolves_public_ip(self):
        with tempfile.TemporaryDirectory() as directory:
            geoip_file = Path(directory) / "dbip-country-lite.csv.gz"
            with gzip.open(geoip_file, "wt", encoding="utf-8", newline="") as target:
                target.write("8.8.8.0,8.8.8.255,US\n")

            with mock.patch.dict(os.environ, {"GEOIP_DB_FILE": str(geoip_file)}):
                country = country_for_ip("8.8.8.8")

        self.assertEqual(country["code"], "US")

    def test_certbot_certificate_state_is_normalized(self):
        state = normalize_state(
            {
                "sites": [],
                "rules": [],
                "certificates": [
                    {
                        "id": "certbot-demo",
                        "name": "example.test",
                        "source": "certbot",
                        "domains": ["example.test", "www.example.test"],
                        "email": "admin@example.test",
                        "certFile": "/etc/letsencrypt/live/example.test/fullchain.pem",
                        "keyFile": "/etc/letsencrypt/live/example.test/privkey.pem",
                    }
                ],
            }
        )

        certificate = state["certificates"][0]
        self.assertEqual(certificate["source"], "certbot")
        self.assertEqual(certificate["domains"], ["example.test", "www.example.test"])
        self.assertEqual(certificate["renewBeforeDays"], 30)
        self.assertTrue(certificate["autoRenew"])

    def test_certbot_certificate_paths_are_recovered_from_last_message(self):
        state = normalize_state(
            {
                "sites": [],
                "rules": [],
                "certificates": [
                    {
                        "id": "certbot-demo",
                        "name": "example.test",
                        "source": "certbot",
                        "domains": ["example.test", "www.example.test"],
                        "email": "admin@example.test",
                        "certFile": "/etc/letsencrypt/live/example.test/fullchain.pem",
                        "keyFile": "/etc/letsencrypt/live/example.test/privkey.pem",
                        "lastMessage": (
                            "Successfully received certificate.\n"
                            "Certificate is saved at: /etc/letsencrypt/live/example.test-0001/fullchain.pem\n"
                            "Key is saved at:         /etc/letsencrypt/live/example.test-0001/privkey.pem\n"
                        ),
                    }
                ],
            }
        )

        certificate = state["certificates"][0]
        self.assertEqual(certificate["certFile"], "/etc/letsencrypt/live/example.test-0001/fullchain.pem")
        self.assertEqual(certificate["keyFile"], "/etc/letsencrypt/live/example.test-0001/privkey.pem")

    def test_ip_group_reference_state_is_normalized(self):
        state = normalize_state(
            {
                "sites": [],
                "rules": [],
                "ipGroups": [
                    {
                        "id": "ipgroup-feed",
                        "name": "Threat feed",
                        "referenceUrl": "https://example.test/feed.txt",
                        "items": [
                            "192.0.2.10 # comment",
                            "# ignored",
                            "198.51.100.0/24",
                            "203.0.113.10 office host",
                            "2001:db8::/32 ipv6 network",
                        ],
                        "lastSyncedAt": "2026-06-10T00:00:00+00:00",
                        "lastSyncStatus": "ok",
                        "lastSyncMessage": "2 entries synced",
                    }
                ],
            }
        )

        group = state["ipGroups"][0]
        self.assertEqual(group["referenceUrl"], "https://example.test/feed.txt")
        self.assertEqual(group["items"], ["192.0.2.10", "198.51.100.0/24", "203.0.113.10", "2001:db8::/32"])
        self.assertEqual(group["lastSyncStatus"], "ok")

    def test_large_ip_group_is_stored_in_external_file(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"IP_GROUP_EXTERNALIZE_COUNT": "2", "IP_GROUP_EXTERNALIZE_BYTES": "1024"}):
                store = Store(Path(directory) / "state.json")
                store.init()
                group = store.upsert_ip_group(
                    {
                        "name": "Large feed",
                        "items": "192.0.2.1\n192.0.2.2\n192.0.2.3\n",
                    }
                )

                self.assertTrue(group["itemsExternal"])
                self.assertEqual(group["itemCount"], 3)
                self.assertEqual(group["items"], [])
                self.assertEqual(group["itemsPreview"], ["192.0.2.1", "192.0.2.2", "192.0.2.3"])
                self.assertTrue(Path(group["itemsFile"]).exists())
                self.assertIn("192.0.2.3", Path(group["itemsFile"]).read_text(encoding="utf-8"))

                updated = store.upsert_ip_group(
                    {
                        "name": "Large feed renamed",
                        "description": "Metadata update only",
                    },
                    group["id"],
                )

                self.assertTrue(Path(updated["itemsFile"]).exists())
                self.assertEqual(updated["itemCount"], 3)
                self.assertEqual(updated["itemsPreview"][0], "192.0.2.1")

    def test_site_features_are_normalized(self):
        state = normalize_state(
            {
                "sites": [
                    {
                        "id": "site-demo",
                        "name": "Demo",
                        "hostnames": ["example.test"],
                        "origin": "http://127.0.0.1:9090",
                        "features": {
                            "httpFlood": False,
                            "botProtection": False,
                            "auth": True,
                            "attacks": True,
                        },
                    }
                ],
                "rules": [],
            }
        )

        features = state["sites"][0]["features"]
        self.assertFalse(features["httpFlood"])
        self.assertFalse(features["botProtection"])
        self.assertTrue(features["auth"])
        self.assertTrue(features["attacks"])

    def test_http_flood_acl_options_are_normalized(self):
        state = normalize_state(
            {
                "sites": [
                    {
                        "id": "site-demo",
                        "name": "Demo",
                        "hostnames": ["example.test"],
                        "origin": "http://127.0.0.1:9090",
                        "acl": {
                            "enabled": True,
                            "rateLimitMode": "global",
                            "waitingRoom": True,
                        },
                    }
                ],
                "rules": [],
            }
        )

        acl = state["sites"][0]["acl"]
        self.assertEqual(acl["rateLimitMode"], "global")
        self.assertTrue(acl["waitingRoom"])
        self.assertEqual(acl["accessLimit"]["action"], "challenge_v1")

    def test_bot_protection_options_are_normalized(self):
        state = normalize_state(
            {
                "sites": [
                    {
                        "id": "site-demo",
                        "name": "Demo",
                        "hostnames": ["example.test"],
                        "origin": "http://127.0.0.1:9090",
                        "features": {"botProtection": True},
                        "botProtection": {
                            "antiBotChallenge": False,
                            "dynamicProtection": {"enabled": True, "html": True, "js": False, "watermark": True},
                            "antiReplay": {"enabled": True},
                        },
                    }
                ],
                "rules": [],
            }
        )

        protection = state["sites"][0]["botProtection"]
        self.assertTrue(protection["enabled"])
        self.assertFalse(protection["antiBotChallenge"])
        self.assertFalse(protection["loginChallenge"]["enabled"])
        self.assertFalse(protection["rateChallenge"]["enabled"])
        self.assertTrue(protection["dynamicProtection"]["enabled"])
        self.assertTrue(protection["dynamicProtection"]["html"])
        self.assertTrue(protection["dynamicProtection"]["watermark"])
        self.assertTrue(protection["antiReplay"]["enabled"])
        self.assertTrue(state["sites"][0]["features"]["botProtection"])

    def test_bot_protection_login_and_rate_defaults_are_normalized(self):
        state = normalize_state(
            {
                "sites": [
                    {
                        "id": "site-demo",
                        "name": "Demo",
                        "hostnames": ["example.test"],
                        "origin": "http://127.0.0.1:9090",
                        "features": {"botProtection": True},
                        "botProtection": {"antiBotChallenge": True},
                    }
                ],
                "rules": [],
            }
        )

        protection = state["sites"][0]["botProtection"]
        self.assertTrue(protection["loginChallenge"]["enabled"])
        self.assertTrue(any("wp-login" in pattern for pattern in protection["loginChallenge"]["pathPatterns"]))
        self.assertTrue(protection["rateChallenge"]["enabled"])
        self.assertEqual(protection["rateChallenge"]["windowSeconds"], 10)
        self.assertEqual(protection["rateChallenge"]["challengeCount"], 100)
        self.assertEqual(protection["rateChallenge"]["blockCount"], 200)

    def test_safeline_application_fields_are_normalized(self):
        state = normalize_state(
            {
                "sites": [
                    {
                        "id": "site-shop",
                        "comment": "Shop",
                        "server_names": ["shop.example.test", "www.shop.example.test"],
                        "upstreams": ["https://203.0.113.10:443", "https://203.0.113.11:443"],
                        "ports": ["80", "443_ssl"],
                        "listen": 443,
                        "tls": {"enabled": True, "redirectHttp": True, "httpListen": 80},
                        "redirect_status_code": 301,
                        "proxy": {
                            "hsts": True,
                            "reset_xff": True,
                            "modify_host_header": False,
                            "forwarded_headers": False,
                        },
                        "modsecurity": {
                            "enabled": True,
                            "mode": "detection_only",
                            "ruleset": "owasp",
                            "request_body_limit": 8388608,
                        },
                        "acl_enabled": True,
                    }
                ],
                "rules": [],
            }
        )

        site = state["sites"][0]
        self.assertEqual(site["name"], "Shop")
        self.assertEqual(site["hostnames"], ["shop.example.test", "www.shop.example.test"])
        self.assertEqual(site["upstreams"], ["https://203.0.113.10:443", "https://203.0.113.11:443"])
        self.assertEqual(site["ports"], ["80", "443_ssl"])
        self.assertEqual(site["proxy"]["redirectStatusCode"], 301)
        self.assertTrue(site["proxy"]["hsts"])
        self.assertFalse(site["proxy"]["modifyHostHeader"])
        self.assertFalse(site["proxy"]["forwardedHeaders"])
        self.assertTrue(site["modSecurity"]["enabled"])
        self.assertEqual(site["modSecurity"]["mode"], "detection_only")
        self.assertEqual(site["modSecurity"]["ruleset"], "owasp")
        self.assertEqual(site["modSecurity"]["requestBodyLimit"], 8388608)
        self.assertTrue(site["acl"]["enabled"])
        self.assertEqual(site["acl"]["accessLimit"]["count"], 200)

    def test_access_rule_insert_position_first_moves_rule_to_top(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.json")
            store.init()

            store.upsert_access_rule(
                {
                    "name": "Last rule",
                    "action": "deny",
                    "insertPosition": "last",
                    "ips": ["198.51.100.10"],
                }
            )
            store.upsert_access_rule(
                {
                    "name": "First rule",
                    "action": "allow",
                    "insertPosition": "first",
                    "conditionGroups": [
                        {
                            "conditions": [
                                {"target": "source_ip", "operator": "equals", "content": "203.0.113.10"}
                            ]
                        }
                    ],
                }
            )

            self.assertEqual([rule["name"] for rule in store.get_state()["accessRules"]], ["First rule", "Last rule"])

    def test_delete_certificate_clears_panel_ssl_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.json")
            store.init()
            certificate = store.upsert_certificate(
                {
                    "name": "Panel cert",
                    "source": "upload",
                    "certFile": "nginx/certs/panel.crt",
                    "keyFile": "nginx/certs/panel.key",
                }
            )
            store.update_settings(
                {
                    "panel": {
                        "httpsEnabled": True,
                        "certificateId": certificate["id"],
                    }
                }
            )

            store.delete_certificate(certificate["id"])

            panel = store.get_state()["settings"]["panel"]
            self.assertFalse(panel["httpsEnabled"])
            self.assertEqual(panel["certificateId"], "")

    def test_application_defaults_are_normalized_and_deep_merged(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.json")
            store.init()
            store.update_settings(
                {
                    "applicationDefaults": {
                        "proxy": {
                            "brotli": True,
                            "hstsMaxAge": 123,
                        },
                        "modSecurity": {
                            "mode": "detection_only",
                            "requestBodyLimit": 8388608,
                        },
                    }
                }
            )
            store.update_settings(
                {
                    "applicationDefaults": {
                        "proxy": {
                            "hostHeader": "$host",
                        },
                    }
                }
            )

            defaults = store.get_state()["settings"]["applicationDefaults"]
            self.assertTrue(defaults["proxy"]["brotli"])
            self.assertEqual(defaults["proxy"]["hstsMaxAge"], 123)
            self.assertEqual(defaults["proxy"]["hostHeader"], "$host")
            self.assertEqual(defaults["modSecurity"]["mode"], "detection_only")
            self.assertEqual(defaults["modSecurity"]["requestBodyLimit"], 8388608)


if __name__ == "__main__":
    unittest.main()
