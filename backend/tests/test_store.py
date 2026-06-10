import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf.store import Store, normalize_state


class StoreTests(unittest.TestCase):
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
        self.assertTrue(protection["dynamicProtection"]["enabled"])
        self.assertTrue(protection["dynamicProtection"]["html"])
        self.assertTrue(protection["dynamicProtection"]["watermark"])
        self.assertTrue(protection["antiReplay"]["enabled"])
        self.assertTrue(state["sites"][0]["features"]["botProtection"])

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
                        "proxy": {"hsts": True, "reset_xff": True},
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


if __name__ == "__main__":
    unittest.main()
