import sys
import tempfile
import unittest
from pathlib import Path

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
                        "items": ["192.0.2.10 # comment", "# ignored", "198.51.100.0/24"],
                        "lastSyncedAt": "2026-06-10T00:00:00+00:00",
                        "lastSyncStatus": "ok",
                        "lastSyncMessage": "2 entries synced",
                    }
                ],
            }
        )

        group = state["ipGroups"][0]
        self.assertEqual(group["referenceUrl"], "https://example.test/feed.txt")
        self.assertEqual(group["items"], ["192.0.2.10", "198.51.100.0/24"])
        self.assertEqual(group["lastSyncStatus"], "ok")

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


if __name__ == "__main__":
    unittest.main()
