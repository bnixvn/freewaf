import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf.server import (
    challenge_nonce,
    combined_logs_page,
    combined_stats_logs,
    enrich_log_countries,
    prepare_certificate_payload,
    prepare_certbot_certificate_payload,
    remove_certificate_files,
    render_challenge_page,
    ip_items_from_reference_text,
    secure_link_token,
    sync_ip_group_reference,
    verify_challenge_nonce,
)
from freewaf.store import Store


CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----"""

KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIB
-----END PRIVATE KEY-----"""


class CertificateServerTests(unittest.TestCase):
    def test_pasted_cert_payload_is_written_to_nginx_cert_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(os.environ, {"NGINX_CERT_DIR": str(Path(temp_dir) / "certs")}):
                prepared = prepare_certificate_payload(
                    {
                        "id": "cert-test",
                        "source": "upload",
                        "name": "Demo cert",
                        "certificate": CERT_PEM,
                        "privateKey": KEY_PEM,
                    }
                )

            self.assertEqual(prepared["source"], "upload")
            self.assertEqual(prepared["name"], "Demo cert")
            self.assertTrue(Path(prepared["certFile"]).exists())
            self.assertTrue(Path(prepared["keyFile"]).exists())
            self.assertIn("BEGIN CERTIFICATE", Path(prepared["certFile"]).read_text(encoding="utf-8"))
            self.assertIn("PRIVATE KEY", Path(prepared["keyFile"]).read_text(encoding="utf-8"))

    def test_certbot_payload_uses_letsencrypt_live_paths_without_running_certbot(self):
        with tempfile.TemporaryDirectory() as live_dir:
            with mock.patch.dict(os.environ, {"CERTBOT_LIVE_DIR": live_dir}):
                with mock.patch(
                    "freewaf.server.run_certbot",
                    return_value={
                        "ok": True,
                        "stdout": (
                            "Successfully received certificate.\n"
                            f"Certificate is saved at: {live_dir}/example.test-0001/fullchain.pem\n"
                            f"Key is saved at:         {live_dir}/example.test-0001/privkey.pem\n"
                        ),
                        "stderr": "",
                    },
                ) as run_certbot:
                    prepared = prepare_certbot_certificate_payload(
                        {
                            "name": "",
                            "source": "certbot",
                            "domains": ["example.test", "www.example.test"],
                            "email": "ops@example.test",
                        }
                    )

        run_certbot.assert_called_once_with(["example.test", "www.example.test"], "ops@example.test")
        expected_live = Path(live_dir) / "example.test-0001"
        self.assertEqual(prepared["source"], "certbot")
        self.assertEqual(prepared["name"], "example.test")
        self.assertEqual(prepared["certFile"], str(expected_live / "fullchain.pem").replace("\\", "/"))
        self.assertEqual(prepared["keyFile"], str(expected_live / "privkey.pem").replace("\\", "/"))
        self.assertEqual(prepared["status"], "ready")

    def test_signed_challenge_nonce_and_edge_token_are_bound_to_context(self):
        context = {
            "siteId": "site-demo",
            "host": "demo.example.test",
            "ip": "203.0.113.10",
            "userAgent": "Mozilla/5.0",
            "proto": "https",
        }
        with mock.patch.dict(os.environ, {"FREEWAF_CHALLENGE_SECRET": "unit-test-secret"}, clear=False):
            nonce = challenge_nonce(context)
            token = secure_link_token(context, 1800000000)
            self.assertTrue(verify_challenge_nonce(nonce, context))
            self.assertFalse(verify_challenge_nonce(nonce, {**context, "ip": "203.0.113.11"}))
        self.assertRegex(token, r"^[A-Za-z0-9_-]+$")

    def test_challenge_nonce_enforces_configured_wait_before_verify(self):
        context = {
            "siteId": "site-demo",
            "host": "demo.example.test",
            "ip": "203.0.113.10",
            "userAgent": "Mozilla/5.0",
            "proto": "https",
        }
        with mock.patch.dict(os.environ, {"FREEWAF_CHALLENGE_SECRET": "unit-test-secret"}, clear=False):
            with mock.patch("freewaf.server.time.time", return_value=1000):
                nonce = challenge_nonce(context, delay_seconds=5)
            with mock.patch("freewaf.server.time.time", return_value=1004):
                self.assertFalse(verify_challenge_nonce(nonce, context))
            with mock.patch("freewaf.server.time.time", return_value=1005):
                self.assertTrue(verify_challenge_nonce(nonce, context))

    def test_challenge_page_uses_configured_wait_seconds(self):
        context = {
            "siteId": "site-demo",
            "host": "demo.example.test",
            "ip": "203.0.113.10",
            "userAgent": "Mozilla/5.0",
            "proto": "https",
        }
        html = render_challenge_page(
            {"settings": {"challengePage": {"waitSeconds": 10}}},
            {"id": "site-demo", "name": "Demo", "enabled": True},
            context,
        )

        self.assertIn("Checking browser integrity... 10s", html)
        self.assertIn("10000", html)

    def test_delete_uploaded_cert_removes_managed_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir) / "certs"
            cert_dir.mkdir()
            cert_file = cert_dir / "demo.crt"
            key_file = cert_dir / "demo.key"
            cert_file.write_text(CERT_PEM, encoding="utf-8")
            key_file.write_text(KEY_PEM, encoding="utf-8")

            with mock.patch.dict(os.environ, {"NGINX_CERT_DIR": str(cert_dir)}):
                remove_certificate_files(
                    {
                        "source": "upload",
                        "certFile": str(cert_file),
                        "keyFile": str(key_file),
                    }
                )

            self.assertFalse(cert_file.exists())
            self.assertFalse(key_file.exists())

    def test_delete_uploaded_cert_does_not_remove_unmanaged_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir) / "certs"
            cert_dir.mkdir()
            outside_file = Path(temp_dir) / "outside.crt"
            outside_file.write_text(CERT_PEM, encoding="utf-8")

            with mock.patch.dict(os.environ, {"NGINX_CERT_DIR": str(cert_dir)}):
                remove_certificate_files(
                    {
                        "source": "upload",
                        "certFile": str(outside_file),
                        "keyFile": "",
                    }
                )

            self.assertTrue(outside_file.exists())

    def test_delete_certbot_certificate_runs_certbot_delete(self):
        with mock.patch(
            "freewaf.server.subprocess.run",
            return_value=mock.Mock(returncode=0, stdout="", stderr=""),
        ) as run:
            remove_certificate_files(
                {
                    "source": "certbot",
                    "domains": ["example.test"],
                    "certFile": "/etc/letsencrypt/live/example.test/fullchain.pem",
                    "keyFile": "/etc/letsencrypt/live/example.test/privkey.pem",
                }
            )

        command = run.call_args.args[0]
        self.assertIn("delete", command)
        self.assertIn("--cert-name", command)
        self.assertIn("example.test", command)

    def test_ip_group_reference_sync_updates_content(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = Store(Path(temp_dir) / "state.json")
            store.init()
            group = store.upsert_ip_group(
                {
                    "name": "Feed",
                    "referenceUrl": "https://example.test/feed.txt",
                    "items": [],
                }
            )

            with mock.patch(
                "freewaf.server.fetch_reference_text",
                return_value="203.0.113.10 office host\n198.51.100.0/24 # test\n2001:db8::/32 ipv6\n",
            ):
                synced = sync_ip_group_reference(store, group["id"])

        self.assertEqual(synced["items"], ["203.0.113.10", "198.51.100.0/24", "2001:db8::/32"])
        self.assertEqual(synced["lastSyncStatus"], "ok")
        self.assertEqual(synced["lastSyncMessage"], "3 entries synced")

    def test_ip_group_reference_parser_reads_json_prefix_feeds(self):
        payload = {
            "creationTime": "2026-06-11T00:00:00Z",
            "prefixes": [
                {"ipv4Prefix": "66.249.64.0/27"},
                {"ipv6Prefix": "2001:4860:4801:10::/64"},
                {"service": "bingbot", "prefix": "40.77.167.0/24"},
                {"cidr": "157.55.39.0/24"},
            ],
        }

        items = ip_items_from_reference_text(json.dumps(payload))

        self.assertEqual(
            items,
            [
                "66.249.64.0/27",
                "2001:4860:4801:10::/64",
                "40.77.167.0/24",
                "157.55.39.0/24",
            ],
        )


class LogPaginationTests(unittest.TestCase):
    def test_enrich_log_countries_adds_country_below_ip_data(self):
        logs = [{"id": "1", "ip": "8.8.8.8"}]

        with mock.patch("freewaf.server.country_for_ip", return_value={"code": "US", "name": "United States"}):
            enriched = enrich_log_countries(logs)

        self.assertEqual(enriched[0]["country"], {"code": "US", "name": "United States"})
        self.assertNotIn("country", logs[0])

    def test_combined_stats_logs_uses_dedicated_scan_limit(self):
        store = mock.Mock()
        store.get_logs.return_value = []

        with mock.patch.dict(os.environ, {"STATS_LOG_SCAN_LIMIT": "1234", "STATS_LOG_SCAN_MAX": "5000"}):
            with mock.patch("freewaf.server.parse_nginx_logs", return_value=[]) as parse_logs:
                combined_stats_logs(store)

        parse_logs.assert_called_once()
        self.assertEqual(parse_logs.call_args.args[1], 1234)
        store.get_logs.assert_called_once_with(1234)

    def test_combined_logs_page_filters_domain_and_paginates(self):
        nginx_logs = [
            {"id": "1", "at": "2026-06-10T10:04:00+00:00", "host": "www.example.test", "siteName": "www.example.test", "path": "/d"},
            {"id": "2", "at": "2026-06-10T10:03:00+00:00", "host": "api.example.test", "siteName": "api.example.test", "path": "/c"},
            {"id": "3", "at": "2026-06-10T10:02:00+00:00", "host": "www.example.test", "siteName": "www.example.test", "path": "/b"},
            {"id": "4", "at": "2026-06-10T10:01:00+00:00", "host": "www.example.test", "siteName": "www.example.test", "path": "/a"},
        ]
        store = mock.Mock()
        store.get_logs.return_value = []
        store.get_state.return_value = {"sites": []}

        with mock.patch.dict(os.environ, {"LOG_PAGE_SCAN_LIMIT": "4", "LOG_PAGE_SCAN_MAX": "10"}):
            with mock.patch("freewaf.server.parse_nginx_logs", return_value=nginx_logs):
                page = combined_logs_page(store, limit=2, offset=2, domain="www.example.test", search="")

        self.assertEqual(page["total"], 3)
        self.assertEqual(page["page"], 2)
        self.assertEqual(page["pages"], 2)
        self.assertEqual([entry["id"] for entry in page["logs"]], ["4"])
        self.assertEqual(page["domains"], ["api.example.test", "www.example.test"])

    def test_combined_logs_page_filters_by_site_id_and_verdict(self):
        nginx_logs = [
            {"id": "1", "at": "2026-06-10T10:04:00+00:00", "siteId": "site-a", "host": "a.example.test", "siteName": "a", "verdict": "allow"},
            {"id": "2", "at": "2026-06-10T10:03:00+00:00", "siteId": "site-b", "host": "b.example.test", "siteName": "b", "verdict": "block"},
            {"id": "3", "at": "2026-06-10T10:02:00+00:00", "siteId": "site-a", "host": "a.example.test", "siteName": "a", "verdict": "block"},
            {"id": "4", "at": "2026-06-10T10:01:00+00:00", "siteId": "site-a", "host": "a.example.test", "siteName": "a", "verdict": "challenge"},
        ]
        store = mock.Mock()
        store.get_logs.return_value = []
        store.get_state.return_value = {
            "sites": [
                {"id": "site-a", "name": "Site A", "hostnames": ["a.example.test"]},
                {"id": "site-b", "name": "Site B", "hostnames": ["b.example.test"]},
            ]
        }

        with mock.patch.dict(os.environ, {"LOG_PAGE_SCAN_LIMIT": "4", "LOG_PAGE_SCAN_MAX": "10"}):
            with mock.patch("freewaf.server.parse_nginx_logs", return_value=nginx_logs):
                page = combined_logs_page(store, limit=10, offset=0, site_id="site-a", verdict="block")

        self.assertEqual(page["total"], 1)
        self.assertEqual([entry["id"] for entry in page["logs"]], ["3"])
        self.assertEqual(page["siteId"], "site-a")
        self.assertEqual(page["verdict"], "block")
        self.assertEqual(
            page["siteOptions"],
            [{"id": "site-a", "name": "Site A"}, {"id": "site-b", "name": "Site B"}],
        )

    def test_combined_logs_page_matches_site_by_host_when_site_id_missing(self):
        nginx_logs = [
            {"id": "1", "at": "2026-06-10T10:02:00+00:00", "siteId": None, "host": "a.example.test", "siteName": "a", "verdict": "allow"},
            {"id": "2", "at": "2026-06-10T10:01:00+00:00", "siteId": None, "host": "other.example.test", "siteName": "other", "verdict": "allow"},
        ]
        store = mock.Mock()
        store.get_logs.return_value = []
        store.get_state.return_value = {
            "sites": [
                {"id": "site-a", "name": "Site A", "hostnames": ["a.example.test"]},
            ]
        }

        with mock.patch.dict(os.environ, {"LOG_PAGE_SCAN_LIMIT": "4", "LOG_PAGE_SCAN_MAX": "10"}):
            with mock.patch("freewaf.server.parse_nginx_logs", return_value=nginx_logs):
                page = combined_logs_page(store, limit=10, offset=0, site_id="site-a")

        self.assertEqual(page["total"], 1)
        self.assertEqual([entry["id"] for entry in page["logs"]], ["1"])


if __name__ == "__main__":
    unittest.main()
