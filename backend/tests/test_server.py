import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf.server import (
    combined_logs_page,
    prepare_certificate_payload,
    prepare_certbot_certificate_payload,
    remove_certificate_files,
    sync_ip_group_reference,
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


class LogPaginationTests(unittest.TestCase):
    def test_combined_logs_page_filters_domain_and_paginates(self):
        nginx_logs = [
            {"id": "1", "at": "2026-06-10T10:04:00+00:00", "host": "www.example.test", "siteName": "www.example.test", "path": "/d"},
            {"id": "2", "at": "2026-06-10T10:03:00+00:00", "host": "api.example.test", "siteName": "api.example.test", "path": "/c"},
            {"id": "3", "at": "2026-06-10T10:02:00+00:00", "host": "www.example.test", "siteName": "www.example.test", "path": "/b"},
            {"id": "4", "at": "2026-06-10T10:01:00+00:00", "host": "www.example.test", "siteName": "www.example.test", "path": "/a"},
        ]
        store = mock.Mock()
        store.get_logs.return_value = []

        with mock.patch.dict(os.environ, {"LOG_PAGE_SCAN_LIMIT": "4", "LOG_PAGE_SCAN_MAX": "10"}):
            with mock.patch("freewaf.server.parse_nginx_logs", return_value=nginx_logs):
                page = combined_logs_page(store, limit=2, offset=2, domain="www.example.test", search="")

        self.assertEqual(page["total"], 3)
        self.assertEqual(page["page"], 2)
        self.assertEqual(page["pages"], 2)
        self.assertEqual([entry["id"] for entry in page["logs"]], ["4"])
        self.assertEqual(page["domains"], ["api.example.test", "www.example.test"])


if __name__ == "__main__":
    unittest.main()
