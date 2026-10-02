import io
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf import backup
from freewaf.server import make_admin_handler
from freewaf.store import Store, StoreError


class BackupArchiveTests(unittest.TestCase):
    def make_store(self, directory: Path) -> Store:
        store = Store(directory / "state.json")
        store.init()
        # A fresh store seeds a "site-demo" entry; tests want a clean slate
        # so site counts below are exact instead of off-by-one.
        store.delete_site("site-demo")
        return store

    def test_export_defaults_to_all_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory))
            store.upsert_site({"name": "Shop", "hostnames": ["shop.example.test"], "origin": "http://127.0.0.1:9001"})

            content, filename = backup.build_backup_archive(store, None)

            self.assertTrue(filename.startswith("freewaf-backup-"))
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                state = json.loads(archive.read("state.json"))

            self.assertEqual(manifest["format"], "freewaf-backup")
            self.assertEqual(set(manifest["categories"]), set(backup.CATEGORIES))
            self.assertEqual(set(state.keys()), set(backup.CATEGORIES))
            self.assertEqual(len(state["sites"]), 1)
            self.assertEqual(state["sites"][0]["name"], "Shop")

    def test_export_respects_category_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory))
            content, _ = backup.build_backup_archive(store, ["settings", "rules"])
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                state = json.loads(archive.read("state.json"))
                manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(set(state.keys()), {"settings", "rules"})
            self.assertEqual(manifest["categories"], ["settings", "rules"])

    def test_export_rejects_unknown_category(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory))
            with self.assertRaises(StoreError):
                backup.build_backup_archive(store, ["not-a-real-category"])

    def test_export_bundles_certificate_files_when_reader_supplied(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory))
            cert = store.upsert_certificate(
                {
                    "name": "example.test",
                    "domains": ["example.test"],
                    "source": "upload",
                    "certFile": "nginx/certs/example.crt",
                    "keyFile": "nginx/certs/example.key",
                }
            )

            def reader(certificate):
                self.assertEqual(certificate["id"], cert["id"])
                return b"CERT-BYTES", b"KEY-BYTES"

            content, _ = backup.build_backup_archive(store, ["certificates"], certificate_file_reader=reader)
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                names = archive.namelist()
                self.assertIn(f"cert-files/{cert['id']}/fullchain.pem", names)
                self.assertIn(f"cert-files/{cert['id']}/privkey.pem", names)
                self.assertEqual(archive.read(f"cert-files/{cert['id']}/fullchain.pem"), b"CERT-BYTES")

    def test_export_skips_auto_synced_ip_group_content(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory))
            items_file = Path(directory) / "data" / "ip-groups" / "ipgroup-custom.txt"
            items_file.parent.mkdir(parents=True, exist_ok=True)
            items_file.write_text("1.2.3.4\n", encoding="utf-8")

            # Simulate an externalized group with no referenceUrl (user-maintained,
            # can't be regenerated automatically) alongside a managed/synced one.
            store.state["ipGroups"].append(
                {
                    "id": "ipgroup-custom",
                    "name": "Custom",
                    "items": [],
                    "itemsFile": str(items_file),
                    "itemsExternal": True,
                    "itemCount": 1,
                    "referenceUrl": "",
                }
            )
            store.persist()

            content, _ = backup.build_backup_archive(store, ["ipGroups"])
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                names = archive.namelist()
            self.assertIn("ip-group-files/ipgroup-custom.txt", names)
            # The managed "Local addresses" group has no itemsFile/referenceUrl
            # collision risk, and provider-backed groups all carry a
            # referenceUrl, so none of those should produce extra files.
            self.assertEqual([n for n in names if n.startswith("ip-group-files/")], ["ip-group-files/ipgroup-custom.txt"])

    def test_read_backup_archive_rejects_non_zip(self):
        with self.assertRaises(StoreError):
            backup.read_backup_archive(b"not a zip file")

    def test_read_backup_archive_rejects_wrong_format(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w") as archive:
            archive.writestr("manifest.json", json.dumps({"format": "something-else"}))
            archive.writestr("state.json", json.dumps({}))
        with self.assertRaises(StoreError):
            backup.read_backup_archive(buffer.getvalue())

    def test_read_backup_archive_rejects_path_traversal_entries(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w") as archive:
            archive.writestr("manifest.json", json.dumps({"format": "freewaf-backup"}))
            archive.writestr("state.json", json.dumps({"settings": {}}))
            archive.writestr("cert-files/../../../etc/passwd", b"evil")
        with self.assertRaises(StoreError):
            backup.read_backup_archive(buffer.getvalue())

    def test_merge_restore_adds_new_and_updates_existing(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as target_dir:
            source = self.make_store(Path(source_dir))
            source.upsert_site({"name": "Shop", "hostnames": ["shop.example.test"], "origin": "http://127.0.0.1:9001"})
            content, _ = backup.build_backup_archive(source, ["sites", "rules"])

            target = self.make_store(Path(target_dir))
            builtin_rule_count = len(target.get_state()["rules"])

            archive_data = backup.read_backup_archive(content)
            result = backup.apply_backup_archive(target, archive_data, None, "merge")

            restored_state = target.get_state()
            self.assertEqual(len(restored_state["sites"]), 1)
            self.assertEqual(restored_state["sites"][0]["name"], "Shop")
            # Builtin rules already on the target survive a merge restore.
            self.assertEqual(len(restored_state["rules"]), builtin_rule_count)
            self.assertEqual(result["mode"], "merge")
            self.assertEqual(result["summary"]["sites"]["added"], 1)

    def test_replace_restore_overwrites_category(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as target_dir:
            source = self.make_store(Path(source_dir))
            source.upsert_site({"name": "Shop", "hostnames": ["shop.example.test"], "origin": "http://127.0.0.1:9001"})
            content, _ = backup.build_backup_archive(source, ["sites"])

            target = self.make_store(Path(target_dir))
            target.upsert_site({"name": "Old", "hostnames": ["old.example.test"], "origin": "http://127.0.0.1:9002"})

            archive_data = backup.read_backup_archive(content)
            backup.apply_backup_archive(target, archive_data, None, "replace")

            restored_sites = target.get_state()["sites"]
            self.assertEqual(len(restored_sites), 1)
            self.assertEqual(restored_sites[0]["name"], "Shop")

    def test_restore_can_be_narrowed_to_a_subset_of_backup_categories(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as target_dir:
            source = self.make_store(Path(source_dir))
            source.upsert_site({"name": "Shop", "hostnames": ["shop.example.test"], "origin": "http://127.0.0.1:9001"})
            content, _ = backup.build_backup_archive(source, None)

            target = self.make_store(Path(target_dir))
            archive_data = backup.read_backup_archive(content)
            result = backup.apply_backup_archive(target, archive_data, ["sites"], "merge")

            self.assertEqual(result["categories"], ["sites"])
            self.assertEqual(len(target.get_state()["sites"]), 1)

    def test_restore_writes_certificate_files_via_writer_callback(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as target_dir:
            source = self.make_store(Path(source_dir))
            cert = source.upsert_certificate(
                {
                    "name": "example.test",
                    "domains": ["example.test"],
                    "source": "certbot",
                    "email": "admin@example.test",
                    "certFile": "/etc/letsencrypt/live/example.test/fullchain.pem",
                    "keyFile": "/etc/letsencrypt/live/example.test/privkey.pem",
                }
            )
            content, _ = backup.build_backup_archive(
                source,
                ["certificates"],
                certificate_file_reader=lambda c: (b"FULLCHAIN", b"PRIVKEY"),
            )

            target = self.make_store(Path(target_dir))
            archive_data = backup.read_backup_archive(content)
            written = {}

            def writer(cert_id, files):
                written[cert_id] = files

            backup.apply_backup_archive(target, archive_data, ["certificates"], "merge", certificate_file_writer=writer)

            self.assertIn(cert["id"], written)
            self.assertEqual(written[cert["id"]]["fullchain.pem"], b"FULLCHAIN")
            self.assertEqual(written[cert["id"]]["privkey.pem"], b"PRIVKEY")

    def test_restore_writes_ip_group_files_into_target_directory(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as target_dir:
            source = self.make_store(Path(source_dir))
            items_file = Path(source_dir) / "data" / "ip-groups" / "ipgroup-custom.txt"
            items_file.parent.mkdir(parents=True, exist_ok=True)
            items_file.write_text("1.2.3.4\n", encoding="utf-8")
            source.state["ipGroups"].append(
                {
                    "id": "ipgroup-custom",
                    "name": "Custom",
                    "items": [],
                    "itemsFile": str(items_file),
                    "itemsExternal": True,
                    "itemCount": 1,
                    "referenceUrl": "",
                }
            )
            source.persist()
            content, _ = backup.build_backup_archive(source, ["ipGroups"])

            target = self.make_store(Path(target_dir))
            archive_data = backup.read_backup_archive(content)
            dest_dir = Path(target_dir) / "restored-ip-groups"
            backup.apply_backup_archive(target, archive_data, ["ipGroups"], "merge", ip_group_dir=dest_dir)

            self.assertEqual((dest_dir / "ipgroup-custom.txt").read_text(encoding="utf-8"), "1.2.3.4\n")

    def test_store_restore_categories_writes_pre_restore_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory))
            store.upsert_site({"name": "Shop", "hostnames": ["shop.example.test"], "origin": "http://127.0.0.1:9001"})

            store.restore_categories({"sites": []}, mode="replace")

            backups_dir = Path(directory) / "backups"
            snapshots = list(backups_dir.glob("state-pre-restore-*.json"))
            self.assertEqual(len(snapshots), 1)
            snapshotted_state = json.loads(snapshots[0].read_text(encoding="utf-8"))
            self.assertEqual(len(snapshotted_state["sites"]), 1)
            self.assertEqual(store.get_state()["sites"], [])

    def test_restore_categories_rejects_invalid_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(Path(directory))
            with self.assertRaises(StoreError):
                store.restore_categories({"sites": []}, mode="wipe")


class BackupEndpointTests(unittest.TestCase):
    def start_admin_server(self, store):
        handler_cls = make_admin_handler(store, 7001, 9090, False, False)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: self.stop_admin_server(server, thread))
        return server

    @staticmethod
    def stop_admin_server(server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    def login_cookie(self, server, username="admin", password="SecretPass123"):
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/api/auth/login",
            data=json.dumps({"username": username, "password": password}).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.headers["Set-Cookie"].split(";", 1)[0]

    def test_export_requires_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.json")
            store.init()
            server = self.start_admin_server(store)
            request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/api/backup/export")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(ctx.exception.code, 401)

    def test_export_then_restore_round_trip_via_http(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "state.json")
            store.init()
            store.delete_site("site-demo")
            store.upsert_user({"username": "admin", "password": "SecretPass123", "enabled": True})
            store.upsert_site({"name": "Shop", "hostnames": ["shop.example.test"], "origin": "http://127.0.0.1:9001"})

            server = self.start_admin_server(store)
            cookie = self.login_cookie(server)

            with mock.patch("freewaf.server.apply_nginx_or_raise", return_value={"ok": True}):
                export_request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/api/backup/export",
                    headers={"Cookie": cookie},
                )
                with urllib.request.urlopen(export_request, timeout=5) as response:
                    archive_bytes = response.read()
                    self.assertEqual(response.headers["Content-Type"], "application/zip")

                import base64

                restore_request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/api/backup/restore",
                    data=json.dumps(
                        {
                            "mode": "replace",
                            "categories": ["sites"],
                            "fileBase64": base64.b64encode(archive_bytes).decode("ascii"),
                        }
                    ).encode("utf-8"),
                    headers={"content-type": "application/json", "Cookie": cookie},
                    method="POST",
                )
                with urllib.request.urlopen(restore_request, timeout=5) as response:
                    result = json.loads(response.read().decode("utf-8"))

            self.assertEqual(result["categories"], ["sites"])
            self.assertEqual(len(store.get_state()["sites"]), 1)
            self.assertEqual(store.get_state()["sites"][0]["name"], "Shop")


if __name__ == "__main__":
    unittest.main()
