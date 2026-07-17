import json
import os
import sys
import tempfile
import threading
import urllib.request
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf import nginx as nginx_module
import freewaf.server as server_module
from freewaf.server import (
    challenge_nonce,
    combined_logs_page,
    combined_stats,
    combined_stats_logs,
    dashboard_period_days,
    enrich_log_countries,
    make_admin_handler,
    prepare_certificate_payload,
    prepare_certbot_certificate_payload,
    remove_certificate_files,
    render_challenge_page,
    ip_items_from_reference_text,
    secure_link_token,
    state_slice_payload,
    sync_ip_group_reference,
    verify_challenge_nonce,
)
from freewaf.store import (
    Store,
    build_stats_from_summary,
    classify_bot_type,
    classify_user_client_browser,
    classify_user_client_os,
    hll_from_values,
)


CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----"""

KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIB
-----END PRIVATE KEY-----"""


class CertificateServerTests(unittest.TestCase):
    def test_state_slice_payload_returns_only_view_dependencies(self):
        state = {
            "sites": [{"id": "site-a", "name": "Site A"}],
            "rules": [{"id": "rule-a", "name": "Rule A"}],
            "accessRules": [{"id": "access-a", "name": "Access A"}],
            "ipGroups": [{"id": "group-a", "name": "Group A"}],
            "certificates": [
                {
                    "id": "cert-a",
                    "name": "Cert A",
                    "source": "cloudflare",
                    "cloudflareApiToken": "secret-token",
                    "cloudflareCredentialsFile": "/tmp/cloudflare.ini",
                }
            ],
            "users": [{"id": "user-a", "username": "admin", "passwordHash": "secret-hash"}],
            "settings": {
                "panel": {"logoUrl": "https://example.test/logo.svg"},
                "applicationDefaults": {"proxy": {"gzip": True}},
            },
        }
        store = mock.Mock()
        store.get_state.return_value = state
        store.get_state_fields.side_effect = lambda *fields: {field: state.get(field) for field in fields}

        with mock.patch("freewaf.server.combined_stats", return_value={"total": 12, "siteStats": []}) as stats:
            dashboard = state_slice_payload(store, "dashboard", {"siteId": ["site-a"], "periodDays": ["1"]})
            sites = state_slice_payload(store, "sites")

        self.assertEqual(set(dashboard), {"sites", "stats", "settings"})
        self.assertEqual(dashboard["settings"], {"panel": state["settings"]["panel"]})
        stats.assert_any_call(
            store,
            {"sites": state["sites"], "settings": state["settings"]},
            site_id="site-a",
            retention_days=1,
        )
        self.assertEqual(set(sites), {"sites", "certificates", "settings"})
        self.assertNotIn("cloudflareApiToken", sites["certificates"][0])
        self.assertNotIn("cloudflareCredentialsFile", sites["certificates"][0])

        self.assertEqual(set(state_slice_payload(store, "rules")), {"rules", "sites"})
        self.assertEqual(set(state_slice_payload(store, "access")), {"accessRules", "sites", "ipGroups"})
        self.assertEqual(set(state_slice_payload(store, "ip-groups")), {"ipGroups"})
        self.assertEqual(set(state_slice_payload(store, "certificates")), {"certificates"})

        settings = state_slice_payload(store, "settings")
        self.assertEqual(set(settings), {"settings", "users", "certificates"})
        self.assertNotIn("passwordHash", settings["users"][0])
        self.assertNotIn("cloudflareApiToken", settings["certificates"][0])

    def test_dashboard_period_defaults_to_one_day(self):
        self.assertEqual(dashboard_period_days(""), 1)
        self.assertEqual(dashboard_period_days("1"), 1)
        self.assertEqual(dashboard_period_days("7"), 7)

    def test_apply_nginx_rolls_back_generated_bundle_when_test_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            generated_dir = root / "nginx" / "generated"
            sites_dir = generated_dir / "sites"
            sites_dir.mkdir(parents=True)
            output_file = generated_dir / "freewaf.conf"
            output_file.write_text("old main config", encoding="utf-8")
            old_site_file = sites_dir / "old.conf"
            old_site_file.write_text("old site config", encoding="utf-8")

            store = mock.Mock()
            store.get_state.return_value = {
                "settings": {},
                "sites": [
                    {
                        "id": "site-new",
                        "name": "New",
                        "hostnames": ["new.example.test"],
                        "origin": "http://127.0.0.1:9090",
                        "listen": 8080,
                        "mode": "block",
                        "enabled": True,
                    }
                ],
                "rules": [],
                "accessRules": [],
                "certificates": [],
            }

            with mock.patch.object(server_module, "ROOT_DIR", root):
                with mock.patch.object(
                    server_module,
                    "run_nginx_command",
                    return_value={"configured": True, "ok": False, "stderr": "nginx test failed"},
                ):
                    result = server_module.apply_nginx(store, {"test": True, "reload": True})

            self.assertFalse(result["ok"])
            self.assertEqual(result["rollback"], {"ok": True, "restored": True})
            self.assertEqual(output_file.read_text(encoding="utf-8"), "old main config")
            self.assertEqual(old_site_file.read_text(encoding="utf-8"), "old site config")
            self.assertEqual(sorted(file.name for file in sites_dir.glob("*.conf")), ["old.conf"])

    def test_apply_nginx_rolls_back_generated_bundle_when_reload_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sites_dir = root / "nginx" / "generated" / "sites"
            sites_dir.mkdir(parents=True)
            output_file = root / "nginx" / "generated" / "freewaf.conf"
            output_file.write_text("old main config", encoding="utf-8")

            store = mock.Mock()
            store.get_state.return_value = {
                "settings": {},
                "sites": [
                    {
                        "id": "site-new",
                        "name": "New",
                        "hostnames": ["new.example.test"],
                        "origin": "http://127.0.0.1:9090",
                        "listen": 8080,
                        "mode": "block",
                        "enabled": True,
                    }
                ],
                "rules": [],
                "accessRules": [],
                "certificates": [],
            }

            with mock.patch.object(server_module, "ROOT_DIR", root):
                with mock.patch.object(
                    server_module,
                    "run_nginx_command",
                    side_effect=[
                        {"configured": True, "ok": True, "stderr": ""},
                        {"configured": True, "ok": False, "stderr": "reload failed"},
                    ],
                ):
                    result = server_module.apply_nginx(store, {"test": True, "reload": True})

            self.assertFalse(result["ok"])
            self.assertEqual(result["rollback"], {"ok": True, "restored": True})
            self.assertEqual(output_file.read_text(encoding="utf-8"), "old main config")

    def test_api_json_responses_disable_cache(self):
        handler_cls = make_admin_handler(mock.Mock(), 7001, 9090, False, False)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/api/health", timeout=5) as response:
                self.assertEqual(response.headers["Cache-Control"], "no-store, no-cache, must-revalidate")
                self.assertEqual(response.headers["Pragma"], "no-cache")
                self.assertEqual(response.headers["Expires"], "0")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_dashboard_stats_count_retention_window_beyond_scan_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_file = root / "freewaf_access.log"
            now = datetime.now(timezone.utc)
            total = 1200
            with log_file.open("w", encoding="utf-8") as handle:
                for index in range(total):
                    at = now - timedelta(seconds=total - index)
                    handle.write(
                        json.dumps(
                            {
                                "time": at.isoformat(),
                                "remote_addr": f"203.0.113.{index % 200}",
                                "host": "demo.test",
                                "method": "GET",
                                "uri": f"/{index}",
                                "status": 403 if index % 3 == 0 else 200,
                                "request_time": 0.01,
                                "verdict": "block" if index % 3 == 0 else "allow",
                                "reason": "Blocked" if index % 3 == 0 else "Allowed",
                                "user_agent": "Googlebot/2.1" if index % 5 == 0 else "Mozilla/5.0",
                                "referer": "",
                            }
                        )
                        + "\n"
                    )

            store = mock.Mock()
            store.get_logs.return_value = []
            state = {"sites": [{"id": "site-demo", "name": "Demo", "hostnames": ["demo.test"]}]}
            with mock.patch("freewaf.server.ROOT_DIR", root):
                with mock.patch.dict(
                    os.environ,
                    {
                        "NGINX_ACCESS_LOG": str(log_file),
                        "NGINX_SITE_LOG_DIR": str(root / "sites"),
                        "STATS_LOG_SCAN_LIMIT": "100",
                        "STATS_LOG_SCAN_MAX": "100",
                        "STATS_RETENTION_DAYS": "7",
                    },
                    clear=False,
                ):
                    with nginx_module._LOG_TAIL_LOCK:
                        nginx_module._LOG_TAIL_CACHE.clear()
                    with nginx_module._LOG_INCREMENTAL_SCAN_LOCK:
                        nginx_module._LOG_INCREMENTAL_SCAN_CACHE.clear()
                    server_module.clear_stats_aggregate_cache()

                    stats = combined_stats(store, state)
                    with log_file.open("a", encoding="utf-8") as handle:
                        for index in range(3):
                            at = now + timedelta(seconds=index + 1)
                            handle.write(
                                json.dumps(
                                    {
                                        "time": at.isoformat(),
                                        "remote_addr": "203.0.113.250",
                                        "host": "demo.test",
                                        "method": "GET",
                                        "uri": f"/new-{index}",
                                        "status": 200,
                                        "request_time": 0.01,
                                        "verdict": "allow",
                                        "reason": "Allowed",
                                        "user_agent": "Mozilla/5.0",
                                        "referer": "",
                                    }
                                )
                                + "\n"
                            )
                    updated_stats = combined_stats(store, state)

        self.assertEqual(stats["total"], total)
        self.assertEqual(stats["blocked"], 400)
        self.assertEqual(stats["botRequestTotal"], 240)
        self.assertEqual(stats["siteStats"][0]["requests"], total)
        self.assertEqual(updated_stats["total"], total + 3)

    def test_dashboard_summary_filters_site_and_user_clients(self):
        def counts(total, blocked, os_name, browser_name, ips, visitors):
            protected = blocked
            return {
                "total": total,
                "blocked": blocked,
                "challenged": 0,
                "monitored": 0,
                "visitorSketch": hll_from_values(visitors),
                "uniqueIpSketch": hll_from_values(ips),
                "botTypes": {},
                "userClientOs": {
                    os_name: {"name": os_name, "type": "os", "count": total, "blocked": blocked, "challenged": 0, "protected": protected}
                },
                "userClientBrowsers": {
                    browser_name: {"name": browser_name, "type": "browser", "count": total, "blocked": blocked, "challenged": 0, "protected": protected}
                },
                "countries": {},
                "topRules": {},
                "statusGroups": {"2xx": total - blocked, "4xx": blocked},
            }

        state = {
            "sites": [
                {"id": "site-a", "name": "Site A", "hostnames": ["a.example.test"]},
                {"id": "site-b", "name": "Site B", "hostnames": ["b.example.test"]},
            ]
        }
        summary = {
            "retentionDays": 7,
            "hosts": {
                "a.example.test": counts(
                    5,
                    2,
                    "Windows",
                    "Chrome",
                    ["203.0.113.1", "203.0.113.2"],
                    ["203.0.113.1\0Chrome", "203.0.113.1\0Firefox", "203.0.113.2\0Chrome"],
                ),
                "b.example.test": counts(9, 0, "Android", "Chrome", ["203.0.113.3"], ["203.0.113.3\0Chrome"]),
            },
        }
        now = datetime.now(timezone.utc).isoformat()
        recent_logs = [
            {"id": "1", "at": now, "host": "a.example.test", "verdict": "block", "statusCode": 403},
            {"id": "2", "at": now, "host": "b.example.test", "verdict": "allow", "statusCode": 200},
        ]

        stats = build_stats_from_summary(state, summary, recent_logs, site_id="site-a")

        self.assertEqual(stats["total"], 5)
        self.assertEqual(stats["blocked"], 2)
        self.assertEqual(stats["siteStats"][0]["requests"], 5)
        self.assertEqual(stats["siteStats"][1]["requests"], 0)
        self.assertEqual(stats["uniqueIps"], 2)
        self.assertEqual(stats["visitors"], 3)
        self.assertEqual(stats["userClientOs"][0]["name"], "Windows")
        self.assertEqual(stats["userClientBrowsers"][0]["name"], "Chrome")
        self.assertEqual(stats["statusGroups"], [{"name": "2xx", "count": 3}, {"name": "4xx", "count": 2}])

    def test_dashboard_stats_period_days_limits_aggregate_window(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_file = root / "freewaf_access.log"
            now = datetime.now(timezone.utc)
            entries = [
                (now - timedelta(days=2), "old"),
                (now - timedelta(minutes=5), "fresh"),
            ]
            with log_file.open("w", encoding="utf-8") as handle:
                for at, suffix in entries:
                    handle.write(
                        json.dumps(
                            {
                                "time": at.isoformat(),
                                "remote_addr": "203.0.113.9",
                                "host": "demo.test",
                                "method": "GET",
                                "uri": f"/{suffix}",
                                "status": 200,
                                "request_time": 0.01,
                                "verdict": "allow",
                                "reason": "Allowed",
                                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
                                "referer": "",
                            }
                        )
                        + "\n"
                    )

            store = mock.Mock()
            store.get_logs.return_value = []
            state = {"sites": [{"id": "site-demo", "name": "Demo", "hostnames": ["demo.test"]}]}
            with mock.patch("freewaf.server.ROOT_DIR", root):
                with mock.patch.dict(
                    os.environ,
                    {
                        "NGINX_ACCESS_LOG": str(log_file),
                        "NGINX_SITE_LOG_DIR": str(root / "sites"),
                        "STATS_LOG_SCAN_LIMIT": "100",
                        "STATS_LOG_SCAN_MAX": "100",
                    },
                    clear=False,
                ):
                    with nginx_module._LOG_TAIL_LOCK:
                        nginx_module._LOG_TAIL_CACHE.clear()
                    with nginx_module._LOG_INCREMENTAL_SCAN_LOCK:
                        nginx_module._LOG_INCREMENTAL_SCAN_CACHE.clear()
                    server_module.clear_stats_aggregate_cache()

                    stats = combined_stats(store, state, retention_days=1)

        self.assertEqual(stats["retentionDays"], 1)
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["uniqueIps"], 1)
        self.assertEqual(stats["visitors"], 1)
        self.assertEqual(stats["userClientOs"][0]["name"], "Windows")
        self.assertEqual(stats["userClientBrowsers"][0]["name"], "Chrome")

    def test_user_client_classifiers_extract_os_and_browser(self):
        edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36 Edg/125.0"
        safari = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1"

        self.assertEqual(classify_user_client_os(edge), "Windows")
        self.assertEqual(classify_user_client_browser(edge), "Microsoft Edge")
        self.assertEqual(classify_user_client_os(safari), "iOS")
        self.assertEqual(classify_user_client_browser(safari), "Mobile Safari")

    def test_bot_classifier_returns_specific_client_and_crawler_names(self):
        cases = {
            "curl/8.5.0": "cURL",
            "python-requests/2.32.3": "Python Requests",
            "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)": "Meta External Agent",
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)": "Facebook External Hit",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)": "GPTBot",
            "ClaudeBot/1.0": "ClaudeBot",
            "FeedFetcher-Google": "FeedFetcher-Google",
            "Mozilla/5.0 Baidu spider": "Baidu crawler",
            "Mozilla/5.0 (compatible; ExampleResearchBot/2.0; +https://example.test/bot)": "ExampleResearchBot",
        }

        for user_agent, expected in cases.items():
            with self.subTest(user_agent=user_agent):
                self.assertEqual(classify_bot_type(user_agent), expected)
                self.assertEqual(classify_user_client_browser(user_agent), expected)

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

        run_certbot.assert_called_once_with(["example.test", "www.example.test"], "ops@example.test", None)
        expected_live = Path(live_dir) / "example.test-0001"
        self.assertEqual(prepared["source"], "certbot")
        self.assertEqual(prepared["name"], "example.test")
        self.assertEqual(prepared["certFile"], str(expected_live / "fullchain.pem").replace("\\", "/"))
        self.assertEqual(prepared["keyFile"], str(expected_live / "privkey.pem").replace("\\", "/"))
        self.assertEqual(prepared["status"], "ready")

    def test_certbot_webroot_prepares_temporary_http01_server_and_restores_nginx(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_file = root / "nginx" / "generated" / "freewaf.conf"
            site_dir = output_file.parent / "sites"
            site_dir.mkdir(parents=True)
            output_file.write_text("include sites/*.conf;\n", encoding="utf-8")
            existing_site = site_dir / "existing.conf"
            existing_site.write_text("server { listen 0.0.0.0:8080; }\n", encoding="utf-8")
            webroot = root / "acme"
            commands = []

            def fake_run(command, capture_output=True, text=True, timeout=180, check=False):
                commands.append(command)
                return mock.Mock(
                    returncode=0,
                    stdout=(
                        "Successfully received certificate.\n"
                        "/etc/letsencrypt/live/example.test/fullchain.pem\n"
                    ),
                    stderr="",
                )

            with mock.patch.object(server_module, "ROOT_DIR", root):
                with mock.patch.dict(
                    os.environ,
                    {
                        "CERTBOT_CMD": "/usr/bin/certbot",
                        "CERTBOT_AUTH_METHOD": "webroot",
                        "CERTBOT_WEBROOT": str(webroot),
                        "NGINX_OUTPUT_FILE": str(output_file),
                        "NGINX_SITE_CONF_DIR": str(site_dir),
                        "NGINX_TEST_CMD": "/usr/sbin/nginx -t",
                        "NGINX_RELOAD_CMD": "/usr/sbin/nginx -s reload",
                    },
                    clear=False,
                ):
                    with mock.patch("freewaf.server.run_nginx_command", return_value={"configured": True, "ok": True, "stderr": ""}) as run_nginx:
                        with mock.patch("freewaf.server.subprocess.run", side_effect=fake_run):
                            result = server_module.run_certbot(["example.test", "www.example.test"], "ops@example.test", state={"sites": []})

            self.assertTrue((webroot / ".well-known" / "acme-challenge").is_dir())
            self.assertFalse((site_dir / "_freewaf_acme_http01.conf").exists())
            self.assertEqual(existing_site.read_text(encoding="utf-8"), "server { listen 0.0.0.0:8080; }\n")
            self.assertEqual(run_nginx.call_count, 3)
            self.assertIn("--webroot", commands[0])
            self.assertIn("-w", commands[0])
            self.assertIn(str(webroot), commands[0])
            self.assertIn("-d", commands[0])
            self.assertEqual(result["ok"], True)

    def test_certbot_http01_rejects_wildcard_domains(self):
        with self.assertRaises(server_module.StoreError) as context:
            server_module.run_certbot(["example.test", "*.example.test"], "ops@example.test")

        self.assertEqual(context.exception.status, 400)
        self.assertIn("Wildcard domains require DNS-01", context.exception.message)

    def test_cloudflare_certificate_payload_writes_credentials_and_uses_dns_challenge(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            credentials_dir = Path(temp_dir) / "credentials"
            live_dir = Path(temp_dir) / "live"
            with mock.patch.dict(
                os.environ,
                {
                    "CERTBOT_CREDENTIALS_DIR": str(credentials_dir),
                    "CERTBOT_LIVE_DIR": str(live_dir),
                },
            ):
                with mock.patch(
                    "freewaf.server.run_certbot_cloudflare",
                    return_value={
                        "ok": True,
                        "stdout": (
                            "Successfully received certificate.\n"
                            f"Certificate is saved at: {live_dir}/cert-wild/fullchain.pem\n"
                            f"Key is saved at:         {live_dir}/cert-wild/privkey.pem\n"
                        ),
                        "stderr": "",
                    },
                ) as run_certbot:
                    prepared = prepare_certificate_payload(
                        {
                            "id": "cert-wild",
                            "name": "",
                            "source": "cloudflare",
                            "domains": ["example.test", "*.example.test"],
                            "email": "ops@example.test",
                            "cloudflareApiToken": "cf-secret-token",
                            "cloudflarePropagationSeconds": 45,
                        }
                    )

            credentials_file = credentials_dir / "cert-wild-cloudflare.ini"
            run_certbot.assert_called_once_with(["example.test", "*.example.test"], "ops@example.test", credentials_file, 45, "cert-wild")
            self.assertEqual(credentials_file.read_text(encoding="utf-8"), "dns_cloudflare_api_token = cf-secret-token\n")
            self.assertNotIn("cloudflareApiToken", prepared)
            self.assertEqual(prepared["source"], "cloudflare")
            self.assertEqual(prepared["name"], "example.test")
            self.assertEqual(prepared["cloudflarePropagationSeconds"], 45)
            self.assertEqual(prepared["certFile"], str(live_dir / "cert-wild" / "fullchain.pem").replace("\\", "/"))
            self.assertEqual(prepared["keyFile"], str(live_dir / "cert-wild" / "privkey.pem").replace("\\", "/"))

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

    def test_combined_stats_logs_uses_recent_log_limit(self):
        store = mock.Mock()
        store.get_logs.return_value = []

        with mock.patch.dict(os.environ, {"STATS_RECENT_LOG_LIMIT": "1234", "STATS_RECENT_LOG_MAX": "5000"}):
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
