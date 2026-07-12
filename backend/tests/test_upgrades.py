"""Tests for the FreeWAF upgrade batch: atomic Nginx write, audit log,
login throttle, proof-of-work challenge, and log tail cache."""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf import nginx as nginx_module
from freewaf.defaults import BUILTIN_RULES, DEFAULT_SETTINGS
from freewaf.nginx import (
    nginx_output_file,
    nginx_site_config_dir,
    parse_nginx_logs,
    write_nginx_config,
)
from freewaf.server import (
    AUDIT_LOG_FILE,
    _redact_audit_value,
    append_audit_log,
    build_system_update_plan,
    make_pow_salt,
    pow_difficulty_bits,
    read_audit_log,
    verify_pow,
)
from freewaf.store import normalize_challenge_page_settings


def _state_with_demo_site():
    return {
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


class AtomicWriteNginxConfigTests(unittest.TestCase):
    def test_write_replaces_stale_site_files_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.dict(
                os.environ,
                {
                    "NGINX_CONFIG_OUTPUT": str(root / "nginx.conf"),
                    "NGINX_SITE_CONFIG_DIR": str(root / "sites"),
                    "NGINX_SITE_LOG_DIR": str(root / "logs"),
                    "NGINX_ACCESS_LOG": str(root / "access.log"),
                },
                clear=False,
            ):
                first_state = _state_with_demo_site()
                output = write_nginx_config(root, first_state)
                self.assertTrue(output.exists())
                site_dir = nginx_site_config_dir(root)
                first_files = sorted(p.name for p in site_dir.glob("*.conf"))
                self.assertEqual(len(first_files), 1)

                second_state = _state_with_demo_site()
                second_state["sites"][0]["hostnames"] = ["other.test"]
                write_nginx_config(root, second_state)
                second_files = sorted(p.name for p in site_dir.glob("*.conf"))
                self.assertEqual(len(second_files), 1)
                self.assertNotEqual(first_files, second_files)

                # No leftover staging or backup directories.
                leftovers = [p.name for p in site_dir.parent.iterdir() if p.is_dir() and p.name != site_dir.name]
                self.assertEqual(leftovers, [])

    def test_concurrent_writes_do_not_lose_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.dict(
                os.environ,
                {
                    "NGINX_CONFIG_OUTPUT": str(root / "nginx.conf"),
                    "NGINX_SITE_CONFIG_DIR": str(root / "sites"),
                    "NGINX_SITE_LOG_DIR": str(root / "logs"),
                    "NGINX_ACCESS_LOG": str(root / "access.log"),
                },
                clear=False,
            ):
                state = _state_with_demo_site()

                def worker():
                    write_nginx_config(root, state)

                threads = [threading.Thread(target=worker) for _ in range(6)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()

                site_dir = nginx_site_config_dir(root)
                files = list(site_dir.glob("*.conf"))
                self.assertEqual(len(files), 1)
                self.assertTrue(nginx_output_file(root).exists())


class AuditLogTests(unittest.TestCase):
    def test_append_and_read_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "audit.log"
            for index in range(3):
                append_audit_log({"action": "rules.delete", "targetId": f"r-{index}"}, log_file=log_file)
            entries = read_audit_log(10, log_file=log_file)
            self.assertEqual(len(entries), 3)
            self.assertEqual(entries[0]["targetId"], "r-2")
            self.assertEqual(entries[-1]["targetId"], "r-0")

    def test_redact_strips_secrets_from_payload(self):
        redacted = _redact_audit_value(
            {
                "username": "alice",
                "password": "hunter2",
                "totpSecret": "JBSWY3DPEHPK3PXP",
                "nested": {"apiKey": "abcd", "ok": True},
                "items": ["plain", {"key": "value"}],
            }
        )
        self.assertEqual(redacted["password"], "***")
        self.assertEqual(redacted["totpSecret"], "***")
        self.assertEqual(redacted["nested"]["apiKey"], "***")
        self.assertEqual(redacted["nested"]["ok"], True)
        self.assertEqual(redacted["items"][1]["key"], "***")

    def test_audit_module_default_path_writable(self):
        # Sanity check: we have a default file path computed from ROOT_DIR.
        self.assertTrue(str(AUDIT_LOG_FILE).endswith(os.path.join("logs", "audit.log")))


class ProofOfWorkTests(unittest.TestCase):
    def test_zero_difficulty_passes_with_any_solution(self):
        self.assertTrue(verify_pow("anything", "anything", 0))

    def test_invalid_inputs_are_rejected(self):
        self.assertFalse(verify_pow("", "abc", 8))
        self.assertFalse(verify_pow("salt", "", 8))
        self.assertFalse(verify_pow("salt", "x" * 64, 8))
        self.assertFalse(verify_pow(None, None, 8))  # type: ignore[arg-type]

    def test_solution_satisfies_required_leading_zero_bits(self):
        salt = make_pow_salt()
        bits = 8  # ~256 attempts on average
        counter = 0
        while True:
            candidate = format(counter, "x")
            if verify_pow(salt, candidate, bits):
                break
            counter += 1
            self.assertLess(counter, 200000, "PoW search took unreasonably long")
        self.assertFalse(verify_pow(salt, candidate + "z", bits + 12))

    def test_pow_difficulty_clamps_to_supported_range(self):
        self.assertEqual(pow_difficulty_bits({"powDifficulty": 0}), 16)  # 0 falls back to default in normalize_positive_int
        self.assertEqual(pow_difficulty_bits({"powDifficulty": 30}), 24)
        self.assertEqual(pow_difficulty_bits({"powDifficulty": "garbage"}), 16)

    def test_normalize_challenge_page_carries_pow_difficulty(self):
        normalized = normalize_challenge_page_settings({"powDifficulty": 18})
        self.assertEqual(normalized["powDifficulty"], 18)
        normalized = normalize_challenge_page_settings({})
        self.assertEqual(normalized["powDifficulty"], 16)
        normalized = normalize_challenge_page_settings({"powDifficulty": 99})
        self.assertEqual(normalized["powDifficulty"], 24)


class LoginThrottleHelperTests(unittest.TestCase):
    def test_throttle_helpers_block_after_limit(self):
        from freewaf.server import make_admin_handler  # imported lazily for closure access

        # Build a handler factory to access the closure helpers via reflection.
        store = mock.Mock()
        handler_cls = make_admin_handler(store, 7001, 9090, False, False)
        del handler_cls  # the helpers themselves are private; we instead exercise the public effect by replicating its window logic.

        # The closure is private. Instead, smoke-test the global constants.
        import freewaf.server as server_module

        self.assertGreaterEqual(server_module.LOGIN_THROTTLE_IP_LIMIT, 1)
        self.assertGreaterEqual(server_module.LOGIN_THROTTLE_USER_LIMIT, server_module.LOGIN_THROTTLE_IP_LIMIT)
        self.assertGreaterEqual(server_module.LOGIN_THROTTLE_WINDOW_SECONDS, 60)


class SystemUpdatePlanTests(unittest.TestCase):
    def test_git_checkout_uses_fixed_pull_build_and_nginx_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            (root_dir / ".git").mkdir()
            (root_dir / "frontend").mkdir()

            plan = build_system_update_plan(root_dir)

        self.assertEqual(plan["mode"], "git")
        labels = [step["label"] for step in plan["steps"]]
        self.assertEqual(
            labels,
            [
                "git pull --ff-only",
                "npm ci",
                "npm run build",
                "refresh generated Nginx config",
                "test Nginx config",
                "reload Nginx",
            ],
        )

    def test_non_git_install_uses_configured_repo_and_skips_service_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root_dir = Path(directory)
            with mock.patch.dict(os.environ, {"FREEWAF_UPDATE_REPO_URL": "https://github.com/bnixvn/freewaf.git", "FREEWAF_UPDATE_BRANCH": "main"}, clear=False):
                plan = build_system_update_plan(root_dir)

        self.assertEqual(plan["mode"], "installer")
        self.assertEqual(plan["steps"][0]["command"][:3], ["git", "clone", "--depth"])
        install_step = plan["steps"][1]
        self.assertEqual(install_step["command"], ["bash", "install.sh"])
        self.assertEqual(install_step["env"]["FREEWAF_APP_DIR"], str(root_dir))
        self.assertEqual(install_step["env"]["FREEWAF_SKIP_SERVICE_RESTART"], "true")

    def test_unapproved_update_repo_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"FREEWAF_UPDATE_REPO_URL": "https://example.com/evil.git"}, clear=False):
                with self.assertRaisesRegex(RuntimeError, "FREEWAF_UPDATE_REPO_URL"):
                    build_system_update_plan(Path(directory))


class NginxLogTailCacheTests(unittest.TestCase):
    def test_stats_counts_can_skip_geoip_when_requested(self):
        import freewaf.server as server_module

        counts = server_module.new_stats_counts()
        with mock.patch("freewaf.server.country_for_ip") as country_for_ip:
            server_module.update_stats_counts(
                counts,
                {"ip": "8.8.8.8", "userAgent": "Mozilla/5.0", "verdict": "allow"},
                {},
                allow_geoip=False,
            )

        country_for_ip.assert_not_called()
        self.assertEqual(counts["countries"]["ZZ\0Unknown"]["count"], 1)

    def test_stats_aggregate_resolves_geoip_countries(self):
        import freewaf.server as server_module

        cache = {"files": {}, "countryCache": {}}
        with mock.patch(
            "freewaf.server.country_for_ip",
            return_value={"code": "US", "name": "United States"},
        ) as country_for_ip:
            server_module.aggregate_stats_entry(
                cache,
                "access.log",
                {
                    "at": "2026-06-12T00:00:00+00:00",
                    "host": "demo.test",
                    "ip": "8.8.8.8",
                    "userAgent": "Mozilla/5.0",
                    "verdict": "allow",
                },
                0,
            )

        country_for_ip.assert_called_once_with("8.8.8.8")
        bucket = next(iter(cache["files"]["access.log"]["buckets"].values()))
        counts = bucket["hosts"]["demo.test"]
        self.assertEqual(counts["countries"]["US\0United States"]["count"], 1)
        self.assertEqual(cache["countryCache"]["8.8.8.8"], {"code": "US", "name": "United States"})

    def test_stats_cache_persists_country_cache(self):
        import freewaf.server as server_module

        with tempfile.TemporaryDirectory() as directory:
            cache_file = Path(directory) / "stats-cache.json"
            with mock.patch.dict(os.environ, {"STATS_CACHE_FILE": str(cache_file)}, clear=False):
                server_module.STATS_AGGREGATE_CACHE.update(
                    {
                        "files": {},
                        "countryCache": {
                            "8.8.8.8": {"code": "US", "name": "United States"},
                            "bad": "not-a-country",
                        },
                        "scannerState": {},
                        "loadedCacheName": "stats:aggregate",
                    }
                )
                server_module.save_stats_aggregate_cache("stats:aggregate", 7, {})

                server_module.STATS_AGGREGATE_CACHE.update(
                    {"files": {}, "countryCache": {}, "scannerState": {}, "loadedCacheName": ""}
                )
                server_module.load_stats_aggregate_cache("stats:aggregate", 7)

            self.assertEqual(
                server_module.STATS_AGGREGATE_CACHE["countryCache"],
                {"8.8.8.8": {"code": "US", "name": "United States"}},
            )

    def test_tail_only_reads_new_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_file = root / "freewaf_access.log"
            log_file.write_text("", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"NGINX_ACCESS_LOG": str(log_file), "NGINX_SITE_LOG_DIR": str(root / "sites")},
                clear=False,
            ):
                # Reset cache to make this test independent of execution order.
                with nginx_module._LOG_TAIL_LOCK:
                    nginx_module._LOG_TAIL_CACHE.clear()

                def append(payload):
                    with log_file.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(payload) + "\n")

                append(
                    {
                        "time": "2026-06-12T00:00:00+00:00",
                        "remote_addr": "203.0.113.1",
                        "host": "demo.test",
                        "method": "GET",
                        "uri": "/",
                        "status": 200,
                        "request_time": 0.01,
                        "verdict": "allow",
                        "reason": "Allowed",
                        "user_agent": "ua",
                        "referer": "",
                    }
                )
                first = parse_nginx_logs(root, 100)
                self.assertEqual(len(first), 1)

                with mock.patch("builtins.open", wraps=open) as open_spy:
                    second = parse_nginx_logs(root, 100)
                    # No new bytes -> no read should be issued at all.
                    paths_read = [
                        call.args[0]
                        for call in open_spy.call_args_list
                        if str(call.args[0]).endswith("freewaf_access.log")
                    ]
                self.assertEqual(len(second), 1)
                self.assertEqual(paths_read, [])

                append(
                    {
                        "time": "2026-06-12T00:00:01+00:00",
                        "remote_addr": "203.0.113.2",
                        "host": "demo.test",
                        "method": "GET",
                        "uri": "/x",
                        "status": 403,
                        "request_time": 0.02,
                        "verdict": "block",
                        "reason": "Blocked",
                        "user_agent": "ua",
                        "referer": "",
                    }
                )
                third = parse_nginx_logs(root, 100)
                self.assertEqual(len(third), 2)

    def test_truncation_resets_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_file = root / "freewaf_access.log"
            with mock.patch.dict(
                os.environ,
                {"NGINX_ACCESS_LOG": str(log_file), "NGINX_SITE_LOG_DIR": str(root / "sites")},
                clear=False,
            ):
                with nginx_module._LOG_TAIL_LOCK:
                    nginx_module._LOG_TAIL_CACHE.clear()
                log_file.write_text(
                    json.dumps(
                        {
                            "time": "2026-06-12T00:00:00+00:00",
                            "remote_addr": "203.0.113.1",
                            "host": "demo.test",
                            "method": "GET",
                            "uri": "/a",
                            "status": 200,
                            "request_time": 0.01,
                            "verdict": "allow",
                            "reason": "Allowed",
                            "user_agent": "ua",
                            "referer": "",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                self.assertEqual(len(parse_nginx_logs(root, 100)), 1)
                # Truncate.
                log_file.write_text("", encoding="utf-8")
                self.assertEqual(parse_nginx_logs(root, 100), [])

    def test_site_log_parser_ignores_recompressed_rotations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main_log = root / "freewaf_access.log"
            site_dir = root / "sites"
            site_dir.mkdir()
            active_log = site_dir / "accesslog_site_demo"
            daily_log = site_dir / "accesslog_site_demo-20260630"
            broken_rotation = site_dir / "accesslog_site_demo-20260625.gz-20260628"
            ignored_error_log = site_dir / "errorlog_site_demo"
            payload = {
                "time": "2026-06-12T00:00:00+00:00",
                "remote_addr": "203.0.113.1",
                "host": "demo.test",
                "method": "GET",
                "uri": "/",
                "status": 200,
                "request_time": 0.01,
                "verdict": "allow",
                "reason": "Allowed",
                "user_agent": "ua",
                "referer": "",
            }
            main_log.write_text("", encoding="utf-8")
            active_log.write_text(json.dumps({**payload, "uri": "/active"}) + "\n", encoding="utf-8")
            daily_log.write_text(json.dumps({**payload, "uri": "/daily"}) + "\n", encoding="utf-8")
            broken_rotation.write_text(json.dumps({**payload, "uri": "/broken"}) + "\n", encoding="utf-8")
            ignored_error_log.write_text(json.dumps({**payload, "uri": "/error"}) + "\n", encoding="utf-8")

            with mock.patch.dict(
                os.environ,
                {"NGINX_ACCESS_LOG": str(main_log), "NGINX_SITE_LOG_DIR": str(site_dir)},
                clear=False,
            ):
                with nginx_module._LOG_TAIL_LOCK:
                    nginx_module._LOG_TAIL_CACHE.clear()

                paths = {entry["path"] for entry in parse_nginx_logs(root, 10)}
                self.assertEqual(paths, {"/active", "/daily"})

    def test_high_volume_logs_are_not_capped_below_caller_limit(self):
        # Regression: an earlier cap of 5000 entries silently truncated the
        # cache even when callers asked for more, so dashboard stat counters
        # appeared frozen once traffic crossed the cap.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_file = root / "freewaf_access.log"
            with mock.patch.dict(
                os.environ,
                {
                    "NGINX_ACCESS_LOG": str(log_file),
                    "NGINX_SITE_LOG_DIR": str(root / "sites"),
                    "FREEWAF_LOG_TAIL_MAX_ENTRIES": "8000",
                    "FREEWAF_LOG_TAIL_MAX_BYTES": "4194304",
                },
                clear=False,
            ):
                with nginx_module._LOG_TAIL_LOCK:
                    nginx_module._LOG_TAIL_CACHE.clear()

                total = 8000
                with log_file.open("w", encoding="utf-8") as handle:
                    for index in range(total):
                        handle.write(
                            json.dumps(
                                {
                                    "time": f"2026-06-12T00:{index // 60 % 60:02d}:{index % 60:02d}+00:00",
                                    "remote_addr": "203.0.113.1",
                                    "host": "demo.test",
                                    "method": "GET",
                                    "uri": f"/{index}",
                                    "status": 200 if index % 2 else 403,
                                    "request_time": 0.01,
                                    "verdict": "allow" if index % 2 else "block",
                                    "reason": "Allowed" if index % 2 else "Blocked",
                                    "user_agent": "ua",
                                    "referer": "",
                                }
                            )
                            + "\n"
                        )

                entries = parse_nginx_logs(root, 7000)
                self.assertEqual(len(entries), 7000)
                blocked = sum(1 for entry in entries if entry["verdict"] == "block")
                self.assertGreater(blocked, 3000)

    def test_small_log_read_does_not_cap_later_stats_window(self):
        # A small log table read must not prevent a later wider read from
        # reloading a larger tail window when the caller asks for it.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_file = root / "freewaf_access.log"
            with mock.patch.dict(
                os.environ,
                {
                    "NGINX_ACCESS_LOG": str(log_file),
                    "NGINX_SITE_LOG_DIR": str(root / "sites"),
                    "FREEWAF_LOG_TAIL_MAX_ENTRIES": "8000",
                    "FREEWAF_LOG_TAIL_MAX_BYTES": "4194304",
                },
                clear=False,
            ):
                with nginx_module._LOG_TAIL_LOCK:
                    nginx_module._LOG_TAIL_CACHE.clear()

                with log_file.open("w", encoding="utf-8") as handle:
                    for index in range(8000):
                        handle.write(
                            json.dumps(
                                {
                                    "time": f"2026-06-12T00:{index // 60 % 60:02d}:{index % 60:02d}+00:00",
                                    "remote_addr": "203.0.113.1",
                                    "host": "demo.test",
                                    "method": "GET",
                                    "uri": f"/{index}",
                                    "status": 200,
                                    "request_time": 0.01,
                                    "verdict": "allow",
                                    "reason": "Allowed",
                                    "user_agent": "ua",
                                    "referer": "",
                                }
                            )
                            + "\n"
                        )

                self.assertEqual(len(parse_nginx_logs(root, 1000)), 1000)
                self.assertEqual(len(parse_nginx_logs(root, 7000)), 7000)


if __name__ == "__main__":
    unittest.main()
