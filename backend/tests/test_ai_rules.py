import json
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf import ai_rules
from freewaf.store import Store


def make_settings(**overrides) -> dict:
    settings = {
        "enabled": True,
        "checkIntervalMinutes": 10,
        "lookbackMinutes": 15,
        "minDistinctIps": 5,
        "minDistinctUris": 1,
        "minRequests": 10,
        "autoBlockConfidence": 0.75,
        "maxRulesPerHour": 5,
        "llmEnabled": False,
        "llmProvider": "openai_compatible",
        "llmBaseUrl": "https://api.openai.com/v1",
        "llmApiKey": "",
        "llmModel": "gpt-4o-mini",
    }
    settings.update(overrides)
    return settings


def make_entry(uri: str, ip: str, host: str = "zamora.vn", when: datetime | None = None) -> dict:
    at = when or datetime.now(timezone.utc)
    return {"host": host, "path": uri, "ip": ip, "at": at.strftime("%Y-%m-%dT%H:%M:%SZ")}


def make_candidate(**overrides) -> dict:
    candidate = {
        "token": "xoilac",
        "distinctIps": 12,
        "distinctUris": 24,
        "requests": 24,
        "sampleUris": ["/net0/xoilac-tv-truc-tiep-bong-da-0/"],
        "uriCoverage": 1.0,
    }
    candidate.update(overrides)
    return candidate


def spam_entries(count_ips: int = 12, host: str = "zamora.vn") -> list[dict]:
    entries = []
    for i in range(count_ips):
        ip = f"203.0.113.{i + 1}"
        entries.append(make_entry(f"/net{i}/Xoilac-tv-truc-tiep-bong-da-{i}/", ip, host))
        entries.append(make_entry(f"/web-lnw{i}/xoilac-tv-xem-{i}/", ip, host))
    return entries


def fixed_url_flood_entries(count_ips: int = 60, host: str = "zamora.vn") -> list[dict]:
    """Reproduces a shape observed live in production: hundreds of distinct
    IPs repeatedly hitting one single, never-rotating URL - a classic HTTP
    flood, distinct from spam_entries()'s rotating-URL campaign shape.
    Default count_ips gives the ip/volume confidence dimensions the same
    kind of comfortable margin over threshold the real incident had (the
    live flood was ~117x minDistinctIps); distinctUris is structurally
    stuck at exactly minDistinctUris(=1) for this shape, capping its own
    contribution to confidence, so ip/volume need real headroom to clear
    autoBlockConfidence on their own.
    """
    uri = "/net649/Xoilac-tv-truc-tiep-bong-da-xoilactv-tieng-viet-90phut/"
    return [make_entry(uri, f"198.51.100.{i + 1}", host) for i in range(count_ips)]


class TokenizeTests(unittest.TestCase):
    def test_drops_short_and_stopword_tokens(self):
        tokens = ai_rules._tokenize_uri("/wp-content/uploads/2024/xoilac-tv/index.php")
        self.assertIn("xoilac", tokens)
        self.assertNotIn("wp", tokens)  # too short
        self.assertNotIn("uploads", tokens)  # stopword
        self.assertNotIn("index", tokens)  # stopword
        self.assertNotIn("php", tokens)  # stopword

    def test_digits_do_not_leak_into_tokens(self):
        tokens = ai_rules._tokenize_uri("/net649/xoilactv90phut/")
        self.assertIn("xoilactv", tokens)
        for token in tokens:
            self.assertFalse(any(ch.isdigit() for ch in token))


class FindMarkerCandidatesTests(unittest.TestCase):
    def test_finds_rotating_campaign_marker(self):
        settings = make_settings()
        entries = spam_entries(count_ips=12)
        candidates = ai_rules.find_marker_candidates(entries, settings)
        tokens = {c["token"] for c in candidates}
        self.assertIn("xoilac", tokens)
        marker = next(c for c in candidates if c["token"] == "xoilac")
        self.assertEqual(marker["distinctIps"], 12)
        self.assertGreaterEqual(marker["distinctUris"], 12)

    def test_below_threshold_is_not_a_candidate(self):
        settings = make_settings(minDistinctIps=50)
        entries = spam_entries(count_ips=12)
        candidates = ai_rules.find_marker_candidates(entries, settings)
        self.assertEqual(candidates, [])

    def test_single_fixed_url_flood_is_detected_without_uri_rotation(self):
        # minDistinctUris defaults to 1 - a flood that never varies its URL
        # at all must still qualify, not just a rotating-URL campaign.
        settings = make_settings()
        entries = fixed_url_flood_entries(count_ips=20)
        candidates = ai_rules.find_marker_candidates(entries, settings)
        tokens = {c["token"] for c in candidates}
        self.assertIn("xoilac", tokens)
        marker = next(c for c in candidates if c["token"] == "xoilac")
        self.assertEqual(marker["distinctUris"], 1)
        self.assertEqual(marker["distinctIps"], 20)

    def test_single_fixed_url_flood_is_rejected_when_uri_rotation_required(self):
        settings = make_settings(minDistinctUris=3)
        entries = fixed_url_flood_entries(count_ips=20)
        candidates = ai_rules.find_marker_candidates(entries, settings)
        self.assertEqual(candidates, [])

    def test_dominant_flood_is_still_detected_despite_full_coverage(self):
        # A real campaign can be the overwhelming majority of a host's
        # traffic during the lookback window - coverage alone must not
        # suppress it, or the detector would miss the exact case it exists
        # to catch (see spam_entries(): every URI contains "xoilac").
        settings = make_settings()
        candidates = ai_rules.find_marker_candidates(spam_entries(count_ips=12), settings)
        tokens = {c["token"] for c in candidates}
        self.assertIn("xoilac", tokens)

    def test_extreme_uniform_coverage_over_a_large_sample_is_suppressed(self):
        # Every single distinct URI (60 of them) containing the same word
        # is a template/vocabulary artifact, not a rotating-spam signature.
        settings = make_settings(minDistinctIps=2, minDistinctUris=2, minRequests=2)
        entries = []
        for i in range(60):
            entries.append(make_entry(f"/shopname/product-{i}/", f"198.51.100.{i % 20}"))
        candidates = ai_rules.find_marker_candidates(entries, settings)
        tokens = {c["token"] for c in candidates}
        self.assertNotIn("shopname", tokens)


class ConfidenceTests(unittest.TestCase):
    def test_statistical_confidence_scales_with_thresholds(self):
        settings = make_settings(minDistinctIps=5, minDistinctUris=3, minRequests=10)
        weak = {"distinctIps": 5, "distinctUris": 3, "requests": 10}
        strong = {"distinctIps": 20, "distinctUris": 20, "requests": 100}
        weak_score = ai_rules.statistical_confidence(weak, settings)
        strong_score = ai_rules.statistical_confidence(strong, settings)
        self.assertLess(weak_score, strong_score)
        self.assertLessEqual(strong_score, 1.0)
        self.assertGreaterEqual(weak_score, 0.0)

    def test_combined_confidence_falls_back_to_statistical_without_llm(self):
        candidate = {"statisticalConfidence": 0.8}
        self.assertEqual(ai_rules.combined_confidence(candidate), 0.8)

    def test_llm_veto_forces_zero_confidence(self):
        candidate = {"statisticalConfidence": 0.95, "llmVeto": True}
        self.assertEqual(ai_rules.combined_confidence(candidate), 0.0)

    def test_llm_confidence_is_averaged_not_overriding(self):
        candidate = {"statisticalConfidence": 1.0, "llmConfidence": 0.5}
        self.assertEqual(ai_rules.combined_confidence(candidate), 0.75)


class DedupeAndRateLimitTests(unittest.TestCase):
    def test_already_covered_by_existing_block_rule(self):
        rules = [{"enabled": True, "action": "block", "siteId": "*", "pattern": "xoilac"}]
        self.assertTrue(ai_rules.already_covered("xoilac", "site-1", rules))
        self.assertTrue(ai_rules.already_covered("xoilactv", "site-1", rules))
        self.assertFalse(ai_rules.already_covered("otherspam", "site-1", rules))

    def test_disabled_rule_does_not_count_as_covered(self):
        rules = [{"enabled": False, "action": "block", "siteId": "*", "pattern": "xoilac"}]
        self.assertFalse(ai_rules.already_covered("xoilac", "site-1", rules))

    def test_recent_ai_rule_count_only_counts_this_site_within_window(self):
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        stale = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        rules = [
            {"name": "AI: spamone", "siteId": "site-1", "createdAt": recent},
            {"name": "AI: spamtwo", "siteId": "site-1", "createdAt": stale},
            {"name": "AI: spamthree", "siteId": "site-2", "createdAt": recent},
            {"name": "Manual rule", "siteId": "site-1", "createdAt": recent},
        ]
        self.assertEqual(ai_rules.recent_ai_rule_count("site-1", rules), 1)
        self.assertEqual(ai_rules.recent_ai_rule_count("site-2", rules), 1)


class BuildRulePayloadTests(unittest.TestCase):
    def test_payload_shape_is_valid_for_upsert_rule(self):
        site = {"id": "site-1", "name": "Zamora", "hostnames": ["zamora.vn"]}
        candidate = {"token": "xoilac", "distinctIps": 12, "distinctUris": 15, "requests": 300}
        payload = ai_rules.build_rule_payload(site, candidate, 0.9)
        self.assertEqual(payload["name"], "AI: xoilac")
        self.assertEqual(payload["pattern"], "xoilac")
        self.assertEqual(payload["siteId"], "site-1")
        self.assertEqual(payload["action"], "block")
        self.assertEqual(payload["matcher"], "contains")
        self.assertEqual(payload["target"], "url")
        self.assertEqual(payload["severity"], "high")
        self.assertIn("xoilac", payload["description"])


class RefineWithLlmTests(unittest.TestCase):
    def test_disabled_llm_returns_candidate_unchanged(self):
        candidate = {"token": "xoilac"}
        settings = make_settings(llmEnabled=False)
        result = ai_rules.refine_with_llm({"hostnames": ["x"]}, candidate, settings)
        self.assertEqual(result, candidate)

    def test_missing_api_key_returns_candidate_unchanged(self):
        candidate = {"token": "xoilac"}
        settings = make_settings(llmEnabled=True, llmApiKey="")
        result = ai_rules.refine_with_llm({"hostnames": ["x"]}, candidate, settings)
        self.assertEqual(result, candidate)

    def test_network_failure_falls_back_gracefully(self):
        candidate = make_candidate()
        settings = make_settings(llmEnabled=True, llmApiKey="sk-test")
        with mock.patch.object(ai_rules, "_call_openai_compatible", side_effect=OSError("boom")):
            result = ai_rules.refine_with_llm({"hostnames": ["x"]}, candidate, settings)
        self.assertEqual(result["token"], "xoilac")
        self.assertIn("llmError", result)

    def test_llm_veto_sets_flag_and_note(self):
        candidate = make_candidate()
        settings = make_settings(llmEnabled=True, llmApiKey="sk-test")
        reply = json.dumps({"malicious": False, "confidence": 0.1, "note": "looks like normal traffic"})
        with mock.patch.object(ai_rules, "_call_openai_compatible", return_value=reply):
            result = ai_rules.refine_with_llm({"hostnames": ["x"]}, candidate, settings)
        self.assertTrue(result["llmVeto"])
        self.assertIn("normal traffic", result["llmNote"])

    def test_llm_confirms_and_supplies_confidence(self):
        candidate = make_candidate()
        settings = make_settings(llmEnabled=True, llmApiKey="sk-test")
        reply = json.dumps({"malicious": True, "confidence": 0.95, "pattern": "xoilac", "note": "botnet"})
        with mock.patch.object(ai_rules, "_call_openai_compatible", return_value=reply):
            result = ai_rules.refine_with_llm({"hostnames": ["x"]}, candidate, settings)
        self.assertNotIn("llmVeto", result)
        self.assertEqual(result["llmConfidence"], 0.95)
        self.assertEqual(result["token"], "xoilac")

    def test_llm_reply_with_extra_text_around_json_is_still_parsed(self):
        candidate = make_candidate()
        settings = make_settings(llmEnabled=True, llmApiKey="sk-test")
        reply = 'Sure, here is my answer:\n{"malicious": true, "confidence": 0.8, "note": "spam"}\nHope that helps!'
        with mock.patch.object(ai_rules, "_call_openai_compatible", return_value=reply):
            result = ai_rules.refine_with_llm({"hostnames": ["x"]}, candidate, settings)
        self.assertEqual(result["llmConfidence"], 0.8)

    def test_llm_suggested_pattern_with_bad_characters_is_ignored(self):
        candidate = make_candidate()
        settings = make_settings(llmEnabled=True, llmApiKey="sk-test")
        reply = json.dumps({"malicious": True, "confidence": 0.8, "pattern": ".*evil(", "note": "spam"})
        with mock.patch.object(ai_rules, "_call_openai_compatible", return_value=reply):
            result = ai_rules.refine_with_llm({"hostnames": ["x"]}, candidate, settings)
        # An unsafe/non-token pattern suggestion must not replace the
        # original statistically-derived token.
        self.assertEqual(result["token"], "xoilac")

    def test_anthropic_provider_is_selected_by_setting(self):
        candidate = make_candidate()
        settings = make_settings(llmEnabled=True, llmApiKey="sk-test", llmProvider="anthropic")
        reply = json.dumps({"malicious": True, "confidence": 0.8, "note": "spam"})
        with mock.patch.object(ai_rules, "_call_anthropic", return_value=reply) as anthropic_mock, \
             mock.patch.object(ai_rules, "_call_openai_compatible") as openai_mock:
            ai_rules.refine_with_llm({"hostnames": ["x"]}, candidate, settings)
        anthropic_mock.assert_called_once()
        openai_mock.assert_not_called()


class RunPassEndToEndTests(unittest.TestCase):
    def _make_store(self, directory: str) -> Store:
        store = Store(Path(directory) / "state.json")
        store.init()
        return store

    def test_disabled_globally_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            store.update_settings({"aiRules": make_settings(enabled=False)})
            for entry in spam_entries(12):
                store.add_log(entry)
            created = ai_rules.run_pass(store, Path(directory))
            self.assertEqual(created, [])
            self.assertEqual(store.get_state()["rules"], store.get_state()["rules"])
            self.assertFalse(any(r["name"].startswith("AI: ") for r in store.get_state()["rules"]))

    def test_high_confidence_campaign_creates_block_rule_automatically(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            store.update_settings({"aiRules": make_settings(enabled=True, llmEnabled=False)})
            store.upsert_site(
                {
                    "name": "Zamora",
                    "hostnames": ["zamora.vn"],
                    "origin": "http://127.0.0.1:9090",
                    "listen": 8080,
                    "enabled": True,
                }
            )
            for entry in spam_entries(count_ips=20):
                store.add_log(entry)

            created = ai_rules.run_pass(store, Path(directory))

            self.assertEqual(len(created), 1)
            self.assertEqual(created[0]["token"], "xoilac")
            rules = store.get_state()["rules"]
            ai_created = [r for r in rules if r["name"].startswith("AI: ")]
            self.assertEqual(len(ai_created), 1)
            self.assertEqual(ai_created[0]["pattern"], "xoilac")
            self.assertEqual(ai_created[0]["action"], "block")

    def test_single_fixed_url_flood_creates_block_rule_automatically(self):
        # End-to-end version of the production incident that motivated
        # minDistinctUris defaulting to 1: a flood on one never-rotating
        # URL must still result in an auto-created block rule.
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            store.update_settings({"aiRules": make_settings(enabled=True, llmEnabled=False)})
            for entry in fixed_url_flood_entries():
                store.add_log(entry)

            created = ai_rules.run_pass(store, Path(directory))

            self.assertEqual(len(created), 1)
            # Several tied candidate tokens ("xoilac", "xoilactv", "tiep", ...)
            # all describe the same flood - the longest wins the tiebreak.
            self.assertEqual(created[0]["token"], "xoilactv")
            ai_created = [r for r in store.get_state()["rules"] if r["name"].startswith("AI: ")]
            self.assertEqual(ai_created[0]["action"], "block")

    def test_second_pass_does_not_duplicate_the_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            store.update_settings({"aiRules": make_settings(enabled=True, llmEnabled=False)})
            for entry in spam_entries(count_ips=20):
                store.add_log(entry)

            first = ai_rules.run_pass(store, Path(directory))
            second = ai_rules.run_pass(store, Path(directory))

            self.assertEqual(len(first), 1)
            self.assertEqual(second, [])
            ai_created = [r for r in store.get_state()["rules"] if r["name"].startswith("AI: ")]
            self.assertEqual(len(ai_created), 1)

    def test_low_volume_traffic_does_not_create_a_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            store.update_settings({"aiRules": make_settings(enabled=True, llmEnabled=False)})
            for entry in spam_entries(count_ips=2):
                store.add_log(entry)

            created = ai_rules.run_pass(store, Path(directory))
            self.assertEqual(created, [])

    def test_max_rules_per_hour_caps_creation_across_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            store.update_settings(
                {"aiRules": make_settings(enabled=True, llmEnabled=False, maxRulesPerHour=1, minDistinctIps=5, minDistinctUris=2, minRequests=5)}
            )
            # Two independent single-host campaigns sharing one siteId ("*",
            # since neither host is registered as a site) - the second must
            # be skipped once the per-site hourly cap is reached.
            entries = []
            for i in range(10):
                ip = f"203.0.113.{i + 1}"
                entries.append(make_entry(f"/campaign-a-{i}/marker-alpha-{i}/", ip, host="a.example.test"))
            for i in range(10):
                ip = f"198.51.100.{i + 1}"
                entries.append(make_entry(f"/campaign-b-{i}/marker-beta-{i}/", ip, host="a.example.test"))
            for entry in entries:
                store.add_log(entry)

            created = ai_rules.run_pass(store, Path(directory))
            self.assertEqual(len(created), 1)


if __name__ == "__main__":
    unittest.main()
