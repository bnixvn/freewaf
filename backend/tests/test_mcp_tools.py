import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf import ai_rules, mcp_tools
from freewaf.store import Store


def make_entry(uri: str, ip: str, host: str = "zamora.vn") -> dict:
    return {"host": host, "path": uri, "ip": ip, "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


class McpToolsTests(unittest.TestCase):
    def _make_store(self, directory: str) -> Store:
        store = Store(Path(directory) / "state.json")
        store.init()
        return store

    def test_list_sites_and_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            store.upsert_site(
                {"name": "Zamora", "hostnames": ["zamora.vn"], "origin": "http://127.0.0.1:9090", "listen": 8080, "enabled": True}
            )
            sites = mcp_tools.call_tool(store, Path(directory), "list_sites", {})
            names = {s["name"] for s in sites["sites"]}
            self.assertIn("Zamora", names)

            rules = mcp_tools.call_tool(store, Path(directory), "list_rules", {})
            self.assertIsInstance(rules["rules"], list)

    def test_get_traffic_candidates_reuses_statistical_detector(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            store.update_settings({"aiRules": {"minRequests": 10}})
            for i in range(12):
                ip = f"203.0.113.{i + 1}"
                store.add_log(make_entry(f"/net{i}/Xoilac-tv-truc-tiep-bong-da-{i}/", ip))
                store.add_log(make_entry(f"/web-lnw{i}/xoilac-tv-xem-{i}/", ip))

            result = mcp_tools.call_tool(store, Path(directory), "get_traffic_candidates", {})
            tokens = {c["token"] for c in result["candidatesByHost"].get("zamora.vn", [])}
            self.assertIn("xoilac", tokens)

    def test_get_recent_logs_respects_host_filter_and_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            for i in range(5):
                store.add_log(make_entry(f"/a{i}/", f"203.0.113.{i}", host="a.example.test"))
            for i in range(5):
                store.add_log(make_entry(f"/b{i}/", f"198.51.100.{i}", host="b.example.test"))

            result = mcp_tools.call_tool(store, Path(directory), "get_recent_logs", {"host": "a.example.test", "limit": 2})
            self.assertEqual(result["totalMatched"], 5)
            self.assertEqual(len(result["logs"]), 2)
            self.assertTrue(all(l["host"] == "a.example.test" for l in result["logs"]))

    def test_create_block_rule_happy_path(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            result = mcp_tools.call_tool(
                store,
                Path(directory),
                "create_block_rule",
                {"siteId": "*", "pattern": "xoilac", "description": "flood observed"},
            )
            self.assertTrue(result["created"])
            self.assertEqual(result["rule"]["pattern"], "xoilac")
            self.assertTrue(result["rule"]["name"].startswith(ai_rules.AI_RULE_NAME_PREFIX))
            self.assertIn("flood observed", result["rule"]["description"])

    def test_create_block_rule_requires_pattern(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            result = mcp_tools.call_tool(store, Path(directory), "create_block_rule", {"siteId": "*", "pattern": ""})
            self.assertFalse(result["created"])
            self.assertIn("pattern", result["reason"])

    def test_create_block_rule_declines_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            store.upsert_rule({"name": "Manual", "siteId": "*", "matcher": "contains", "target": "url", "pattern": "xoilac", "action": "block"})
            result = mcp_tools.call_tool(store, Path(directory), "create_block_rule", {"siteId": "*", "pattern": "xoilactv"})
            self.assertFalse(result["created"])
            self.assertIn("already covers", result["reason"])

    def test_create_block_rule_respects_max_rules_per_hour(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            store.update_settings({"aiRules": {"maxRulesPerHour": 1}})
            first = mcp_tools.call_tool(store, Path(directory), "create_block_rule", {"siteId": "*", "pattern": "spamone"})
            second = mcp_tools.call_tool(store, Path(directory), "create_block_rule", {"siteId": "*", "pattern": "spamtwo"})
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertIn("maxRulesPerHour", second["reason"])

    def test_disable_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            created = mcp_tools.call_tool(store, Path(directory), "create_block_rule", {"siteId": "*", "pattern": "spam"})
            rule_id = created["rule"]["id"]

            result = mcp_tools.call_tool(store, Path(directory), "disable_rule", {"ruleId": rule_id})
            self.assertTrue(result["disabled"])
            self.assertFalse(result["rule"]["enabled"])

    def test_disable_rule_missing_id(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            result = mcp_tools.call_tool(store, Path(directory), "disable_rule", {"ruleId": "does-not-exist"})
            self.assertFalse(result["disabled"])
            self.assertEqual(result["reason"], "rule not found")

    def test_call_tool_unknown_name_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._make_store(directory)
            with self.assertRaises(KeyError):
                mcp_tools.call_tool(store, Path(directory), "not_a_real_tool", {})

    def test_every_tool_has_a_description_and_schema(self):
        for name, spec in mcp_tools.TOOLS.items():
            self.assertTrue(spec["description"])
            self.assertEqual(spec["inputSchema"]["type"], "object")


if __name__ == "__main__":
    unittest.main()
