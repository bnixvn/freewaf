import json
import ssl
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from freewaf import mcp_agent

MCP_URL = "http://127.0.0.1:7001/mcp"


def make_ai_settings(**overrides) -> dict:
    settings = {
        "enabled": True,
        "detectionMode": "agent",
        "llmProvider": "openai_compatible",
        "llmBaseUrl": "https://api.example.test/v1",
        "llmApiKey": "sk-test",
        "llmModel": "test-model",
        "mcpToken": "test-token",
    }
    settings.update(overrides)
    return settings


def make_store(ai_settings: dict) -> mock.Mock:
    store = mock.Mock()
    store.get_state.return_value = {"settings": {"aiRules": ai_settings}}
    return store


class RunAgentPassSkipTests(unittest.TestCase):
    def test_skipped_when_not_enabled(self):
        result = mcp_agent.run_agent_pass(make_store(make_ai_settings(enabled=False)), Path("."), MCP_URL)
        self.assertIn("skipped", result)

    def test_skipped_when_statistical_mode(self):
        result = mcp_agent.run_agent_pass(make_store(make_ai_settings(detectionMode="statistical")), Path("."), MCP_URL)
        self.assertIn("skipped", result)

    def test_skipped_without_api_key(self):
        result = mcp_agent.run_agent_pass(make_store(make_ai_settings(llmApiKey="")), Path("."), MCP_URL)
        self.assertIn("skipped", result)

    def test_skipped_without_mcp_token(self):
        result = mcp_agent.run_agent_pass(make_store(make_ai_settings(mcpToken="")), Path("."), MCP_URL)
        self.assertIn("skipped", result)


class OpenAiLoopTests(unittest.TestCase):
    def test_tool_call_then_final_answer(self):
        store = make_store(make_ai_settings())
        first_response = {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_traffic_candidates", "arguments": "{}"}}],
        }
        second_response = {"role": "assistant", "content": "No action needed.", "tool_calls": []}

        with mock.patch.object(mcp_agent, "_call_openai_compatible", side_effect=[first_response, second_response]) as call_llm, \
                mock.patch.object(mcp_agent, "_call_mcp_tool", return_value={"candidatesByHost": {}}) as call_tool:
            result = mcp_agent.run_agent_pass(store, Path("."), MCP_URL)

        self.assertEqual(call_llm.call_count, 2)
        call_tool.assert_called_once_with(MCP_URL, "test-token", "get_traffic_candidates", {})
        self.assertEqual(result["steps"], 2)
        self.assertEqual(result["finalMessage"], "No action needed.")
        self.assertEqual(result["actions"], [])

    def test_write_tool_call_is_recorded_as_an_action(self):
        store = make_store(make_ai_settings())
        first_response = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "create_block_rule", "arguments": json.dumps({"siteId": "*", "pattern": "xoilac"})},
                }
            ],
        }
        second_response = {"role": "assistant", "content": "Blocked xoilac.", "tool_calls": []}

        with mock.patch.object(mcp_agent, "_call_openai_compatible", side_effect=[first_response, second_response]), \
                mock.patch.object(mcp_agent, "_call_mcp_tool", return_value={"created": True, "rule": {"id": "rule-1"}}):
            result = mcp_agent.run_agent_pass(store, Path("."), MCP_URL)

        self.assertEqual(len(result["actions"]), 1)
        self.assertEqual(result["actions"][0]["tool"], "create_block_rule")
        self.assertEqual(result["actions"][0]["result"]["rule"]["id"], "rule-1")

    def test_unknown_tool_call_from_model_does_not_crash(self):
        store = make_store(make_ai_settings())
        first_response = {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "delete_everything", "arguments": "{}"}}],
        }
        second_response = {"role": "assistant", "content": "Never mind.", "tool_calls": []}

        with mock.patch.object(mcp_agent, "_call_openai_compatible", side_effect=[first_response, second_response]) as call_llm, \
                mock.patch.object(mcp_agent, "_call_mcp_tool") as call_tool:
            result = mcp_agent.run_agent_pass(store, Path("."), MCP_URL)

        call_tool.assert_not_called()
        self.assertEqual(result["actions"], [])
        self.assertEqual(call_llm.call_count, 2)

    def test_step_limit_stops_the_loop(self):
        store = make_store(make_ai_settings())
        looping_response = {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_traffic_candidates", "arguments": "{}"}}],
        }

        with mock.patch.object(mcp_agent, "_call_openai_compatible", return_value=looping_response) as call_llm, \
                mock.patch.object(mcp_agent, "_call_mcp_tool", return_value={}):
            result = mcp_agent.run_agent_pass(store, Path("."), MCP_URL)

        self.assertEqual(call_llm.call_count, mcp_agent.MAX_AGENT_STEPS)
        self.assertEqual(result["steps"], mcp_agent.MAX_AGENT_STEPS)

    def test_llm_failure_is_caught_gracefully(self):
        store = make_store(make_ai_settings())
        with mock.patch.object(mcp_agent, "_call_openai_compatible", side_effect=OSError("boom")):
            result = mcp_agent.run_agent_pass(store, Path("."), MCP_URL)
        self.assertIn("skipped", result)


class AnthropicLoopTests(unittest.TestCase):
    def test_tool_use_then_final_answer(self):
        store = make_store(make_ai_settings(llmProvider="anthropic"))
        first_response = {
            "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "id": "toolu_1", "name": "get_traffic_candidates", "input": {}}],
        }
        second_response = {"stop_reason": "end_turn", "content": [{"type": "text", "text": "Nothing suspicious."}]}

        with mock.patch.object(mcp_agent, "_call_anthropic", side_effect=[first_response, second_response]) as call_llm, \
                mock.patch.object(mcp_agent, "_call_mcp_tool", return_value={"candidatesByHost": {}}):
            result = mcp_agent.run_agent_pass(store, Path("."), MCP_URL)

        self.assertEqual(call_llm.call_count, 2)
        self.assertEqual(result["finalMessage"], "Nothing suspicious.")


class DispatchToolCallTests(unittest.TestCase):
    def test_unknown_tool_returns_error_result_without_calling_mcp(self):
        actions = []
        with mock.patch.object(mcp_agent, "_call_mcp_tool") as call_tool:
            result = mcp_agent._dispatch_tool_call(MCP_URL, "token", "not_a_tool", {}, actions)
        call_tool.assert_not_called()
        self.assertIn("error", result)
        self.assertEqual(actions, [])

    def test_mcp_call_failure_is_caught_and_returned_as_error(self):
        actions = []
        with mock.patch.object(mcp_agent, "_call_mcp_tool", side_effect=OSError("connection refused")):
            result = mcp_agent._dispatch_tool_call(MCP_URL, "token", "list_sites", {}, actions)
        self.assertIn("error", result)


class SslContextForTests(unittest.TestCase):
    def test_loopback_hosts_get_a_verification_disabled_context(self):
        for url in ("https://127.0.0.1:7001/mcp", "https://localhost:7001/mcp"):
            context = mcp_agent._ssl_context_for(url)
            self.assertIsNotNone(context)
            self.assertFalse(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_NONE)

    def test_non_loopback_host_keeps_default_verification(self):
        self.assertIsNone(mcp_agent._ssl_context_for("https://waf.example.test/mcp"))

    def test_plain_http_loopback_still_gets_a_context_harmlessly(self):
        # urlopen ignores `context` for plain http:// URLs, so it's fine
        # (and simpler) to always compute one for a loopback host.
        self.assertIsNotNone(mcp_agent._ssl_context_for("http://127.0.0.1:7001/mcp"))


class CallMcpToolTests(unittest.TestCase):
    def _mock_response(self, body: dict):
        fake = mock.MagicMock()
        fake.read.return_value = json.dumps(body).encode("utf-8")
        fake.__enter__.return_value = fake
        return fake

    def test_disables_certificate_verification_for_the_loopback_mcp_url(self):
        fake_response = self._mock_response({"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": {}}})
        https_loopback_url = "https://127.0.0.1:7001/mcp"
        with mock.patch("urllib.request.urlopen", return_value=fake_response) as urlopen:
            mcp_agent._call_mcp_tool(https_loopback_url, "token", "list_sites", {})
        context = urlopen.call_args.kwargs["context"]
        self.assertIsNotNone(context)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)

    def test_unwraps_structured_content(self):
        fake_response = self._mock_response({"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": {"ok": True}}})
        with mock.patch("urllib.request.urlopen", return_value=fake_response):
            result = mcp_agent._call_mcp_tool(MCP_URL, "token", "list_sites", {})
        self.assertEqual(result, {"ok": True})

    def test_surfaces_jsonrpc_error(self):
        fake_response = self._mock_response({"jsonrpc": "2.0", "id": 1, "error": {"message": "bad token"}})
        with mock.patch("urllib.request.urlopen", return_value=fake_response):
            result = mcp_agent._call_mcp_tool(MCP_URL, "token", "list_sites", {})
        self.assertEqual(result, {"error": "bad token"})

    def test_falls_back_to_parsing_text_content_block(self):
        fake_response = self._mock_response(
            {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": json.dumps({"sites": []})}]}}
        )
        with mock.patch("urllib.request.urlopen", return_value=fake_response):
            result = mcp_agent._call_mcp_tool(MCP_URL, "token", "list_sites", {})
        self.assertEqual(result, {"sites": []})


if __name__ == "__main__":
    unittest.main()
