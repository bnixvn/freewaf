"""Autonomous agent loop for AI-rules "agent" detection mode.

Where ai_rules.py's statistical pipeline is a fixed score-then-threshold
recipe (and its optional llmEnabled step is one prompt, one JSON reply,
done), this is a real multi-step tool-using agent: it gets read tools
(traffic candidates, raw logs, sites, rules) and write tools (create/
disable a rule) over MCP, and decides for itself what to look at and
whether to act - see mcp_tools.py for the tool surface itself.

The agent talks to that tool surface over real HTTP (POST to /mcp on this
same FreeWAF instance by default), not an in-process function call, so the
same tool contract also works for a client - human or agent - running
anywhere else that can reach this instance's admin port.

Two LLM wire protocols are implemented, chosen by aiRules.llmProvider:
OpenAI-compatible chat-completions tool calling, and Anthropic's Messages
API tool use. Both are plain stdlib urllib - no SDK dependency, matching
ai_rules.py's LLM client. Any failure at any point (network, malformed
response, an unknown tool the model hallucinated) ends the pass early and
returns what was accomplished so far - it must never crash the worker
loop, and a failed/partial pass is equivalent to the statistical detector
finding nothing this cycle, not a safety problem.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from . import mcp_tools
from .store import Store

MAX_AGENT_STEPS = 6
_HTTP_TIMEOUT = 30

# The default self-referential MCP URL (see start_ai_rule_worker() in
# server.py) points at 127.0.0.1, but the admin panel's HTTPS certificate
# - if one is configured - is issued for the panel's real hostname, not
# the loopback IP, so standard hostname verification always fails here.
# nginx has the exact same problem proxying to this same URL and solves it
# the same way (proxy_ssl_verify off; - see challenge_backend_url() in
# nginx.py); loopback traffic to our own process doesn't need it. A
# non-loopback mcp_base_url (a future remote agent target) keeps full
# verification.
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _ssl_context_for(url: str) -> ssl.SSLContext | None:
    if urlparse(url).hostname not in _LOOPBACK_HOSTS:
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

_SYSTEM_PROMPT = (
    "You are the automated security analyst for a web application firewall (FreeWAF). "
    "You have tools to inspect recent traffic and to create or disable blocking rules. "
    "Each run: survey recent traffic across sites (get_traffic_candidates is the fastest "
    "starting point; use get_recent_logs when you need more detail), decide whether any "
    "pattern is a real spam/bot/DDoS campaign worth blocking, and call create_block_rule "
    "for anything you are confident about. Do not block on ambiguous or ordinary traffic - "
    "when in doubt, do nothing. Prefer a specific, safe substring pattern over something "
    "broad enough to affect unrelated legitimate requests. If you disable or create a rule "
    "and then realize it was wrong, use disable_rule to undo it. Keep investigating only as "
    "long as it's useful, then stop - you do not need to use every tool every run."
)


def _openai_tool_schemas() -> list[dict]:
    return [
        {
            "type": "function",
            "function": {"name": name, "description": spec["description"], "parameters": spec["inputSchema"]},
        }
        for name, spec in mcp_tools.TOOLS.items()
    ]


def _anthropic_tool_schemas() -> list[dict]:
    return [
        {"name": name, "description": spec["description"], "input_schema": spec["inputSchema"]}
        for name, spec in mcp_tools.TOOLS.items()
    ]


def _call_mcp_tool(mcp_base_url: str, mcp_token: str, name: str, arguments: dict) -> dict:
    url = mcp_base_url.rstrip("/")
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}}
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {mcp_token}"},
    )
    with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT, context=_ssl_context_for(url)) as response:
        parsed = json.loads(response.read().decode("utf-8"))
    if parsed.get("error"):
        return {"error": parsed["error"].get("message") or "tool call failed"}
    result = parsed.get("result") or {}
    if "structuredContent" in result:
        return result["structuredContent"]
    text_blocks = [item.get("text", "") for item in result.get("content", []) if item.get("type") == "text"]
    if text_blocks:
        try:
            return json.loads(text_blocks[0])
        except json.JSONDecodeError:
            return {"text": text_blocks[0]}
    return result


def _call_openai_compatible(base_url: str, api_key: str, model: str, messages: list[dict]) -> dict:
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps(
        {
            "model": model,
            "messages": messages,
            "tools": _openai_tool_schemas(),
            "tool_choice": "auto",
            "temperature": 0,
            # Always explicit: "OpenAI-compatible" endpoints disagree on the
            # default. Some routers stream unless told otherwise and answer
            # with text/event-stream, which this client cannot parse - it
            # reads one JSON document. Leaving it unset made the provider's
            # default decide whether the feature worked at all.
            "stream": False,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    )
    with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT) as response:
        parsed = json.loads(response.read().decode("utf-8"))
    return parsed["choices"][0]["message"]


def _run_openai_loop(ai_settings: dict, mcp_base_url: str, mcp_token: str) -> dict:
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": "Analyze recent traffic across all sites and take any warranted action."},
    ]
    actions = []
    for step in range(MAX_AGENT_STEPS):
        assistant_message = _call_openai_compatible(
            ai_settings["llmBaseUrl"], ai_settings["llmApiKey"], ai_settings["llmModel"], messages
        )
        tool_calls = assistant_message.get("tool_calls") or []
        messages.append(
            {"role": "assistant", "content": assistant_message.get("content"), "tool_calls": tool_calls or None}
        )
        if not tool_calls:
            return {"steps": step + 1, "finalMessage": assistant_message.get("content") or "", "actions": actions}

        for call in tool_calls:
            function = call.get("function") or {}
            name = function.get("name") or ""
            try:
                arguments = json.loads(function.get("arguments") or "{}")
            except json.JSONDecodeError:
                arguments = {}
            result = _dispatch_tool_call(mcp_base_url, mcp_token, name, arguments, actions)
            messages.append({"role": "tool", "tool_call_id": call.get("id") or "", "content": json.dumps(result)})

    return {"steps": MAX_AGENT_STEPS, "finalMessage": "Stopped: reached the step limit.", "actions": actions}


def _call_anthropic(base_url: str, api_key: str, model: str, messages: list[dict]) -> dict:
    url = base_url.rstrip("/") + "/messages"
    body = json.dumps(
        {
            "model": model,
            "max_tokens": 1024,
            "system": _SYSTEM_PROMPT,
            "messages": messages,
            "tools": _anthropic_tool_schemas(),
            "stream": False,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "x-api-key": api_key, "anthropic-version": "2023-06-01"},
    )
    with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def _run_anthropic_loop(ai_settings: dict, mcp_base_url: str, mcp_token: str) -> dict:
    messages = [{"role": "user", "content": "Analyze recent traffic across all sites and take any warranted action."}]
    actions = []
    for step in range(MAX_AGENT_STEPS):
        response = _call_anthropic(ai_settings["llmBaseUrl"], ai_settings["llmApiKey"], ai_settings["llmModel"], messages)
        content = response.get("content") or []
        messages.append({"role": "assistant", "content": content})

        tool_use_blocks = [block for block in content if block.get("type") == "tool_use"]
        if response.get("stop_reason") != "tool_use" or not tool_use_blocks:
            text = "".join(block.get("text", "") for block in content if block.get("type") == "text")
            return {"steps": step + 1, "finalMessage": text, "actions": actions}

        tool_results = []
        for block in tool_use_blocks:
            name = block.get("name") or ""
            arguments = block.get("input") or {}
            result = _dispatch_tool_call(mcp_base_url, mcp_token, name, arguments, actions)
            tool_results.append({"type": "tool_result", "tool_use_id": block.get("id") or "", "content": json.dumps(result)})
        messages.append({"role": "user", "content": tool_results})

    return {"steps": MAX_AGENT_STEPS, "finalMessage": "Stopped: reached the step limit.", "actions": actions}


def _dispatch_tool_call(mcp_base_url: str, mcp_token: str, name: str, arguments: dict, actions: list[dict]) -> dict:
    if name not in mcp_tools.TOOLS:
        result = {"error": f"unknown tool {name!r}"}
    else:
        try:
            result = _call_mcp_tool(mcp_base_url, mcp_token, name, arguments)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
            result = {"error": str(error)[:300]}
    if name in mcp_tools.WRITE_TOOLS:
        actions.append({"tool": name, "arguments": arguments, "result": result})
    return result


def run_agent_pass(store: Store, root_dir: Path, mcp_base_url: str) -> dict:
    """One agent-mode detection pass. Returns {steps, finalMessage, actions}
    on a normal completion, or {"skipped": reason} when agent mode isn't
    actually runnable right now (disabled, wrong mode, no LLM configured).
    Never raises - the worker loop in server.py treats any exception as a
    bug, not an expected "nothing to do" outcome.
    """
    ai_settings = store.get_state().get("settings", {}).get("aiRules", {})
    if not ai_settings.get("enabled") or ai_settings.get("detectionMode") != "agent":
        return {"skipped": "agent mode is not enabled"}
    if not ai_settings.get("llmApiKey"):
        return {"skipped": "agent mode requires an LLM API key"}
    mcp_token = ai_settings.get("mcpToken") or ""
    if not mcp_token:
        return {"skipped": "no MCP token configured"}

    provider = ai_settings.get("llmProvider") or "openai_compatible"
    started = time.time()
    try:
        if provider == "anthropic":
            outcome = _run_anthropic_loop(ai_settings, mcp_base_url, mcp_token)
        else:
            outcome = _run_openai_loop(ai_settings, mcp_base_url, mcp_token)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, IndexError, json.JSONDecodeError) as error:
        return {"skipped": f"agent pass failed: {error}"[:300]}
    outcome["elapsedSeconds"] = round(time.time() - started, 1)
    return outcome
