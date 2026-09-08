"""Tool surface for the MCP (Model Context Protocol) endpoint.

This module is the read/write control surface an agent uses to investigate
and act on FreeWAF traffic - it deliberately mirrors the pieces of
ai_rules.py's statistical detector (get_traffic_candidates reuses its
token-clustering logic directly) but adds free-form log inspection and,
crucially, lets the caller decide what to do rather than following a fixed
score-then-threshold pipeline. mcp_agent.py's agent loop is the intended
caller, reached over HTTP at POST /mcp (see server.py); a human operator's
own MCP-compatible client can use the same tools directly too.

Kept dependency-free of server.py (only store.py, nginx.py, ai_rules.py) so
this can be imported without pulling in the whole HTTP server - the actual
/mcp route, auth, and post-mutation nginx apply live in server.py, same
split as ai_rules.py's run_pass() vs. server.py's start_ai_rule_worker().

Each tool handler takes (store, root_dir, arguments) and returns a plain
JSON-serializable dict. Handlers never raise for "the answer is no" cases
(e.g. rate-limited, already covered) - they return a result saying so, so
the agent can reason about it instead of receiving an opaque error.
"""

from __future__ import annotations

from pathlib import Path

from . import ai_rules
from .store import Store, StoreError

WRITE_TOOLS = {"create_block_rule", "disable_rule"}


def _site_by_id(store: Store, site_id: str) -> dict | None:
    if not site_id or site_id == "*":
        return None
    state = store.get_state()
    return next((site for site in state.get("sites", []) if site.get("id") == site_id), None)


def tool_list_sites(store: Store, root_dir: Path, arguments: dict) -> dict:
    state = store.get_state()
    sites = [
        {
            "id": site.get("id"),
            "name": site.get("name"),
            "hostnames": site.get("hostnames") or [],
            "enabled": bool(site.get("enabled")),
            "mode": site.get("mode"),
        }
        for site in state.get("sites", [])
    ]
    return {"sites": sites}


def tool_list_rules(store: Store, root_dir: Path, arguments: dict) -> dict:
    site_id = str(arguments.get("siteId") or "").strip()
    state = store.get_state()
    rules = state.get("rules", [])
    if site_id:
        rules = [r for r in rules if (r.get("siteId") or "*") in ("*", site_id)]
    return {
        "rules": [
            {
                "id": r.get("id"),
                "name": r.get("name"),
                "siteId": r.get("siteId"),
                "matcher": r.get("matcher"),
                "target": r.get("target"),
                "pattern": r.get("pattern"),
                "action": r.get("action"),
                "enabled": bool(r.get("enabled", True)),
                "severity": r.get("severity"),
                "createdAt": r.get("createdAt"),
            }
            for r in rules
        ]
    }


def tool_get_traffic_candidates(store: Store, root_dir: Path, arguments: dict) -> dict:
    """Pre-digested view of the same token-clustering analysis
    ai_rules.py's statistical detector uses: per host, marker tokens whose
    spread across distinct IPs/URIs/requests looks like a spam/flood
    campaign. Read-only - use create_block_rule to act on a candidate.
    """
    host_filter = str(arguments.get("host") or "").strip().lower()
    lookback_minutes = int(arguments.get("lookbackMinutes") or 15)
    lookback_minutes = max(1, min(lookback_minutes, 24 * 60))

    ai_settings = store.get_state().get("settings", {}).get("aiRules", {})
    entries = ai_rules._load_recent_entries(store, root_dir, lookback_minutes)
    groups = ai_rules._group_by_host(entries)
    if host_filter:
        groups = {host: items for host, items in groups.items() if host == host_filter}

    result = {}
    for host, host_entries in groups.items():
        candidates = ai_rules.find_marker_candidates(host_entries, ai_settings)
        result[host] = [
            {
                "token": c["token"],
                "distinctIps": c["distinctIps"],
                "distinctUris": c["distinctUris"],
                "requests": c["requests"],
                "uriCoverage": c["uriCoverage"],
                "sampleUris": c["sampleUris"],
            }
            for c in candidates[:20]
        ]
    return {"lookbackMinutes": lookback_minutes, "candidatesByHost": result}


def tool_get_recent_logs(store: Store, root_dir: Path, arguments: dict) -> dict:
    """Raw recent request log entries, for when a candidate summary isn't
    enough detail (e.g. to check user-agents or confirm a hunch)."""
    host_filter = str(arguments.get("host") or "").strip().lower()
    lookback_minutes = int(arguments.get("lookbackMinutes") or 15)
    lookback_minutes = max(1, min(lookback_minutes, 24 * 60))
    limit = int(arguments.get("limit") or 30)
    limit = max(1, min(limit, 200))

    entries = ai_rules._load_recent_entries(store, root_dir, lookback_minutes)
    if host_filter:
        entries = [e for e in entries if str(e.get("host") or "").strip().lower() == host_filter]

    sample = [
        {
            "at": e.get("at"),
            "host": e.get("host"),
            "ip": e.get("ip"),
            "method": e.get("method"),
            "path": e.get("path"),
            "statusCode": e.get("statusCode"),
            "verdict": e.get("verdict"),
            "userAgent": e.get("userAgent"),
        }
        for e in entries[:limit]
    ]
    return {"totalMatched": len(entries), "logs": sample}


def tool_create_block_rule(store: Store, root_dir: Path, arguments: dict) -> dict:
    """Create (or, if an equivalent one already exists, decline to
    duplicate) a blocking rule. Subject to the same maxRulesPerHour cap and
    duplicate-pattern skip as the statistical detector, since this tool is
    the write path for both."""
    site_id = str(arguments.get("siteId") or "*").strip() or "*"
    pattern = str(arguments.get("pattern") or "").strip()
    if not pattern:
        return {"created": False, "reason": "pattern is required"}

    state = store.get_state()
    rules = state.get("rules", [])
    ai_settings = state.get("settings", {}).get("aiRules", {})
    max_per_hour = int(ai_settings.get("maxRulesPerHour") or 5)

    if ai_rules.already_covered(pattern.lower(), site_id, rules):
        return {"created": False, "reason": "an existing enabled block rule already covers this pattern"}
    if ai_rules.recent_ai_rule_count(site_id, rules, 3600) >= max_per_hour:
        return {"created": False, "reason": f"maxRulesPerHour ({max_per_hour}) already reached for this site in the last hour"}

    site = _site_by_id(store, site_id)
    site_label = (site or {}).get("name") or site_id
    name = str(arguments.get("name") or "").strip() or pattern
    if not name.startswith(ai_rules.AI_RULE_NAME_PREFIX):
        name = f"{ai_rules.AI_RULE_NAME_PREFIX}{name}"
    description = str(arguments.get("description") or "").strip()
    description = f"Created by the MCP analyst agent for {site_label}. {description}".strip()

    matcher = str(arguments.get("matcher") or "contains").strip().lower()
    if matcher not in {"contains", "regex", "equals"}:
        matcher = "contains"
    target = str(arguments.get("target") or "url").strip().lower()
    if target not in {"all", "url", "headers", "body", "method", "ip"}:
        target = "url"
    severity = str(arguments.get("severity") or "medium").strip().lower()
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "medium"

    try:
        saved = store.upsert_rule(
            {
                "name": name,
                "description": description,
                "enabled": True,
                "siteId": site_id,
                "matcher": matcher,
                "target": target,
                "pattern": pattern,
                "action": "block",
                "severity": severity,
            }
        )
    except StoreError as error:
        return {"created": False, "reason": error.message}

    return {"created": True, "rule": saved}


def tool_disable_rule(store: Store, root_dir: Path, arguments: dict) -> dict:
    """Turn off a rule without deleting it - the agent's undo/correction
    tool, e.g. after realizing a just-created rule was too broad."""
    rule_id = str(arguments.get("ruleId") or "").strip()
    if not rule_id:
        return {"disabled": False, "reason": "ruleId is required"}
    state = store.get_state()
    existing = next((r for r in state.get("rules", []) if r.get("id") == rule_id), None)
    if not existing:
        return {"disabled": False, "reason": "rule not found"}
    try:
        saved = store.upsert_rule({**existing, "enabled": False}, rule_id)
    except StoreError as error:
        return {"disabled": False, "reason": error.message}
    return {"disabled": True, "rule": saved}


TOOLS = {
    "list_sites": {
        "description": "List configured sites (id, name, hostnames, enabled, mode).",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": tool_list_sites,
    },
    "list_rules": {
        "description": "List WAF rules, optionally filtered to one site (global '*' rules are always included).",
        "inputSchema": {
            "type": "object",
            "properties": {"siteId": {"type": "string", "description": "Site id to filter by; omit for all rules."}},
        },
        "handler": tool_list_rules,
    },
    "get_traffic_candidates": {
        "description": (
            "Statistical pre-analysis of recent traffic: per host, marker tokens whose spread across distinct "
            "IPs/URIs/requests looks like a spam or flood campaign. Start here before reading raw logs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Limit to one hostname; omit for all hosts with recent traffic."},
                "lookbackMinutes": {"type": "integer", "description": "How far back to look (default 15, max 1440)."},
            },
        },
        "handler": tool_get_traffic_candidates,
    },
    "get_recent_logs": {
        "description": "Raw recent request log entries (time, ip, method, path, status, verdict, user agent) for closer inspection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Limit to one hostname."},
                "lookbackMinutes": {"type": "integer", "description": "How far back to look (default 15, max 1440)."},
                "limit": {"type": "integer", "description": "Max entries to return (default 30, max 200)."},
            },
        },
        "handler": tool_get_recent_logs,
    },
    "create_block_rule": {
        "description": (
            "Create a blocking rule for a pattern found in traffic. Refused (not an error - check the 'created' "
            "field) if an equivalent rule already exists or the per-site hourly rule-creation cap is reached."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "siteId": {"type": "string", "description": "Site id to scope the rule to, or '*' for all sites."},
                "pattern": {"type": "string", "description": "Substring to match (case-insensitive) in the request URL."},
                "matcher": {"type": "string", "enum": ["contains", "regex", "equals"], "description": "Defaults to contains."},
                "target": {
                    "type": "string",
                    "enum": ["all", "url", "headers", "body", "method", "ip"],
                    "description": "Defaults to url.",
                },
                "name": {"type": "string", "description": "Short rule name; the 'AI: ' prefix is added automatically if missing."},
                "description": {"type": "string", "description": "Why this pattern was chosen - what you observed."},
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Defaults to medium."},
            },
            "required": ["siteId", "pattern"],
        },
        "handler": tool_create_block_rule,
    },
    "disable_rule": {
        "description": "Disable a rule (does not delete it) - use to undo or correct a previous action.",
        "inputSchema": {
            "type": "object",
            "properties": {"ruleId": {"type": "string"}},
            "required": ["ruleId"],
        },
        "handler": tool_disable_rule,
    },
}


def call_tool(store: Store, root_dir: Path, name: str, arguments: dict | None) -> dict:
    """Dispatch one tool call. Raises KeyError for an unknown tool name -
    callers (the /mcp route) turn that into a JSON-RPC error response."""
    tool = TOOLS[name]
    return tool["handler"](store, root_dir, arguments or {})
