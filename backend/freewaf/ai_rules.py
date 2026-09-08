"""AI-assisted proactive WAF rule generation.

Two stages, both governed by settings.aiRules (see defaults.py):

1. Statistical detector (runs whenever aiRules.enabled). Scans recent
   traffic per-host for the "same spam campaign" shape: many distinct
   source IPs and requests sharing one stable token (a marker word in the
   path), while that token is not just ordinary site vocabulary. URI
   rotation is NOT required - a single fixed URL taking a flood from many
   distinct IPs (the classic HTTP-flood shape) is detected exactly the same
   way a botnet that varies the rest of the URL around a constant marker
   is, since both look identical from the marker token's point of view.
   This automates the manual triage that was previously done by hand for
   the zamora.vn "xoilac" botnet - see the "Spam xoilac" rule broadened
   from an anchored path prefix to the bare marker after the bot started
   rotating URL prefixes, and later observed flooding a single fixed URL
   instead - the reason minDistinctUris defaults to 1, not higher.
2. Optional LLM refinement (aiRules.llmEnabled). Sends the statistical
   candidate to a pluggable LLM - OpenAI-compatible chat-completions or
   Anthropic's native Messages API, selected by aiRules.llmProvider, both
   over stdlib urllib so no extra dependency is required - to confirm or
   veto it and optionally suggest a tighter pattern. This step never runs
   standalone and any failure (network, timeout, bad JSON, missing fields)
   silently falls back to the statistical-only candidate: the feature must
   keep working even when no LLM is configured or reachable.

A candidate that clears aiRules.autoBlockConfidence gets a blocking rule
created immediately via Store.upsert_rule - no pending/approval step, by
product decision (FreeWAF also has no schema for a half-applied
"suggestion", so there is nowhere to safely park a low-confidence guess
even if we wanted a review step). Rules this module creates are named
with the AI_RULE_NAME_PREFIX so the panel/rule list can flag them, and so
this module can find its own past output again for rate limiting and
duplicate-pattern skipping.

The actual worker loop (thread creation, calling maybe_auto_write() to
apply the generated rule to nginx) lives in server.py alongside the other
background workers, to avoid this module importing server.py.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from .nginx import parse_nginx_logs
from .store import Store

AI_RULE_NAME_PREFIX = "AI: "

# Path/query tokens too generic to ever be a useful campaign marker on their
# own - filtering these out keeps the detector from proposing a rule that
# would end up blocking large swaths of ordinary traffic.
_STOPWORDS = {
    "http", "https", "www", "html", "htm", "php", "asp", "aspx", "jsp",
    "index", "home", "page", "pages", "post", "posts", "category",
    "categories", "product", "products", "item", "items", "api", "static",
    "assets", "asset", "images", "image", "img", "icon", "icons", "css",
    "js", "json", "xml", "true", "false", "null", "undefined", "utm",
    "source", "medium", "campaign", "content", "term", "ref", "id", "ids",
    "search", "query", "tag", "tags", "feed", "wp", "content", "uploads",
    "admin", "login", "logout", "account", "cart", "checkout", "user",
}

_TOKEN_SPLIT_RE = re.compile(r"[^a-z]+")


def _tokenize_uri(uri: str) -> set[str]:
    """Break a URI into lowercase letter-only tokens (>=4 chars).

    Splitting on anything that isn't a-z drops digits and punctuation as
    delimiters in one pass, so rotating numeric IDs or query separators
    never become (or break up) a candidate marker - only path/query
    segments that stay textually constant across the campaign matter here.
    """
    tokens = {tok for tok in _TOKEN_SPLIT_RE.split((uri or "").lower()) if len(tok) >= 4}
    return tokens - _STOPWORDS


def _parse_iso(value) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _load_recent_entries(store: Store, root_dir: Path, lookback_minutes: int, max_entries: int = 8000) -> list[dict]:
    """Merge nginx access-log tail entries with the store's own log buffer -
    the same two sources the dashboard combines - then trim to the lookback
    window. Uses a generous cap so a short lookback during a high-volume
    flood isn't starved by the dashboard's smaller default page size.
    """
    nginx_entries = parse_nginx_logs(root_dir, limit=max_entries)
    store_entries = store.get_logs(max_entries)
    combined = sorted(
        [*nginx_entries, *store_entries],
        key=lambda entry: entry.get("at") or "",
        reverse=True,
    )
    cutoff = time.time() - max(1, lookback_minutes) * 60
    recent = []
    for entry in combined:
        at = _parse_iso(entry.get("at"))
        if at is not None and at < cutoff:
            continue
        recent.append(entry)
        if len(recent) >= max_entries:
            break
    return recent


def _group_by_host(entries: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        host = str(entry.get("host") or entry.get("siteName") or "").strip().lower()
        if host:
            groups[host].append(entry)
    return groups


def _host_to_site(sites: list[dict]) -> dict[str, dict]:
    mapping: dict[str, dict] = {}
    for site in sites:
        for hostname in site.get("hostnames") or []:
            host = str(hostname or "").strip().lower()
            if host:
                mapping[host] = site
    return mapping


def find_marker_candidates(entries: list[dict], settings: dict) -> list[dict]:
    """Within one host's recent traffic, find tokens whose spread across
    distinct IPs/URIs/requests clears the configured thresholds, and which
    are not just ordinary site vocabulary (present on most of the host's
    own URI diversity, e.g. the site's own name showing up in every path).

    minDistinctUris defaults to 1, so this catches a single fixed URL
    flooded by many distinct IPs just as readily as a botnet rotating URLs
    around a constant marker - distinctUris/uriCoverage are still computed
    and carried on the candidate as informational signals either way.
    """
    token_ips: dict[str, set[str]] = defaultdict(set)
    token_uris: dict[str, set[str]] = defaultdict(set)
    token_requests: Counter = Counter()
    token_samples: dict[str, list[str]] = defaultdict(list)
    all_uris: set[str] = set()

    for entry in entries:
        uri = str(entry.get("path") or "")
        ip = str(entry.get("ip") or "")
        if not uri or not ip:
            continue
        all_uris.add(uri)
        for token in _tokenize_uri(uri):
            token_ips[token].add(ip)
            token_uris[token].add(uri)
            token_requests[token] += 1
            if len(token_samples[token]) < 5:
                token_samples[token].append(uri)

    total_uris = max(1, len(all_uris))
    candidates = []
    for token, ips in token_ips.items():
        uris = token_uris[token]
        requests = token_requests[token]
        if len(ips) < settings["minDistinctIps"]:
            continue
        if len(uris) < settings["minDistinctUris"]:
            continue
        if requests < settings["minRequests"]:
            continue
        coverage = len(uris) / total_uris
        # A dominant flood during the lookback window can legitimately push
        # a spam marker's coverage close to 100% of the host's traffic - so
        # coverage alone can't gate detection, or the exact case this
        # feature exists for (the campaign IS most of the traffic) would be
        # the one case it misses. Only the pathological extreme - literally
        # every distinct URI over a large, diverse sample containing the
        # same word - gets treated as a template/vocabulary artifact rather
        # than a candidate; the LLM refinement stage (when enabled) is the
        # real backstop for "legitimate traffic that shares a common word".
        if coverage > 0.95 and total_uris >= 50:
            continue
        candidates.append(
            {
                "token": token,
                "distinctIps": len(ips),
                "distinctUris": len(uris),
                "requests": requests,
                "sampleUris": sorted(token_samples[token]),
                "uriCoverage": round(coverage, 3),
                # Full URI set, used by run_pass() to collapse near-duplicate
                # candidates (e.g. several words from the same fixed spam
                # phrase all independently clearing the thresholds) down to
                # one rule. Not part of the rule payload - build_rule_payload
                # only reads the named fields above.
                "uriSet": uris,
            }
        )

    # Ties (e.g. several words from the same fixed phrase, all with
    # identical stats on a single-URL flood) prefer the longer, more
    # specific token - less likely to collide with unrelated legitimate
    # content elsewhere on the site than a short generic word - then break
    # alphabetically. Without an explicit tiebreak, which one wins (and
    # therefore which rule ends up created) would depend on dict/set
    # iteration order, which varies with Python's per-process hash
    # randomization.
    candidates.sort(key=lambda item: (-item["distinctIps"], -item["requests"], -len(item["token"]), item["token"]))
    return candidates


def statistical_confidence(candidate: dict, settings: dict) -> float:
    ip_ratio = candidate["distinctIps"] / max(1, settings["minDistinctIps"])
    uri_ratio = candidate["distinctUris"] / max(1, settings["minDistinctUris"])
    volume_ratio = candidate["requests"] / max(1, settings["minRequests"])
    # Diminishing returns past 3x the threshold - being 10x over a threshold
    # isn't 10x more suspicious than being 3x over it.
    score = min(1.0, ip_ratio / 3) * 0.4 + min(1.0, uri_ratio / 3) * 0.3 + min(1.0, volume_ratio / 3) * 0.3
    return round(max(0.0, min(1.0, score)), 3)


def already_covered(token: str, site_id: str, rules: list[dict]) -> bool:
    """True if an existing enabled block rule already covers this token
    (for this site or globally), so the detector doesn't create a
    near-duplicate rule every scan interval."""
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if rule.get("action") != "block":
            continue
        scope = rule.get("siteId") or "*"
        if scope not in ("*", site_id):
            continue
        pattern = str(rule.get("pattern") or "").strip().lower()
        if not pattern:
            continue
        if token in pattern or pattern in token:
            return True
    return False


def recent_ai_rule_count(site_id: str, rules: list[dict], window_seconds: int = 3600) -> int:
    cutoff = time.time() - window_seconds
    count = 0
    for rule in rules:
        if not str(rule.get("name") or "").startswith(AI_RULE_NAME_PREFIX):
            continue
        if (rule.get("siteId") or "*") != site_id:
            continue
        created = _parse_iso(rule.get("createdAt"))
        if created is not None and created >= cutoff:
            count += 1
    return count


def build_rule_payload(site: dict, candidate: dict, confidence: float) -> dict:
    site_id = str(site.get("id") or "*")
    hostnames = site.get("hostnames") or []
    site_label = site.get("name") or (hostnames[0] if hostnames else "this host")
    description = (
        f"Auto-created by the AI rule detector: \"{candidate['token']}\" seen across "
        f"{candidate['distinctIps']} distinct IPs and {candidate['distinctUris']} distinct URIs "
        f"on {site_label} ({candidate['requests']} requests in the scan window). "
        f"Confidence {confidence:.2f}."
    )
    if candidate.get("llmNote"):
        description += f" LLM notes: {candidate['llmNote']}"
    return {
        "name": f"{AI_RULE_NAME_PREFIX}{candidate['token']}",
        "description": description,
        "enabled": True,
        "siteId": site_id,
        "matcher": "contains",
        "target": "url",
        "pattern": candidate["token"],
        "action": "block",
        "severity": "high" if confidence >= 0.9 else "medium",
    }


def _llm_prompt(site: dict, candidate: dict) -> str:
    hostnames = site.get("hostnames") or []
    label = site.get("name") or (hostnames[0] if hostnames else "unknown host")
    sample = "\n".join(f"- {uri}" for uri in candidate["sampleUris"][:5]) or "(no samples)"
    return (
        "You are a WAF analyst reviewing a candidate spam/bot campaign flagged by "
        "statistical traffic analysis. Decide whether this looks like malicious or "
        "spam traffic that should be blocked, or legitimate traffic that happens to "
        "share a common word.\n\n"
        f"Site: {label}\n"
        f"Candidate marker token found repeated in URLs: \"{candidate['token']}\"\n"
        f"Distinct source IPs: {candidate['distinctIps']}\n"
        f"Distinct URLs containing the token: {candidate['distinctUris']}\n"
        f"Total requests: {candidate['requests']}\n"
        f"Sample URLs:\n{sample}\n\n"
        "Reply with ONLY a JSON object, no other text, in exactly this shape:\n"
        '{"malicious": true or false, "confidence": a number from 0.0 to 1.0, '
        '"pattern": "marker substring to block", "note": "one sentence explaining why"}\n'
        "The \"pattern\" field should normally just be the candidate token above unless "
        "the sample URLs show a clearly better, safer substring to match instead."
    )


def _extract_json_object(text: str) -> dict | None:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _call_openai_compatible(base_url: str, api_key: str, model: str, prompt: str, timeout: int) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        parsed = json.loads(response.read().decode("utf-8"))
    return str(parsed["choices"][0]["message"]["content"])


def _call_anthropic(base_url: str, api_key: str, model: str, prompt: str, timeout: int) -> str:
    url = base_url.rstrip("/") + "/messages"
    body = json.dumps(
        {
            "model": model,
            "max_tokens": 512,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        parsed = json.loads(response.read().decode("utf-8"))
    return str(parsed["content"][0]["text"])


def refine_with_llm(site: dict, candidate: dict, ai_settings: dict) -> dict:
    """Best-effort LLM refinement of one statistical candidate.

    Returns the candidate unchanged (aside from an 'llmError' note) on ANY
    failure - network, timeout, bad JSON, unexpected shape - so a
    misconfigured or unreachable LLM can never block the statistical
    pipeline or crash the worker loop.
    """
    if not ai_settings.get("llmEnabled") or not ai_settings.get("llmApiKey"):
        return candidate
    provider = ai_settings.get("llmProvider") or "openai_compatible"
    caller = _call_anthropic if provider == "anthropic" else _call_openai_compatible
    try:
        raw_text = caller(
            str(ai_settings.get("llmBaseUrl") or ""),
            str(ai_settings.get("llmApiKey") or ""),
            str(ai_settings.get("llmModel") or ""),
            _llm_prompt(site, candidate),
            20,
        )
        parsed = _extract_json_object(raw_text)
        if not parsed:
            return candidate

        refined = dict(candidate)
        if parsed.get("malicious") is False:
            refined["llmVeto"] = True
            refined["llmNote"] = str(parsed.get("note") or "LLM assessed this as likely legitimate traffic.")[:300]
            return refined

        try:
            llm_confidence = float(parsed.get("confidence"))
        except (TypeError, ValueError):
            llm_confidence = None
        if llm_confidence is not None:
            refined["llmConfidence"] = max(0.0, min(1.0, llm_confidence))

        pattern = str(parsed.get("pattern") or "").strip().lower()
        # Only accept a refined pattern that is itself a plain lowercase
        # token - anything else risks smuggling regex metacharacters or an
        # overly broad match into an auto-applied rule.
        if pattern and re.fullmatch(r"[a-z]{3,}", pattern):
            refined["token"] = pattern

        note = parsed.get("note")
        if note:
            refined["llmNote"] = str(note)[:300]
        return refined
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, IndexError, json.JSONDecodeError) as error:
        candidate = dict(candidate)
        candidate["llmError"] = str(error)[:200]
        return candidate


def combined_confidence(candidate: dict) -> float:
    statistical = float(candidate.get("statisticalConfidence") or 0.0)
    if candidate.get("llmVeto"):
        return 0.0
    llm_confidence = candidate.get("llmConfidence")
    if llm_confidence is None:
        return statistical
    # Once the LLM has an opinion, weight it evenly against the statistics -
    # neither stage should be able to force a create on its own.
    return round((statistical + float(llm_confidence)) / 2, 3)


def run_pass(store: Store, root_dir: Path) -> list[dict]:
    """One detection pass: scan recent logs, score candidates, create
    blocking rules for anything that clears the confidence bar. Returns a
    summary of what was created (for logging by the caller)."""
    state = store.get_state()
    ai_settings = (state.get("settings") or {}).get("aiRules") or {}
    if not ai_settings.get("enabled"):
        return []

    sites = state.get("sites", [])
    rules = list(state.get("rules", []))
    host_map = _host_to_site(sites)

    entries = _load_recent_entries(store, root_dir, ai_settings["lookbackMinutes"])
    created = []

    for host, host_entries in _group_by_host(entries).items():
        site = host_map.get(host)
        if site and not site.get("enabled", True):
            continue
        site_id = str(site.get("id")) if site else "*"

        if recent_ai_rule_count(site_id, rules, 3600) >= ai_settings["maxRulesPerHour"]:
            continue

        # Several distinct words from one fixed spam phrase (e.g. "xoilac",
        # "truc", "tiep", "bong" all appearing in the same rotating-URL
        # campaign) independently clear the thresholds. Track which URIs a
        # handled candidate already accounts for so near-duplicate siblings
        # collapse into the first (strongest - candidates are pre-sorted by
        # distinctIps/requests) one instead of each spawning its own rule.
        covered_uris: set[str] = set()

        for candidate in find_marker_candidates(host_entries, ai_settings):
            uri_set = candidate.get("uriSet") or set()
            if covered_uris and uri_set:
                overlap = len(uri_set & covered_uris) / max(1, len(uri_set))
                if overlap >= 0.8:
                    continue

            if already_covered(candidate["token"], site_id, rules):
                covered_uris |= uri_set
                continue

            candidate = dict(candidate)
            candidate["statisticalConfidence"] = statistical_confidence(candidate, ai_settings)
            effective_site = site or {"id": "*", "name": host, "hostnames": [host]}
            candidate = refine_with_llm(effective_site, candidate, ai_settings)
            if already_covered(candidate["token"], site_id, rules):
                # The LLM may have refined the token to something an
                # existing rule already covers - re-check before creating.
                covered_uris |= uri_set
                continue

            confidence = combined_confidence(candidate)
            if confidence < ai_settings["autoBlockConfidence"]:
                continue

            payload = build_rule_payload(effective_site, candidate, confidence)
            try:
                saved = store.upsert_rule(payload)
            except Exception as error:  # never let one bad candidate abort the pass
                print(f"ai-rules: failed to create rule for {candidate['token']!r} on {host}: {error}", flush=True)
                continue

            covered_uris |= uri_set
            rules.append(saved)
            created.append(
                {
                    "host": host,
                    "siteId": site_id,
                    "token": candidate["token"],
                    "confidence": confidence,
                    "ruleId": saved.get("id"),
                }
            )
            if recent_ai_rule_count(site_id, rules, 3600) >= ai_settings["maxRulesPerHour"]:
                break

    return created
