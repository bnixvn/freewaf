from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone


DEFAULT_SETTINGS = {
    "logRetention": 1500,
    "bodyInspectionLimit": 131072,
    "panel": {
        "httpsEnabled": False,
        "certificateId": "",
        "publicUrl": "",
        "sessionHours": 12,
    },
    "rateLimit": {
        "enabled": True,
        "windowMs": 60000,
        "max": 120,
    },
    "blockPageTitle": "Request blocked",
    "blockSupportIdPrefix": "SFL",
}


BUILTIN_RULES = [
    {
        "id": "builtin-sqli-basic",
        "name": "SQL injection probes",
        "description": "Common tautology, UNION, delay, and schema probing payloads.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "all",
        "pattern": r"(?:\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1|\band\b\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema|--\s|/\*)",
        "action": "block",
        "severity": "critical",
    },
    {
        "id": "builtin-xss-basic",
        "name": "Cross-site scripting probes",
        "description": "Script tags, JavaScript URLs, event handlers, and cookie theft strings.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "all",
        "pattern": r"(?:<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=|<\s*iframe\b|document\.cookie)",
        "action": "block",
        "severity": "high",
    },
    {
        "id": "builtin-path-traversal",
        "name": "Path traversal and local file reads",
        "description": "Traversal sequences and common sensitive local files.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "all",
        "pattern": r"(?:\.\./|\.\.\\|/etc/passwd|boot\.ini|proc/self/environ)",
        "action": "block",
        "severity": "high",
    },
    {
        "id": "builtin-command-injection",
        "name": "Command injection markers",
        "description": "Shell metacharacters followed by common command execution tools.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "all",
        "pattern": r"(?:;\s*(?:cat|curl|wget|bash|sh|powershell)\b|\|\s*(?:cat|curl|wget|bash|sh)\b|\$\(|`)",
        "action": "block",
        "severity": "critical",
    },
    {
        "id": "builtin-scanner-agent",
        "name": "Scanner user agents",
        "description": "Common vulnerability scanners and mass HTTP clients.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "headers",
        "pattern": r"(?:sqlmap|nikto|acunetix|nessus|masscan|nmap|zgrab|go-http-client)",
        "action": "block",
        "severity": "medium",
    },
    {
        "id": "builtin-sensitive-file",
        "name": "Sensitive file discovery",
        "description": "Requests for common secrets, source folders, and backup archives.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "url",
        "pattern": r"(?:/\.env\b|/\.git/|wp-config\.php|composer\.json|id_rsa|backup\.(?:zip|sql|tar))",
        "action": "block",
        "severity": "high",
    },
    {
        "id": "builtin-dangerous-methods",
        "name": "Dangerous HTTP methods",
        "description": "Methods that are usually unnecessary for public web applications.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "method",
        "pattern": r"^(?:TRACE|TRACK)$",
        "action": "block",
        "severity": "medium",
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_default_state(now: str | None = None) -> dict:
    timestamp = now or utc_now()
    return {
        "version": 1,
        "settings": deepcopy(DEFAULT_SETTINGS),
        "sites": [
            {
                "id": "site-demo",
                "name": "Demo origin",
                "applicationType": "reverse_proxy",
                "hostnames": ["localhost", "127.0.0.1"],
                "origin": "http://127.0.0.1:9090",
                "upstreams": ["http://127.0.0.1:9090"],
                "ports": ["8080"],
                "listen": 8080,
                "redirectStatusCode": 301,
                "tls": {
                    "enabled": False,
                    "certificateId": "",
                    "redirectHttp": False,
                    "httpListen": 80,
                    "http2": True,
                },
                "proxy": {
                    "forceHttps": False,
                    "redirectStatusCode": 301,
                    "hsts": False,
                    "hstsMaxAge": "15768000",
                    "gzip": True,
                    "brotli": False,
                    "http2": True,
                    "ipv6": False,
                    "resetXff": True,
                    "defaultServer": False,
                    "strictHost": False,
                    "accessLog": True,
                    "hostHeader": "$http_host",
                    "xForwardedProto": "$scheme",
                    "xForwardedHost": "$http_host",
                    "proxySslServerName": True,
                },
                "redirect": {
                    "statusCode": 301,
                    "address": "",
                },
                "static": {
                    "root": "",
                },
                "acl": {
                    "enabled": True,
                    "accessLimit": {
                        "enabled": True,
                        "period": 10,
                        "count": 200,
                        "action": "challenge_v1",
                        "blockMin": 60,
                    },
                    "attackLimit": {
                        "enabled": True,
                        "period": 60,
                        "count": 10,
                        "action": "block",
                        "blockMin": 30,
                    },
                    "errorLimit": {
                        "enabled": True,
                        "period": 10,
                        "count": 10,
                        "action": "block",
                        "blockMin": 30,
                        "statusCodes": ["403", "404"],
                    },
                },
                "features": {
                    "httpFlood": True,
                    "botProtection": True,
                    "auth": False,
                    "attacks": True,
                },
                "mode": "block",
                "enabled": True,
                "createdAt": timestamp,
                "updatedAt": timestamp,
            }
        ],
        "rules": [
            {
                **deepcopy(rule),
                "createdAt": timestamp,
                "updatedAt": timestamp,
            }
            for rule in BUILTIN_RULES
        ],
        "certificates": [],
        "ipGroups": [
            {
                "id": "ipgroup-local",
                "name": "Local addresses",
                "description": "Loopback addresses useful for local testing.",
                "referenceUrl": "",
                "items": ["127.0.0.1/32", "::1/128"],
                "lastSyncedAt": "",
                "lastSyncStatus": "",
                "lastSyncMessage": "",
                "enabled": True,
                "createdAt": timestamp,
                "updatedAt": timestamp,
            }
        ],
        "accessRules": [],
        "users": [],
        "logs": [],
    }
