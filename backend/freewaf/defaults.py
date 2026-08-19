from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import os
import secrets


DEFAULT_SETTINGS = {
    "logRetention": 1500,
    "bodyInspectionLimit": 131072,
    "panel": {
        "httpsEnabled": False,
        "certificateId": "",
        "publicUrl": "",
        "faviconUrl": "",
        "logoUrl": "",
        "sessionHours": 12,
    },
    "rateLimit": {
        "enabled": True,
        "windowMs": 60000,
        "max": 1200,
    },
    "clientIp": {
        "source": "socket",
        "headerName": "X-Forwarded-For",
    },
    "applicationDefaults": {
        "proxy": {
            "forceHttps": False,
            "hsts": False,
            "hstsMaxAge": 15768000,
            "gzip": True,
            "brotli": False,
            "http2": True,
            "resetXff": True,
            "modifyHostHeader": True,
            "forwardedHeaders": True,
            "hostHeader": "$http_host",
            "xForwardedProto": "$scheme",
            "xForwardedHost": "$http_host",
            "proxySslServerName": True,
        },
        "modSecurity": {
            "enabled": False,
            "mode": "on",
            "ruleset": "cms",
            "requestBodyLimit": 13107200,
        },
    },
    "challengePage": {
        "brandName": "FreeWAF",
        "title": "Security check",
        "message": "We are verifying your browser before continuing.",
        "logoUrl": "",
        "supportUrl": "",
        "primaryColor": "#18a69a",
        "backgroundColor": "#f5f7f8",
        "textColor": "#17202a",
        "tokenTtlMinutes": 30,
        "waitSeconds": 5,
        "powDifficulty": 16,
    },
    "blockPageTitle": "Request blocked",
    "blockSupportIdPrefix": "SFL",
}

DEFAULT_BOT_LOGIN_PATH_PATTERNS = [
    r"^/wp-login\.php(?:\?|$)",
    r"^/wp-admin/?(?:\?|$)",
    r"^/(?:admin|administrator)(?:/login)?/?(?:\?|$)",
    r"^/(?:login|user/login|account/login)(?:/|\?|$)",
    r"^/cart\.php(?:\?[^#]*\ba=login\b|$)",
    r"^/index\.php/(?:login|admin)(?:/|\?|$)",
    r"^/admin/index\.php(?:\?|$)",
]

LEGACY_WHMCS_LOGIN_PATH_PATTERNS = {
    r"^/clientarea\.php(?:\?|$)",
}

DEFAULT_BOT_RATE_CHALLENGE = {
    "enabled": False,
    "windowSeconds": 10,
    "challengeCount": 300,
    "blockCount": 500,
    "blockMinutes": 30,
}

VERIFIED_BOT_PROVIDERS = {
    "google": {
        "id": "ipgroup-verified-googlebot",
        "name": "Verified Google Common Crawlers",
        "description": "Official Google common crawler CIDR ranges. Managed and synced daily by FreeWAF.",
        "referenceUrl": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
        "userAgentPattern": r"(?:Googlebot|Google-InspectionTool|GoogleOther|Storebot-Google|Google-CloudVertexBot)",
    },
    "bing": {
        "id": "ipgroup-verified-bingbot",
        "name": "Verified Bingbot",
        "description": "Official Bingbot CIDR ranges. Managed and synced daily by FreeWAF.",
        "referenceUrl": "https://www.bing.com/toolbox/bingbot.json",
        "userAgentPattern": r"(?:bingbot|adidxbot|MicrosoftPreview)",
    },
}

VERIFIED_AI_BOT_PROVIDERS = {
    "openai_search": {
        "id": "ipgroup-verified-openai-searchbot",
        "name": "Verified OpenAI SearchBot",
        "description": "Official OAI-SearchBot CIDR ranges. Managed and synced daily by FreeWAF.",
        "referenceUrl": "https://openai.com/searchbot.json",
        "userAgentPattern": r"(?:OAI-SearchBot)",
    },
    "openai_user": {
        "id": "ipgroup-verified-chatgpt-user",
        "name": "Verified ChatGPT User",
        "description": "Official ChatGPT-User CIDR ranges. Managed and synced daily by FreeWAF.",
        "referenceUrl": "https://openai.com/chatgpt-user.json",
        "userAgentPattern": r"(?:ChatGPT-User)",
    },
    "openai_gptbot": {
        "id": "ipgroup-verified-gptbot",
        "name": "Verified GPTBot",
        "description": "Official GPTBot CIDR ranges. Managed and synced daily by FreeWAF.",
        "referenceUrl": "https://openai.com/gptbot.json",
        "userAgentPattern": r"(?:GPTBot)",
    },
    "anthropic_search": {
        "id": "ipgroup-verified-claude-searchbot",
        "name": "Verified Claude SearchBot",
        "description": "Official Anthropic outbound crawler range for Claude-SearchBot. Managed by FreeWAF.",
        "referenceUrl": "",
        "items": ["160.79.104.0/21"],
        "userAgentPattern": r"(?:Claude-SearchBot)",
    },
    "anthropic_user": {
        "id": "ipgroup-verified-claude-user",
        "name": "Verified Claude User",
        "description": "Official Anthropic outbound user-fetch range for Claude-User. Managed by FreeWAF.",
        "referenceUrl": "",
        "items": ["160.79.104.0/21"],
        "userAgentPattern": r"(?:Claude-User)",
    },
    "anthropic_claudebot": {
        "id": "ipgroup-verified-claudebot",
        "name": "Verified ClaudeBot",
        "description": "Official Anthropic outbound crawler range for ClaudeBot. Managed by FreeWAF.",
        "referenceUrl": "",
        "items": ["160.79.104.0/21"],
        "userAgentPattern": r"(?:ClaudeBot)",
    },
    "perplexity_bot": {
        "id": "ipgroup-verified-perplexitybot",
        "name": "Verified PerplexityBot",
        "description": "Official PerplexityBot CIDR ranges. Managed and synced daily by FreeWAF.",
        "referenceUrl": "https://www.perplexity.com/perplexitybot.json",
        "userAgentPattern": r"(?:PerplexityBot)",
    },
    "perplexity_user": {
        "id": "ipgroup-verified-perplexity-user",
        "name": "Verified Perplexity User",
        "description": "Official Perplexity user-fetch CIDR ranges. Managed and synced daily by FreeWAF.",
        "referenceUrl": "https://www.perplexity.com/perplexity-user.json",
        "userAgentPattern": r"(?:Perplexity-User)",
    },
}


def managed_verified_bot_providers() -> dict:
    return {**VERIFIED_BOT_PROVIDERS, **VERIFIED_AI_BOT_PROVIDERS}


_PERSISTED_CHALLENGE_SECRET = ""


def challenge_secret() -> str:
    """Return the configured challenge secret.

    Priority: FREEWAF_CHALLENGE_SECRET env var, then a random secret persisted to
    the state directory so challenge tokens are not forgeable across installs.
    """
    global _PERSISTED_CHALLENGE_SECRET
    configured = os.environ.get("FREEWAF_CHALLENGE_SECRET", "").strip()
    if configured and configured != "freewaf-development-challenge-secret":
        return configured
    if not _PERSISTED_CHALLENGE_SECRET:
        secret_file = os.environ.get("FREEWAF_CHALLENGE_SECRET_FILE", "")
        if not secret_file:
            data_dir = os.environ.get("FREEWAF_DATA_DIR", "")
            if not data_dir:
                data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
            secret_file = os.path.join(data_dir, "challenge_secret.key")
        try:
            if os.path.exists(secret_file):
                with open(secret_file, "r", encoding="utf-8") as handle:
                    value = handle.read().strip()
                if value:
                    _PERSISTED_CHALLENGE_SECRET = value
                    return value
            value = secrets.token_urlsafe(48)
            directory = os.path.dirname(secret_file)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(secret_file, "w", encoding="utf-8") as handle:
                handle.write(value)
            try:
                os.chmod(secret_file, 0o600)
            except OSError:
                pass
            _PERSISTED_CHALLENGE_SECRET = value
        except OSError:
            pass
    return _PERSISTED_CHALLENGE_SECRET or secrets.token_urlsafe(48)


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
    {
        "id": "builtin-wordpress-sensitive-files",
        "name": "[WordPress] Sensitive application files",
        "description": "Blocks direct access to WordPress config, install/upgrade scripts, debug logs, and PHP payloads in uploads.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "url",
        "pattern": r"(?:/wp-config\.php(?:[.~]|$|\?)|/wp-content/(?:debug\.log|uploads/[^?]*\.(?:php[0-9]?|phtml|phar))|/wp-admin/(?:install|setup-config|upgrade)\.php|/(?:readme|license)\.txt(?:$|\?))",
        "action": "block",
        "severity": "high",
    },
    {
        "id": "builtin-wordpress-enumeration",
        "name": "[WordPress] User enumeration probes",
        "description": "Blocks common author and REST API user enumeration scans.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "url",
        "pattern": r"(?:[?&]author=\d+\b)",
        "action": "block",
        "severity": "medium",
    },
    {
        "id": "builtin-whmcs-sensitive-paths",
        "name": "[WHMCS] Sensitive files and directories",
        "description": "Blocks direct access to WHMCS configuration, installer, crons, compiled templates, attachments, downloads, and vendor folders.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "url",
        "pattern": r"(?:/(?:configuration\.php|install/|crons/|templates_c/|attachments/|downloads/|vendor/)(?:$|[/?])|/vendor/composer/(?:installed|autoload_(?:real|static))\.php)",
        "action": "block",
        "severity": "high",
    },
    {
        "id": "builtin-laravel-sensitive-files",
        "name": "[Laravel] Env, logs, and framework internals",
        "description": "Blocks exposed Laravel environment files, logs, artisan/server scripts, storage, cache, vendor, Telescope, Horizon, and Ignition endpoints.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "url",
        "pattern": r"(?:/\.env(?:$|\?|/)|/storage/logs/laravel(?:-\d{4}-\d{2}-\d{2})?\.log|/(?:artisan|server\.php|composer\.(?:json|lock))(?:$|\?)|^/vendor(?:/|$)|/(?:bootstrap/cache|storage/framework)(?:/|$)|/_ignition/(?:execute-solution|health-check)|/(?:telescope|horizon)(?:/|$))",
        "action": "block",
        "severity": "critical",
    },
    {
        "id": "builtin-codeigniter-sensitive-paths",
        "name": "[CodeIgniter] Protected framework paths",
        "description": "Blocks common CodeIgniter application, system, writable logs/cache/session paths and traversal probes.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "url",
        "pattern": r"(?:/application/(?:config|logs|cache|sessions|core|helpers|libraries)/|/system/(?:core|database|helpers|libraries)/|/writable/(?:logs|cache|session|uploads)/|/\.env(?:$|\?)|/index\.php/\.\./)",
        "action": "block",
        "severity": "high",
    },
    {
        "id": "builtin-hostbill-sensitive-paths",
        "name": "[HostBill] Sensitive files and directories",
        "description": "Blocks direct access to HostBill config, install/upgrade, vendor, compiled templates, attachments, downloads, and backup-like module files.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "url",
        "pattern": r"(?:/(?:hb_config\.php|includes/config\.php|install/|upgrade/|vendor/|templates_c/|attachments/|downloads/)(?:$|[/?])|/includes/(?:libs|modules|hooks)/[^?]*\.(?:bak|old|save|swp|sql)(?:$|\?))",
        "action": "block",
        "severity": "high",
    },
    {
        "id": "builtin-php-vendor-test-exposure",
        "name": "[PHP] Vendor and PHPUnit exposure",
        "description": "Blocks package-manager metadata and PHPUnit/vendor paths commonly probed across PHP applications.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": "url",
        "pattern": r"(?:/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php|/vendor/(?:phpunit|composer)(?:/|$)|/composer\.(?:json|lock)(?:$|\?))",
        "action": "block",
        "severity": "critical",
    },
]


def _safeline_rule(
    rule_id: int | str,
    name: str,
    pattern: str,
    target: str = "url",
    severity: str = "high",
    suffix: str = "",
) -> dict:
    id_suffix = f"-{suffix}" if suffix else ""
    return {
        "id": f"builtin-safeline-{rule_id}{id_suffix}",
        "name": f"[Rule {rule_id}] {name}",
        "description": f"WAF signature rule {rule_id}: {name}.",
        "builtin": True,
        "enabled": True,
        "siteId": "*",
        "matcher": "regex",
        "target": target,
        "pattern": pattern,
        "action": "block",
        "severity": severity,
    }


_HTTP_SPLITTING_PATTERN = r"(?:%0a|%0d%0a|%0a%0d|\\r\\n)(?:set-cookie|location|content-type|x-forwarded|host:)?"
_GIT_REPOSITORY_PATTERN = r"(?:/(?:\.git)(?:/|%2f)(?:config|HEAD|index|objects|refs|logs)|(?:^|/)\.git(?:$|[/?])|git-upload-pack|git-receive-pack)"
_PHP_FASTCGI_PATTERN = r"(?:\?%ad[dsc]\+|%ad(?:d|s|c|n)|\?-d\+allow_url_include|\?-s\b|\?%2dd|/[^?]+\.(?:jpg|png|gif|txt|css|js)/[^?]+\.php|PATH_INFO=.*\.php)"
_RANDOM_QUERY_PARAMETER_PATTERN = (
    r"(?:^/\?query-[0-9a-f]{8}=[^&]{0,64}(?:$|&)|[?&]query-[0-9a-f]{8}=[^&]{0,64}&query-[0-9a-f]{8}=[^&]{0,64}(?:$|&))"
)
_WOOCOMMERCE_CART_CONFLICT_PATTERN = (
    r"(?:[?&]remove_item=[0-9a-f]{32}(?:&[^#\s]*)?&add-to-cart=\d+(?:$|[&#])|[?&]add-to-cart=\d+(?:&[^#\s]*)?&remove_item=[0-9a-f]{32}(?:$|[&#]))"
)
_GHOSTSCRIPT_PATTERN = r"(?:(?:\.ps|\.eps|\.pdf)(?:$|\?|/)|-dSAFER|\.forceput|%pipe%|\.setdevice|/invalidaccess)"

# Only PHP / WordPress / Laravel / general-web SafeLine rules.
SAFELINE_COMPATIBILITY_RULES = [
    # General web attacks
    _safeline_rule(131095, "%0a permission bypass", _HTTP_SPLITTING_PATTERN, severity="medium", suffix="line-break"),
    _safeline_rule(131095, "Request to access the Git repository", _GIT_REPOSITORY_PATTERN, severity="high", suffix="git-repository"),
    _safeline_rule(131091, "Request to access the Git repository", _GIT_REPOSITORY_PATTERN, severity="high"),
    _safeline_rule(131090, "Request to access the Git repository", _GIT_REPOSITORY_PATTERN, severity="high"),
    _safeline_rule(65884, "Random query parameter probing", _RANDOM_QUERY_PARAMETER_PATTERN, severity="medium"),
    _safeline_rule(65585, "Nginx range filter overflow (CVE-2017-7529)", r"(?:bytes=0-,-|bytes=-\d+,\s*-\d+|bytes=\d+-\d+,\d+-\d+,\d+-\d+)", target="headers", severity="high"),
    _safeline_rule(65713, "Apache HTTPD SSRF (CVE-2021-40438)", r"(?:(?:unix|balancer|ajp|gopher)://|http://169\.254\.169\.254|%{REQUEST_URI}|/cgi-bin/.*proxy:)", target="all", severity="critical"),
    # Ghostscript
    _safeline_rule(131085, "CVE-2018-14715 Ghostscript Command Execution", _GHOSTSCRIPT_PATTERN, target="all", severity="critical", suffix="command-execution"),
    _safeline_rule(131085, "CVE-2018-17961 Ghostscript Arbitrary File IO", _GHOSTSCRIPT_PATTERN, target="all", severity="critical", suffix="file-io"),
    # PHP / PHP-FPM / PHP-CGI
    _safeline_rule(131088, "PHP FastCGI parsing vulnerability", _PHP_FASTCGI_PATTERN, severity="critical"),
    _safeline_rule(65849, "PHP-CGI Windows Platform Remote Code Execution Vulnerability (CVE-2024-4577)", _PHP_FASTCGI_PATTERN, severity="critical"),
    _safeline_rule(65712, "Execute PHP scripts taking advantage of Apache parsing vulnerabilities", _PHP_FASTCGI_PATTERN, severity="critical"),
    _safeline_rule(65646, "PHP code execution vulnerability", _PHP_FASTCGI_PATTERN, target="all", severity="critical"),
    _safeline_rule(65603, "CVE-2012-1823 PHP FastCGI Remote Code Execution Vulnerability", _PHP_FASTCGI_PATTERN, target="all", severity="critical"),
    _safeline_rule(65566, "PHP FPM RCE (CVE-2019-11043)", _PHP_FASTCGI_PATTERN, target="all", severity="critical"),
    _safeline_rule(65719, "phpinfo information leakage", r"(?:/phpinfo\.php|[?&](?:-s|info)=phpinfo|phpinfo\(\)|/(?:info|test)\.php(?:$|\?))", target="all", severity="medium"),
    _safeline_rule(65595, "PHPSpy backdoor", r"(?:/(?:php(?:spy|cmd|shell)|c99|r57|wso|b374k|cmdshell|antichat|shell)\.php|(?:pass|pwd|cmd)=.*(?:system|eval|assert))", target="all", severity="critical"),
    _safeline_rule(65628, "Nginx code parsing vulnerability", r"(?:/[^?]+\.(?:jpg|png|gif|txt|css|js)/[^?]+\.php|%00\.php|\.php/(?:\.\./|%2e%2e))", severity="critical"),
    # WordPress
    _safeline_rule(65885, "WooCommerce cart action conflict", _WOOCOMMERCE_CART_CONFLICT_PATTERN, severity="medium"),
    # WordPress code injection rule (65720) removed - too aggressive for modern WP.
    # wp-json/ matches ALL REST API (Gutenberg, Customizer, plugin settings).
    # action= is ubiquitous in admin-ajax.php. WP core has nonce+capability checks.
    # Laravel
    _safeline_rule(65701, "Laravel Debug Mode RCE (CVE-2021-3129)", r"(?:/_ignition/execute-solution|/vendor/facade/ignition|solution=Facade\\Ignition)", target="all", severity="critical"),
    # Other PHP apps
    _safeline_rule(65845, "Vtiger deserialization vulnerability", r"(?:/vtigercrm|/index\.php\?module=Users&action=Login|__vtrftk|file_put_contents|VtigerCRM)", target="all", severity="critical"),
    _safeline_rule(65773, "Nextcloud FileRead", r"(?:/index\.php/apps/files/.*(?:\.\./|%2e%2e)|/remote\.php/(?:dav|webdav)|/config/config\.php|/apps/files_sharing/)", severity="high"),
    _safeline_rule(65583, "Horde Groupware Webmail Edition RCE", r"(?:/horde/(?:turba/|imp/|rpc\.php|services/(?:prefs|portal))|/horde/.*(?:phpinfo|cmd=|test=))", target="all", severity="critical"),
]

def _deduplicate_safeline_rules(rules: list[dict]) -> list[dict]:
    """Merge SafeLine rules that share the same (target, pattern) into one rule.

    Keeps the first-seen rule per unique key and appends merged SafeLine IDs to
    the description so operators can still trace provenance.
    """
    seen: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for rule in rules:
        key = (rule.get("target", "url"), rule.get("pattern", ""))
        if key in seen:
            # Append the SafeLine ID from the duplicate into the kept rule's description.
            kept = seen[key]
            kept["description"] = (
                kept.get("description", "")
                + f" | also covers SL-{rule.get('id', '')}"
            ).strip(" |")
            continue
        seen[key] = rule
        order.append(key)
    return [seen[key] for key in order]

# SafeLine rule IDs that are relevant to PHP / WordPress / Laravel or general
# web attacks.  Everything else targets Java, .NET, VMware,
# F5, network appliances, etc. and is removed to reduce noise and nginx size.
_SAFELINE_KEEP_IDS: set[str] = {
    # General web attacks
    "builtin-safeline-131095-line-break",   # HTTP splitting
    "builtin-safeline-131095-git-repository",
    "builtin-safeline-131091",              # Git repository
    "builtin-safeline-131090",              # Git repository
    "builtin-safeline-131085-command-execution",  # Ghostscript
    "builtin-safeline-131085-file-io",      # Ghostscript
    "builtin-safeline-65884",               # Random query parameter probing
    "builtin-safeline-65585",               # Nginx range filter overflow
    # PHP / PHP-FPM / PHP-CGI
    "builtin-safeline-131088",              # PHP FastCGI parsing
    "builtin-safeline-65849",               # PHP-CGI Windows RCE
    "builtin-safeline-65712",               # PHP FastCGI
    "builtin-safeline-65646",               # PHP code execution
    "builtin-safeline-65603",               # PHP FastCGI RCE
    "builtin-safeline-65566",               # PHP FPM RCE
    "builtin-safeline-65719",               # phpinfo leakage
    "builtin-safeline-65595",               # PHPSpy backdoor
    "builtin-safeline-65628",               # Nginx code parsing (PHP-FPM)
    # WordPress
    "builtin-safeline-65885",               # WooCommerce cart conflict
    # WordPress code injection (65720) removed - too broad for modern WP
    # Laravel
    "builtin-safeline-65701",               # Laravel Debug Mode RCE
    # Other PHP apps
    "builtin-safeline-65845",               # Vtiger (PHP)
    "builtin-safeline-65773",               # Nextcloud (PHP)
    "builtin-safeline-65583",               # Horde Groupware (PHP)
    # Apache HTTPD (common PHP web server)
    "builtin-safeline-65713",               # Apache HTTPD SSRF
}

def _filter_safeline_rules(rules: list[dict]) -> list[dict]:
    """Keep only SafeLine rules relevant to PHP/WordPress/Laravel/general web."""
    return [rule for rule in rules if rule.get("id") in _SAFELINE_KEEP_IDS]

BUILTIN_RULES.extend(_deduplicate_safeline_rules(_filter_safeline_rules(SAFELINE_COMPATIBILITY_RULES)))


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
                    "modifyHostHeader": True,
                    "forwardedHeaders": True,
                    "hostHeader": "$http_host",
                    "xForwardedProto": "$scheme",
                    "xForwardedHost": "$http_host",
                    "proxySslServerName": True,
                },
                "modSecurity": {
                    "enabled": False,
                    "mode": "on",
                    "ruleset": "cms",
                    "requestBodyLimit": 13107200,
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
                    "rateLimitMode": "custom",
                    "waitingRoom": False,
                    "accessLimit": {
                        "enabled": True,
                        "period": 10,
                        "count": 2000,
                        "blockCount": 4000,
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
                    "geoBlock": False,
                },
                "botProtection": {
                    "enabled": True,
                    "antiBotChallenge": True,
                    "verifiedSearchBots": {
                        "enabled": True,
                        "bypassChallenge": True,
                        "bypassRateLimit": True,
                    },
                    "verifiedAIBots": {
                        "enabled": False,
                        "bypassChallenge": True,
                        "bypassRateLimit": True,
                    },
                    "loginChallenge": {
                        "enabled": True,
                        "pathPatterns": deepcopy(DEFAULT_BOT_LOGIN_PATH_PATTERNS),
                    },
                    "rateChallenge": deepcopy(DEFAULT_BOT_RATE_CHALLENGE),
                    "dynamicProtection": {
                        "enabled": False,
                        "html": False,
                        "js": False,
                        "watermark": False,
                    },
                    "antiReplay": {
                        "enabled": False,
                    },
                },
                "geoBlock": {
                    "enabled": False,
                    "countries": [],
                    "action": "block",
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
            },
            *[
                {
                    "id": provider["id"],
                    "name": provider["name"],
                    "description": provider["description"],
                    "referenceUrl": provider["referenceUrl"],
                    "items": deepcopy(provider.get("items", [])),
                    "lastSyncedAt": "",
                    "lastSyncStatus": "",
                    "lastSyncMessage": "",
                    "enabled": True,
                    "managed": True,
                    "provider": provider_name,
                    "createdAt": timestamp,
                    "updatedAt": timestamp,
                }
                for provider_name, provider in managed_verified_bot_providers().items()
            ],
        ],
        "accessRules": [
        ],
        "blockedIps": [],
        "users": [],
        "logs": [],
    }



