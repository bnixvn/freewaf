from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import os


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
        "max": 600,
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


def challenge_secret() -> str:
    return os.environ.get("FREEWAF_CHALLENGE_SECRET", "").strip() or "freewaf-development-challenge-secret"


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
        "name": f"[SafeLine {rule_id}] {name}",
        "description": f"Compatibility signature for SafeLine rule {rule_id}: {name}.",
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
_LOG4J_PATTERN = r"(?:\$\{jndi:(?:ldap|rmi|dns|iiop|http):|%24%7Bjndi%3A|jndi%3A(?:ldap|rmi|dns))"
_PHP_FASTCGI_PATTERN = r"(?:\?%ad[dsc]\+|%ad(?:d|s|c|n)|\?-d\+allow_url_include|\?-s\b|\?%2dd|/[^?]+\.(?:jpg|png|gif|txt|css|js)/[^?]+\.php|PATH_INFO=.*\.php)"
_RANDOM_QUERY_PARAMETER_PATTERN = (
    r"(?:^/\?query-[0-9a-f]{8}=[^&]{0,64}(?:$|&)|[?&]query-[0-9a-f]{8}=[^&]{0,64}&query-[0-9a-f]{8}=[^&]{0,64}(?:$|&))"
)
_WOOCOMMERCE_CART_CONFLICT_PATTERN = (
    r"(?:[?&]remove_item=[0-9a-f]{32}(?:&[^#\s]*)?&add-to-cart=\d+(?:$|[&#])|[?&]add-to-cart=\d+(?:&[^#\s]*)?&remove_item=[0-9a-f]{32}(?:$|[&#]))"
)
_GHOSTSCRIPT_PATTERN = r"(?:(?:\.ps|\.eps|\.pdf)(?:$|\?|/)|-dSAFER|\.forceput|%pipe%|\.setdevice|/invalidaccess)"
_JAVA_STRUTS_PATTERN = r"(?:(?:%24%7B|\$\{|%\{).*?(?:ognl|memberAccess|#context|#_memberAccess|com\.opensymphony|xwork|Runtime|getRuntime)|struts2|redirect(?:Action)?:)"
_WEBLOGIC_PATTERN = r"(?:/(?:wls-wsat|_async|bea_wls_internal|uddiexplorer|console)(?:/|$)|/console/.*(?:%252e%252e%252f|com\.tangosol|MVEL|ShellSession|JNDI)|T3://|weblogic)"
_JACKSON_PATTERN = r"(?:(?:\"|%22)@(?:type|class)(?:\"|%22)|enableDefaultTyping|DefaultTyping|com\.fasterxml\.jackson|TemplatesImpl|JdbcRowSetImpl|BasicDataSource|LdapAttribute|JNDIConnectionPoolDataSource)"
_SPRING_PATTERN = r"(?:/actuator/(?:env|heapdump|jolokia|logfile|refresh|restart|shutdown|gateway/routes)(?:[/?]|$)|class\.module\.classLoader|spring\.cloud\.bootstrap\.location|/oauth/.*?(?:T\(|Runtime)|jolokia.*(?:reloadByURL|createJNDIRealm))"
_NOSQL_PATTERN = r"(?:(?:[$%24](?:ne|gt|gte|lt|lte|regex|where|nin|or|and)\b)|%24(?:ne|gt|where)|\b(?:username|password)\[[^\]]+\]=|(?:\"|%22)\$(?:ne|gt|where|regex))"
_F5_BIGIP_PATTERN = r"(?:/mgmt/tm/util/(?:bash|unix-ls|qkview)|/mgmt/shared/authn/login|/mgmt/tm/ltm/(?:pool|virtual)|/tmui/login\.jsp/..;/tmui/|/tmui/.*(?:fileRead|workspace))"
_DRUPALGEDDON_PATTERN = r"(?:(?:_drupal_ajax=1|ajax_form=1).*?(?:element_parents|form_id)|element_parents=.*%23(?:value|post_render)|form_id=user_(?:register|password)_form|/user/(?:register|password).*(?:%23|#)post_render)"
_EXCHANGE_PROXY_PATTERN = r"(?:/autodiscover/autodiscover\.json.*(?:/mapi/nspi|/powershell|@)|/ecp/(?:[^/]+\.js|proxyLogon\.ecp|DDI/DDIService\.svc)|/owa/auth/Current/themes/resources/|/powershell/?\?X-Rps-CAT=)"
_EXCHANGE_RCE_PATTERN = r"(?:/ecp/default\.aspx|/ecp/[A-Za-z0-9._-]+\.js|/ews/exchange\.asmx|__VIEWSTATE=.*__VIEWSTATEGENERATOR|/autodiscover/autodiscover\.xml)"
_SHIRO_PATTERN = r"(?:rememberMe=(?:deleteMe|[A-Za-z0-9+/]{80,}=*)|JSESSIONID=.*shiro|ysoserial|CommonsCollections)"
_JENKINS_PATTERN = r"(?:/(?:jenkins/)?(?:script|scriptText|cli|securityRealm|descriptorByName|computer/.*/scriptText)(?:/|\?|$)|/jenkins/.*(?:checkScriptCompile|Stapler)|Accept-Language.*(?:\.\./|%2e%2e))"
_FASTJSON_PATTERN = r"(?:(?:\"|%22)@type(?:\"|%22)\s*:|autoType|TemplatesImpl|JdbcRowSetImpl|JndiDataSourceFactory|Inet4Address)"
_GITLAB_PATTERN = r"(?:/uploads/.*/(?:\.\./|%2e%2e)|/api/v4/projects/.*/(?:repository/files|uploads)|/users/sign_in.*(?:multipart|\.djvu)|\.djvu(?:$|\?))"
_VMWARE_SSTI_PATTERN = r"(?:/catalog-portal/ui/oauth/verify\?.*(?:deviceUdid|code)=.*(?:\$\{|freemarker|Execute)|/catalog-portal/ui/oauth/verify|/SAAS/(?:auth|API|jersey))"
_JIRA_SSRF_PATTERN = r"(?:/plugins/servlet/(?:gadgets/makeRequest|oauth/users/icon-uri|avatar|relay)|/jira/plugins/servlet/gadgets/makeRequest|[?&]url=https?://)"
_ATLASSIAN_OGNL_PATTERN = r"(?:/(?:confluence|wiki)/.*(?:%24%7B|\$\{|ognl|xwork|TextParseUtil)|/plugins/servlet/.*(?:%24%7B|\$\{))"
_IMAGE_MAGICK_PATTERN = r"(?:(?:\.mvg|\.svg)(?:$|\?)|mvg:|ephemeral:|push graphic-context|fill 'url\(|delegate|caption:|label:)"
_ACTIVEMQ_PATTERN = r"(?:/fileserver/(?:.*\.jsp|\.\.|%2e%2e)|/admin/(?:test/systemProperties\.jsp|queueBrowse)|/api/message/)"
_COUCHDB_PATTERN = r"(?:/(?:_users|_config|_replicator|_membership|_utils)(?:/|$|\?)|/_node/[^/]+/_config|/_config/.*(?:os_daemons|query_servers)|_temp_view)"
_ELASTICSEARCH_PATTERN = r"(?:/(?:_cat|_cluster|_nodes|_all|_search|_mapping|_scripts|_template|_snapshot)(?:/|\?|$)|_search.*(?:script|groovy|mvel|painless))"
_SOLR_PATTERN = r"(?:/solr/.*/(?:config|dataimport|admin/cores|debug/dump|select|schema)\b.*(?:stream\.body|dataConfig|add-listener|RunExecutableListener|VelocityResponseWriter|v\.template|<!DOCTYPE|SYSTEM)|/solr/.*/config.*add-listener)"
_NEXUS_PATTERN = r"(?:/(?:nexus/)?service/rest/(?:beta|v1)/(?:repositories|script|security|components)|/service/rapture/session|/repository/.*(?:\.\./|%2e%2e)|/nexus/service/local/)"
_APACHE_OF_BIZ_PATTERN = r"(?:/(?:webtools|control)/control/(?:forgotPassword|ProgramExport|ArtifactInfo|EntitySQLProcessor)|/webtools/control/.*(?:\.\./|%2e%2e)|/control/main/ProgramExport)"
_APACHE_AXIS_PATTERN = r"(?:/axis2?/services/(?:AdminService|Version|.*\.jws)|/axis/.*(?:AdminService|happyaxis)|/services/.*(?:xsd=|wsdl))"
_APACHE_UNOMI_PATTERN = r"(?:/context\.json|/cxs/.*(?:execute|script|groovy)|/graphql|/unomi/)"
_ZABBIX_PATTERN = r"(?:/zabbix/(?:scripts_exec\.php|host_screen\.php|jsrpc\.php|api_jsonrpc\.php).*?(?:scriptid|execute|system\.run)|/api_jsonrpc\.php.*system\.run)"
_SALTSTACK_PATTERN = r"(?:/(?:run|events|hook/.*|login|minions)(?:$|[/?]).*(?:client=(?:local|runner)&fun=)?|salt-api)"
_IIS_PATTERN = r"(?:/[^?]+\.(?:asp|aspx|cer|asa|cdx|htr)(?:;|%3b|/|%2f)|~[0-9]\.(?:asp|aspx|txt)|\*~1\*|::\$INDEX_ALLOCATION)"
_APACHE_SHIRO_PATTERN = _SHIRO_PATTERN

SAFELINE_COMPATIBILITY_RULES = [
    _safeline_rule(131095, "%0a permission bypass", _HTTP_SPLITTING_PATTERN, severity="medium", suffix="line-break"),
    _safeline_rule(131095, "Request to access the Git repository", _GIT_REPOSITORY_PATTERN, severity="high", suffix="git-repository"),
    _safeline_rule(131094, "Apache Log4j remote execution vulnerability", _LOG4J_PATTERN, target="all", severity="critical"),
    _safeline_rule(131091, "Request to access the Git repository", _GIT_REPOSITORY_PATTERN, severity="high"),
    _safeline_rule(131090, "Request to access the Git repository", _GIT_REPOSITORY_PATTERN, severity="high"),
    _safeline_rule(131088, "PHP FastCGI parsing vulnerability", _PHP_FASTCGI_PATTERN, severity="critical"),
    _safeline_rule(131085, "CVE-2018-14715 Ghostscript Command Execution", _GHOSTSCRIPT_PATTERN, target="all", severity="critical", suffix="command-execution"),
    _safeline_rule(131085, "CVE-2018-17961 Ghostscript Arbitrary File IO", _GHOSTSCRIPT_PATTERN, target="all", severity="critical", suffix="file-io"),
    _safeline_rule(131081, "Java code injection vulnerability (general defense against Struts2 vulnerabilities)", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(131080, "CVE-2018-4881 WebLogic wls9-async and wls-wsat Deserialization", _WEBLOGIC_PATTERN, target="all", severity="critical"),
    _safeline_rule(131078, "Jackson-databind deserialization (CVE-2020-36179-CVE-2020-36180)", _JACKSON_PATTERN, target="all", severity="critical"),
    _safeline_rule(131077, "Jackson-databind deserialization (CVE-2020-35490/CVE-2020-35491)", _JACKSON_PATTERN, target="all", severity="critical"),
    _safeline_rule(131076, "Jackson deserialization (CVE-2017-17485)", _JACKSON_PATTERN, target="all", severity="critical"),
    _safeline_rule(131075, "Jackson deserialization (CVE-2017-7525)", _JACKSON_PATTERN, target="all", severity="critical"),
    _safeline_rule(131074, "Spring Framework Vulnerability", _SPRING_PATTERN, target="all", severity="critical"),
    _safeline_rule(131073, "Spring Framework Vulnerability", _SPRING_PATTERN, target="all", severity="critical"),
    _safeline_rule(65884, "Random query parameter probing", _RANDOM_QUERY_PARAMETER_PATTERN, severity="medium"),
    _safeline_rule(65885, "WooCommerce cart action conflict", _WOOCOMMERCE_CART_CONFLICT_PATTERN, severity="medium"),
    _safeline_rule(65883, "RaspAP command Injection vulnerability (CVE-2021-33396)", r"(?:/ajax/networking/get_netcfg\.php|/hostapd_conf|/includes/provider\.php|interface=.*[;&|])", severity="critical"),
    _safeline_rule(65882, "Vite Arbitrary File Read Vulnerability (CVE-2025-31125)", r"(?:/@fs/(?:/)?(?:etc/passwd|proc/self/environ|[^?]*\.env)|/@id/__x00__|[?&](?:raw|import|url)\b.*(?:\.\./|%2e%2e))", severity="critical"),
    _safeline_rule(65881, "Vite Arbitrary File Read Vulnerability (CVE-2025-30208)", r"(?:/@fs/(?:/)?(?:etc/passwd|proc/self/environ|[^?]*\.env)|/@id/__x00__|[?&](?:raw|import|url)\b.*(?:\.\./|%2e%2e))", severity="critical"),
    _safeline_rule(65877, "mongodb nosql injection-json key", _NOSQL_PATTERN, target="all", severity="high"),
    _safeline_rule(65876, "mongodb nosql injection-form", _NOSQL_PATTERN, target="all", severity="high"),
    _safeline_rule(65875, "mongodb nosql injection-query", _NOSQL_PATTERN, target="all", severity="high"),
    _safeline_rule(65874, "Gitlab Arbitrary File Read Vulnerability (CVE-2020-10977)", _GITLAB_PATTERN, severity="critical"),
    _safeline_rule(65873, "Pulse Secure SSL VPN Command Injection Vulnerability (CVE-2019-11539)", r"(?:/dana/(?:html5acc/guacamole/|admin/diag/diag\.cgi|meeting/meeting_testjs\.cgi)|/dana-na/\.\./dana/html5acc|/dana/html5acc/guacamole/.*[;&|])", severity="critical"),
    _safeline_rule(65869, "F5 BIG-IP iControl REST code execution vulnerability", _F5_BIGIP_PATTERN, target="all", severity="critical"),
    _safeline_rule(65854, "Joomla 3.4.6 remote code execution vulnerability", r"(?:/index\.php(?:\?option=com_users&view=registration|/component/users/)|(?:jform|user)\[groups\]|%7B%7B.*jndi)", target="all", severity="critical"),
    _safeline_rule(65849, "PHP-CGI Windows Platform Remote Code Execution Vulnerability (CVE-2024-4577)", _PHP_FASTCGI_PATTERN, severity="critical"),
    _safeline_rule(65848, "Spring Boot Actuator Sensitive Information Leakage Vulnerability", _SPRING_PATTERN, target="all", severity="high"),
    _safeline_rule(65847, "D-Link D-View 8 v2.0.1.28 unauthorized access (CVE-2023-5074)", r"(?:/dview8|/DView8|/api/(?:login|users|devices)|/cgi-bin/.*DView|D-Link D-View)", severity="high"),
    _safeline_rule(65846, "Apache OfBiz Arbitrary File Reading Vulnerability (CVE-2023-50968)", _APACHE_OF_BIZ_PATTERN, severity="critical"),
    _safeline_rule(65845, "Vtiger deserialization vulnerability", r"(?:/vtigercrm|/index\.php\?module=Users&action=Login|__vtrftk|file_put_contents|VtigerCRM)", target="all", severity="critical"),
    _safeline_rule(65844, "Apache solr XML entity injection vulnerability (CVE-2017-12629)", _SOLR_PATTERN, target="all", severity="critical"),
    _safeline_rule(65837, "F5 BIG-IP Vulnerability", _F5_BIGIP_PATTERN, target="all", severity="critical"),
    _safeline_rule(65836, "F5 BIG-IP Vulnerability", _F5_BIGIP_PATTERN, target="all", severity="critical"),
    _safeline_rule(65835, "F5 BIG-IP Vulnerability", _F5_BIGIP_PATTERN, target="all", severity="critical"),
    _safeline_rule(65832, "Kibana UI message RCE (CVE-2023-25251)", r"(?:/app/kibana.*(?:Timelion|\.es\(|props\.label|constructor\.constructor)|/api/console/proxy|/api/timelion/run|CVE-2023-25251)", target="all", severity="critical"),
    _safeline_rule(65827, "D-Link Remote Code Execution (CVE-2019-16920)", r"(?:/cgi-bin/webproc|/apply_sec\.cgi|/HNAP1/|(?:command|cmd)=.*(?:telnetd|wget|curl))", target="all", severity="critical"),
    _safeline_rule(65825, "Oracle E-Business Suite XXE information leakage vulnerability", r"(?:/OA_HTML/(?:BneViewerXMLService|BneUploaderService|FNDWRR|jtfLOVInProcess\.jsp|frmservlet)|<!DOCTYPE|%3C!DOCTYPE|SYSTEM)", target="all", severity="critical"),
    _safeline_rule(65823, "MinIO information leakage vulnerability (CVE-2023-28432)", r"(?:/minio/bootstrap/v1/verify|/minio/admin/v3/(?:info|update|profile)|/api/v1/login/oauth2/auth)", severity="high"),
    _safeline_rule(65808, "MobileIron Unauthorized Access (CVE-2020-15506)", r"(?:/mifs/.*/api/v2/|/mifs/rs/api/v2/featureusage|/mifs/.*/download/)", severity="critical"),
    _safeline_rule(65787, "Kentico CMS RCE (CVE-2019-10068)", r"(?:/CMSPages/(?:PortalTemplate\.aspx|GetResource\.ashx)|/CMSModules/AdminControls/Controls/UIControls/ExportObject\.aspx|cms\.documentengine)", target="all", severity="critical"),
    _safeline_rule(65778, "Adobe ColdFusion deserialization (CVE-2023-26359)", r"(?:/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/|/CFIDE/(?:administrator|wizards|componentutils|adminapi)|/flex2gateway/amf|\.cfc(?:\?|/))", target="all", severity="critical"),
    _safeline_rule(65773, "Nextcloud FileRead", r"(?:/index\.php/apps/files/.*(?:\.\./|%2e%2e)|/remote\.php/(?:dav|webdav)|/config/config\.php|/apps/files_sharing/)", severity="high"),
    _safeline_rule(65772, "Pentaho BA Server RCE (CVE-2022-43769)", r"(?:/pentaho/(?:api/repos|plugin|content|ViewAction|Xmla)|/kettle/.*(?:exec|runTrans)|/api/repos/.*(?:\.xaction|parameterProvider))", target="all", severity="critical"),
    _safeline_rule(65769, "eQ-3 Homematic RCE (CVE-2021-33032)", r"(?:/addons/xmlapi/|/config/xmlapi/|/pages/jpages/system/|/esp/system\.htm|sid=@.*[;&|])", target="all", severity="critical"),
    _safeline_rule(65768, "eQ-3 Homematic RCE (CVE-2019-14985)", r"(?:/addons/xmlapi/|/config/xmlapi/|/pages/jpages/system/|/esp/system\.htm|sid=@.*[;&|])", target="all", severity="critical"),
    _safeline_rule(65767, "GeneACS Command Injection (CVE-2021-46704)", r"(?:/genieacs|/cwmp|/api/devices/.*(?:ping|traceroute|diagnostics)|(?:ping_host|traceRouteHost)=.*[;&|])", target="all", severity="critical"),
    _safeline_rule(65766, "Gogs unauthorized access", r"(?:/api/v1/users/search|/repo/.*/raw/.*(?:\.\./|%2e%2e)|/user/login.*remember|/gogs/)", severity="high"),
    _safeline_rule(65762, "Draytek CODE INJECTION (CVE-2020-8515)", r"(?:/(?:cgi-bin/)?mainfunction\.cgi|/goform/.*(?:sysTools|diag)|(?:action|cmd)=.*(?:ping|traceroute).*[;&|])", target="all", severity="critical"),
    _safeline_rule(65761, "Atlassian Crowd Unauthorized Access (CVE-2019-11580)", r"(?:/crowd/(?:admin|console|rest/usermanagement/latest)|/plugins/servlet/embedded-crowd|/crowd/services/SecurityServer)", severity="critical"),
    _safeline_rule(65759, "Struts2 Remote Code Execution (CVE-2017-5638)", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65751, "Microsoft ProxyNotShell SSRF (CVE-2022-41040)", _EXCHANGE_PROXY_PATTERN, severity="critical"),
    _safeline_rule(65749, "Python Dangerous Function", r"(?:__import__\(|eval\(|exec\(|pickle\.loads|os\.system|subprocess\.(?:Popen|call)|input=__import__)", target="all", severity="critical"),
    _safeline_rule(65748, "Reolink RCE (CVE-2018-16763)", r"(?:/cgi-bin/api\.cgi.*(?:cmd=Login|cmd=GetDevInfo|cmd=SetUser|cmd=Upgrade)|/cgi-bin/api\.cgi.*[;&|])", target="all", severity="critical"),
    _safeline_rule(65747, "RichFaces RCE (CVE-2018-14667)", r"(?:/(?:a4j|richfaces)/(?:.*\.jsf|.*org\.richfaces\.resource)|javax\.faces\.ViewState|rfRes)", target="all", severity="critical"),
    _safeline_rule(65746, "OpenTSDB 2.4.0 Remote Code Execution (CVE-2020-35476)", r"(?:/api/(?:suggest|query|put|aggregators)|/q\?.*(?:m=|start=).*?(?:%60|;|%7C|\$\()|/api/uid/assign)", target="all", severity="critical"),
    _safeline_rule(65745, "Atlassian Jira Server Limited Remote File Read Include (CVE-2021-26086)", r"(?:/s/.*/_/download/(?:resources|batch)/.*(?:WEB-INF|%2e%2e|\.vm)|/plugins/servlet/.*(?:\.\./|%2e%2e))", severity="high"),
    _safeline_rule(65744, "Joomla Unauthorized access (CVE-2023-23752)", r"(?:/api/index\.php/v1/(?:config/application|users|banners|contacts)|/index\.php/v1/config/application)", severity="critical"),
    _safeline_rule(65742, "F5 BIG-IP Format String Vulnerability (CVE-2023-22374)", _F5_BIGIP_PATTERN, target="all", severity="critical"),
    _safeline_rule(65741, "Nexus Repository Manager 3 Execution (CVE-2020-10204)", _NEXUS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65740, "Apache Unomi Code Execution (CVE-2020-13942)", _APACHE_UNOMI_PATTERN, target="all", severity="critical"),
    _safeline_rule(65739, "ImageMagick DoS Attack (CVE-2022-44267)", _IMAGE_MAGICK_PATTERN, target="all", severity="high"),
    _safeline_rule(65738, "Apache Kylin Remote Code Execution (CVE-2023-29012)", r"(?:/kylin/api/(?:admin|diag|cube|query|user)|/kylin/api/admin/config|project=.*[;&|])", target="all", severity="critical"),
    _safeline_rule(65737, "Microsoft PowerShell Code Execution (CVE-2022-41076)", r"(?:/powershell(?:/|\?|$)|New-Object|Invoke-Expression|IEX|DownloadString|FromBase64String|Start-Process|EncodedCommand)", target="all", severity="critical"),
    _safeline_rule(65735, "Jackson deserialization code execution vulnerability (CVE-2020-36188)", _JACKSON_PATTERN, target="all", severity="critical"),
    _safeline_rule(65734, "Microsoft Exchange Server Code Execution (CVE-2021-42321)", _EXCHANGE_RCE_PATTERN, severity="critical"),
    _safeline_rule(65733, "Microsoft Exchange Code Execution (CVE-2020-16875)", _EXCHANGE_RCE_PATTERN, severity="critical"),
    _safeline_rule(65732, "Microsoft Exchange Server Code Execution (CVE-2021-28482)", _EXCHANGE_RCE_PATTERN, severity="critical"),
    _safeline_rule(65731, "Microsoft Exchange ProxyShell Code Execution (CVE-2021-34473)", _EXCHANGE_PROXY_PATTERN, severity="critical"),
    _safeline_rule(65730, "Microsoft Exchange ProxyLogon SSRF (CVE-2021-26855)", _EXCHANGE_PROXY_PATTERN, severity="critical"),
    _safeline_rule(65729, "Microsoft SharePoint Code Execution (CVE-2020-1181)", r"(?:/_layouts/15/(?:ToolPane\.aspx|Authenticate\.aspx|download\.aspx)|/sites/.*/_api/web/|/sharepoint/.*(?:%24%7B|\$\{|cmd=))", target="all", severity="critical"),
    _safeline_rule(65728, "XStream deserialization code execution vulnerability (CVE-2021-29505)", r"(?:<map>|<sorted-set>|<java\.lang\.ProcessBuilder>|<void method=\"start\"|javax\.script\.ScriptEngineManager|com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.TemplatesImpl|xstream)", target="all", severity="critical"),
    _safeline_rule(65727, "Citrix Unauthorized API", r"(?:/vpn/\.\./vpns/|/vpns/(?:cfg/smb\.conf|portal/scripts/newbm\.pl|ns_gui/)|/nitro/v1/config/.*(?:filelocation|systemfile)|/cgi/setclient\?wica)", severity="critical"),
    _safeline_rule(65725, "Microsoft Exchange Code Execution (CVE-2020-0688)", _EXCHANGE_RCE_PATTERN, severity="critical"),
    _safeline_rule(65720, "Code Injection vulnerability (against WordPress)", r"(?:/(?:wp-admin/admin-ajax\.php|wp-json/|wp-content/plugins/[^?]+/(?:ajax|upload|download))(?:[^\s]*(?:[?&](?:action|cmd|exec|page|include|file|path|load)=|/)(?:assert|eval|system|exec|passthru|shell_exec|popen|proc_open)|[^\s]*<(?:php|script|\?))|(?:action|cmd|exec|page|include|file)=.*(?:assert|eval|system|exec|passthru|shell_exec|popen|proc_open|preg_replace))", target="all", severity="critical"),
    _safeline_rule(65719, "phpinfo information leakage", r"(?:/phpinfo\.php|[?&](?:-s|info)=phpinfo|phpinfo\(\)|/(?:info|test)\.php(?:$|\?))", target="all", severity="medium"),
    _safeline_rule(65715, "WebLogic console Remote Code Execution (CVE-2020-14882)", _WEBLOGIC_PATTERN, target="all", severity="critical"),
    _safeline_rule(65713, "Apache HTTPD SSRF (CVE-2021-40438)", r"(?:(?:unix|balancer|ajp|gopher)://|http://169\.254\.169\.254|%{REQUEST_URI}|/cgi-bin/.*proxy:)", target="all", severity="critical"),
    _safeline_rule(65712, "Execute PHP scripts taking advantage of Apache parsing vulnerabilities", _PHP_FASTCGI_PATTERN, severity="critical"),
    _safeline_rule(65711, "Apache AXIS remote execution vulnerability", _APACHE_AXIS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65710, "Drupalgeddon2 - Drupal Core Remote Code Execution", _DRUPALGEDDON_PATTERN, target="all", severity="critical"),
    _safeline_rule(65709, "Drupalgeddon2 - Drupal Core Remote Code Execution", _DRUPALGEDDON_PATTERN, target="all", severity="critical"),
    _safeline_rule(65708, "Drupalgeddon2 - Drupal Core Remote Code Execution", _DRUPALGEDDON_PATTERN, target="all", severity="critical"),
    _safeline_rule(65707, "Drupal Mail Command Injection", r"(?:/user/password.*(?:name%5B%23post_render%5D|mail%5B%23type%5D)|mail\[#post_render\]|sendmail_path)", target="all", severity="critical"),
    _safeline_rule(65706, "Drupal core remote code execution vulnerability (CVE-2018-7602)", _DRUPALGEDDON_PATTERN, target="all", severity="critical"),
    _safeline_rule(65701, "Laravel Debug Mode RCE (CVE-2021-3129)", r"(?:/_ignition/execute-solution|/vendor/facade/ignition|solution=Facade\\Ignition)", target="all", severity="critical"),
    _safeline_rule(65700, "Apache Solr Remote Code Execution (CVE-2019-0192)", _SOLR_PATTERN, target="all", severity="critical"),
    _safeline_rule(65699, "Apache Solr Remote Code Execution (CVE-2019-0193)", _SOLR_PATTERN, target="all", severity="critical"),
    _safeline_rule(65698, "F5 BIG-IP information bypass vulnerability (CVE-2018-9905)", _F5_BIGIP_PATTERN, target="all", severity="high"),
    _safeline_rule(65697, "CVE-2018-18925 Jenkins Accept-Language Information Leakage", r"(?:\.\./|\.\.%2f|%2e%2e).*?(?:plugins|resource|WEB-INF)|(?:zh-cn|en-us).*(?:\.\./|%2e%2e)", target="headers", severity="medium"),
    _safeline_rule(65696, "Joomla remote code execution", r"(?:/index\.php(?:\?option=com_users&view=registration|/component/users/)|(?:jform|user)\[groups\]|%7B%7B.*jndi)", target="all", severity="critical"),
    _safeline_rule(65695, "Joomla remote code execution", r"(?:/index\.php(?:\?option=com_users&view=registration|/component/users/)|(?:jform|user)\[groups\]|%7B%7B.*jndi)", target="all", severity="critical"),
    _safeline_rule(65694, "F5 BIG-IP RCE (CVE-2021-22986)", _F5_BIGIP_PATTERN, target="all", severity="critical"),
    _safeline_rule(65693, "F5 BIG-IP Vulnerability", _F5_BIGIP_PATTERN, target="all", severity="critical"),
    _safeline_rule(65692, "F5 BIG-IP Vulnerability", _F5_BIGIP_PATTERN, target="all", severity="critical"),
    _safeline_rule(65691, "VMware ACL bypass (CVE-2022-22972)", r"(?:/SAAS/(?:jersey/manager/api/system/properties|auth/login/embeddedauthbroker/callback|t/.*/auth/login)|/SAAS/API/1\.0/REST/system/health)", severity="critical"),
    _safeline_rule(65689, "Weblogic Server information leaks", _WEBLOGIC_PATTERN, target="all", severity="high"),
    _safeline_rule(65688, "Weblogic Server information leaks (CVE-2022-21371)", _WEBLOGIC_PATTERN, target="all", severity="high"),
    _safeline_rule(65687, "VMware SSTI (CVE-2022-22954)", _VMWARE_SSTI_PATTERN, target="all", severity="critical"),
    _safeline_rule(65686, "VMware SSTI (CVE-2022-22954)", _VMWARE_SSTI_PATTERN, target="all", severity="critical"),
    _safeline_rule(65682, "VMware vRealize SSRF (CVE-2021-21975)", r"(?:/casa/(?:nodes/thumbprints|security/config)|/SAAS/API/1\.0/REST/system/health|[?&]url=http)", target="all", severity="critical"),
    _safeline_rule(65681, "VMware SSRF XSS", r"(?:/SAAS/.*(?:url=|redirect=|<script|%3Cscript)|/vcac/.*(?:url=|redirect=))", target="all", severity="high"),
    _safeline_rule(65680, "VMware arbitrary file reading", r"(?:/eam/vib\?.*(?:\.\./|%2e%2e)|/ui/.*(?:\.\./|%2e%2e)|/SAAS/.*(?:\.\./|%2e%2e))", severity="high"),
    _safeline_rule(65678, "Gitlab extract RCE (CVE-2021-22205)", _GITLAB_PATTERN, target="all", severity="critical"),
    _safeline_rule(65677, "Gitlab exploit RCE (CVE-2021-22205)", _GITLAB_PATTERN, target="all", severity="critical"),
    _safeline_rule(65674, "Zyxel NBG2105 vulnerability (CVE-2021-3295)", r"(?:/cgi-bin/Export_Log|/goform/.*(?:setSysAdm|diagnostic)|/Forms/.*(?:ping|nslookup))", target="all", severity="critical"),
    _safeline_rule(65673, "Apache Solr SSRF vulnerability (CVE-2021-27905)", _SOLR_PATTERN, target="all", severity="critical"),
    _safeline_rule(65668, "VMware Workspace ONE UEM SSRF (CVE-2021-22054)", r"(?:/AirWatch/(?:OAuth|DeviceManagement|api)|/Catalog-Portal/|/awcm/.*url=)", target="all", severity="critical"),
    _safeline_rule(65667, "Spring Cloud Config Directory Traversal (CVE-2020-5405)", r"(?:/(?:application|default|master|main)/(?:\.\.%252F|%2e%2e|%252e%252e)|/actuator/env.*spring\.cloud\.config)", severity="critical"),
    _safeline_rule(65666, "Spring Framework Vulnerability", _SPRING_PATTERN, target="all", severity="critical"),
    _safeline_rule(65665, "Spring Framework Vulnerability", _SPRING_PATTERN, target="all", severity="critical"),
    _safeline_rule(65664, "Spring Framework Vulnerability", _SPRING_PATTERN, target="all", severity="critical"),
    _safeline_rule(65663, "Spring Framework Vulnerability", _SPRING_PATTERN, target="all", severity="critical"),
    _safeline_rule(65662, "Spring Framework Vulnerability", _SPRING_PATTERN, target="all", severity="critical"),
    _safeline_rule(65661, "Spring Framework Vulnerability", _SPRING_PATTERN, target="all", severity="critical"),
    _safeline_rule(65660, "Spring file directory traversal (CVE-2014-3625)", r"(?:/static/.*(?:\.\./|%2e%2e)|/resources/.*(?:\.\./|%2e%2e)|/spring/.*(?:\.\./|%2e%2e))", severity="high"),
    _safeline_rule(65659, "Jackson deserialization", _JACKSON_PATTERN, target="all", severity="critical"),
    _safeline_rule(65656, "Jenkins remote code execution vulnerability (CVE-2018-1000861)", _JENKINS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65655, "CVE-2018-1999001 Jenkins Administrator Privilege Public", _JENKINS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65654, "SECURITY-595 Jenkins Unexpected Method Call Vulnerability", _JENKINS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65653, "Atlassian Jira SSRF (CVE-2022-26135)", _JIRA_SSRF_PATTERN, target="all", severity="critical"),
    _safeline_rule(65652, "Atlassian vulnerability", _ATLASSIAN_OGNL_PATTERN, target="all", severity="critical"),
    _safeline_rule(65651, "Java code injection vulnerability (general defense against Struts 2 vulnerabilities)", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65646, "PHP code execution vulnerability", _PHP_FASTCGI_PATTERN, target="all", severity="critical"),
    _safeline_rule(65645, "Struts2 Java Code Injection Vulnerability", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65644, "Struts2 S2-016", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65643, "Struts2 S2-008", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65642, "Fastjson deserialization code execution vulnerability", _FASTJSON_PATTERN, target="all", severity="critical"),
    _safeline_rule(65641, "Apache Log4j remote execution vulnerability", _LOG4J_PATTERN, target="all", severity="critical"),
    _safeline_rule(65637, "Java code Injection vulnerability (general defense against Struts 2 vulnerabilities)", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65636, "Java code Injection vulnerability (general defense against Struts 2 vulnerabilities)", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65635, "Struts2 S2-020", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65629, "Apache Druid remote execution vulnerability", r"(?:/druid/(?:indexer|coordinator|overlord|router|console)|/status/selfDiscovered/status|/proxy/coordinator|/druid/.*(?:javascript|script))", target="all", severity="critical"),
    _safeline_rule(65628, "Nginx code parsing vulnerability", r"(?:/[^?]+\.(?:jpg|png|gif|txt|css|js)/[^?]+\.php|%00\.php|\.php/(?:\.\./|%2e%2e))", severity="critical"),
    _safeline_rule(65627, "Oracle Access Manager RCE (CVE-2021-35587)", r"(?:/oam/server/(?:obrareq\.cgi|opensso/sessionservice|authentication|login)|/iam/governance/.*(?:\.\.|%2e%2e))", severity="critical"),
    _safeline_rule(65625, "Sitecore XP RCE (CVE-2021-42237)", r"(?:/sitecore/(?:shell|admin|api/ssc|service/.*\.asmx)|/-/xaml/|sitecore_xaml)", target="all", severity="critical"),
    _safeline_rule(65624, "Total.js RCE (CVE-2021-23389)", r"(?:/api/(?:upload|exec|shell)|/total\.js|[?&](?:cmd|command)=.*(?:require\(|child_process|eval))", target="all", severity="critical"),
    _safeline_rule(65623, "Zabbix 5.0.17 Remote Code Execution (Authenticated)", _ZABBIX_PATTERN, target="all", severity="critical"),
    _safeline_rule(65622, "VMware vCenter Server RCE (CVE-2021-21985)", r"(?:/ui/vropspluginui/rest/services/(?:uploadova|query|getstatus)|/analytics/telemetry/ph/api/hyper/send)", target="all", severity="critical"),
    _safeline_rule(65621, "GoAhead Server environment variable injection (CVE-2021-42342)", r"(?:/cgi-bin/.*(?:LD_PRELOAD|LD_LIBRARY_PATH|REMOTE_HOST)|/goform/.*(?:cmd|command)=)", target="all", severity="critical"),
    _safeline_rule(65620, "SolarWinds remote execution vulnerability (CVE-2020-10148)", r"(?:/Orion/(?:Login\.aspx|Services/|i18n\.ashx)|/WebResource\.axd\?d=|/SWNetPerfMon\.db)", severity="critical"),
    _safeline_rule(65619, "SaltStack vulnerability (CVE-2020-16846,CVE-2020-17490,CVE-2020-25592)", _SALTSTACK_PATTERN, target="all", severity="critical"),
    _safeline_rule(65616, "Microsoft SQL Server remote execution vulnerability (CVE-2020-0618)", r"(?:/ReportServer/(?:Pages/ReportViewer\.aspx|ReportService2010\.asmx)|/Reports/(?:browse|powerbi)|rs:Command=Render)", target="all", severity="critical"),
    _safeline_rule(65615, "WebSphere privilege escalation vulnerability (CVE-2020-4276)", r"(?:/ibm/console|/wps/portal|/wsadmin|/adminCenter|/ibm/console/logon\.jsp)", severity="critical"),
    _safeline_rule(65614, "Microsoft Exchange remote execution vulnerability (CVE-2020-16875)", _EXCHANGE_RCE_PATTERN, severity="critical"),
    _safeline_rule(65612, "SAP NetWeaver AS JAVA Vulnerability (CVE-2020-6287)", r"(?:/CTCWebService/CTCWebServiceBean|/ctc/servlet/|/irj/portal|/sap/bc/)", severity="critical"),
    _safeline_rule(65608, "F5 BIG-IP remote execution vulnerability (CVE-2020-5902)", _F5_BIGIP_PATTERN, target="all", severity="critical"),
    _safeline_rule(65607, "Drupal PHP Code Execution vulnerability", _DRUPALGEDDON_PATTERN, target="all", severity="critical"),
    _safeline_rule(65606, "Apache Shiro vulnerability (CVE-2020-17523)", _APACHE_SHIRO_PATTERN, target="headers", severity="critical"),
    _safeline_rule(65605, "Apache Shiro vulnerability (CVE-2020-13933)", _APACHE_SHIRO_PATTERN, target="headers", severity="critical"),
    _safeline_rule(65603, "CVE-2012-1823 PHP FastCGI Remote Code Execution Vulnerability", _PHP_FASTCGI_PATTERN, target="all", severity="critical"),
    _safeline_rule(65602, "IIS file extension vulnerability", _IIS_PATTERN, severity="high"),
    _safeline_rule(65601, "Scan IIS short filename / folder", _IIS_PATTERN, severity="medium"),
    _safeline_rule(65600, "Scan IIS short filename / folder", _IIS_PATTERN, severity="medium"),
    _safeline_rule(65599, "CVE-2018-18925 Gogs, Gitea Remote Code Execution Vulnerability", r"(?:/(?:gogs|gitea)/.*(?:repo|hook|api)|/api/v1/repos/.*/hooks|/user/events.*(?:\.\./|%2e%2e))", target="all", severity="critical"),
    _safeline_rule(65598, "Fastjson deserialization code execution vulnerability", _FASTJSON_PATTERN, target="all", severity="critical"),
    _safeline_rule(65595, "PHPSpy backdoor", r"(?:/(?:php(?:spy|cmd|shell)|c99|r57|wso|b374k|cmdshell|antichat|shell)\.php|(?:pass|pwd|cmd)=.*(?:system|eval|assert))", target="all", severity="critical"),
    _safeline_rule(65590, "CVE-2019-7238 Nexus Repository Manager 3 Remote Code Execution", _NEXUS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65586, "ActiveMQ Arbitrary File Write Vulnerability (CVE-2016-3088)", _ACTIVEMQ_PATTERN, target="all", severity="critical"),
    _safeline_rule(65585, "Nginx range filter overflow (CVE-2017-7529)", r"(?:bytes=0-,-|bytes=-\d+,\s*-\d+|bytes=\d+-\d+,\d+-\d+,\d+-\d+)", target="headers", severity="high"),
    _safeline_rule(65583, "Horde Groupware Webmail Edition RCE", r"(?:/horde/(?:turba/|imp/|rpc\.php|services/(?:prefs|portal))|/horde/.*(?:phpinfo|cmd=|test=))", target="all", severity="critical"),
    _safeline_rule(65582, "Kibana RCE (CVE-2019-7609)", r"(?:/app/kibana.*(?:Timelion|\.es\(|props\.label|constructor\.constructor)|/api/console/proxy|/api/timelion/run)", target="all", severity="critical"),
    _safeline_rule(65581, "Tomcat RCE (CVE-2019-0232)", r"(?:/cgi-bin/.*(?:\?|%20|%09).*(?:cmd=|&|%26)|/manager/html(?:/upload|/undeploy|/deploy))", target="all", severity="critical"),
    _safeline_rule(65580, "Druid unauthorized access", r"(?:/druid/(?:indexer|coordinator|overlord|router|console)|/status/selfDiscovered/status|/proxy/coordinator)", severity="high"),
    _safeline_rule(65579, "Mura CMS RCE", r"(?:/index\.cfm/_api/json/v1/default/\?method=processAsyncObject|/admin/\?muraAction=|/plugins/.*\.cfm)", target="all", severity="critical"),
    _safeline_rule(65577, "Palo Alto Global Protect SSL RCE (CVE-2019-1579)", r"(?:/global-protect/(?:login\.esp|portal|prelogin\.esp)|/ssl-vpn/.*(?:\.\./|%2e%2e)|/esp/cms_changeDeviceContext\.esp)", severity="critical"),
    _safeline_rule(65576, "HFS RCE", r"(?:\?search=%00|%00\{\.exec|/\?mode=section&id=)", target="all", severity="critical"),
    _safeline_rule(65575, "Kibana RCE (CVE-2019-7609)", r"(?:/app/kibana.*(?:Timelion|\.es\(|props\.label|constructor\.constructor)|/api/console/proxy|/api/timelion/run)", target="all", severity="critical"),
    _safeline_rule(65573, "Gitlab LFI RCE", _GITLAB_PATTERN, target="all", severity="critical"),
    _safeline_rule(65572, "Gitlab file access (CVE-2017-0915, CVE-2016-9086)", _GITLAB_PATTERN, severity="high"),
    _safeline_rule(65570, "Webmin RCE (CVE-2019-15107)", r"(?:/password_change\.cgi.*(?:expired|old=|new1=)|/session_login\.cgi|/rpc\.cgi)", target="all", severity="critical"),
    _safeline_rule(65567, "Apache Shiro deserialization attack (CVE-2016-4437)", _APACHE_SHIRO_PATTERN, target="headers", severity="critical"),
    _safeline_rule(65566, "PHP FPM RCE (CVE-2019-11043)", _PHP_FASTCGI_PATTERN, target="all", severity="critical"),
    _safeline_rule(65565, "Apache Spark unauthorized access", r"(?:/(?:jobs|stages|storage|environment|executors|api/v1/applications)(?:/|$)|/v1/submissions/(?:create|kill|status))", severity="high"),
    _safeline_rule(65564, "Nexus default login unauthorized access (CVE-2020-10199, CVE-2019-7238)", _NEXUS_PATTERN, severity="high"),
    _safeline_rule(65563, "GoAhead RCE (CVE-2017-17562)", r"(?:/cgi-bin/.*(?:LD_PRELOAD|LD_LIBRARY_PATH|REMOTE_HOST)|/goform/.*(?:cmd|command)=)", target="all", severity="critical"),
    _safeline_rule(65562, "ffmpeg SSRF (CVE-2016-1898)", r"(?:(?:concat|subfile|gopher|file):|http://169\.254\.169\.254).*(?:\.m3u8|\.mpd|ffmpeg|url=)", target="all", severity="high"),
    _safeline_rule(65561, "ffmpeg file reading (CVE-2016-1897)", r"(?:(?:concat|subfile|file):|/etc/passwd).*(?:\.m3u8|\.mpd|ffmpeg|url=)", target="all", severity="high"),
    _safeline_rule(65560, "Couchdb command execution (CVE-2017-12636)", _COUCHDB_PATTERN, target="all", severity="critical"),
    _safeline_rule(65559, "Couchdb vertical access controls (2) (CVE-2017-12635)", _COUCHDB_PATTERN, severity="high"),
    _safeline_rule(65558, "Couchdb vertical access controls (1) (CVE-2017-12635)", _COUCHDB_PATTERN, severity="high"),
    _safeline_rule(65557, "Couchdb vertical access controls (1) (CVE-2017-12635)", _COUCHDB_PATTERN, severity="high"),
    _safeline_rule(65556, "ActiveMQ file writing vulnerability (CVE-2016-3088)", _ACTIVEMQ_PATTERN, target="all", severity="critical"),
    _safeline_rule(65555, "ElasticSearch command execute (CVE-2015-1427)", _ELASTICSEARCH_PATTERN, target="all", severity="critical"),
    _safeline_rule(65554, "ElasticSearch unauthorized access", _ELASTICSEARCH_PATTERN, severity="high"),
    _safeline_rule(65553, "Spring RCE (CVE-2018-1270)", _SPRING_PATTERN, target="all", severity="critical"),
    _safeline_rule(65552, "Spring Data Rest RCE (CVE-2017-8046)", _SPRING_PATTERN, target="all", severity="critical"),
    _safeline_rule(65550, "S2-005 (2) (CVE-2010-1870)", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65549, "S2-005 (1) (CVE-2010-1870)", _JAVA_STRUTS_PATTERN, target="all", severity="critical"),
    _safeline_rule(65548, "ImageMagick RCE (CVE-2016-3714)", _IMAGE_MAGICK_PATTERN, target="all", severity="critical"),
    _safeline_rule(65547, "WebLogic weak password", r"(?:/console/(?:login/LoginForm\.jsp|j_security_check)|j_username=weblogic|j_password=(?:weblogic|welcome1|password))", target="all", severity="high"),
    _safeline_rule(65546, "JIRA SSRF (CVE-2019-8451)", _JIRA_SSRF_PATTERN, target="all", severity="critical"),
    _safeline_rule(65545, "JIRA OAuth SSRF (CVE-2017-9506)", _JIRA_SSRF_PATTERN, target="all", severity="critical"),
]

BUILTIN_RULES.extend(SAFELINE_COMPATIBILITY_RULES)


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
                        "count": 500,
                        "blockCount": 1200,
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
                        "allowedProviders": [],
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
        "accessRules": [],
        "users": [],
        "logs": [],
    }
