from __future__ import annotations

import json
import os
import re
import threading
import uuid
import ipaddress
import base64
import hashlib
import hmac
import secrets
import struct
import time
from collections import Counter
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from .defaults import BUILTIN_RULES, DEFAULT_SETTINGS, create_default_state, utc_now


ACTIONS = {"allow", "block", "monitor"}
MATCHERS = {"regex", "contains", "equals"}
MODES = {"block", "monitor"}
TARGETS = {"all", "url", "headers", "body", "method", "ip"}
SEVERITIES = {"low", "medium", "high", "critical"}
ACCESS_ACTIONS = {"allow", "deny", "monitor"}
ACL_ACTIONS = {"allow", "block", "challenge_v1", "monitor"}
ACL_RATE_LIMIT_MODES = {"global", "custom"}
APPLICATION_TYPES = {"reverse_proxy", "static_files", "redirect"}
ACCESS_CONDITION_TARGETS = {"source_ip", "uri", "host", "user_agent", "method"}
ACCESS_CONDITION_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "regex",
    "not_regex",
    "cidr",
    "not_cidr",
    "in_ip_group",
    "not_in_ip_group",
}
ACCESS_INSERT_POSITIONS = {"first", "last"}
USER_ROLES = {"admin", "viewer"}
PASSWORD_ITERATIONS = 200_000


class StoreError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Store:
    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)
        self.state: dict | None = None
        self.lock = threading.RLock()

    def init(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.file_path.exists():
            self.state = create_default_state()
            self.persist()
            return

        with self.file_path.open("r", encoding="utf-8") as handle:
            raw_state = json.load(handle)
        self.state = normalize_state(raw_state)

        changed = self.state != raw_state
        now = utc_now()
        existing = {rule["id"] for rule in self.state["rules"]}
        for rule in BUILTIN_RULES:
            if rule["id"] not in existing:
                self.state["rules"].append({**deepcopy(rule), "createdAt": now, "updatedAt": now})
                changed = True

        if not self.state["ipGroups"]:
            self.state["ipGroups"].append(
                {
                    "id": "ipgroup-local",
                    "name": "Local addresses",
                    "description": "Loopback addresses useful for local testing.",
                    "items": ["127.0.0.1/32", "::1/128"],
                    "enabled": True,
                    "createdAt": now,
                    "updatedAt": now,
                }
            )
            changed = True

        for index, group in enumerate(self.state["ipGroups"]):
            prepared = self.prepare_ip_group_storage(group)
            if prepared != group:
                self.state["ipGroups"][index] = prepared
                changed = True

        if changed:
            self.persist()

    def get_state(self) -> dict:
        with self.lock:
            return deepcopy(self._state())

    def persist(self) -> None:
        with self.lock:
            payload = json.dumps(self._state(), indent=2, ensure_ascii=True)
            tmp_path = self.file_path.with_suffix(f"{self.file_path.suffix}.tmp")
            tmp_path.write_text(payload, encoding="utf-8")
            tmp_path.replace(self.file_path)

    def upsert_site(self, payload: dict, site_id: str | None = None) -> dict:
        with self.lock:
            now = utc_now()
            site = normalize_site_input(payload, site_id or payload.get("id"), now)
            sites = self._state()["sites"]
            index = find_index(sites, site["id"])

            if index >= 0:
                site["createdAt"] = sites[index].get("createdAt", now)
                sites[index] = {**sites[index], **site, "updatedAt": now}
                saved = sites[index]
            else:
                site["createdAt"] = now
                site["updatedAt"] = now
                sites.append(site)
                saved = site

            self.persist()
            return deepcopy(saved)

    def delete_site(self, site_id: str) -> None:
        with self.lock:
            before = len(self._state()["sites"])
            self._state()["sites"] = [site for site in self._state()["sites"] if site["id"] != site_id]
            if len(self._state()["sites"]) == before:
                raise StoreError(404, "Site not found")
            self.persist()

    def upsert_rule(self, payload: dict, rule_id: str | None = None) -> dict:
        with self.lock:
            now = utc_now()
            rules = self._state()["rules"]
            existing = next((rule for rule in rules if rule["id"] == (rule_id or payload.get("id"))), None)
            rule = normalize_rule_input(payload, rule_id or payload.get("id"), now, existing)
            index = find_index(rules, rule["id"])

            if index >= 0:
                rule["createdAt"] = rules[index].get("createdAt", now)
                rules[index] = {**rules[index], **rule, "updatedAt": now}
                saved = rules[index]
            else:
                rule["createdAt"] = now
                rule["updatedAt"] = now
                rules.append(rule)
                saved = rule

            self.persist()
            return deepcopy(saved)

    def delete_rule(self, rule_id: str) -> None:
        with self.lock:
            rule = next((item for item in self._state()["rules"] if item["id"] == rule_id), None)
            if not rule:
                raise StoreError(404, "Rule not found")
            if rule.get("builtin"):
                raise StoreError(400, "Built-in rules can be disabled but not deleted")

            self._state()["rules"] = [item for item in self._state()["rules"] if item["id"] != rule_id]
            self.persist()

    def upsert_certificate(self, payload: dict, certificate_id: str | None = None) -> dict:
        with self.lock:
            now = utc_now()
            certificate = normalize_certificate_input(payload, certificate_id or payload.get("id"), now)
            certificates = self._state()["certificates"]
            index = find_index(certificates, certificate["id"])

            if index >= 0:
                certificate["createdAt"] = certificates[index].get("createdAt", now)
                certificates[index] = {**certificates[index], **certificate, "updatedAt": now}
                saved = certificates[index]
            else:
                certificate["createdAt"] = now
                certificate["updatedAt"] = now
                certificates.append(certificate)
                saved = certificate

            self.persist()
            return deepcopy(saved)

    def delete_certificate(self, certificate_id: str) -> None:
        with self.lock:
            before = len(self._state()["certificates"])
            self._state()["certificates"] = [
                certificate for certificate in self._state()["certificates"] if certificate["id"] != certificate_id
            ]
            if len(self._state()["certificates"]) == before:
                raise StoreError(404, "Certificate not found")

            for site in self._state()["sites"]:
                tls = site.get("tls") or {}
                if tls.get("certificateId") == certificate_id:
                    tls["certificateId"] = ""
                    tls["enabled"] = False
                    site["tls"] = tls

            panel = (self._state().get("settings") or {}).get("panel") or {}
            if panel.get("certificateId") == certificate_id:
                panel["certificateId"] = ""
                panel["httpsEnabled"] = False
                self._state()["settings"]["panel"] = panel

            self.persist()

    def upsert_ip_group(self, payload: dict, group_id: str | None = None) -> dict:
        with self.lock:
            now = utc_now()
            target_id = group_id or payload.get("id")
            groups = self._state()["ipGroups"]
            index = find_index(groups, target_id) if target_id else -1
            existing = groups[index] if index >= 0 else None
            has_items = "items" in payload or "content" in payload
            group = normalize_ip_group_input(payload, target_id, now)
            if existing and not has_items:
                group = {**group, **preserve_ip_group_storage(existing)}
            else:
                group = self.prepare_ip_group_storage(group)
            groups = self._state()["ipGroups"]
            index = find_index(groups, group["id"])

            if index >= 0:
                group["createdAt"] = groups[index].get("createdAt", now)
                groups[index] = {**groups[index], **group, "updatedAt": now}
                saved = groups[index]
            else:
                group["createdAt"] = now
                group["updatedAt"] = now
                groups.append(group)
                saved = group

            self.persist()
            return deepcopy(saved)

    def delete_ip_group(self, group_id: str) -> None:
        with self.lock:
            existing = next((group for group in self._state()["ipGroups"] if group["id"] == group_id), None)
            before = len(self._state()["ipGroups"])
            self._state()["ipGroups"] = [group for group in self._state()["ipGroups"] if group["id"] != group_id]
            if len(self._state()["ipGroups"]) == before:
                raise StoreError(404, "IP group not found")
            if existing:
                self.remove_ip_group_file(existing)

            for rule in self._state()["accessRules"]:
                rule["ipGroupIds"] = [item for item in rule.get("ipGroupIds", []) if item != group_id]

            self.persist()

    def upsert_access_rule(self, payload: dict, access_rule_id: str | None = None) -> dict:
        with self.lock:
            now = utc_now()
            rule = normalize_access_rule_input(payload, access_rule_id or payload.get("id"), now)
            rules = self._state()["accessRules"]
            index = find_index(rules, rule["id"])
            should_move = bool(payload.get("_moveAccessRule"))
            position = normalize_insert_position(payload.get("insertPosition"))

            if index >= 0:
                existing = rules.pop(index)
                rule["createdAt"] = existing.get("createdAt", now)
                saved = {**existing, **rule, "updatedAt": now}
                if should_move and position == "first":
                    rules.insert(0, saved)
                elif should_move and position == "last":
                    rules.append(saved)
                else:
                    rules.insert(index, saved)
            else:
                rule["createdAt"] = now
                rule["updatedAt"] = now
                saved = rule
                if position == "first":
                    rules.insert(0, saved)
                else:
                    rules.append(saved)

            self.persist()
            return deepcopy(saved)

    def delete_access_rule(self, access_rule_id: str) -> None:
        with self.lock:
            before = len(self._state()["accessRules"])
            self._state()["accessRules"] = [rule for rule in self._state()["accessRules"] if rule["id"] != access_rule_id]
            if len(self._state()["accessRules"]) == before:
                raise StoreError(404, "Access rule not found")
            self.persist()

    def update_settings(self, payload: dict) -> dict:
        with self.lock:
            current = deepcopy(self._state()["settings"])
            incoming = payload or {}
            for key, value in incoming.items():
                if key in {"panel", "rateLimit"} and isinstance(value, dict):
                    current[key] = {**(current.get(key) or {}), **value}
                else:
                    current[key] = value
            settings = normalize_settings(current)
            self._state()["settings"] = settings
            self.persist()
            return deepcopy(settings)

    def has_users(self) -> bool:
        with self.lock:
            return bool(self._state().get("users"))

    def upsert_user(self, payload: dict, user_id: str | None = None) -> dict:
        with self.lock:
            now = utc_now()
            users = self._state()["users"]
            existing = next((user for user in users if user["id"] == (user_id or payload.get("id"))), None)
            user = normalize_user_input(payload, user_id or payload.get("id"), now, existing)
            totp_secret_generated = bool(user.pop("_totpSecretGenerated", False))
            if any(item["id"] != user["id"] and item["username"].lower() == user["username"].lower() for item in users):
                raise StoreError(400, "Username already exists")

            index = find_index(users, user["id"])
            candidate_users = deepcopy(users)
            if index >= 0:
                user["createdAt"] = candidate_users[index].get("createdAt", now)
                saved = {**candidate_users[index], **user, "updatedAt": now}
                candidate_users[index] = saved
            else:
                user["createdAt"] = now
                user["updatedAt"] = now
                saved = user
                candidate_users.append(saved)

            self.ensure_admin_user(candidate_users)
            self._state()["users"] = candidate_users
            self.persist()
            result = deepcopy(saved)
            if totp_secret_generated:
                result["_totpSecretGenerated"] = True
            return result

    def delete_user(self, user_id: str) -> None:
        with self.lock:
            user = next((item for item in self._state()["users"] if item["id"] == user_id), None)
            if not user:
                raise StoreError(404, "User not found")
            remaining = [item for item in self._state()["users"] if item["id"] != user_id]
            if not any(item.get("enabled") and item.get("role") == "admin" for item in remaining):
                raise StoreError(400, "Cannot delete the last enabled admin user")
            self._state()["users"] = remaining
            self.persist()

    def change_user_password(self, user_id: str, password: str) -> dict:
        with self.lock:
            user = next((item for item in self._state()["users"] if item["id"] == user_id), None)
            if not user:
                raise StoreError(404, "User not found")
            password_fields = hash_password(validate_password(password))
            user.update(password_fields)
            user["updatedAt"] = utc_now()
            self.persist()
            return deepcopy(user)

    def authenticate_user(self, username: str, password: str, totp_code: str = "") -> dict:
        with self.lock:
            user = next((item for item in self._state()["users"] if item["username"].lower() == str(username or "").lower()), None)
            if not user or not user.get("enabled"):
                raise StoreError(401, "Invalid username or password")
            if not verify_password(password, user):
                raise StoreError(401, "Invalid username or password")
            if user.get("totpEnabled"):
                if not verify_totp(user.get("totpSecret", ""), totp_code):
                    raise StoreError(401, "Google Authenticator code is required")
            user["lastLoginAt"] = utc_now()
            self.persist()
            return deepcopy(user)

    def ensure_admin_user(self, users: list[dict] | None = None) -> None:
        source = users if users is not None else self._state().get("users", [])
        if not any(user.get("enabled") and user.get("role") == "admin" for user in source):
            raise StoreError(400, "At least one enabled admin user is required")

    def add_log(self, entry: dict) -> None:
        with self.lock:
            retention = int(self._state()["settings"].get("logRetention") or DEFAULT_SETTINGS["logRetention"])
            self._state()["logs"].insert(0, entry)
            del self._state()["logs"][retention:]
            self.persist()

    def get_logs(self, limit: int = 200) -> list[dict]:
        with self.lock:
            return deepcopy(self._state()["logs"][:limit])

    def clear_logs(self) -> None:
        with self.lock:
            self._state()["logs"] = []
            self.persist()

    def get_stats(self) -> dict:
        with self.lock:
            return build_stats(self._state())

    def _state(self) -> dict:
        if self.state is None:
            raise RuntimeError("Store.init() must be called before use")
        return self.state

    def prepare_ip_group_storage(self, group: dict) -> dict:
        items = normalize_ip_items(group.get("items"))
        if not items and group.get("itemsFile"):
            return {
                **group,
                "items": [],
                "itemsExternal": True,
                "itemCount": normalize_non_negative_int(group.get("itemCount"), len(group.get("itemsPreview") or [])),
                "itemsPreview": normalize_ip_items(group.get("itemsPreview"))[:8],
            }

        if should_externalize_ip_group(items, group):
            path = self.ip_group_items_file(group["id"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
            return {
                **group,
                "items": [],
                "itemsFile": str(path).replace("\\", "/"),
                "itemsExternal": True,
                "itemCount": len(items),
                "itemsPreview": items[:8],
            }

        self.remove_ip_group_file(group)
        return {
            **group,
            "items": items,
            "itemsFile": "",
            "itemsExternal": False,
            "itemCount": len(items),
            "itemsPreview": items[:8],
        }

    def ip_group_items_file(self, group_id: str) -> Path:
        safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(group_id or "ipgroup")).strip("._") or "ipgroup"
        return self.file_path.parent / "ip-groups" / f"{safe_id}.txt"

    def remove_ip_group_file(self, group: dict) -> None:
        path = ip_group_file_path(group)
        if not path:
            return
        try:
            if path.exists() and is_relative_to(path.resolve(), (self.file_path.parent / "ip-groups").resolve()):
                path.unlink()
        except OSError:
            return


def resolve_data_file(root_dir: Path) -> Path:
    configured = Path(os.environ.get("DATA_FILE", "./data/state.json"))
    return configured if configured.is_absolute() else root_dir / configured


def normalize_state(state: dict) -> dict:
    settings = normalize_settings(state.get("settings") or {})
    return {
        "version": 1,
        "settings": settings,
        "sites": [normalize_stored_site(site) for site in state.get("sites", [])],
        "rules": [normalize_stored_rule(rule) for rule in state.get("rules", [])],
        "certificates": [normalize_stored_certificate(certificate) for certificate in state.get("certificates", [])],
        "ipGroups": [normalize_stored_ip_group(group) for group in state.get("ipGroups", [])],
        "accessRules": [normalize_stored_access_rule(rule) for rule in state.get("accessRules", [])],
        "users": [normalize_stored_user(user) for user in state.get("users", [])],
        "logs": state.get("logs", []) if isinstance(state.get("logs"), list) else [],
    }


def normalize_settings(settings: dict) -> dict:
    source = settings if isinstance(settings, dict) else {}
    return {
        **deepcopy(DEFAULT_SETTINGS),
        **source,
        "panel": normalize_panel_settings(source.get("panel") or {}),
        "rateLimit": {
            **DEFAULT_SETTINGS["rateLimit"],
            **(source.get("rateLimit") or {}),
        },
    }


def normalize_panel_settings(value) -> dict:
    source = value if isinstance(value, dict) else {}
    session_hours = normalize_positive_int(source.get("sessionHours") or source.get("session_hours"), DEFAULT_SETTINGS["panel"]["sessionHours"])
    return {
        "httpsEnabled": normalize_bool(source.get("httpsEnabled") if "httpsEnabled" in source else source.get("https_enabled"), False),
        "certificateId": str(source.get("certificateId") or source.get("certificate_id") or ""),
        "publicUrl": normalize_panel_url(source.get("publicUrl") or source.get("public_url") or ""),
        "sessionHours": min(max(session_hours, 1), 168),
    }


def normalize_stored_site(site: dict) -> dict:
    now = utc_now()
    tls = normalize_tls(site.get("tls"))
    application_type = normalize_application_type(site.get("applicationType") or site.get("application_type"))
    upstreams = normalize_upstreams(
        site.get("upstreams") or site.get("origin") or ("http://127.0.0.1:9090" if application_type == "reverse_proxy" else ""),
        required=application_type == "reverse_proxy",
    )
    listen = normalize_listen(site.get("listen") or infer_listen_from_ports(site.get("ports"), tls))
    ports = normalize_ports(site.get("ports"), listen, tls)
    proxy = normalize_proxy_config(site.get("proxy"), tls, site.get("redirectStatusCode") or site.get("redirect_status_code"))
    enabled_value = site.get("enabled") if "enabled" in site else site.get("is_enabled")
    redirect = normalize_redirect_config(site.get("redirect"), proxy)
    features = normalize_site_features(site.get("features"))
    bot_protection = normalize_bot_protection_config(site.get("botProtection") or site.get("bot_protection"), features.get("botProtection"))
    features["botProtection"] = bot_protection["enabled"]
    return {
        "id": str(site.get("id") or create_id("site")),
        "name": str(site.get("name") or site.get("comment") or "Untitled site"),
        "hostnames": normalize_hostnames(site.get("hostnames") or site.get("server_names") or ["*"]),
        "applicationType": application_type,
        "origin": upstreams[0] if upstreams else "",
        "upstreams": upstreams,
        "ports": ports,
        "listen": listen,
        "redirectStatusCode": proxy["redirectStatusCode"],
        "tls": tls,
        "proxy": proxy,
        "redirect": redirect,
        "static": normalize_static_config(site.get("static")),
        "acl": normalize_acl_config(site.get("acl"), site.get("acl_enabled")),
        "features": features,
        "botProtection": bot_protection,
        "mode": site.get("mode") if site.get("mode") in MODES else "block",
        "enabled": normalize_bool(enabled_value, False),
        "createdAt": site.get("createdAt") or now,
        "updatedAt": site.get("updatedAt") or now,
    }


def normalize_stored_rule(rule: dict) -> dict:
    now = utc_now()
    return {
        "id": str(rule.get("id") or create_id("rule")),
        "name": str(rule.get("name") or "Untitled rule"),
        "description": str(rule.get("description") or ""),
        "builtin": bool(rule.get("builtin")),
        "enabled": bool(rule.get("enabled")),
        "siteId": str(rule.get("siteId") or "*"),
        "matcher": rule.get("matcher") if rule.get("matcher") in MATCHERS else "regex",
        "target": rule.get("target") if rule.get("target") in TARGETS else "all",
        "pattern": str(rule.get("pattern") or ""),
        "action": rule.get("action") if rule.get("action") in ACTIONS else "block",
        "severity": rule.get("severity") if rule.get("severity") in SEVERITIES else "medium",
        "createdAt": rule.get("createdAt") or now,
        "updatedAt": rule.get("updatedAt") or now,
    }


def normalize_stored_certificate(certificate: dict) -> dict:
    now = utc_now()
    source = normalize_certificate_source(certificate.get("source"))
    last_message = str(certificate.get("lastMessage") or "")
    cert_file = normalize_file_reference(certificate.get("certFile") or certificate.get("cert_file") or "")
    key_file = normalize_file_reference(certificate.get("keyFile") or certificate.get("key_file") or "")
    if source == "certbot":
        parsed_cert_file, parsed_key_file = parse_certbot_paths(last_message)
        cert_file = parsed_cert_file or cert_file
        key_file = parsed_key_file or key_file

    return {
        "id": str(certificate.get("id") or create_id("cert")),
        "name": str(certificate.get("name") or "Untitled certificate"),
        "source": source,
        "domains": normalize_domain_list(certificate.get("domains")),
        "email": str(certificate.get("email") or ""),
        "autoRenew": certificate.get("autoRenew") is not False,
        "renewBeforeDays": normalize_positive_int(certificate.get("renewBeforeDays"), 30),
        "status": str(certificate.get("status") or "ready"),
        "lastMessage": last_message,
        "certFile": cert_file,
        "keyFile": key_file,
        "createdAt": certificate.get("createdAt") or now,
        "updatedAt": certificate.get("updatedAt") or now,
    }


def parse_certbot_paths(message: str) -> tuple[str, str]:
    cert_match = re.search(r"Certificate is saved at:\s*(\S+)", message or "")
    key_match = re.search(r"Key is saved at:\s*(\S+)", message or "")
    return (
        normalize_file_reference(cert_match.group(1)) if cert_match else "",
        normalize_file_reference(key_match.group(1)) if key_match else "",
    )


def normalize_stored_ip_group(group: dict) -> dict:
    now = utc_now()
    items = normalize_ip_items(group.get("items"))
    items_preview = normalize_ip_items(group.get("itemsPreview") or group.get("items_preview") or items[:8])[:8]
    item_count = normalize_non_negative_int(group.get("itemCount") or group.get("item_count"), len(items))
    items_file = normalize_file_reference(group.get("itemsFile") or group.get("items_file") or "")
    items_external = bool(items_file) or group.get("itemsExternal") is True
    return {
        "id": str(group.get("id") or create_id("ipgroup")),
        "name": str(group.get("name") or "Untitled IP group"),
        "description": str(group.get("description") or ""),
        "referenceUrl": normalize_reference_url(group.get("referenceUrl") or group.get("reference") or "", strict=False),
        "items": [] if items_external else items,
        "itemsFile": items_file,
        "itemsExternal": items_external,
        "itemCount": item_count if items_external else len(items),
        "itemsPreview": items_preview,
        "lastSyncedAt": str(group.get("lastSyncedAt") or ""),
        "lastSyncStatus": str(group.get("lastSyncStatus") or ""),
        "lastSyncMessage": str(group.get("lastSyncMessage") or ""),
        "enabled": group.get("enabled") is not False,
        "createdAt": group.get("createdAt") or now,
        "updatedAt": group.get("updatedAt") or now,
    }


def normalize_stored_access_rule(rule: dict) -> dict:
    now = utc_now()
    return {
        "id": str(rule.get("id") or create_id("access")),
        "name": str(rule.get("name") or "Untitled access rule"),
        "description": str(rule.get("description") or ""),
        "enabled": rule.get("enabled") is not False,
        "siteId": str(rule.get("siteId") or "*"),
        "action": normalize_access_action(rule.get("action")),
        "insertPosition": normalize_insert_position(rule.get("insertPosition")),
        "continueDetect": normalize_bool(rule.get("continueDetect"), False),
        "ipGroupIds": normalize_id_list(rule.get("ipGroupIds")),
        "ips": normalize_ip_items(rule.get("ips")),
        "methods": normalize_string_list(rule.get("methods"), uppercase=True),
        "uriPatterns": normalize_string_list(rule.get("uriPatterns")),
        "hostPatterns": normalize_string_list(rule.get("hostPatterns")),
        "userAgentPatterns": normalize_string_list(rule.get("userAgentPatterns")),
        "conditionGroups": normalize_access_condition_groups(rule.get("conditionGroups") or rule.get("condition_groups")),
        "createdAt": rule.get("createdAt") or now,
        "updatedAt": rule.get("updatedAt") or now,
    }


def normalize_stored_user(user: dict) -> dict:
    now = utc_now()
    username = normalize_username(user.get("username") or "admin")
    return {
        "id": str(user.get("id") or create_id("user")),
        "username": username,
        "displayName": str(user.get("displayName") or user.get("display_name") or username),
        "role": normalize_user_role(user.get("role")),
        "enabled": user.get("enabled") is not False,
        "passwordSalt": str(user.get("passwordSalt") or user.get("password_salt") or ""),
        "passwordHash": str(user.get("passwordHash") or user.get("password_hash") or ""),
        "passwordIterations": normalize_positive_int(user.get("passwordIterations") or user.get("password_iterations"), PASSWORD_ITERATIONS),
        "totpEnabled": normalize_bool(user.get("totpEnabled") if "totpEnabled" in user else user.get("totp_enabled"), False),
        "totpSecret": normalize_totp_secret(user.get("totpSecret") or user.get("totp_secret") or ""),
        "lastLoginAt": str(user.get("lastLoginAt") or user.get("last_login_at") or ""),
        "createdAt": user.get("createdAt") or now,
        "updatedAt": user.get("updatedAt") or now,
    }


def normalize_site_input(payload: dict, site_id: str | None, now: str) -> dict:
    name = str(payload.get("name") or "").strip()
    if not name:
        raise StoreError(400, "Site name is required")

    tls = normalize_tls(payload.get("tls"))
    application_type = normalize_application_type(payload.get("applicationType") or payload.get("application_type"))
    upstreams = normalize_upstreams(
        payload.get("upstreams") or payload.get("origin"),
        required=application_type == "reverse_proxy",
    )
    listen = normalize_listen(payload.get("listen") or infer_listen_from_ports(payload.get("ports"), tls))
    ports = normalize_ports(payload.get("ports"), listen, tls)
    proxy = normalize_proxy_config(payload.get("proxy"), tls, payload.get("redirectStatusCode"))
    redirect = normalize_redirect_config(payload.get("redirect"), proxy, required=application_type == "redirect")

    features = normalize_site_features(payload.get("features"))
    bot_protection = normalize_bot_protection_config(payload.get("botProtection") or payload.get("bot_protection"), features.get("botProtection"))
    features["botProtection"] = bot_protection["enabled"]
    return {
        "id": site_id or create_id("site"),
        "name": name,
        "hostnames": normalize_hostnames(payload.get("hostnames")),
        "applicationType": application_type,
        "origin": upstreams[0] if upstreams else "",
        "upstreams": upstreams,
        "ports": ports,
        "listen": listen,
        "redirectStatusCode": proxy["redirectStatusCode"],
        "tls": tls,
        "proxy": proxy,
        "redirect": redirect,
        "static": normalize_static_config(payload.get("static")),
        "acl": normalize_acl_config(payload.get("acl")),
        "features": features,
        "botProtection": bot_protection,
        "mode": payload.get("mode") if payload.get("mode") in MODES else "block",
        "enabled": payload.get("enabled") is not False,
        "createdAt": now,
        "updatedAt": now,
    }


def normalize_certificate_input(payload: dict, certificate_id: str | None, now: str) -> dict:
    name = str(payload.get("name") or "").strip()
    source = normalize_certificate_source(payload.get("source"))
    cert_file = normalize_file_reference(payload.get("certFile") or payload.get("cert_file") or "")
    key_file = normalize_file_reference(payload.get("keyFile") or payload.get("key_file") or "")
    domains = normalize_domain_list(payload.get("domains"))
    email = str(payload.get("email") or "").strip()

    if not name:
        raise StoreError(400, "Certificate name is required")
    if not cert_file or not key_file:
        raise StoreError(400, "Certificate and key files are required")
    if source == "certbot":
        if not domains:
            raise StoreError(400, "At least one domain is required for certbot certificates")
        if "@" not in email:
            raise StoreError(400, "A valid email address is required for certbot certificates")

    return {
        "id": certificate_id or create_id("cert"),
        "name": name,
        "source": source,
        "domains": domains,
        "email": email,
        "autoRenew": payload.get("autoRenew") is not False,
        "renewBeforeDays": normalize_positive_int(payload.get("renewBeforeDays"), 30),
        "status": str(payload.get("status") or "ready"),
        "lastMessage": str(payload.get("lastMessage") or ""),
        "certFile": cert_file,
        "keyFile": key_file,
        "createdAt": now,
        "updatedAt": now,
    }


def normalize_ip_group_input(payload: dict, group_id: str | None, now: str) -> dict:
    name = str(payload.get("name") or "").strip()
    if not name:
        raise StoreError(400, "IP group name is required")
    items = payload.get("items")
    if items is None and "content" in payload:
        items = payload.get("content")

    return {
        "id": group_id or create_id("ipgroup"),
        "name": name,
        "description": str(payload.get("description") or ""),
        "referenceUrl": normalize_reference_url(payload.get("referenceUrl") or payload.get("reference") or ""),
        "items": normalize_ip_items(items),
        "lastSyncedAt": str(payload.get("lastSyncedAt") or ""),
        "lastSyncStatus": str(payload.get("lastSyncStatus") or ""),
        "lastSyncMessage": str(payload.get("lastSyncMessage") or ""),
        "enabled": payload.get("enabled") is not False,
        "createdAt": now,
        "updatedAt": now,
    }


def normalize_access_rule_input(payload: dict, rule_id: str | None, now: str) -> dict:
    name = str(payload.get("name") or "").strip()
    if not name:
        raise StoreError(400, "Access rule name is required")

    rule = {
        "id": rule_id or create_id("access"),
        "name": name,
        "description": str(payload.get("description") or ""),
        "enabled": payload.get("enabled") is not False,
        "siteId": str(payload.get("siteId") or "*"),
        "action": normalize_access_action(payload.get("action")),
        "insertPosition": normalize_insert_position(payload.get("insertPosition")),
        "continueDetect": normalize_bool(payload.get("continueDetect"), False),
        "ipGroupIds": normalize_id_list(payload.get("ipGroupIds")),
        "ips": normalize_ip_items(payload.get("ips")),
        "methods": normalize_string_list(payload.get("methods"), uppercase=True),
        "uriPatterns": normalize_string_list(payload.get("uriPatterns")),
        "hostPatterns": normalize_string_list(payload.get("hostPatterns")),
        "userAgentPatterns": normalize_string_list(payload.get("userAgentPatterns")),
        "conditionGroups": normalize_access_condition_groups(payload.get("conditionGroups") or payload.get("condition_groups")),
        "createdAt": now,
        "updatedAt": now,
    }

    if not any(
        [
            rule["ipGroupIds"],
            rule["ips"],
            rule["methods"],
            rule["uriPatterns"],
            rule["hostPatterns"],
            rule["userAgentPatterns"],
            rule["conditionGroups"],
        ]
    ):
        raise StoreError(400, "Access rule needs at least one condition")

    return rule


def normalize_user_input(payload: dict, user_id: str | None, now: str, existing: dict | None = None) -> dict:
    username = normalize_username(payload.get("username") or (existing or {}).get("username") or "")
    display_name = str(payload.get("displayName") or payload.get("display_name") or username).strip()
    role = normalize_user_role(payload.get("role") or (existing or {}).get("role"))
    enabled = normalize_bool(payload.get("enabled"), (existing or {}).get("enabled", True))

    user = {
        "id": user_id or create_id("user"),
        "username": username,
        "displayName": display_name or username,
        "role": role,
        "enabled": enabled,
        "passwordSalt": (existing or {}).get("passwordSalt", ""),
        "passwordHash": (existing or {}).get("passwordHash", ""),
        "passwordIterations": int((existing or {}).get("passwordIterations") or PASSWORD_ITERATIONS),
        "totpEnabled": normalize_bool(payload.get("totpEnabled"), (existing or {}).get("totpEnabled", False)),
        "totpSecret": (existing or {}).get("totpSecret", ""),
        "lastLoginAt": (existing or {}).get("lastLoginAt", ""),
        "createdAt": now,
        "updatedAt": now,
    }

    password = str(payload.get("password") or "")
    if password:
        user.update(hash_password(validate_password(password)))
    elif not existing:
        raise StoreError(400, "Password is required for new users")

    reset_totp = payload.get("resetTotp") is True or payload.get("reset_totp") is True
    if user["totpEnabled"] and (reset_totp or not user["totpSecret"]):
        user["totpSecret"] = generate_totp_secret()
        user["_totpSecretGenerated"] = True
    if not user["totpEnabled"]:
        user["totpSecret"] = ""

    return user


def normalize_rule_input(payload: dict, rule_id: str | None, now: str, existing: dict | None) -> dict:
    name = str(payload.get("name") or "").strip()
    matcher = payload.get("matcher") if payload.get("matcher") in MATCHERS else "regex"
    pattern = str(payload.get("pattern") or "").strip()

    if not name:
        raise StoreError(400, "Rule name is required")
    if not pattern:
        raise StoreError(400, "Rule pattern is required")
    if matcher == "regex":
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error:
            raise StoreError(400, "Rule regex pattern is invalid") from None

    return {
        "id": rule_id or create_id("rule"),
        "name": name,
        "description": str(payload.get("description") or ""),
        "builtin": bool((existing or {}).get("builtin") or payload.get("builtin")),
        "enabled": payload.get("enabled") is not False,
        "siteId": str(payload.get("siteId") or "*"),
        "matcher": matcher,
        "target": payload.get("target") if payload.get("target") in TARGETS else "all",
        "pattern": pattern,
        "action": payload.get("action") if payload.get("action") in ACTIONS else "block",
        "severity": payload.get("severity") if payload.get("severity") in SEVERITIES else "medium",
        "createdAt": now,
        "updatedAt": now,
    }


def normalize_hostnames(hostnames) -> list[str]:
    if isinstance(hostnames, list):
        values = hostnames
    else:
        values = re.split(r"[\s,]+", str(hostnames or ""))

    normalized = []
    for value in values:
        item = str(value).strip().lower()
        if not item:
            continue
        item = re.sub(r"^https?://", "", item).split("/")[0]
        if item.startswith("[") and "]" in item:
            item = item[1:].split("]")[0]
        else:
            item = item.split(":")[0]
        if item:
            normalized.append(item)

    return list(dict.fromkeys(normalized or ["*"]))


def normalize_origin(origin: str | None) -> str:
    parsed = urlparse(str(origin or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise StoreError(400, "Origin must be a valid http or https URL")
    return f"{parsed.scheme}://{parsed.netloc}"


def normalize_upstreams(upstreams, required: bool = True) -> list[str]:
    values = normalize_string_list(upstreams)
    normalized = [normalize_origin(value) for value in values]
    if required and not normalized:
        raise StoreError(400, "At least one upstream origin is required")
    return list(dict.fromkeys(normalized))


def normalize_application_type(value) -> str:
    item = str(value or "reverse_proxy").lower().replace("-", "_")
    if item in {"reverse", "proxy", "reverseproxy"}:
        item = "reverse_proxy"
    if item in {"static", "static_file", "staticfiles"}:
        item = "static_files"
    return item if item in APPLICATION_TYPES else "reverse_proxy"


def normalize_redirect_config(value, proxy: dict | None = None, required: bool = False) -> dict:
    source = value if isinstance(value, dict) else {}
    address = normalize_redirect_address(source.get("address") or source.get("url") or "", required=required)
    status_code = normalize_redirect_status(source.get("statusCode") or source.get("status_code") or (proxy or {}).get("redirectStatusCode") or 301)
    return {
        "statusCode": status_code,
        "address": address,
    }


def normalize_redirect_address(value, required: bool = False) -> str:
    raw = str(value or "").strip()
    if not raw:
        if required:
            raise StoreError(400, "Redirect address is required")
        return ""
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise StoreError(400, "Redirect address must be a valid http or https URL")
    return f"{parsed.scheme}://{parsed.netloc}"


def normalize_static_config(value) -> dict:
    source = value if isinstance(value, dict) else {}
    return {
        "root": normalize_file_reference(source.get("root") or source.get("path") or ""),
    }


def normalize_listen(value) -> int:
    try:
        listen = int(value or 8080)
    except (TypeError, ValueError):
        listen = 8080
    if listen < 1 or listen > 65535:
        raise StoreError(400, "Listen port must be between 1 and 65535")
    return listen


def normalize_tls(value) -> dict:
    source = value if isinstance(value, dict) else {}
    return {
        "enabled": normalize_bool(source.get("enabled"), False),
        "certificateId": str(source.get("certificateId") or ""),
        "redirectHttp": normalize_bool(source.get("redirectHttp"), False),
        "httpListen": normalize_listen(source.get("httpListen") or 80),
        "http2": normalize_bool(source.get("http2"), True),
    }


def infer_listen_from_ports(ports, tls: dict) -> int:
    preferred_ssl = normalize_bool(tls.get("enabled"), False)
    fallback = 443 if preferred_ssl else 8080
    values = normalize_string_list(ports)
    parsed_tokens = []
    for value in values:
        parsed = parse_port_token(value, strict=False)
        if parsed:
            parsed_tokens.append(parsed)
    for port, is_ssl in parsed_tokens:
        if is_ssl == preferred_ssl:
            return port
    return parsed_tokens[0][0] if parsed_tokens else fallback


def normalize_ports(ports, listen: int, tls: dict) -> list[str]:
    values = normalize_string_list(ports)
    if not values:
        if normalize_bool(tls.get("enabled"), False):
            if normalize_bool(tls.get("redirectHttp"), False):
                return [str(normalize_listen(tls.get("httpListen") or 80)), f"{listen}_ssl"]
            return [f"{listen}_ssl"]
        return [str(listen)]
    return list(dict.fromkeys(format_port_token(*parse_port_token(value)) for value in values))


def parse_port_token(value, strict: bool = True) -> tuple[int, bool] | None:
    item = str(value or "").strip().lower()
    if not item:
        return None
    is_ssl = item.endswith("_ssl")
    port_value = item[:-4] if is_ssl else item
    if not re.match(r"^\d+$", port_value):
        if strict:
            raise StoreError(400, f"Invalid port token: {value}")
        return None
    port = int(port_value)
    if port < 1 or port > 65535:
        if strict:
            raise StoreError(400, "Port must be between 1 and 65535")
        return None
    return port, is_ssl


def format_port_token(port: int, is_ssl: bool) -> str:
    return f"{port}_ssl" if is_ssl else str(port)


def normalize_proxy_config(value, tls: dict, redirect_status_code=None) -> dict:
    source = value if isinstance(value, dict) else {}
    force_https = normalize_bool(proxy_value(source, "forceHttps", "force_https"), normalize_bool(tls.get("redirectHttp"), False))
    return {
        "forceHttps": force_https,
        "redirectStatusCode": normalize_redirect_status(
            redirect_status_code if redirect_status_code is not None else proxy_value(source, "redirectStatusCode", "redirect_status_code")
        ),
        "hsts": normalize_bool(proxy_value(source, "hsts"), normalize_bool(tls.get("enabled"), False)),
        "hstsMaxAge": str(proxy_value(source, "hstsMaxAge", "hsts_max_age") or "15768000"),
        "gzip": normalize_bool(proxy_value(source, "gzip"), True),
        "brotli": normalize_bool(proxy_value(source, "brotli", "br"), False),
        "http2": normalize_bool(proxy_value(source, "http2"), normalize_bool(tls.get("http2"), True)),
        "ipv6": normalize_bool(proxy_value(source, "ipv6"), False),
        "resetXff": normalize_bool(proxy_value(source, "resetXff", "reset_xff"), True),
        "defaultServer": normalize_bool(proxy_value(source, "defaultServer", "default_server"), False),
        "strictHost": normalize_bool(proxy_value(source, "strictHost", "strict_host"), False),
        "accessLog": normalize_bool(proxy_value(source, "accessLog", "access_log"), True),
        "hostHeader": normalize_proxy_header(proxy_value(source, "hostHeader", "host") or "$http_host"),
        "xForwardedProto": normalize_proxy_header(proxy_value(source, "xForwardedProto", "xfp") or "$scheme"),
        "xForwardedHost": normalize_proxy_header(proxy_value(source, "xForwardedHost", "xfh") or "$http_host"),
        "proxySslServerName": normalize_bool(proxy_value(source, "proxySslServerName", "proxy_ssl_server_name"), True),
    }


def proxy_value(source: dict, *keys):
    for key in keys:
        if key not in source:
            continue
        value = source.get(key)
        if isinstance(value, dict) and "value" in value:
            return value.get("value")
        return value
    return None


def normalize_proxy_header(value) -> str:
    header = str(value or "").strip()
    if not header:
        return ""
    return header.replace("\x00", "").replace(";", "").replace("{", "").replace("}", "").replace("\n", " ")


def normalize_redirect_status(value) -> int:
    try:
        status = int(value or 301)
    except (TypeError, ValueError):
        status = 301
    if status == 0:
        return 0
    return status if status in {301, 302, 307, 308} else 301


def normalize_acl_config(value, enabled_value=None) -> dict:
    source = value if isinstance(value, dict) else {}
    enabled = normalize_bool(source.get("enabled"), normalize_bool(enabled_value, True))
    return {
        "enabled": enabled,
        "rateLimitMode": normalize_acl_rate_limit_mode(source.get("rateLimitMode") or source.get("rate_limit_mode") or source.get("rateMode")),
        "waitingRoom": normalize_bool(source.get("waitingRoom") if "waitingRoom" in source else source.get("waiting_room"), False),
        "accessLimit": normalize_acl_limit(
            source.get("accessLimit") or source.get("access_limit"),
            {"enabled": True, "period": 10, "count": 200, "action": "challenge_v1", "blockMin": 60},
        ),
        "attackLimit": normalize_acl_limit(
            source.get("attackLimit") or source.get("attack_limit"),
            {"enabled": True, "period": 60, "count": 10, "action": "block", "blockMin": 30},
        ),
        "errorLimit": normalize_acl_limit(
            source.get("errorLimit") or source.get("error_limit"),
            {"enabled": True, "period": 10, "count": 10, "action": "block", "blockMin": 30, "statusCodes": ["403", "404"]},
            include_status_codes=True,
        ),
    }


def normalize_acl_limit(value, defaults: dict, include_status_codes: bool = False) -> dict:
    source = value if isinstance(value, dict) else {}
    limit = {
        "enabled": normalize_bool(source.get("enabled"), defaults["enabled"]),
        "period": normalize_positive_int(source.get("period"), defaults["period"]),
        "count": normalize_positive_int(source.get("count"), defaults["count"]),
        "action": normalize_acl_action(source.get("action") or defaults["action"]),
        "blockMin": normalize_positive_int(source.get("blockMin") or source.get("block_min"), defaults["blockMin"]),
    }
    if include_status_codes:
        limit["statusCodes"] = normalize_status_codes(source.get("statusCodes") or source.get("status_codes") or defaults["statusCodes"])
    return limit


def normalize_acl_action(value) -> str:
    action = str(value or "block").lower()
    return action if action in ACL_ACTIONS else "block"


def normalize_acl_rate_limit_mode(value) -> str:
    mode = str(value or "custom").lower()
    return mode if mode in ACL_RATE_LIMIT_MODES else "custom"


def normalize_status_codes(values) -> list[str]:
    codes = []
    for value in normalize_string_list(values):
        try:
            code = int(value)
        except (TypeError, ValueError):
            continue
        if 100 <= code <= 599:
            codes.append(str(code))
    return list(dict.fromkeys(codes or ["403", "404"]))


def normalize_bool(value, fallback: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return fallback
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
        return fallback
    return bool(value)


def normalize_site_features(value) -> dict:
    source = value if isinstance(value, dict) else {}
    return {
        "httpFlood": normalize_bool(source.get("httpFlood"), True),
        "botProtection": normalize_bool(source.get("botProtection"), True),
        "auth": normalize_bool(source.get("auth"), False),
        "attacks": normalize_bool(source.get("attacks"), True),
    }


def normalize_bot_protection_config(value, enabled_value=None) -> dict:
    source = value if isinstance(value, dict) else {}
    dynamic = source.get("dynamicProtection") or source.get("dynamic_protection")
    dynamic = dynamic if isinstance(dynamic, dict) else {}
    anti_replay = source.get("antiReplay") or source.get("anti_replay")
    anti_replay = anti_replay if isinstance(anti_replay, dict) else {}

    dynamic_html = normalize_bool(dynamic.get("html") if "html" in dynamic else source.get("htmlDynamicEncryption"), False)
    dynamic_js = normalize_bool(dynamic.get("js") if "js" in dynamic else source.get("jsDynamicEncryption"), False)
    dynamic_watermark = normalize_bool(dynamic.get("watermark") if "watermark" in dynamic else source.get("pictureDynamicWatermark"), False)
    dynamic_enabled = normalize_bool(dynamic.get("enabled") if "enabled" in dynamic else source.get("dynamicProtectionEnabled"), any([dynamic_html, dynamic_js, dynamic_watermark]))
    anti_bot = normalize_bool(source.get("antiBotChallenge") if "antiBotChallenge" in source else source.get("anti_bot_challenge"), normalize_bool(enabled_value, True))
    replay_enabled = normalize_bool(anti_replay.get("enabled") if "enabled" in anti_replay else source.get("antiReplayEnabled"), False)
    enabled = normalize_bool(source.get("enabled"), normalize_bool(enabled_value, True))
    enabled = enabled and (anti_bot or dynamic_enabled or replay_enabled)

    return {
        "enabled": enabled,
        "antiBotChallenge": anti_bot,
        "dynamicProtection": {
            "enabled": dynamic_enabled,
            "html": dynamic_html,
            "js": dynamic_js,
            "watermark": dynamic_watermark,
        },
        "antiReplay": {
            "enabled": replay_enabled,
        },
    }


def normalize_file_reference(value) -> str:
    item = str(value or "").strip().replace("\\", "/")
    item = item.replace("\x00", "").replace(";", "").replace("{", "").replace("}", "")
    return item


def normalize_certificate_source(value) -> str:
    source = str(value or "upload").lower()
    return source if source in {"upload", "certbot"} else "upload"


def normalize_domain_list(values) -> list[str]:
    domains = []
    for item in normalize_string_list(values):
        domain = item.lower().strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if not domain:
            continue
        if not re.match(r"^(\*\.)?[a-z0-9][a-z0-9.-]*[a-z0-9]$", domain):
            raise StoreError(400, f"Invalid domain: {item}") from None
        domains.append(domain)
    return list(dict.fromkeys(domains))


def normalize_positive_int(value, fallback: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = fallback
    return max(1, number)


def normalize_non_negative_int(value, fallback: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = fallback
    return max(0, number)


def normalize_ip_items(items) -> list[str]:
    values = ip_item_candidates(items)
    normalized = []
    for value in values:
        try:
            if "/" in value:
                item = str(ipaddress.ip_network(value, strict=False))
            else:
                item = str(ipaddress.ip_address(value))
        except ValueError:
            raise StoreError(400, f"Invalid IP/CIDR entry: {value}") from None
        normalized.append(item)
    return list(dict.fromkeys(normalized))


def ip_item_candidates(items) -> list[str]:
    if items is None:
        return []
    if isinstance(items, list):
        chunks = [str(item or "") for item in items]
    else:
        chunks = str(items or "").replace(",", "\n").replace(";", "\n").splitlines()

    candidates = []
    saw_content = False
    for chunk in chunks:
        line = chunk.split("#", 1)[0].strip()
        if not line:
            continue
        saw_content = True
        for token in re.split(r"\s+", line):
            candidate = normalize_ip_token(token)
            if not candidate:
                continue
            candidates.append(candidate)

    if saw_content and not candidates:
        raise StoreError(400, "No IP/CIDR entries found")
    return list(dict.fromkeys(candidates))


def normalize_ip_token(token: str) -> str:
    item = str(token or "").strip().strip("[](){}<>\"'`")
    item = item.rstrip(".,;")
    if not item or not re.search(r"\d", item):
        return ""

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d+$", item):
        item = item.rsplit(":", 1)[0]

    if "." not in item and ":" not in item and "/" not in item:
        return ""
    return item


def preserve_ip_group_storage(group: dict) -> dict:
    return {
        "items": list(group.get("items") or []),
        "itemsFile": str(group.get("itemsFile") or ""),
        "itemsExternal": bool(group.get("itemsExternal")),
        "itemCount": normalize_non_negative_int(group.get("itemCount"), len(group.get("items") or [])),
        "itemsPreview": list(group.get("itemsPreview") or (group.get("items") or [])[:8]),
    }


def should_externalize_ip_group(items: list[str], group: dict) -> bool:
    if not items:
        return False
    if group.get("itemsExternal"):
        return True
    count_threshold = normalize_non_negative_int(os.environ.get("IP_GROUP_EXTERNALIZE_COUNT"), 5000)
    bytes_threshold = normalize_non_negative_int(os.environ.get("IP_GROUP_EXTERNALIZE_BYTES"), 256 * 1024)
    payload_size = sum(len(item) + 1 for item in items)
    return len(items) > count_threshold or payload_size > bytes_threshold


def ip_group_file_path(group: dict) -> Path | None:
    item_file = str(group.get("itemsFile") or "").strip()
    if not item_file:
        return None
    return Path(item_file)


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def normalize_reference_url(value, strict: bool = True) -> str:
    item = str(value or "").strip().replace("\x00", "")
    if not item:
        return ""
    parsed = urlparse(item)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        if strict:
            raise StoreError(400, "Reference URL must be a valid http or https URL")
        return ""
    return item


def normalize_panel_url(value) -> str:
    item = str(value or "").strip().replace("\x00", "")
    if not item:
        return ""
    parsed = urlparse(item)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise StoreError(400, "Panel URL must be a valid http or https URL")
    return item.rstrip("/")


def normalize_string_list(values, uppercase: bool = False) -> list[str]:
    if isinstance(values, list):
        source = values
    else:
        source = re.split(r"[\n,]+", str(values or ""))
    normalized = []
    for value in source:
        item = str(value).strip()
        if not item:
            continue
        item = item.upper() if uppercase else item
        normalized.append(item)
    return list(dict.fromkeys(normalized))


def normalize_id_list(values) -> list[str]:
    return [item for item in normalize_string_list(values) if re.match(r"^[A-Za-z0-9_.:-]+$", item)]


def normalize_username(value) -> str:
    username = str(value or "").strip().lower()
    if not re.match(r"^[a-z0-9_.-]{3,64}$", username):
        raise StoreError(400, "Username must be 3-64 chars: letters, numbers, dot, dash, underscore")
    return username


def normalize_user_role(value) -> str:
    role = str(value or "admin").strip().lower()
    return role if role in USER_ROLES else "admin"


def validate_password(password: str) -> str:
    value = str(password or "")
    if len(value) < 10:
        raise StoreError(400, "Password must be at least 10 characters")
    return value


def hash_password(password: str) -> dict:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), PASSWORD_ITERATIONS)
    return {
        "passwordSalt": salt,
        "passwordHash": digest.hex(),
        "passwordIterations": PASSWORD_ITERATIONS,
    }


def verify_password(password: str, user: dict) -> bool:
    salt = str(user.get("passwordSalt") or "")
    expected = str(user.get("passwordHash") or "")
    iterations = int(user.get("passwordIterations") or PASSWORD_ITERATIONS)
    if not salt or not expected:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", str(password or "").encode("utf-8"), salt.encode("ascii"), iterations)
    return hmac.compare_digest(digest.hex(), expected)


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def normalize_totp_secret(value) -> str:
    return re.sub(r"[^A-Z2-7]", "", str(value or "").upper())


def verify_totp(secret: str, code: str, timestamp: int | None = None) -> bool:
    normalized = normalize_totp_secret(secret)
    digits = re.sub(r"\D", "", str(code or ""))
    if not normalized or len(digits) != 6:
        return False
    current = int(timestamp or time.time()) // 30
    return any(hmac.compare_digest(totp_code(normalized, current + offset), digits) for offset in (-1, 0, 1))


def totp_code(secret: str, counter: int) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    message = struct.pack(">Q", counter)
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def normalize_insert_position(value) -> str:
    position = str(value or "last").strip().lower()
    return position if position in ACCESS_INSERT_POSITIONS else "last"


def normalize_access_condition_groups(value) -> list[dict]:
    if not isinstance(value, list):
        return []

    groups = []
    for raw_group in value:
        raw_conditions = raw_group.get("conditions") if isinstance(raw_group, dict) else raw_group
        if not isinstance(raw_conditions, list):
            continue
        conditions = []
        for raw_condition in raw_conditions:
            condition = normalize_access_condition(raw_condition)
            if condition:
                conditions.append(condition)
        if conditions:
            groups.append({"conditions": conditions})
    return groups


def normalize_access_condition(value) -> dict | None:
    if not isinstance(value, dict):
        return None

    target = normalize_access_condition_target(value.get("target") or value.get("matchTarget"))
    operator = normalize_access_condition_operator(value.get("operator"), target)
    content = str(value.get("content") or value.get("value") or "").strip()
    if not content:
        return None

    return {
        "target": target,
        "operator": operator,
        "content": normalize_access_condition_content(target, operator, content),
    }


def normalize_access_condition_target(value) -> str:
    item = str(value or "source_ip").strip()
    snake = re.sub(r"(?<!^)([A-Z])", r"_\1", item).lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "ip": "source_ip",
        "source": "source_ip",
        "sourceip": "source_ip",
        "source_ip": "source_ip",
        "url": "uri",
        "path": "uri",
        "hostname": "host",
        "useragent": "user_agent",
        "user_agent": "user_agent",
        "ua": "user_agent",
    }
    target = aliases.get(snake, snake)
    return target if target in ACCESS_CONDITION_TARGETS else "source_ip"


def normalize_access_condition_operator(value, target: str) -> str:
    item = str(value or "equals").strip()
    snake = re.sub(r"(?<!^)([A-Z])", r"_\1", item).lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "equal": "equals",
        "does_not_equal": "not_equals",
        "not_equal": "not_equals",
        "does_not_match": "not_regex",
        "fuzzy_match": "contains",
        "fuzzy": "contains",
        "in_ip_group": "in_ip_group",
        "not_in_ip_group": "not_in_ip_group",
        "does_not_in_ip_group": "not_in_ip_group",
        "does_not_in_cidr": "not_cidr",
    }
    operator = aliases.get(snake, snake)
    if target == "source_ip" and operator not in {"equals", "not_equals", "cidr", "not_cidr", "in_ip_group", "not_in_ip_group"}:
        operator = "equals"
    if target == "method" and operator not in {"equals", "not_equals"}:
        operator = "equals"
    if target in {"uri", "host", "user_agent"} and operator not in {"equals", "not_equals", "contains", "not_contains", "regex", "not_regex"}:
        operator = "equals"
    return operator if operator in ACCESS_CONDITION_OPERATORS else "equals"


def normalize_access_condition_content(target: str, operator: str, content: str) -> str:
    item = content.replace("\x00", "").strip()
    if target == "source_ip":
        if operator in {"in_ip_group", "not_in_ip_group"}:
            ids = normalize_id_list([item])
            if not ids:
                raise StoreError(400, "Access condition needs a valid IP group")
            return ids[0]
        try:
            if operator in {"cidr", "not_cidr"}:
                return str(ipaddress.ip_network(item, strict=False))
            return str(ipaddress.ip_address(item))
        except ValueError:
            raise StoreError(400, f"Invalid access condition IP/CIDR: {content}") from None

    if target == "method":
        method = item.upper()
        if not re.match(r"^[A-Z][A-Z0-9_-]*$", method):
            raise StoreError(400, "Invalid access condition method")
        return method

    if operator in {"regex", "not_regex"}:
        try:
            re.compile(item, re.IGNORECASE)
        except re.error:
            raise StoreError(400, "Access condition regex is invalid") from None

    return item


def normalize_access_action(value) -> str:
    action = str(value or "deny").lower()
    if action == "block":
        action = "deny"
    return action if action in ACCESS_ACTIONS else "deny"


def build_stats(state: dict) -> dict:
    logs = state.get("logs") or []
    blocked = sum(1 for entry in logs if entry.get("verdict") == "block")
    challenged = sum(1 for entry in logs if entry.get("verdict") == "challenge")
    monitored = sum(1 for entry in logs if entry.get("verdict") == "monitor")
    protected = blocked + challenged
    total = len(logs)

    top_rules = Counter(
        rule.get("name") or rule.get("id")
        for entry in logs
        for rule in entry.get("matchedRules", [])
    )
    top_sites = Counter(entry.get("siteName") or "Unmatched" for entry in logs)
    status_groups = Counter(status_group(entry) for entry in logs)

    return {
        "total": total,
        "blocked": blocked,
        "challenged": challenged,
        "protected": protected,
        "monitored": monitored,
        "allowed": max(total - protected - monitored, 0),
        "blockRate": round((blocked / total) * 100, 1) if total else 0,
        "protectedRate": round((protected / total) * 100, 1) if total else 0,
        "topRules": counter_items(top_rules),
        "topSites": counter_items(top_sites),
        "statusGroups": counter_items(status_groups),
        "timeline": build_timeline(logs),
    }


def build_timeline(logs: list[dict]) -> list[dict]:
    import time

    bucket_ms = 5 * 60 * 1000
    bucket_count = 24
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - bucket_ms * (bucket_count - 1)
    buckets = []
    for index in range(bucket_count):
        at = start_ms + bucket_ms * index
        label = datetime.fromtimestamp(at / 1000).strftime("%H:%M")
        buckets.append({"at": at, "label": label, "total": 0, "blocked": 0, "challenged": 0, "protected": 0})

    for entry in logs:
        try:
            at_ms = int(datetime.fromisoformat(str(entry.get("at")).replace("Z", "+00:00")).timestamp() * 1000)
        except ValueError:
            continue
        if at_ms < start_ms:
            continue
        index = min(bucket_count - 1, max(0, (at_ms - start_ms) // bucket_ms))
        buckets[index]["total"] += 1
        if entry.get("verdict") == "block":
            buckets[index]["blocked"] += 1
            buckets[index]["protected"] += 1
        elif entry.get("verdict") == "challenge":
            buckets[index]["challenged"] += 1
            buckets[index]["protected"] += 1

    return buckets


def status_group(entry: dict) -> str:
    status = int(entry.get("upstreamStatus") or entry.get("statusCode") or 0)
    return f"{status // 100}xx" if status else "n/a"


def counter_items(counter: Counter) -> list[dict]:
    return [{"name": name, "count": count} for name, count in counter.most_common(8)]


def find_index(items: list[dict], item_id: str) -> int:
    for index, item in enumerate(items):
        if item.get("id") == item_id:
            return index
    return -1


def create_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"
