from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import mimetypes
import os
import re
import secrets
import shlex
import ssl
import subprocess
import uuid
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from .nginx import (
    clear_nginx_logs,
    generate_nginx_config,
    nginx_runtime,
    parse_nginx_logs,
    run_nginx_command,
    scan_nginx_log_entries,
    seed_nginx_log_scan_cache,
    site_ports,
    write_nginx_config,
)
from .defaults import challenge_secret, utc_now
from .store import (
    Store,
    StoreError,
    build_stats,
    build_stats_from_summary,
    classify_bot_type,
    country_for_ip,
    match_log_site,
    normalize_ip_items,
    resolve_data_file,
)


ROOT_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"
LOGIN_THROTTLE_WINDOW_SECONDS = 300
LOGIN_THROTTLE_IP_LIMIT = 5
LOGIN_THROTTLE_USER_LIMIT = 10
STATS_AGGREGATE_BUCKET_MS = 5 * 60 * 1000
STATS_AGGREGATE_LOCK = threading.RLock()
STATS_AGGREGATE_CACHE_VERSION = 1
STATS_AGGREGATE_CACHE = {"files": {}, "countryCache": {}, "loadedCacheName": ""}


def main() -> None:
    admin_port = int(os.environ.get("ADMIN_PORT", "7001"))
    demo_origin_port = int(os.environ.get("DEMO_ORIGIN_PORT", "9090"))
    enable_demo_origin = os.environ.get("ENABLE_DEMO_ORIGIN", "true").lower() != "false"

    store = Store(resolve_data_file(ROOT_DIR))
    store.init()
    start_ip_group_sync_worker(store)
    start_stats_warmup_worker(store)
    state = store.get_state()
    panel = state.get("settings", {}).get("panel", {})
    admin_https = bool(panel.get("httpsEnabled"))

    admin_server = ThreadingHTTPServer(
        ("0.0.0.0", admin_port),
        make_admin_handler(store, admin_port, demo_origin_port, enable_demo_origin, admin_https),
    )
    if admin_https:
        certificate = next((item for item in state.get("certificates", []) if item["id"] == panel.get("certificateId")), None)
        if certificate:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(resolve_reference(certificate.get("certFile")), resolve_reference(certificate.get("keyFile")))
                admin_server.socket = context.wrap_socket(admin_server.socket, server_side=True)
            except Exception as error:
                admin_https = False
                print(f"Panel HTTPS failed to load certificate: {error}. Falling back to HTTP.")
        else:
            admin_https = False
            print("Panel HTTPS is enabled, but the selected certificate was not found. Falling back to HTTP.")

    servers = [("Admin dashboard", admin_server)]

    if enable_demo_origin:
        servers.append(("Demo origin", ThreadingHTTPServer(("127.0.0.1", demo_origin_port), make_demo_handler())))

    threads = []
    for label, server in servers:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
        scheme = "https" if label == "Admin dashboard" and admin_https else "http"
        print(f"{label}: {scheme}://localhost:{server.server_port}")

    ports = sorted({port for site in store.get_state().get("sites", []) if site.get("enabled") for port, _ in site_ports(site)})
    print(f"Nginx WAF listen ports from config: {', '.join(str(port) for port in ports) or 'none'}")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nStopping servers...")
    finally:
        for _, server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def make_admin_handler(store: Store, admin_port: int, demo_origin_port: int, demo_enabled: bool, secure_cookie: bool = False):
    sessions: dict[str, dict] = {}
    sessions_lock = threading.RLock()
    login_attempts: dict[str, list[float]] = {}
    login_attempts_lock = threading.RLock()

    def login_throttle_check(ip: str, username: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds). Uses sliding windows on
        (ip) and (username) separately so an attacker cannot lock out a real
        user just by spraying that username from many addresses."""
        now = time.monotonic()
        window = float(LOGIN_THROTTLE_WINDOW_SECONDS)
        ip_limit = LOGIN_THROTTLE_IP_LIMIT
        user_limit = LOGIN_THROTTLE_USER_LIMIT
        ip_key = f"ip:{ip}" if ip else ""
        user_key = f"user:{(username or '').strip().lower()}" if username else ""
        with login_attempts_lock:
            # Garbage collect every now and then so dict does not grow forever.
            if len(login_attempts) > 4096:
                cutoff = now - window
                for stored_key in list(login_attempts.keys()):
                    fresh = [t for t in login_attempts[stored_key] if t > cutoff]
                    if fresh:
                        login_attempts[stored_key] = fresh
                    else:
                        login_attempts.pop(stored_key, None)
            for key, limit in ((ip_key, ip_limit), (user_key, user_limit)):
                if not key or limit <= 0:
                    continue
                attempts = [t for t in login_attempts.get(key, []) if t > now - window]
                login_attempts[key] = attempts
                if len(attempts) >= limit:
                    oldest = attempts[0]
                    retry_after = max(1, int(window - (now - oldest)) + 1)
                    return False, retry_after
        return True, 0

    def login_throttle_record_failure(ip: str, username: str) -> None:
        now = time.monotonic()
        with login_attempts_lock:
            if ip:
                login_attempts.setdefault(f"ip:{ip}", []).append(now)
            if username:
                login_attempts.setdefault(f"user:{username.strip().lower()}", []).append(now)

    def login_throttle_record_success(ip: str, username: str) -> None:
        with login_attempts_lock:
            if ip:
                login_attempts.pop(f"ip:{ip}", None)
            if username:
                login_attempts.pop(f"user:{username.strip().lower()}", None)

    class AdminHandler(BaseHTTPRequestHandler):
        server_version = "FreeWAFAdmin/1.0"

        def end_headers(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "content-type,accept")
            super().end_headers()

        def do_OPTIONS(self):
            self.send_empty(204)

        def do_HEAD(self):
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", "0")
            self.end_headers()

        def do_GET(self):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)

            if self.headers.get("X-FreeWAF-Challenge-Render") == "1":
                self.serve_challenge_page()
                return

            if parsed.path == "/api/health":
                self.send_json(200, {"ok": True, "adminPort": admin_port, "waf": "nginx"})
                return

            if parsed.path == "/api/auth/status":
                self.send_json(200, self.auth_status())
                return

            if parsed.path.startswith("/api/") and not self.require_auth(parsed.path):
                return

            if parsed.path == "/api/state":
                state = store.get_state()
                limit = parse_int((query.get("logLimit") or ["200"])[0], 200)
                logs = combined_logs(store, clamp(limit, 1, 1000))
                state["logs"] = logs
                state["stats"] = combined_stats(store, state)
                state["runtime"] = runtime_payload(state, admin_port, demo_origin_port, demo_enabled)
                state["users"] = [public_user(user) for user in state.get("users", [])]
                self.send_json(200, state)
                return

            if parsed.path == "/api/stats":
                state = store.get_state()
                self.send_json(200, combined_stats(store, state))
                return

            if parsed.path == "/api/logs":
                page_size = clamp(parse_int((query.get("pageSize") or query.get("limit") or ["50"])[0], 50), 1, 200)
                page = max(1, parse_int((query.get("page") or ["1"])[0], 1))
                offset = max(0, parse_int((query.get("offset") or [str((page - 1) * page_size)])[0], (page - 1) * page_size))
                domain = str((query.get("domain") or [""])[0]).strip()
                site_id = str((query.get("siteId") or query.get("site_id") or [""])[0]).strip()
                verdict = str((query.get("verdict") or [""])[0]).strip()
                search = str((query.get("search") or [""])[0]).strip()
                self.send_json(200, combined_logs_page(store, page_size, offset, domain, search, site_id, verdict))
                return

            if parsed.path == "/api/nginx/render":
                self.send_json(
                    200,
                    {
                        "config": generate_nginx_config(store.get_state()),
                        "runtime": nginx_runtime(ROOT_DIR),
                    },
                )
                return

            if parsed.path == "/api/audit-log":
                limit = parse_int((query.get("limit") or ["200"])[0], 200)
                self.send_json(200, {"entries": read_audit_log(clamp(limit, 1, 1000))})
                return

            self.serve_static(parsed.path)

        def do_POST(self):
            try:
                if urlparse(self.path).path == "/.freewaf/challenge/verify":
                    self.verify_challenge()
                    return

                if self.path == "/api/auth/setup":
                    payload = self.read_payload()
                    if store.has_users():
                        self.send_json(400, {"error": "Initial admin user already exists"})
                        return
                    saved = store.upsert_user(
                        {
                            "username": payload.get("username"),
                            "displayName": payload.get("displayName") or payload.get("username"),
                            "password": payload.get("password"),
                            "role": "admin",
                            "enabled": True,
                            "totpEnabled": bool(payload.get("totpEnabled")),
                        }
                    )
                    self.record_audit(action="auth.setup", target="users", target_id=saved.get("id", ""), status=200, actor=saved, extra={"username": saved.get("username", "")})
                    self.login_user(saved)
                    return

                if self.path == "/api/auth/login":
                    payload = self.read_payload()
                    username = str(payload.get("username") or "").strip()
                    remote_ip = self.client_remote_address()
                    allowed, retry_after = login_throttle_check(remote_ip, username)
                    if not allowed:
                        self.record_audit(
                            action="auth.login.throttled",
                            target="users",
                            status=429,
                            actor={},
                            extra={"username": username[:64], "retryAfter": retry_after},
                        )
                        self.send_json(
                            429,
                            {"error": "Too many login attempts. Please wait and try again.", "retryAfter": retry_after},
                            headers={"Retry-After": str(retry_after)},
                        )
                        return
                    try:
                        user = store.authenticate_user(username, payload.get("password", ""), payload.get("totpCode", ""))
                    except Exception:
                        login_throttle_record_failure(remote_ip, username)
                        self.record_audit(action="auth.login.failed", target="users", status=401, actor={}, extra={"username": username[:64]})
                        raise
                    login_throttle_record_success(remote_ip, username)
                    self.record_audit(action="auth.login", target="users", target_id=user.get("id", ""), status=200, actor=user, extra={"username": user.get("username", "")})
                    self.login_user(user)
                    return

                if self.path == "/api/auth/logout":
                    self.record_audit(action="auth.logout", target="users", status=200)
                    self.logout_user()
                    return

                if self.path.startswith("/api/") and not self.require_auth(self.path):
                    return

                resource, item_id, action = split_action_path(self.path)
                if resource == "ip-groups" and action == "sync":
                    saved = sync_ip_group_reference(store, item_id)
                    maybe_auto_write(store)
                    self.record_audit(action="ip-groups.sync", target="ip-groups", target_id=item_id, status=200)
                    self.send_json(200, saved)
                    return

                if resource == "users" and action == "password":
                    payload = self.read_payload()
                    saved = store.change_user_password(item_id, payload.get("password", ""))
                    self.record_audit(action="users.password", target="users", target_id=item_id, status=200)
                    self.send_json(200, public_user(saved))
                    return

                payload = self.read_payload()
                if self.path == "/api/sites":
                    saved = store.upsert_site(payload)
                    apply_nginx_or_raise(store)
                    self.record_audit(action="sites.create", target="sites", target_id=saved.get("id", ""), status=201, payload=payload)
                    self.send_json(201, saved)
                    return
                if self.path == "/api/rules":
                    saved = store.upsert_rule(payload)
                    maybe_auto_write(store)
                    self.record_audit(action="rules.create", target="rules", target_id=saved.get("id", ""), status=201, payload=payload)
                    self.send_json(201, saved)
                    return
                if self.path == "/api/certificates":
                    saved = store.upsert_certificate(prepare_certificate_payload(payload))
                    apply_nginx_or_raise(store)
                    self.record_audit(action="certificates.create", target="certificates", target_id=saved.get("id", ""), status=201, payload=payload)
                    self.send_json(201, saved)
                    return
                if self.path == "/api/ip-groups":
                    saved = store.upsert_ip_group(payload)
                    saved = maybe_sync_new_reference_ip_group(store, saved)
                    maybe_auto_write(store)
                    self.record_audit(action="ip-groups.create", target="ip-groups", target_id=saved.get("id", ""), status=201, payload=payload)
                    self.send_json(201, saved)
                    return
                if self.path == "/api/access-rules":
                    saved = store.upsert_access_rule(payload)
                    maybe_auto_write(store)
                    self.record_audit(action="access-rules.create", target="access-rules", target_id=saved.get("id", ""), status=201, payload=payload)
                    self.send_json(201, saved)
                    return
                if self.path == "/api/users":
                    saved = store.upsert_user(payload)
                    self.record_audit(action="users.create", target="users", target_id=saved.get("id", ""), status=201, payload=payload)
                    self.send_json(201, public_user(saved, include_totp_secret=bool(saved.get("_totpSecretGenerated"))))
                    return
                if self.path == "/api/nginx/apply":
                    result = apply_nginx(store, payload)
                    self.record_audit(action="nginx.apply", target="nginx", status=200, payload=payload, extra={"ok": bool(result.get("ok"))})
                    self.send_json(200, result)
                    return
                self.send_json(404, {"error": "Not found"})
            except StoreError as error:
                self.send_json(error.status, error_payload(error))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})

        def do_PUT(self):
            if self.path.startswith("/api/") and not self.require_auth(self.path):
                return
            self.handle_resource_update(replace=True)

        def do_PATCH(self):
            if self.path.startswith("/api/") and not self.require_auth(self.path):
                return
            if self.path == "/api/settings":
                try:
                    payload = self.read_payload()
                    saved = store.update_settings(payload)
                    self.record_audit(action="settings.update", target="settings", status=200, payload=payload)
                    self.send_json(200, saved)
                except StoreError as error:
                    self.send_json(error.status, error_payload(error))
                except ValueError as error:
                    self.send_json(400, {"error": str(error)})
                return
            self.handle_resource_update(replace=False)

        def do_DELETE(self):
            try:
                if self.path.startswith("/api/") and not self.require_auth(self.path):
                    return
                resource, item_id = split_resource_path(self.path)
                if resource == "sites":
                    store.delete_site(item_id)
                    apply_nginx_or_raise(store)
                    self.record_audit(action="sites.delete", target="sites", target_id=item_id, status=204)
                    self.send_empty(204)
                    return
                if resource == "rules":
                    store.delete_rule(item_id)
                    maybe_auto_write(store)
                    self.record_audit(action="rules.delete", target="rules", target_id=item_id, status=204)
                    self.send_empty(204)
                    return
                if resource == "certificates":
                    certificate = next((item for item in store.get_state()["certificates"] if item["id"] == item_id), None)
                    if not certificate:
                        self.send_json(404, {"error": "Certificate not found"})
                        return
                    remove_certificate_files(certificate)
                    store.delete_certificate(item_id)
                    apply_nginx_or_raise(store)
                    self.record_audit(action="certificates.delete", target="certificates", target_id=item_id, status=204)
                    self.send_empty(204)
                    return
                if resource == "ip-groups":
                    store.delete_ip_group(item_id)
                    maybe_auto_write(store)
                    self.record_audit(action="ip-groups.delete", target="ip-groups", target_id=item_id, status=204)
                    self.send_empty(204)
                    return
                if resource == "access-rules":
                    store.delete_access_rule(item_id)
                    maybe_auto_write(store)
                    self.record_audit(action="access-rules.delete", target="access-rules", target_id=item_id, status=204)
                    self.send_empty(204)
                    return
                if resource == "users":
                    token_user = self.authenticated_user()
                    if token_user and token_user.get("id") == item_id:
                        self.send_json(400, {"error": "You cannot delete the signed-in user"})
                        return
                    store.delete_user(item_id)
                    self.record_audit(action="users.delete", target="users", target_id=item_id, status=204)
                    self.send_empty(204)
                    return
                if self.path in {"/api/logs", "/api/stats"}:
                    store.clear_logs()
                    clear_nginx_logs(ROOT_DIR)
                    clear_stats_aggregate_cache()
                    self.record_audit(action="logs.clear", target="logs", status=204)
                    self.send_empty(204)
                    return
                self.send_json(404, {"error": "Not found"})
            except StoreError as error:
                self.send_json(error.status, error_payload(error))

        def handle_resource_update(self, replace: bool):
            try:
                payload = self.read_payload()
                resource, item_id = split_resource_path(self.path)
                state = store.get_state()
                action_verb = "replace" if replace else "update"

                if resource == "sites":
                    if not replace:
                        current = next((item for item in state["sites"] if item["id"] == item_id), None)
                        if not current:
                            self.send_json(404, {"error": "Site not found"})
                            return
                        payload = {**current, **payload}
                    saved = store.upsert_site(payload, item_id)
                    apply_nginx_or_raise(store)
                    self.record_audit(action=f"sites.{action_verb}", target="sites", target_id=item_id, status=200, payload=payload)
                    self.send_json(200, saved)
                    return

                if resource == "rules":
                    if not replace:
                        current = next((item for item in state["rules"] if item["id"] == item_id), None)
                        if not current:
                            self.send_json(404, {"error": "Rule not found"})
                            return
                        payload = {**current, **payload}
                    saved = store.upsert_rule(payload, item_id)
                    maybe_auto_write(store)
                    self.record_audit(action=f"rules.{action_verb}", target="rules", target_id=item_id, status=200, payload=payload)
                    self.send_json(200, saved)
                    return

                if resource == "certificates":
                    if not replace:
                        current = next((item for item in state["certificates"] if item["id"] == item_id), None)
                        if not current:
                            self.send_json(404, {"error": "Certificate not found"})
                            return
                        payload = {**current, **payload}
                    saved = store.upsert_certificate(prepare_certificate_payload(payload, item_id), item_id)
                    apply_nginx_or_raise(store)
                    self.record_audit(action=f"certificates.{action_verb}", target="certificates", target_id=item_id, status=200, payload=payload)
                    self.send_json(200, saved)
                    return

                if resource == "ip-groups":
                    payload_has_items = "items" in payload or "content" in payload
                    if not replace:
                        current = next((item for item in state["ipGroups"] if item["id"] == item_id), None)
                        if not current:
                            self.send_json(404, {"error": "IP group not found"})
                            return
                        payload = {**current, **payload}
                    if not payload_has_items:
                        payload.pop("items", None)
                        payload.pop("content", None)
                    saved = store.upsert_ip_group(payload, item_id)
                    saved = maybe_sync_new_reference_ip_group(store, saved)
                    maybe_auto_write(store)
                    self.record_audit(action=f"ip-groups.{action_verb}", target="ip-groups", target_id=item_id, status=200, payload=payload)
                    self.send_json(200, saved)
                    return

                if resource == "access-rules":
                    move_rule = "insertPosition" in payload
                    if not replace:
                        current = next((item for item in state["accessRules"] if item["id"] == item_id), None)
                        if not current:
                            self.send_json(404, {"error": "Access rule not found"})
                            return
                        payload = {**current, **payload}
                    if move_rule:
                        payload["_moveAccessRule"] = True
                    saved = store.upsert_access_rule(payload, item_id)
                    maybe_auto_write(store)
                    self.record_audit(action=f"access-rules.{action_verb}", target="access-rules", target_id=item_id, status=200, payload=payload)
                    self.send_json(200, saved)
                    return

                if resource == "users":
                    if not replace:
                        current = next((item for item in state["users"] if item["id"] == item_id), None)
                        if not current:
                            self.send_json(404, {"error": "User not found"})
                            return
                        payload = {**current, **payload}
                    saved = store.upsert_user(payload, item_id)
                    self.record_audit(action=f"users.{action_verb}", target="users", target_id=item_id, status=200, payload=payload)
                    self.send_json(200, public_user(saved, include_totp_secret=bool(saved.get("_totpSecretGenerated"))))
                    return

                self.send_json(404, {"error": "Not found"})
            except StoreError as error:
                self.send_json(error.status, error_payload(error))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})

        def auth_status(self) -> dict:
            user = self.authenticated_user()
            return {
                "authenticated": bool(user),
                "setupRequired": not store.has_users(),
                "user": public_user(user) if user else None,
            }

        def require_auth(self, path: str) -> bool:
            if is_public_api_path(path):
                return True
            if not store.has_users():
                self.send_json(401, {"error": "Initial admin user is required", "setupRequired": True})
                return False
            if self.authenticated_user():
                return True
            self.send_json(401, {"error": "Login required"})
            return False

        def login_user(self, user: dict) -> None:
            token = secrets.token_urlsafe(32)
            max_age = session_max_age_seconds(store.get_state())
            with sessions_lock:
                sessions[token] = {
                    "userId": user["id"],
                    "expiresAt": time.time() + max_age,
                }
                prune_sessions(sessions)
            self.send_json(
                200,
                {
                    "authenticated": True,
                    "setupRequired": False,
                    "user": public_user(user, include_totp_secret=bool(user.get("_totpSecretGenerated"))),
                },
                headers={"Set-Cookie": session_cookie(token, max_age, secure_cookie)},
            )

        def logout_user(self) -> None:
            token = session_token_from_headers(self.headers.get("cookie", ""))
            if token:
                with sessions_lock:
                    sessions.pop(token, None)
            self.send_json(
                200,
                {"authenticated": False},
                headers={"Set-Cookie": expired_session_cookie(secure_cookie)},
            )

        def authenticated_user(self) -> dict | None:
            token = session_token_from_headers(self.headers.get("cookie", ""))
            if not token:
                return None
            with sessions_lock:
                session = sessions.get(token)
                if not session:
                    return None
                if session.get("expiresAt", 0) < time.time():
                    sessions.pop(token, None)
                    return None
                user_id = session.get("userId")
            user = next((item for item in store.get_state().get("users", []) if item["id"] == user_id and item.get("enabled")), None)
            return user

        def serve_challenge_page(self) -> None:
            context = internal_challenge_context(self.headers)
            if not context:
                self.send_json(403, {"error": "Invalid challenge request"})
                return
            state = store.get_state()
            site = challenge_site(state, context["siteId"])
            if not site:
                self.send_json(404, {"error": "Application not found"})
                return
            body = render_challenge_page(state, site, context)
            self.send_html(
                200,
                body,
                headers=[
                    ("Cache-Control", "no-store, no-cache, must-revalidate"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Referrer-Policy", "no-referrer"),
                ],
            )

        def verify_challenge(self) -> None:
            context = internal_challenge_context(self.headers)
            if not context:
                self.send_json(403, {"error": "Invalid challenge request"})
                return
            state = store.get_state()
            site = challenge_site(state, context["siteId"])
            if not site:
                self.send_json(404, {"error": "Application not found"})
                return
            payload = self.read_payload()
            if not verify_challenge_nonce(payload.get("nonce"), context):
                self.send_json(403, {"error": "Challenge expired or invalid"})
                return
            settings = state.get("settings", {}).get("challengePage", {})
            pow_bits = pow_difficulty_bits(settings)
            if pow_bits > 0:
                pow_salt = payload.get("powSalt")
                pow_solution = payload.get("powSolution")
                if not verify_pow(pow_salt if isinstance(pow_salt, str) else "",
                                  pow_solution if isinstance(pow_solution, str) else "",
                                  pow_bits):
                    self.send_json(403, {"error": "Proof of work failed"})
                    return
            ttl_minutes = clamp(parse_int(settings.get("tokenTtlMinutes"), 30), 1, 1440)
            max_age = ttl_minutes * 60
            expires = int(time.time()) + max_age
            token = secure_link_token(context, expires)
            secure = context["proto"] == "https"
            self.send_json(
                200,
                {"ok": True, "expiresAt": expires},
                headers=[
                    ("Set-Cookie", challenge_cookie("freewaf_challenge", token, max_age, secure)),
                    ("Set-Cookie", challenge_cookie("freewaf_challenge_expires", str(expires), max_age, secure)),
                    ("Cache-Control", "no-store"),
                ],
            )

        def serve_static(self, request_path: str):
            if not FRONTEND_DIST.exists():
                body = (
                    "<!doctype html><title>FreeWAF</title>"
                    "<p>Build the React app with <code>npm --prefix frontend run build</code>, "
                    "or run <code>npm --prefix frontend run dev</code>.</p>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            relative = request_path.lstrip("/") or "index.html"
            candidate = (FRONTEND_DIST / relative).resolve()
            if not is_relative_to(candidate, FRONTEND_DIST.resolve()) or not candidate.is_file():
                candidate = FRONTEND_DIST / "index.html"

            if not candidate.exists():
                self.send_json(404, {"error": "Frontend build not found"})
                return

            content = candidate.read_bytes()
            content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("content-type", content_type)
            self.send_header("content-length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def read_payload(self) -> dict:
            length = int(self.headers.get("content-length") or "0")
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError as error:
                raise ValueError("Invalid JSON body") from error
            if not isinstance(payload, dict):
                raise ValueError("JSON body must be an object")
            return payload

        def send_json(self, status: int, payload: dict, headers=None):
            body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
            header_items = response_headers(headers)
            header_names = {str(key).lower() for key, _value in header_items}
            self.send_response(status)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            if "cache-control" not in header_names:
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            if "pragma" not in header_names:
                self.send_header("Pragma", "no-cache")
            if "expires" not in header_names:
                self.send_header("Expires", "0")
            for key, value in header_items:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def send_html(self, status: int, content: str, headers=None):
            body = content.encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            for key, value in response_headers(headers):
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def send_empty(self, status: int, headers=None):
            self.send_response(status)
            self.send_header("content-length", "0")
            for key, value in response_headers(headers):
                self.send_header(key, value)
            self.end_headers()

        def log_message(self, format, *args):
            return

        def client_remote_address(self) -> str:
            forwarded = self.headers.get("x-forwarded-for") or ""
            if forwarded:
                first = forwarded.split(",")[0].strip()
                if first:
                    return first
            real_ip = self.headers.get("x-real-ip")
            if real_ip:
                return real_ip.strip()
            try:
                return self.client_address[0]
            except (IndexError, TypeError):
                return ""

        def record_audit(
            self,
            *,
            action: str,
            target: str = "",
            target_id: str = "",
            status: int = 200,
            payload: dict | None = None,
            extra: dict | None = None,
            actor: dict | None = None,
        ) -> None:
            try:
                user = actor if actor is not None else self.authenticated_user()
                entry = {
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "action": action,
                    "method": self.command,
                    "path": self.path,
                    "target": target,
                    "targetId": target_id or "",
                    "status": status,
                    "remoteAddr": self.client_remote_address(),
                    "userAgent": (self.headers.get("user-agent") or "")[:256],
                    "userId": (user or {}).get("id", ""),
                    "username": (user or {}).get("username", ""),
                }
                if payload is not None:
                    entry["payload"] = _redact_audit_value(payload)
                if extra:
                    entry["extra"] = _redact_audit_value(extra)
                append_audit_log(entry)
            except Exception:
                # never let audit break the API path
                pass

    return AdminHandler


def apply_nginx(store: Store, payload: dict) -> dict:
    output_file = write_nginx_config(ROOT_DIR, store.get_state())
    result = {
        "ok": True,
        "outputFile": str(output_file),
        "config": generate_nginx_config(store.get_state()),
        "test": None,
        "reload": None,
    }

    if payload.get("test"):
        test_result = run_nginx_command(os.environ.get("NGINX_TEST_CMD", "nginx -t"))
        result["test"] = test_result
        result["ok"] = result["ok"] and test_result.get("ok", False)

    if payload.get("reload"):
        if result["test"] and not result["test"].get("ok"):
            result["reload"] = {"configured": True, "ok": False, "stderr": "Skipped reload because nginx test failed"}
            result["ok"] = False
        else:
            reload_result = run_nginx_command(os.environ.get("NGINX_RELOAD_CMD", "nginx -s reload"))
            result["reload"] = reload_result
            result["ok"] = result["ok"] and reload_result.get("ok", False)

    return result


def apply_nginx_or_raise(store: Store) -> dict:
    result = apply_nginx(store, {"test": True, "reload": True})
    if result.get("ok"):
        return result

    messages = []
    for key in ("test", "reload"):
        item = result.get(key) or {}
        for stream in ("stderr", "stdout"):
            value = str(item.get(stream) or "").strip()
            if value:
                messages.append(value)
    message = "\n".join(dict.fromkeys(messages)) or "Nginx config update failed"
    raise StoreError(500, message)


def public_user(user: dict | None, include_totp_secret: bool = False) -> dict | None:
    if not user:
        return None
    payload = {
        "id": user.get("id"),
        "username": user.get("username"),
        "displayName": user.get("displayName") or user.get("username"),
        "role": user.get("role") or "admin",
        "enabled": user.get("enabled") is not False,
        "totpEnabled": bool(user.get("totpEnabled")),
        "lastLoginAt": user.get("lastLoginAt", ""),
        "createdAt": user.get("createdAt", ""),
        "updatedAt": user.get("updatedAt", ""),
    }
    if include_totp_secret and user.get("totpSecret"):
        payload["totpSetupSecret"] = user["totpSecret"]
        payload["totpSetupUri"] = totp_setup_uri(user)
    return payload


def error_payload(error: StoreError) -> dict:
    payload = {"error": error.message}
    if "Google Authenticator" in error.message:
        payload["totpRequired"] = True
    return payload


def totp_setup_uri(user: dict) -> str:
    issuer = "FreeWAF"
    label = quote(f"{issuer}:{user.get('username')}", safe="")
    secret = quote(str(user.get("totpSecret") or ""), safe="")
    issuer_value = quote(issuer, safe="")
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer_value}&algorithm=SHA1&digits=6&period=30"


def is_public_api_path(path: str) -> bool:
    parsed = urlparse(path)
    return parsed.path in {"/api/health", "/api/auth/status", "/api/auth/setup", "/api/auth/login", "/api/auth/logout"}


def response_headers(headers) -> list[tuple[str, str]]:
    if not headers:
        return []
    return list(headers.items()) if isinstance(headers, dict) else list(headers)


def internal_challenge_context(headers) -> dict | None:
    supplied_secret = str(headers.get("X-FreeWAF-Challenge-Secret") or "")
    if not supplied_secret or not hmac.compare_digest(supplied_secret, challenge_secret()):
        return None
    site_id = str(headers.get("X-FreeWAF-Challenge-Site") or "").strip()
    host = str(headers.get("X-FreeWAF-Challenge-Host") or "").strip().lower()
    ip = str(headers.get("X-Real-IP") or "").strip()
    user_agent = str(headers.get("User-Agent") or "")
    proto = str(headers.get("X-Forwarded-Proto") or "http").strip().lower()
    if not site_id or not host or not ip:
        return None
    return {
        "siteId": site_id,
        "host": host,
        "ip": ip,
        "userAgent": user_agent,
        "proto": "https" if proto == "https" else "http",
    }


def challenge_site(state: dict, site_id: str) -> dict | None:
    return next((site for site in state.get("sites", []) if site.get("id") == site_id and site.get("enabled")), None)


def challenge_nonce(context: dict, ttl_seconds: int = 120, delay_seconds: int = 0) -> str:
    now = int(time.time())
    payload = {
        "exp": now + ttl_seconds,
        "nbf": now + max(0, int(delay_seconds or 0)),
        "site": context["siteId"],
        "host": context["host"],
        "ip": context["ip"],
        "ua": hashlib.sha256(context["userAgent"].encode("utf-8")).hexdigest(),
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(challenge_secret().encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')}"


def verify_challenge_nonce(value, context: dict) -> bool:
    try:
        encoded, supplied_signature = str(value or "").split(".", 1)
        expected_signature = base64.urlsafe_b64encode(
            hmac.new(challenge_secret().encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
        ).decode("ascii").rstrip("=")
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return False
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (ValueError, TypeError, json.JSONDecodeError):
        return False
    try:
        expires = int(payload.get("exp") or 0)
    except (TypeError, ValueError):
        return False
    expected_ua = hashlib.sha256(context["userAgent"].encode("utf-8")).hexdigest()
    try:
        not_before = int(payload.get("nbf") or 0)
    except (TypeError, ValueError):
        return False
    now = int(time.time())
    return (
        expires >= now
        and not_before <= now
        and payload.get("site") == context["siteId"]
        and payload.get("host") == context["host"]
        and payload.get("ip") == context["ip"]
        and payload.get("ua") == expected_ua
    )


def secure_link_token(context: dict, expires: int) -> str:
    value = f"{expires}|{context['host']}|{context['ip']}|{context['userAgent']}|{challenge_secret()}"
    digest = hashlib.md5(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def challenge_cookie(name: str, value: str, max_age: int, secure: bool) -> str:
    flags = "HttpOnly; SameSite=Lax; Path=/"
    if secure:
        flags += "; Secure"
    return f"{name}={value}; Max-Age={max_age}; {flags}"


def render_challenge_page(state: dict, site: dict, context: dict) -> str:
    settings = state.get("settings", {}).get("challengePage", {})
    brand = html.escape(str(settings.get("brandName") or "FreeWAF"))
    title = html.escape(str(settings.get("title") or "Security check"))
    message = html.escape(str(settings.get("message") or "We are verifying your browser before continuing."))
    application = html.escape(str(site.get("name") or context["host"]))
    logo_url = html.escape(str(settings.get("logoUrl") or ""), quote=True)
    support_url = html.escape(str(settings.get("supportUrl") or ""), quote=True)
    primary = str(settings.get("primaryColor") or "#18a69a")
    background = str(settings.get("backgroundColor") or "#f5f7f8")
    text = str(settings.get("textColor") or "#17202a")
    wait_seconds = challenge_wait_seconds(settings)
    nonce = json.dumps(challenge_nonce(context, delay_seconds=wait_seconds))
    pow_bits = pow_difficulty_bits(settings)
    pow_salt = json.dumps(make_pow_salt())
    pow_bits_json = json.dumps(pow_bits)
    wait_ms = wait_seconds * 1000
    logo = f'<img class="logo" src="{logo_url}" alt="{brand}">' if logo_url else f'<div class="brand-mark">{brand[:1] or "F"}</div>'
    support = f'<a href="{support_url}" rel="noreferrer">Contact support</a>' if support_url else ""
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{title}</title><style>"
        f":root{{--primary:{primary};--background:{background};--text:{text}}}"
        "*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--background);"
        "color:var(--text);font-family:Segoe UI,Arial,sans-serif}main{width:min(520px,100%);text-align:center}.logo{display:block;max-width:180px;"
        "max-height:64px;margin:0 auto 24px;object-fit:contain}.brand-mark{display:grid;place-items:center;width:54px;height:54px;margin:0 auto 24px;"
        "border-radius:8px;background:var(--primary);color:#fff;font-size:24px;font-weight:800}h1{margin:0 0 12px;font-size:28px;letter-spacing:0}"
        "p{margin:0 auto 18px;max-width:460px;line-height:1.6;opacity:.75}.application{font-size:13px;font-weight:700;opacity:.6}"
        ".loader{width:34px;height:34px;margin:26px auto;border:3px solid color-mix(in srgb,var(--primary) 20%,transparent);"
        "border-top-color:var(--primary);border-radius:50%;animation:spin .8s linear infinite}.status{min-height:22px;font-size:13px;opacity:.72}"
        "a{display:inline-block;margin-top:20px;color:var(--primary);font-size:13px;font-weight:700;text-decoration:none}@keyframes spin{to{transform:rotate(360deg)}}"
        "</style></head><body><main>"
        f"{logo}<h1>{title}</h1><p>{message}</p><div class=\"application\">{application}</div><div class=\"loader\"></div>"
        f"<div class=\"status\" id=\"status\">Checking browser integrity... {wait_seconds}s</div>{support}"
        "<noscript><p>JavaScript is required to complete this security check.</p></noscript></main>"
        "<script>(function(){const status=document.getElementById('status');let remaining="
        f"{wait_seconds};const powSalt={pow_salt};const powBits={pow_bits_json};const challengeNonce={nonce};"
        "function tick(){status.textContent=remaining>0?'Checking browser integrity... '+remaining+'s':'Finalizing verification...';}"
        "function leadingZeroBitsHex(hex){let bits=0;for(let i=0;i<hex.length;i++){const nibble=parseInt(hex[i],16);"
        "if(nibble===0){bits+=4;continue;}if(nibble<2)bits+=3;else if(nibble<4)bits+=2;else if(nibble<8)bits+=1;return bits;}return bits;}"
        "async function sha256Hex(text){const buffer=new TextEncoder().encode(text);"
        "const digest=await crypto.subtle.digest('SHA-256',buffer);return Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,'0')).join('');}"
        "async function solvePow(){if(!powBits)return '0';let counter=0;while(true){const candidate=counter.toString(36);"
        "const hex=await sha256Hex(powSalt+':'+candidate);if(leadingZeroBitsHex(hex)>=powBits)return candidate;counter+=1;"
        "if(counter%2048===0){status.textContent='Computing proof of work... '+counter;await new Promise(r=>setTimeout(r,0));}"
        "if(counter>5000000){throw new Error('PoW timeout');}}}"
        "async function verify(){try{status.textContent='Computing proof of work...';const solution=await solvePow();"
        "status.textContent='Finalizing verification...';"
        "const response=await fetch('/.freewaf/challenge/verify',"
        "{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},"
        "body:JSON.stringify({nonce:challengeNonce,powSalt:powSalt,powSolution:solution})});"
        "if(!response.ok)throw new Error('Verification failed');status.textContent='Verification complete. Continuing...';"
        "window.setTimeout(function(){window.location.reload();},350)}catch(error){status.textContent='Unable to verify this browser. Please refresh and try again.'}}"
        "tick();window.setTimeout(function(){verify();},"
        f"{wait_ms});if(remaining>0){{window.setInterval(function(){{remaining-=1;tick();}},1000);}}}})();</script>"
        "</body></html>"
    )


def challenge_wait_seconds(settings: dict) -> int:
    try:
        seconds = int(settings.get("waitSeconds") or 5)
    except (TypeError, ValueError):
        seconds = 5
    return seconds if seconds in {3, 5, 10} else 5


def pow_difficulty_bits(settings: dict) -> int:
    try:
        bits = int(settings.get("powDifficulty") or 16)
    except (TypeError, ValueError):
        bits = 16
    return clamp(bits, 0, 24)


def make_pow_salt() -> str:
    return secrets.token_urlsafe(16)


def verify_pow(salt: str, solution: str, bits: int) -> bool:
    if bits <= 0:
        return True
    if not isinstance(salt, str) or not isinstance(solution, str):
        return False
    if not salt or not solution or len(solution) > 32:
        return False
    digest = hashlib.sha256(f"{salt}:{solution}".encode("utf-8")).digest()
    full_bytes, remainder = divmod(bits, 8)
    if any(byte != 0 for byte in digest[:full_bytes]):
        return False
    if remainder and (digest[full_bytes] >> (8 - remainder)) != 0:
        return False
    return True


def session_max_age_seconds(state: dict) -> int:
    panel = state.get("settings", {}).get("panel", {})
    try:
        hours = int(panel.get("sessionHours") or 12)
    except (TypeError, ValueError):
        hours = 12
    return max(1, min(hours, 168)) * 3600


def session_cookie(token: str, max_age: int, secure: bool) -> str:
    flags = "HttpOnly; SameSite=Lax; Path=/"
    if secure:
        flags += "; Secure"
    return f"freewaf_session={token}; Max-Age={max_age}; {flags}"


def expired_session_cookie(secure: bool) -> str:
    flags = "HttpOnly; SameSite=Lax; Path=/"
    if secure:
        flags += "; Secure"
    return f"freewaf_session=; Max-Age=0; {flags}"


def session_token_from_headers(cookie_header: str) -> str:
    for part in str(cookie_header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == "freewaf_session":
            return value
    return ""


def prune_sessions(sessions: dict[str, dict]) -> None:
    now = time.time()
    for token in [token for token, session in sessions.items() if session.get("expiresAt", 0) < now]:
        sessions.pop(token, None)


def combined_logs(store: Store, limit: int) -> list[dict]:
    logs = [*parse_nginx_logs(ROOT_DIR, limit), *store.get_logs(limit)]
    return sorted(logs, key=lambda entry: entry.get("at") or "", reverse=True)[:limit]


def combined_stats_logs(store: Store) -> list[dict]:
    limit = stats_scan_limit()
    logs = [*parse_nginx_logs(ROOT_DIR, limit), *store.get_logs(limit)]
    return sorted(logs, key=lambda entry: entry.get("at") or "", reverse=True)[:limit]


def combined_stats(store: Store, state: dict | None = None) -> dict:
    source_state = state or store.get_state()
    recent_logs = combined_stats_logs(store)
    summary = nginx_stats_summary()
    if (summary.get("total") or 0) > 0:
        return build_stats_from_summary(source_state, summary, recent_logs)
    return build_stats({**source_state, "logs": recent_logs})


def nginx_stats_summary() -> dict:
    retention_days = stats_retention_days()
    now_ms = int(time.time() * 1000)
    retention_start_ms = now_ms - retention_days * 24 * 60 * 60 * 1000
    cache_name = f"stats:{retention_days}"

    with STATS_AGGREGATE_LOCK:
        load_stats_aggregate_cache(cache_name, retention_days)
        STATS_AGGREGATE_CACHE["retentionDays"] = retention_days

        def on_reset(path: str) -> None:
            STATS_AGGREGATE_CACHE["files"].pop(path, None)

        def on_entry(path: str, entry: dict) -> None:
            aggregate_stats_entry(STATS_AGGREGATE_CACHE, path, entry, retention_start_ms)

        scanner_state = scan_nginx_log_entries(ROOT_DIR, cache_name, on_entry, on_reset)
        STATS_AGGREGATE_CACHE["scannerState"] = scanner_state
        prune_stats_aggregate(STATS_AGGREGATE_CACHE, retention_start_ms)
        summary = collapse_stats_aggregate(STATS_AGGREGATE_CACHE, retention_start_ms)
        save_stats_aggregate_cache(cache_name, retention_days, scanner_state)
        return summary


def clear_stats_aggregate_cache() -> None:
    with STATS_AGGREGATE_LOCK:
        STATS_AGGREGATE_CACHE["files"] = {}
        STATS_AGGREGATE_CACHE["countryCache"] = {}
        STATS_AGGREGATE_CACHE["scannerState"] = {}
        STATS_AGGREGATE_CACHE["loadedCacheName"] = ""
    try:
        stats_cache_file().unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def load_stats_aggregate_cache(cache_name: str, retention_days: int) -> None:
    if STATS_AGGREGATE_CACHE.get("loadedCacheName") == cache_name:
        return
    STATS_AGGREGATE_CACHE["files"] = {}
    STATS_AGGREGATE_CACHE["countryCache"] = {}
    STATS_AGGREGATE_CACHE["scannerState"] = {}
    STATS_AGGREGATE_CACHE["loadedCacheName"] = cache_name
    path = stats_cache_file()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if payload.get("version") != STATS_AGGREGATE_CACHE_VERSION:
        return
    if int(payload.get("retentionDays") or 0) != retention_days:
        return

    files = {}
    for file_path, file_summary in (payload.get("files") or {}).items():
        buckets = {}
        for raw_at, bucket in (file_summary.get("buckets") or {}).items():
            try:
                bucket_at = int(raw_at)
            except (TypeError, ValueError):
                continue
            buckets[bucket_at] = bucket
        files[file_path] = {"buckets": buckets}
    scanner_state = payload.get("scannerState") if isinstance(payload.get("scannerState"), dict) else {}
    STATS_AGGREGATE_CACHE["files"] = files
    STATS_AGGREGATE_CACHE["scannerState"] = scanner_state
    seed_nginx_log_scan_cache(cache_name, scanner_state)


def save_stats_aggregate_cache(cache_name: str, retention_days: int, scanner_state: dict) -> None:
    path = stats_cache_file()
    files = {}
    for file_path, file_summary in (STATS_AGGREGATE_CACHE.get("files") or {}).items():
        files[file_path] = {
            "buckets": {
                str(bucket_at): bucket
                for bucket_at, bucket in (file_summary.get("buckets") or {}).items()
            }
        }
    payload = {
        "version": STATS_AGGREGATE_CACHE_VERSION,
        "cacheName": cache_name,
        "retentionDays": retention_days,
        "savedAt": utc_now(),
        "files": files,
        "scannerState": scanner_state,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, path)
    except OSError:
        pass


def stats_cache_file() -> Path:
    configured = Path(os.environ.get("STATS_CACHE_FILE", "./data/stats-cache.json"))
    return configured if configured.is_absolute() else ROOT_DIR / configured


def aggregate_stats_entry(cache: dict, path: str, entry: dict, retention_start_ms: int) -> None:
    at_ms = log_entry_timestamp_ms(entry)
    if at_ms is None or at_ms < retention_start_ms:
        return
    bucket_at = at_ms - (at_ms % STATS_AGGREGATE_BUCKET_MS)
    host = str(entry.get("host") or entry.get("siteName") or "").strip().lower()
    file_summary = cache["files"].setdefault(path, {"buckets": {}})
    bucket = file_summary["buckets"].setdefault(bucket_at, {"hosts": {}})
    counts = bucket["hosts"].setdefault(host, new_stats_counts())
    update_stats_counts(counts, entry, cache["countryCache"])


def new_stats_counts() -> dict:
    return {
        "total": 0,
        "blocked": 0,
        "challenged": 0,
        "monitored": 0,
        "botTypes": {},
        "countries": {},
        "topRules": {},
        "statusGroups": {},
    }


def update_stats_counts(counts: dict, entry: dict, country_cache: dict) -> None:
    counts["total"] += 1
    verdict = entry.get("verdict")
    if verdict == "block":
        counts["blocked"] += 1
    elif verdict == "challenge":
        counts["challenged"] += 1
    elif verdict == "monitor":
        counts["monitored"] += 1

    bot_type = classify_bot_type(entry.get("userAgent") or entry.get("user_agent") or "")
    if bot_type:
        increment_named_stats(counts["botTypes"], bot_type, {"name": bot_type}, verdict)

    ip = str(entry.get("ip") or entry.get("remote_addr") or "").strip()
    if ip not in country_cache:
        country_cache[ip] = country_for_ip(ip)
    country = country_cache[ip]
    country_key = f"{country['code']}\0{country['name']}"
    increment_named_stats(counts["countries"], country_key, country, verdict)

    for rule in entry.get("matchedRules", []):
        name = rule.get("name") or rule.get("id")
        if name:
            counts["topRules"][name] = counts["topRules"].get(name, 0) + 1

    group = aggregate_status_group(entry)
    counts["statusGroups"][group] = counts["statusGroups"].get(group, 0) + 1


def increment_named_stats(target: dict, key: str, base: dict, verdict: str) -> None:
    item = target.setdefault(
        key,
        {
            **base,
            "count": 0,
            "blocked": 0,
            "challenged": 0,
            "protected": 0,
        },
    )
    item["count"] += 1
    if verdict == "block":
        item["blocked"] += 1
        item["protected"] += 1
    elif verdict == "challenge":
        item["challenged"] += 1
        item["protected"] += 1


def prune_stats_aggregate(cache: dict, retention_start_ms: int) -> None:
    for file_summary in list(cache["files"].values()):
        buckets = file_summary.get("buckets") or {}
        for bucket_at in [at for at in buckets if at + STATS_AGGREGATE_BUCKET_MS <= retention_start_ms]:
            buckets.pop(bucket_at, None)

    country_cache = cache.get("countryCache") or {}
    if len(country_cache) > 200000:
        country_cache.clear()


def collapse_stats_aggregate(cache: dict, retention_start_ms: int) -> dict:
    hosts: dict[str, dict] = {}
    total = 0
    for file_summary in cache.get("files", {}).values():
        for bucket_at, bucket in (file_summary.get("buckets") or {}).items():
            if bucket_at + STATS_AGGREGATE_BUCKET_MS <= retention_start_ms:
                continue
            for host, counts in (bucket.get("hosts") or {}).items():
                target = hosts.setdefault(host, new_stats_counts())
                merge_aggregate_counts(target, counts)
                total += int(counts.get("total") or 0)
    return {
        "hosts": hosts,
        "total": total,
        "retentionDays": cache.get("retentionDays"),
    }


def merge_aggregate_counts(target: dict, source: dict) -> None:
    target["total"] += int(source.get("total") or 0)
    target["blocked"] += int(source.get("blocked") or 0)
    target["challenged"] += int(source.get("challenged") or 0)
    target["monitored"] += int(source.get("monitored") or 0)
    merge_aggregate_named_stats(target["botTypes"], source.get("botTypes") or {})
    merge_aggregate_named_stats(target["countries"], source.get("countries") or {})
    merge_int_maps(target["topRules"], source.get("topRules") or {})
    merge_int_maps(target["statusGroups"], source.get("statusGroups") or {})


def merge_aggregate_named_stats(target: dict, source: dict) -> None:
    for key, value in source.items():
        item = target.setdefault(key, {**value, "count": 0, "blocked": 0, "challenged": 0, "protected": 0})
        item["count"] += int(value.get("count") or 0)
        item["blocked"] += int(value.get("blocked") or 0)
        item["challenged"] += int(value.get("challenged") or 0)
        item["protected"] += int(value.get("protected") or 0)


def merge_int_maps(target: dict, source: dict) -> None:
    for key, value in source.items():
        target[key] = int(target.get(key) or 0) + int(value or 0)


def log_entry_timestamp_ms(entry: dict) -> int | None:
    try:
        return int(datetime.fromisoformat(str(entry.get("at")).replace("Z", "+00:00")).timestamp() * 1000)
    except (TypeError, ValueError):
        return None


def aggregate_status_group(entry: dict) -> str:
    status = int(entry.get("upstreamStatus") or entry.get("statusCode") or 0)
    return f"{status // 100}xx" if status else "n/a"


def combined_logs_page(store: Store, limit: int, offset: int = 0, domain: str = "", search: str = "", site_id: str = "", verdict: str = "") -> dict:
    scan_limit = log_scan_limit(offset + limit)
    state = store.get_state()
    sites = state.get("sites", []) or []
    site_by_id = {str(site.get("id") or ""): site for site in sites if site.get("id")}
    logs = [*parse_nginx_logs(ROOT_DIR, scan_limit), *store.get_logs(scan_limit)]
    logs = sorted(logs, key=lambda entry: entry.get("at") or "", reverse=True)
    domains = sorted({log_domain(entry) for entry in logs if log_domain(entry)})
    site_options = [{"id": str(site.get("id") or ""), "name": str(site.get("name") or "")} for site in sites if site.get("id")]
    filtered = [entry for entry in logs if log_matches(entry, domain, search, site_id, verdict, sites, site_by_id)]
    total = len(filtered)
    pages = max(1, (total + limit - 1) // limit) if limit else 1
    if total and offset >= total:
        offset = (pages - 1) * limit
    else:
        offset = max(0, offset)
    page = (offset // limit) + 1 if limit else 1
    page_logs = enrich_log_countries(filtered[offset : offset + limit])
    return {
        "logs": page_logs,
        "total": total,
        "limit": limit,
        "pageSize": limit,
        "offset": offset,
        "page": page,
        "pages": pages,
        "domain": domain,
        "siteId": site_id,
        "verdict": verdict,
        "search": search,
        "domains": domains,
        "siteOptions": site_options,
        "scanLimit": scan_limit,
    }


def enrich_log_countries(logs: list[dict]) -> list[dict]:
    countries = {}
    enriched = []
    for entry in logs:
        ip = str(entry.get("ip") or entry.get("remote_addr") or "").strip()
        if ip not in countries:
            countries[ip] = country_for_ip(ip)
        enriched.append({**entry, "country": countries[ip]})
    return enriched


def log_scan_limit(requested: int) -> int:
    default_limit = parse_int(os.environ.get("LOG_PAGE_SCAN_LIMIT"), 10000)
    maximum = parse_int(os.environ.get("LOG_PAGE_SCAN_MAX"), 50000)
    return clamp(max(requested, default_limit), 1, max(1, maximum))


def stats_scan_limit() -> int:
    default_limit = parse_int(os.environ.get("STATS_LOG_SCAN_LIMIT"), 50000)
    maximum = parse_int(os.environ.get("STATS_LOG_SCAN_MAX"), 250000)
    return clamp(default_limit, 1, max(1, maximum))


def stats_retention_days() -> int:
    return clamp(parse_int(os.environ.get("STATS_RETENTION_DAYS"), 7), 1, 31)


def log_domain(entry: dict) -> str:
    return str(entry.get("host") or entry.get("siteName") or "").strip()


def log_matches(
    entry: dict,
    domain: str = "",
    search: str = "",
    site_id: str = "",
    verdict: str = "",
    sites: list[dict] | None = None,
    site_by_id: dict[str, dict] | None = None,
) -> bool:
    normalized_domain = domain.strip().lower()
    if normalized_domain and log_domain(entry).lower() != normalized_domain:
        return False

    normalized_site = site_id.strip()
    if normalized_site:
        entry_site_id = str(entry.get("siteId") or "").strip()
        if entry_site_id != normalized_site:
            # Fall back to host-based site matching for nginx-parsed entries that lack siteId.
            matched = None
            if sites is not None:
                matched = match_log_site(entry, sites, site_by_id or {})
            if not matched or str(matched.get("id") or "") != normalized_site:
                return False

    normalized_verdict = verdict.strip().lower()
    if normalized_verdict and str(entry.get("verdict") or "").strip().lower() != normalized_verdict:
        return False

    needle = search.strip().lower()
    if not needle:
        return True
    haystack = " ".join(
        str(entry.get(key) or "")
        for key in ("siteName", "host", "method", "path", "ip", "reason", "verdict", "statusCode", "upstreamStatus")
    ).lower()
    return needle in haystack


def start_ip_group_sync_worker(store: Store) -> None:
    if os.environ.get("IP_GROUP_AUTO_SYNC", "true").lower() == "false":
        return

    def worker() -> None:
        time.sleep(2)
        while True:
            try:
                if sync_due_ip_groups(store):
                    maybe_auto_write(store)
            except Exception as error:
                print(f"IP group sync worker failed: {error}")
            time.sleep(ip_group_sync_check_seconds())

    thread = threading.Thread(target=worker, daemon=True, name="ip-group-sync")
    thread.start()


def start_stats_warmup_worker(store: Store) -> None:
    if os.environ.get("FREEWAF_STATS_WARMUP", "true").lower() == "false":
        return

    def worker() -> None:
        started = time.time()
        try:
            stats = combined_stats(store, store.get_state())
            elapsed = time.time() - started
            print(f"stats-warmup-complete total={stats.get('total', 0)} elapsed={elapsed:.3f}s", flush=True)
        except Exception as error:
            print(f"stats-warmup-failed: {error}", flush=True)

    thread = threading.Thread(target=worker, daemon=True, name="stats-warmup")
    thread.start()


def sync_due_ip_groups(store: Store) -> int:
    state = store.get_state()
    synced = 0
    for group in state.get("ipGroups", []):
        if is_ip_group_sync_due(group):
            sync_ip_group_reference(store, group["id"])
            synced += 1
    return synced


def maybe_sync_new_reference_ip_group(store: Store, group: dict) -> dict:
    if group.get("referenceUrl") and not group.get("lastSyncedAt"):
        return sync_ip_group_reference(store, group["id"])
    return group


def sync_ip_group_reference(store: Store, group_id: str) -> dict:
    group = next((item for item in store.get_state().get("ipGroups", []) if item["id"] == group_id), None)
    if not group:
        raise StoreError(404, "IP group not found")
    if not group.get("referenceUrl"):
        raise StoreError(400, "IP group does not have a reference URL")

    try:
        text = fetch_reference_text(group["referenceUrl"])
        items = ip_items_from_reference_text(text)
        if not items:
            raise StoreError(400, "Reference URL did not contain any IP/CIDR entries")
        return store.upsert_ip_group(
            {
                **group,
                "items": items,
                "lastSyncedAt": utc_now(),
                "lastSyncStatus": "ok",
                "lastSyncMessage": f"{len(items)} entries synced",
            },
            group_id,
        )
    except StoreError as error:
        return mark_ip_group_sync_failed(store, group, error.message)
    except Exception as error:
        return mark_ip_group_sync_failed(store, group, str(error))


def mark_ip_group_sync_failed(store: Store, group: dict, message: str) -> dict:
    return store.upsert_ip_group(
        {
            **group,
            "lastSyncedAt": utc_now(),
            "lastSyncStatus": "failed",
            "lastSyncMessage": message[:500],
        },
        group["id"],
    )


def fetch_reference_text(url: str) -> str:
    timeout = parse_int(os.environ.get("IP_GROUP_REFERENCE_TIMEOUT"), 20)
    max_bytes = parse_int(os.environ.get("IP_GROUP_REFERENCE_MAX_BYTES"), 20 * 1024 * 1024)
    request = urllib.request.Request(url, headers={"User-Agent": "FreeWAF/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise StoreError(400, "Reference file is too large")
            charset = response.headers.get_content_charset() or "utf-8"
            return data.decode(charset, errors="replace")
    except urllib.error.URLError as error:
        raise StoreError(502, f"Reference fetch failed: {error.reason}") from None


def ip_items_from_reference_text(text: str) -> list[str]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return normalize_ip_items(text)

    candidates = []

    def walk(value) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = str(key).lower()
                if isinstance(item, str) and (
                    lowered in {"ipv4prefix", "ipv6prefix", "prefix", "cidr"}
                    or lowered.endswith("prefix")
                    or lowered.endswith("cidr")
                ):
                    candidates.append(item)
                    continue
                walk(item)
            return
        if isinstance(value, list):
            for item in value:
                walk(item)

    walk(payload)
    return normalize_ip_items(candidates) if candidates else normalize_ip_items(text)


def is_ip_group_sync_due(group: dict) -> bool:
    if not group.get("referenceUrl"):
        return False
    last_synced = str(group.get("lastSyncedAt") or "")
    if not last_synced:
        return True
    try:
        synced_at = datetime.fromisoformat(last_synced.replace("Z", "+00:00"))
    except ValueError:
        return True
    if synced_at.tzinfo is None:
        synced_at = synced_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - synced_at >= timedelta(seconds=ip_group_sync_interval_seconds())


def ip_group_sync_interval_seconds() -> int:
    return max(60, parse_int(os.environ.get("IP_GROUP_SYNC_INTERVAL_SECONDS"), 86400))


def ip_group_sync_check_seconds() -> int:
    return max(60, parse_int(os.environ.get("IP_GROUP_SYNC_CHECK_SECONDS"), 3600))


def prepare_certificate_payload(payload: dict, certificate_id: str | None = None) -> dict:
    prepared = dict(payload)
    source = str(prepared.get("source") or "upload").lower()
    if source == "certbot":
        return prepare_certbot_certificate_payload(prepared, certificate_id)

    cert_text = str(prepared.pop("certificate", "") or "").strip()
    key_text = str(prepared.pop("privateKey", "") or "").strip()
    cert_id = certificate_id or str(prepared.get("id") or f"cert-{uuid.uuid4().hex[:8]}")

    if cert_text or key_text:
        if "BEGIN CERTIFICATE" not in cert_text:
            raise StoreError(400, "Certificate PEM must include BEGIN CERTIFICATE")
        if "BEGIN" not in key_text or "PRIVATE KEY" not in key_text:
            raise StoreError(400, "Private key PEM must include PRIVATE KEY")
        cert_dir = certificate_dir()
        cert_dir.mkdir(parents=True, exist_ok=True)
        cert_file = cert_dir / f"{safe_file_stem(cert_id)}.crt"
        key_file = cert_dir / f"{safe_file_stem(cert_id)}.key"
        cert_file.write_text(cert_text + "\n", encoding="utf-8")
        key_file.write_text(key_text + "\n", encoding="utf-8")
        prepared["id"] = cert_id
        prepared["source"] = "upload"
        prepared["certFile"] = relative_to_root(cert_file)
        prepared["keyFile"] = relative_to_root(key_file)

    return prepared


def prepare_certbot_certificate_payload(payload: dict, certificate_id: str | None = None) -> dict:
    domains = normalize_payload_list(payload.get("domains"))
    email = str(payload.get("email") or "").strip()
    if not domains:
        raise StoreError(400, "Domain is required")
    if "@" not in email:
        raise StoreError(400, "Email address is required")

    result = run_certbot(domains, email)
    primary_domain = domains[0].lower()
    cert_file, key_file = certbot_paths_from_result(result, primary_domain)
    cert_id = certificate_id or str(payload.get("id") or f"certbot-{uuid.uuid4().hex[:8]}")

    return {
        **payload,
        "id": cert_id,
        "name": str(payload.get("name") or primary_domain),
        "source": "certbot",
        "domains": domains,
        "email": email,
        "autoRenew": payload.get("autoRenew") is not False,
        "renewBeforeDays": int(payload.get("renewBeforeDays") or 30),
        "certFile": cert_file,
        "keyFile": key_file,
        "status": "ready" if result["ok"] else "failed",
        "lastMessage": result["stdout"] or result["stderr"],
    }


def certbot_paths_from_result(result: dict, primary_domain: str) -> tuple[str, str]:
    output = "\n".join([str(result.get("stdout") or ""), str(result.get("stderr") or "")])
    cert_match = re.search(r"Certificate is saved at:\s*(\S+)", output)
    key_match = re.search(r"Key is saved at:\s*(\S+)", output)
    if cert_match and key_match:
        return cert_match.group(1).replace("\\", "/"), key_match.group(1).replace("\\", "/")

    live_dir = Path(os.environ.get("CERTBOT_LIVE_DIR", "/etc/letsencrypt/live")) / primary_domain
    return str(live_dir / "fullchain.pem").replace("\\", "/"), str(live_dir / "privkey.pem").replace("\\", "/")


def run_certbot(domains: list[str], email: str) -> dict:
    certbot = os.environ.get("CERTBOT_CMD", "certbot")
    method = os.environ.get("CERTBOT_AUTH_METHOD", "nginx").lower()
    command = [certbot, "certonly", "--non-interactive", "--agree-tos", "--email", email, "--keep-until-expiring"]

    if method == "webroot":
        webroot = os.environ.get("CERTBOT_WEBROOT", "/var/www/html")
        command.extend(["--webroot", "-w", webroot])
    elif method == "standalone":
        command.append("--standalone")
    else:
        command.append("--nginx")

    for domain in domains:
        command.extend(["-d", domain])

    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    except FileNotFoundError:
        raise StoreError(500, f"Certbot command not found: {certbot}") from None
    except subprocess.TimeoutExpired:
        raise StoreError(500, "Certbot command timed out") from None

    if completed.returncode != 0:
        message = completed.stderr or completed.stdout or "Certbot failed"
        raise StoreError(500, message.strip())

    return {
        "ok": True,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def remove_certificate_files(certificate: dict) -> None:
    if certificate.get("source") == "certbot":
        remove_certbot_certificate(certificate)
        return
    for key in ("certFile", "keyFile"):
        path = resolve_reference(certificate.get(key))
        if path and is_managed_certificate_path(path):
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                raise StoreError(500, f"Cannot delete certificate file {path}: {error}") from error


def remove_certbot_certificate(certificate: dict) -> None:
    cert_name = certbot_certificate_name(certificate)
    if not cert_name:
        return
    certbot = os.environ.get("CERTBOT_CMD", "certbot")
    command = [*shlex.split(certbot), "delete", "--cert-name", cert_name, "--non-interactive"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    except FileNotFoundError:
        raise StoreError(500, f"Certbot command not found: {certbot}") from None
    except subprocess.TimeoutExpired:
        raise StoreError(500, "Certbot delete command timed out") from None

    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "Certbot delete failed").strip()
        if not certbot_files_exist(certificate) and re.search(r"not found|could not find|no certificate", message, re.IGNORECASE):
            return
        raise StoreError(500, f"Certbot delete failed: {message}")


def certbot_certificate_name(certificate: dict) -> str:
    for key in ("certFile", "keyFile"):
        path = resolve_reference(certificate.get(key))
        if path and path.name in {"fullchain.pem", "cert.pem", "privkey.pem", "chain.pem"} and path.parent.name:
            return path.parent.name
    domains = normalize_payload_list(certificate.get("domains"))
    if not domains:
        return ""
    return domains[0].removeprefix("*.")


def certbot_files_exist(certificate: dict) -> bool:
    paths = [resolve_reference(certificate.get(key)) for key in ("certFile", "keyFile")]
    return any(path and path.exists() for path in paths)


def is_managed_certificate_path(path: Path) -> bool:
    resolved = path.resolve(strict=False)
    roots = {
        certificate_dir().resolve(strict=False),
        (ROOT_DIR / "nginx" / "certs").resolve(strict=False),
    }
    return any(is_relative_to(resolved, root) for root in roots)


def normalize_payload_list(values) -> list[str]:
    if isinstance(values, list):
        source = values
    else:
        source = str(values or "").replace(",", "\n").splitlines()
    return [str(item).strip().lower() for item in source if str(item).strip()]


def certificate_dir() -> Path:
    configured = Path(os.environ.get("NGINX_CERT_DIR", "./nginx/certs"))
    return configured if configured.is_absolute() else ROOT_DIR / configured


def resolve_reference(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else ROOT_DIR / path


def relative_to_root(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT_DIR.resolve()).as_posix()
    except ValueError:
        return str(path)


def safe_file_stem(value: str) -> str:
    return "".join(char if char.isalnum() or char in "-_." else "_" for char in value)[:80] or "cert"


def maybe_auto_write(store: Store) -> None:
    if os.environ.get("NGINX_AUTO_WRITE", "false").lower() == "true":
        write_nginx_config(ROOT_DIR, store.get_state())


def runtime_payload(state: dict, admin_port: int, demo_origin_port: int, demo_enabled: bool) -> dict:
    listen_ports = sorted({port for site in state.get("sites", []) if site.get("enabled") for port, _ in site_ports(site)})
    panel = state.get("settings", {}).get("panel", {})
    return {
        "adminPort": admin_port,
        "adminProtocol": "https" if panel.get("httpsEnabled") else "http",
        "wafMode": "nginx",
        "nginxListenPorts": listen_ports,
        "proxyPort": listen_ports[0] if listen_ports else None,
        "demoOriginPort": demo_origin_port if demo_enabled else None,
        "demoOriginEnabled": demo_enabled,
        "nginx": nginx_runtime(ROOT_DIR),
        "certbot": {
            "command": os.environ.get("CERTBOT_CMD", "certbot"),
            "authMethod": os.environ.get("CERTBOT_AUTH_METHOD", "nginx"),
            "webroot": os.environ.get("CERTBOT_WEBROOT", "/var/www/html"),
            "liveDir": os.environ.get("CERTBOT_LIVE_DIR", "/etc/letsencrypt/live"),
            "renewBeforeDays": 30,
        },
        "ipGroupSync": {
            "enabled": os.environ.get("IP_GROUP_AUTO_SYNC", "true").lower() != "false",
            "intervalSeconds": ip_group_sync_interval_seconds(),
            "checkSeconds": ip_group_sync_check_seconds(),
        },
    }


def make_demo_handler():
    class DemoHandler(BaseHTTPRequestHandler):
        server_version = "FreeWAFDemo/1.0"

        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def do_PUT(self):
            self.respond()

        def do_PATCH(self):
            self.respond()

        def do_DELETE(self):
            self.respond()

        def respond(self):
            length = int(self.headers.get("content-length") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            payload = {
                "ok": True,
                "service": "demo-origin",
                "method": self.command,
                "path": self.path,
                "receivedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "headers": {
                    "host": self.headers.get("host"),
                    "x-forwarded-for": self.headers.get("x-forwarded-for"),
                    "x-freewaf": self.headers.get("x-freewaf"),
                },
                "body": body,
            }
            encoded = json.dumps(payload, ensure_ascii=True, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format, *args):
            return

    return DemoHandler


AUDIT_LOG_FILE = ROOT_DIR / "logs" / "audit.log"
_AUDIT_LOG_LOCK = threading.Lock()
_AUDIT_REDACT_KEYS = {
    "password",
    "newpassword",
    "currentpassword",
    "totpsecret",
    "totp_secret",
    "totpcode",
    "totp_code",
    "secret",
    "token",
    "apikey",
    "api_key",
    "key",
    "privatekey",
    "private_key",
    "certificate",
    "cert",
    "csr",
    "p12",
    "passphrase",
    "authorization",
    "cookie",
}


def _redact_audit_value(value, depth: int = 0):
    if depth > 4:
        return "<truncated>"
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "").replace("_", "")
            if normalized in _AUDIT_REDACT_KEYS:
                redacted[key] = "***" if item not in (None, "", []) else ""
            else:
                redacted[key] = _redact_audit_value(item, depth + 1)
        return redacted
    if isinstance(value, list):
        if len(value) > 50:
            return [_redact_audit_value(item, depth + 1) for item in value[:50]] + [f"<{len(value) - 50} more>"]
        return [_redact_audit_value(item, depth + 1) for item in value]
    if isinstance(value, str) and len(value) > 1024:
        return value[:1024] + "<truncated>"
    return value


def append_audit_log(entry: dict, log_file: Path | None = None) -> None:
    target = log_file or AUDIT_LOG_FILE
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=True, default=str)
        with _AUDIT_LOG_LOCK, target.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError as error:
        # Audit log must never break the API path; surface to stderr instead.
        try:
            print(f"audit-log-write-failed: {error}")
        except OSError:
            pass


def read_audit_log(limit: int = 200, log_file: Path | None = None) -> list[dict]:
    target = log_file or AUDIT_LOG_FILE
    if not target.exists():
        return []
    capped = clamp(int(limit or 200), 1, 1000)
    try:
        with target.open("r", encoding="utf-8") as handle:
            tail = handle.readlines()[-capped:]
    except OSError:
        return []
    entries: list[dict] = []
    for raw in reversed(tail):
        raw = raw.strip()
        if not raw:
            continue
        try:
            entries.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return entries


def split_resource_path(path: str) -> tuple[str, str]:
    parsed = urlparse(path)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) == 3 and parts[0] == "api" and parts[1] in {"sites", "rules", "certificates", "ip-groups", "access-rules", "users"}:
        return parts[1], parts[2]
    return "", ""


def split_action_path(path: str) -> tuple[str, str, str]:
    parsed = urlparse(path)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) == 4 and parts[0] == "api" and parts[1] in {"ip-groups", "users"}:
        return parts[1], parts[2], parts[3]
    return "", "", ""


def clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def parse_int(value, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    main()
