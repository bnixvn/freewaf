from __future__ import annotations

import json
import mimetypes
import os
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
    site_ports,
    write_nginx_config,
)
from .defaults import utc_now
from .store import Store, StoreError, build_stats, resolve_data_file


ROOT_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"


def main() -> None:
    admin_port = int(os.environ.get("ADMIN_PORT", "7001"))
    demo_origin_port = int(os.environ.get("DEMO_ORIGIN_PORT", "9090"))
    enable_demo_origin = os.environ.get("ENABLE_DEMO_ORIGIN", "true").lower() != "false"

    store = Store(resolve_data_file(ROOT_DIR))
    store.init()
    start_ip_group_sync_worker(store)
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
                state["stats"] = build_stats({**state, "logs": logs})
                state["runtime"] = runtime_payload(state, admin_port, demo_origin_port, demo_enabled)
                state["users"] = [public_user(user) for user in state.get("users", [])]
                self.send_json(200, state)
                return

            if parsed.path == "/api/stats":
                state = store.get_state()
                self.send_json(200, build_stats({**state, "logs": combined_logs(store, 1000)}))
                return

            if parsed.path == "/api/logs":
                limit = parse_int((query.get("limit") or ["200"])[0], 200)
                self.send_json(200, {"logs": combined_logs(store, clamp(limit, 1, 1000))})
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

            self.serve_static(parsed.path)

        def do_POST(self):
            try:
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
                    self.login_user(saved)
                    return

                if self.path == "/api/auth/login":
                    payload = self.read_payload()
                    user = store.authenticate_user(payload.get("username", ""), payload.get("password", ""), payload.get("totpCode", ""))
                    self.login_user(user)
                    return

                if self.path == "/api/auth/logout":
                    self.logout_user()
                    return

                if self.path.startswith("/api/") and not self.require_auth(self.path):
                    return

                resource, item_id, action = split_action_path(self.path)
                if resource == "ip-groups" and action == "sync":
                    saved = sync_ip_group_reference(store, item_id)
                    maybe_auto_write(store)
                    self.send_json(200, saved)
                    return

                if resource == "users" and action == "password":
                    payload = self.read_payload()
                    saved = store.change_user_password(item_id, payload.get("password", ""))
                    self.send_json(200, public_user(saved))
                    return

                payload = self.read_payload()
                if self.path == "/api/sites":
                    saved = store.upsert_site(payload)
                    maybe_auto_write(store)
                    self.send_json(201, saved)
                    return
                if self.path == "/api/rules":
                    saved = store.upsert_rule(payload)
                    maybe_auto_write(store)
                    self.send_json(201, saved)
                    return
                if self.path == "/api/certificates":
                    saved = store.upsert_certificate(prepare_certificate_payload(payload))
                    maybe_auto_write(store)
                    self.send_json(201, saved)
                    return
                if self.path == "/api/ip-groups":
                    saved = store.upsert_ip_group(payload)
                    saved = maybe_sync_new_reference_ip_group(store, saved)
                    maybe_auto_write(store)
                    self.send_json(201, saved)
                    return
                if self.path == "/api/access-rules":
                    saved = store.upsert_access_rule(payload)
                    maybe_auto_write(store)
                    self.send_json(201, saved)
                    return
                if self.path == "/api/users":
                    saved = store.upsert_user(payload)
                    self.send_json(201, public_user(saved, include_totp_secret=bool(saved.get("_totpSecretGenerated"))))
                    return
                if self.path == "/api/nginx/apply":
                    self.send_json(200, apply_nginx(store, payload))
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
                    saved = store.update_settings(self.read_payload())
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
                    maybe_auto_write(store)
                    self.send_empty(204)
                    return
                if resource == "rules":
                    store.delete_rule(item_id)
                    maybe_auto_write(store)
                    self.send_empty(204)
                    return
                if resource == "certificates":
                    certificate = next((item for item in store.get_state()["certificates"] if item["id"] == item_id), None)
                    if not certificate:
                        self.send_json(404, {"error": "Certificate not found"})
                        return
                    remove_certificate_files(certificate)
                    store.delete_certificate(item_id)
                    write_nginx_config(ROOT_DIR, store.get_state())
                    self.send_empty(204)
                    return
                if resource == "ip-groups":
                    store.delete_ip_group(item_id)
                    maybe_auto_write(store)
                    self.send_empty(204)
                    return
                if resource == "access-rules":
                    store.delete_access_rule(item_id)
                    maybe_auto_write(store)
                    self.send_empty(204)
                    return
                if resource == "users":
                    token_user = self.authenticated_user()
                    if token_user and token_user.get("id") == item_id:
                        self.send_json(400, {"error": "You cannot delete the signed-in user"})
                        return
                    store.delete_user(item_id)
                    self.send_empty(204)
                    return
                if self.path == "/api/logs":
                    store.clear_logs()
                    clear_nginx_logs(ROOT_DIR)
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

                if resource == "sites":
                    if not replace:
                        current = next((item for item in state["sites"] if item["id"] == item_id), None)
                        if not current:
                            self.send_json(404, {"error": "Site not found"})
                            return
                        payload = {**current, **payload}
                    saved = store.upsert_site(payload, item_id)
                    maybe_auto_write(store)
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
                    maybe_auto_write(store)
                    self.send_json(200, saved)
                    return

                if resource == "ip-groups":
                    if not replace:
                        current = next((item for item in state["ipGroups"] if item["id"] == item_id), None)
                        if not current:
                            self.send_json(404, {"error": "IP group not found"})
                            return
                        payload = {**current, **payload}
                    saved = store.upsert_ip_group(payload, item_id)
                    saved = maybe_sync_new_reference_ip_group(store, saved)
                    maybe_auto_write(store)
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

        def send_json(self, status: int, payload: dict, headers: dict | None = None):
            body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def send_empty(self, status: int, headers: dict | None = None):
            self.send_response(status)
            self.send_header("content-length", "0")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()

        def log_message(self, format, *args):
            return

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
    max_bytes = parse_int(os.environ.get("IP_GROUP_REFERENCE_MAX_BYTES"), 1024 * 1024)
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
    items = []
    for line in str(text or "").replace(",", "\n").splitlines():
        item = line.split("#", 1)[0].strip()
        if item:
            items.append(item)
    return list(dict.fromkeys(items))


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
    live_dir = Path(os.environ.get("CERTBOT_LIVE_DIR", "/etc/letsencrypt/live")) / primary_domain
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
        "certFile": str(live_dir / "fullchain.pem").replace("\\", "/"),
        "keyFile": str(live_dir / "privkey.pem").replace("\\", "/"),
        "status": "ready" if result["ok"] else "failed",
        "lastMessage": result["stdout"] or result["stderr"],
    }


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
        "auth": {
            "file": os.environ.get("NGINX_AUTH_FILE", ""),
        },
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
