"""Export/import of FreeWAF configuration as a single portable zip archive.

Bundles the four things an operator means by "config" when migrating or
disaster-recovering a FreeWAF install: panel settings, protected
applications (sites), WAF rules, and certificates. IP groups and access
rules are always carried along too, since rules/sites reference them by id
and a backup missing them would restore into a broken, dangling state.

The archive holds the relevant slice of state.json plus the certificate
PEM bytes (private keys included - callers must gate this behind
platform-admin auth) and any non-auto-synced IP group item files, since
those live outside state.json on disk.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .store import Store, StoreError

BACKUP_FORMAT = "freewaf-backup"
BACKUP_FORMAT_VERSION = 1

# Order also defines manifest/display order.
CATEGORIES = ("settings", "sites", "rules", "certificates", "ipGroups", "accessRules")
RESTORE_MODES = ("merge", "replace")

MANIFEST_ENTRY = "manifest.json"
STATE_ENTRY = "state.json"
CERT_FILES_PREFIX = "cert-files/"
IP_GROUP_FILES_PREFIX = "ip-group-files/"

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 5000


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def normalize_categories(raw) -> list[str]:
    if not raw:
        return list(CATEGORIES)
    requested = {str(item) for item in raw}
    selected = [category for category in CATEGORIES if category in requested]
    if not selected:
        raise StoreError(400, "No valid backup categories selected")
    return selected


def build_backup_archive(store: Store, categories=None, *, certificate_file_reader=None) -> tuple[bytes, str]:
    """Build the backup zip. certificate_file_reader(certificate) -> (cert_bytes, key_bytes)."""
    selected = normalize_categories(categories)
    state = store.get_state_fields(*selected)

    manifest = {
        "format": BACKUP_FORMAT,
        "formatVersion": BACKUP_FORMAT_VERSION,
        "createdAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "categories": selected,
        "includesCertificateFiles": bool(certificate_file_reader and "certificates" in selected),
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_ENTRY, json.dumps(manifest, indent=2, ensure_ascii=True))
        archive.writestr(STATE_ENTRY, json.dumps(state, indent=2, ensure_ascii=True))

        if certificate_file_reader and "certificates" in selected:
            for certificate in state.get("certificates", []):
                cert_id = str(certificate.get("id") or "").strip()
                if not cert_id:
                    continue
                try:
                    cert_bytes, key_bytes = certificate_file_reader(certificate)
                except StoreError:
                    continue
                if cert_bytes:
                    archive.writestr(f"{CERT_FILES_PREFIX}{cert_id}/fullchain.pem", cert_bytes)
                if key_bytes:
                    archive.writestr(f"{CERT_FILES_PREFIX}{cert_id}/privkey.pem", key_bytes)

        if "ipGroups" in selected:
            for group in state.get("ipGroups", []):
                # Auto-synced lists (itemsExternal + a referenceUrl) regenerate
                # themselves on the next sync; only bundle content that can't
                # be recreated automatically.
                if group.get("referenceUrl"):
                    continue
                items_file = str(group.get("itemsFile") or "").strip()
                group_id = str(group.get("id") or "").strip()
                if not items_file or not group_id:
                    continue
                path = Path(items_file)
                if path.exists() and path.is_file():
                    archive.writestr(f"{IP_GROUP_FILES_PREFIX}{group_id}.txt", path.read_bytes())

    filename = f"freewaf-backup-{_utc_stamp()}.zip"
    return buffer.getvalue(), filename


def _safe_member_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or ".." in normalized.split("/"):
        raise StoreError(400, f"Unsafe archive entry: {name}")
    return normalized


def read_backup_archive(content: bytes) -> dict:
    """Parse an uploaded backup zip into {manifest, state, certFiles, ipGroupFiles}."""
    if len(content) > MAX_ARCHIVE_BYTES:
        raise StoreError(400, "Backup archive is too large")

    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise StoreError(400, "Uploaded file is not a valid backup archive") from None

    infos = archive.infolist()
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        raise StoreError(400, "Backup archive has too many entries")
    if sum(info.file_size for info in infos) > MAX_ARCHIVE_BYTES:
        raise StoreError(400, "Backup archive is too large once extracted")

    names = {_safe_member_name(info.filename): info.filename for info in infos}
    if MANIFEST_ENTRY not in names or STATE_ENTRY not in names:
        raise StoreError(400, "Backup archive is missing manifest.json or state.json")

    try:
        manifest = json.loads(archive.read(names[MANIFEST_ENTRY]).decode("utf-8"))
        state = json.loads(archive.read(names[STATE_ENTRY]).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise StoreError(400, f"Backup archive is corrupt: {error}") from None

    if not isinstance(manifest, dict) or manifest.get("format") != BACKUP_FORMAT:
        raise StoreError(400, "Not a FreeWAF backup archive")
    if not isinstance(state, dict):
        raise StoreError(400, "Backup archive state.json is malformed")

    cert_files: dict[str, dict[str, bytes]] = {}
    ip_group_files: dict[str, bytes] = {}
    for safe_name, original_name in names.items():
        if safe_name.startswith(CERT_FILES_PREFIX):
            rest = safe_name[len(CERT_FILES_PREFIX):]
            cert_id, _, filename = rest.partition("/")
            if cert_id and filename in {"fullchain.pem", "privkey.pem"}:
                cert_files.setdefault(cert_id, {})[filename] = archive.read(original_name)
        elif safe_name.startswith(IP_GROUP_FILES_PREFIX):
            group_id = safe_name[len(IP_GROUP_FILES_PREFIX):]
            if group_id.endswith(".txt"):
                group_id = group_id[: -len(".txt")]
            if group_id:
                ip_group_files[group_id] = archive.read(original_name)

    return {"manifest": manifest, "state": state, "certFiles": cert_files, "ipGroupFiles": ip_group_files}


def apply_backup_archive(
    store: Store,
    archive_data: dict,
    categories=None,
    mode: str = "merge",
    *,
    certificate_file_writer=None,
    ip_group_dir: Path | None = None,
) -> dict:
    """Restore selected categories from a parsed backup into `store`.

    certificate_file_writer(cert_id, {"fullchain.pem": bytes, "privkey.pem": bytes}) -> None
    """
    if mode not in RESTORE_MODES:
        raise StoreError(400, "mode must be 'merge' or 'replace'")

    backup_state = archive_data["state"]
    available = [key for key in CATEGORIES if key in backup_state]
    if not available:
        raise StoreError(400, "Backup archive does not contain any known categories")

    if categories:
        requested = {str(item) for item in categories}
        selected = [key for key in available if key in requested]
        if not selected:
            raise StoreError(400, "None of the requested categories are present in this backup")
    else:
        selected = available

    payload = {key: backup_state[key] for key in selected}
    summary = store.restore_categories(payload, mode=mode)

    if certificate_file_writer and "certificates" in selected:
        for cert_id, files in archive_data.get("certFiles", {}).items():
            certificate_file_writer(cert_id, files)

    if ip_group_dir is not None and "ipGroups" in selected:
        ip_group_dir.mkdir(parents=True, exist_ok=True)
        for group_id, file_content in archive_data.get("ipGroupFiles", {}).items():
            safe_id = "".join(ch for ch in group_id if ch.isalnum() or ch in "_-.").strip("._") or "ipgroup"
            (ip_group_dir / f"{safe_id}.txt").write_bytes(file_content)

    return {"mode": mode, "categories": selected, "summary": summary}
