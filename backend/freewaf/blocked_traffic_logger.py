"""Parse kernel log entries produced by iptables LOG for blocked IPs.

Tails ``journalctl -f -k`` (or ``/var/log/kern.log``) for lines matching
``FREEWAF_BLOCKED:`` and writes JSON entries to a log file in the same
format as the nginx ``freewaf`` log_format so the existing stats engine
picks them up automatically.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .ipset_manager import LOG_PREFIX

# Regex to parse iptables LOG line:
#   Aug 11 10:23:45 host kernel: [...] FREEWAF_BLOCKED: IN=eth0 ... SRC=1.2.3.4 ... DPT=443 ...
_KERN_LOG_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+kernel:.*?"
    + re.escape(LOG_PREFIX.strip())
    + r"\b.*?SRC=(\S+).*?DPT=(\S+)",
)

_thread: threading.Thread | None = None
_stop_event = threading.Event()


def _resolve_log_path(root_dir: Path) -> Path:
    configured = Path(os.environ.get("BLOCKED_TRAFFIC_LOG", "./logs/freewaf_blocked.log"))
    return configured if configured.is_absolute() else root_dir / configured


def _parse_timestamp(raw: str) -> str:
    """Convert 'Aug 11 10:23:45' to ISO-8601 with current year."""
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(raw, "%b %d %H:%M:%S").replace(year=now.year, tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return now.isoformat()


def _port_to_host(port: str, port_site_map: dict[int, str]) -> str:
    try:
        return port_site_map.get(int(port), "blocked")
    except (TypeError, ValueError):
        return "blocked"


def _make_entry(match: re.Match, seq: int, port_site_map: dict[int, str]) -> dict:
    ts_raw, src_ip, dpt = match.group(1), match.group(2), match.group(3)
    host = _port_to_host(dpt, port_site_map)
    return {
        "id": f"blocked-{seq}",
        "time": _parse_timestamp(ts_raw),
        "remote_addr": src_ip,
        "host": host,
        "method": "BLOCKED",
        "uri": "/",
        "status": 403,
        "bytes": 0,
        "request_time": 0,
        "upstream_status": "",
        "verdict": "block",
        "reason": "Blocked by ipset/iptables",
        "user_agent": "",
        "referer": "",
    }


def _build_port_site_map(state: dict) -> dict[int, str]:
    """Map listen port -> site name for logging."""
    mapping: dict[int, str] = {}
    for site in state.get("sites", []):
        if not site.get("enabled"):
            continue
        name = site.get("name") or site.get("id") or "site"
        for port_val in site.get("ports", []):
            try:
                mapping[int(port_val)] = name
            except (TypeError, ValueError):
                pass
        # Also check proxy config ports
        proxy = site.get("proxy") or {}
        for port_val in [proxy.get("port"), proxy.get("httpsPort")]:
            if port_val is not None:
                try:
                    mapping[int(port_val)] = name
                except (TypeError, ValueError):
                    pass
    return mapping


def _run_logger(root_dir: Path, get_state) -> None:
    """Background thread: tail kernel log and write blocked entries."""
    log_path = _resolve_log_path(root_dir)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    seq = 0
    port_site_map: dict[int, str] = {}
    last_map_refresh = 0.0

    # Try journalctl first, fall back to /var/log/kern.log
    proc = None
    for cmd in [
        ["journalctl", "-f", "-k", "--no-pager", "-o", "short"],
        ["tail", "-F", "-n", "0", "/var/log/kern.log"],
    ]:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            break
        except FileNotFoundError:
            continue

    if proc is None or proc.stdout is None:
        print("[blocked_traffic_logger] could not start journalctl or tail kern.log")
        return

    print(f"[blocked_traffic_logger] started, writing to {log_path}")

    try:
        for line in proc.stdout:
            if _stop_event.is_set():
                break
            line = line.strip()
            if LOG_PREFIX.strip() not in line:
                continue

            match = _KERN_LOG_RE.search(line)
            if not match:
                continue

            # Refresh port->site map every 60s
            now = time.monotonic()
            if now - last_map_refresh > 60:
                try:
                    state = get_state()
                    port_site_map = _build_port_site_map(state)
                except Exception:
                    pass
                last_map_refresh = now

            seq += 1
            entry = _make_entry(match, seq, port_site_map)
            try:
                with log_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except OSError as exc:
                print(f"[blocked_traffic_logger] write error: {exc}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def start(root_dir: Path, get_state) -> None:
    """Start the blocked traffic logger thread (call once at startup)."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop_event.clear()
    _thread = threading.Thread(
        target=_run_logger,
        args=(root_dir, get_state),
        daemon=True,
        name="blocked-traffic-logger",
    )
    _thread.start()


def stop() -> None:
    """Signal the logger thread to stop."""
    _stop_event.set()
