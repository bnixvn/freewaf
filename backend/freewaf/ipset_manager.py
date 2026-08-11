"""ipset + iptables integration for FreeWAF IP blocking.

Manages an ipset named ``freewaf_blocked`` and iptables INPUT rules that
log then drop traffic from IPs in the set.  The LOG rule is inserted
before DROP so blocked traffic appears in kernel log for
``blocked_traffic_logger`` to parse into access-log format.
All commands are best-effort -- failures are logged to stderr but never
crash the server.
"""

from __future__ import annotations

import ipaddress
import subprocess
import threading
from typing import Iterable

IPSET_NAME = "freewaf_blocked"
IPTABLES_CHAIN = "INPUT"
LOG_PREFIX = "FREEWAF_BLOCKED: "
_lock = threading.Lock()

def _run(args: list[str], check: bool = False) -> subprocess.CompletedProcess:
    """Run a command, swallow errors unless *check* is True."""
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=10,
            check=check,
        )
    except FileNotFoundError:
        print(f"[ipset] command not found: {args[0]}")
    except subprocess.TimeoutExpired:
        print(f"[ipset] command timed out: {' '.join(args)}")
    except subprocess.CalledProcessError as exc:
        print(f"[ipset] command failed: {' '.join(args)}\n{exc.stderr}")
    return subprocess.CompletedProcess(args, 1, "", "")

def _normalize_ip(raw: str) -> str:
    """Return a normalised IP/CIDR string."""
    raw = raw.strip()
    if not raw:
        return raw
    try:
        if "/" in raw:
            return str(ipaddress.ip_network(raw, strict=False))
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw

# ------------------------------------------------------------------
# ipset helpers
# ------------------------------------------------------------------

def ensure_ipset() -> bool:
    """Create the ipset if it does not already exist."""
    with _lock:
        result = _run(["ipset", "list", IPSET_NAME])
        if result.returncode == 0:
            return True
        result = _run(["ipset", "create", IPSET_NAME, "hash:net", "-exist"])
        return result.returncode == 0

def add_ip(ip: str) -> bool:
    """Add *ip* (single address or CIDR) to the block set."""
    ip = _normalize_ip(ip)
    if not ip:
        return False
    with _lock:
        ensure_ipset()
        result = _run(["ipset", "add", IPSET_NAME, ip, "-exist"])
        return result.returncode == 0

def remove_ip(ip: str) -> bool:
    """Remove *ip* from the block set."""
    ip = _normalize_ip(ip)
    if not ip:
        return False
    with _lock:
        result = _run(["ipset", "del", IPSET_NAME, ip, "-exist"])
        return result.returncode == 0

def list_ips() -> list[str]:
    """Return all IPs/CIDRs currently in the block set."""
    with _lock:
        result = _run(["ipset", "list", IPSET_NAME, "output"])
        if result.returncode != 0:
            return []
        ips: list[str] = []
        in_members = False
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Members:"):
                in_members = True
                continue
            if in_members and line:
                ips.append(line)
        return ips

def sync_ips(ips: Iterable[str]) -> bool:
    """Replace the entire set contents with *ips*."""
    normalised = [_normalize_ip(ip) for ip in ips if _normalize_ip(ip)]
    with _lock:
        ensure_ipset()
        # flush then add
        _run(["ipset", "flush", IPSET_NAME])
        for ip in normalised:
            _run(["ipset", "add", IPSET_NAME, ip, "-exist"])
    return True

def destroy_ipset() -> bool:
    """Destroy the ipset entirely."""
    with _lock:
        result = _run(["ipset", "destroy", IPSET_NAME])
        return result.returncode == 0

# ------------------------------------------------------------------
# iptables helpers
# ------------------------------------------------------------------

def _iptables_log_rule_exists() -> bool:
    result = _run(["iptables", "-C", IPTABLES_CHAIN, "-m", "set",
                    "--match-set", IPSET_NAME, "src",
                    "-j", "LOG", "--log-prefix", LOG_PREFIX, "--log-level", "4"])
    return result.returncode == 0

def ensure_iptables_log_rule() -> bool:
    """Insert the INPUT LOG rule if it doesn't exist yet."""
    if _iptables_log_rule_exists():
        return True
    result = _run(["iptables", "-I", IPTABLES_CHAIN, "1", "-m", "set",
                    "--match-set", IPSET_NAME, "src",
                    "-j", "LOG", "--log-prefix", LOG_PREFIX, "--log-level", "4"])
    return result.returncode == 0

def remove_iptables_log_rule() -> bool:
    """Remove the INPUT LOG rule."""
    if not _iptables_log_rule_exists():
        return True
    result = _run(["iptables", "-D", IPTABLES_CHAIN, "-m", "set",
                    "--match-set", IPSET_NAME, "src",
                    "-j", "LOG", "--log-prefix", LOG_PREFIX, "--log-level", "4"])
    return result.returncode == 0

def _iptables_drop_rule_exists() -> bool:
    result = _run(["iptables", "-C", IPTABLES_CHAIN, "-m", "set",
                    "--match-set", IPSET_NAME, "src", "-j", "DROP"])
    return result.returncode == 0

def ensure_iptables_drop_rule() -> bool:
    """Insert the INPUT DROP rule if it doesn't exist yet."""
    if _iptables_drop_rule_exists():
        return True
    result = _run(["iptables", "-I", IPTABLES_CHAIN, "1", "-m", "set",
                    "--match-set", IPSET_NAME, "src", "-j", "DROP"])
    return result.returncode == 0

def remove_iptables_drop_rule() -> bool:
    """Remove the INPUT DROP rule."""
    if not _iptables_drop_rule_exists():
        return True
    result = _run(["iptables", "-D", IPTABLES_CHAIN, "-m", "set",
                    "--match-set", IPSET_NAME, "src", "-j", "DROP"])
    return result.returncode == 0

def ensure_iptables_rule() -> bool:
    """Insert LOG + DROP rules. LOG inserted first so it matches before DROP."""
    ensure_iptables_drop_rule()
    ensure_iptables_log_rule()
    return True

def remove_iptables_rule() -> bool:
    """Remove both LOG and DROP rules."""
    remove_iptables_log_rule()
    remove_iptables_drop_rule()
    return True

# ------------------------------------------------------------------
# Combined helpers
# ------------------------------------------------------------------

def initialise() -> bool:
    """Create ipset + iptables rule (call once at startup)."""
    ok = ensure_ipset()
    if ok:
        ok = ensure_iptables_rule()
    return ok

def block_ips(ips: Iterable[str]) -> int:
    """Block a list of IPs; returns how many were added."""
    count = 0
    for ip in ips:
        if add_ip(ip):
            count += 1
    return count

def unblock_ips(ips: Iterable[str]) -> int:
    """Unblock a list of IPs; returns how many were removed."""
    count = 0
    for ip in ips:
        if remove_ip(ip):
            count += 1
    return count
