"""ipset + iptables integration for FreeWAF IP blocking.

Manages the ipsets ``freewaf_blocked`` (IPv4) and ``freewaf_blocked6``
(IPv6) plus the matching iptables/ip6tables INPUT rules that log then drop
traffic from IPs in the set.  The LOG rule is inserted before DROP so
blocked traffic appears in kernel log for ``blocked_traffic_logger`` to
parse into access-log format.

An ipset carries a single address family, so IPv6 needs its own set and its
own ip6tables rules.  The IPv6 side is created lazily, the first time a v6
address is actually blocked, so IPv4-only hosts never touch ip6tables.

All commands are best-effort -- failures are logged to stderr but never
crash the server.
"""

from __future__ import annotations

import ipaddress
import subprocess
import threading
from typing import Iterable

IPSET_NAME = "freewaf_blocked"
IPSET_NAME6 = "freewaf_blocked6"
IPTABLES_CHAIN = "INPUT"
LOG_PREFIX = "FREEWAF_BLOCKED: "
_lock = threading.RLock()

_FAMILIES = (4, 6)


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


def ip_family(raw: str) -> int | None:
    """4 or 6 for a parseable address/CIDR, None when it is neither."""
    raw = str(raw or "").strip()
    if not raw:
        return None
    try:
        if "/" in raw:
            return ipaddress.ip_network(raw, strict=False).version
        return ipaddress.ip_address(raw).version
    except ValueError:
        return None


def _set_name(family: int) -> str:
    return IPSET_NAME6 if family == 6 else IPSET_NAME


def _iptables_bin(family: int) -> str:
    return "ip6tables" if family == 6 else "iptables"


# ------------------------------------------------------------------
# ipset helpers
# ------------------------------------------------------------------

def ensure_ipset(family: int = 4) -> bool:
    """Create the ipset for *family* if it does not already exist."""
    name = _set_name(family)
    with _lock:
        result = _run(["ipset", "list", name])
        if result.returncode == 0:
            return True
        create = ["ipset", "create", name, "hash:net"]
        if family == 6:
            # Without this the set is created inet (IPv4) and rejects v6 members.
            create += ["family", "inet6"]
        create.append("-exist")
        result = _run(create)
        return result.returncode == 0


def add_ip(ip: str) -> bool:
    """Add *ip* (single address or CIDR) to the block set for its family."""
    family = ip_family(ip)
    if family is None:
        return False
    ip = _normalize_ip(ip)
    if not ip:
        return False
    with _lock:
        ensure_ipset(family)
        if family == 6:
            # Rules are only needed once something v6 is actually blocked.
            ensure_iptables_rule(6)
        result = _run(["ipset", "add", _set_name(family), ip, "-exist"])
        return result.returncode == 0


def remove_ip(ip: str) -> bool:
    """Remove *ip* from the block set for its family."""
    family = ip_family(ip)
    if family is None:
        return False
    ip = _normalize_ip(ip)
    if not ip:
        return False
    with _lock:
        result = _run(["ipset", "del", _set_name(family), ip, "-exist"])
        return result.returncode == 0


def list_ips(family: int | None = None) -> list[str]:
    """Return blocked IPs/CIDRs, from both families unless one is given."""
    families = (family,) if family in _FAMILIES else _FAMILIES
    ips: list[str] = []
    with _lock:
        for item in families:
            result = _run(["ipset", "list", _set_name(item), "output"])
            if result.returncode != 0:
                continue
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
    """Replace the contents of both sets with *ips*, split by family."""
    grouped: dict[int, list[str]] = {4: [], 6: []}
    for raw in ips:
        family = ip_family(raw)
        if family is None:
            continue
        normalised = _normalize_ip(raw)
        if normalised:
            grouped[family].append(normalised)

    with _lock:
        for family in _FAMILIES:
            members = grouped[family]
            # Leave an untouched v6 set alone on hosts that never block v6.
            if family == 6 and not members and not _ipset_exists(6):
                continue
            ensure_ipset(family)
            if family == 6 and members:
                ensure_iptables_rule(6)
            _run(["ipset", "flush", _set_name(family)])
            for ip in members:
                _run(["ipset", "add", _set_name(family), ip, "-exist"])
    return True


def _ipset_exists(family: int) -> bool:
    return _run(["ipset", "list", _set_name(family)]).returncode == 0


def destroy_ipset(family: int | None = None) -> bool:
    """Destroy the ipset(s)."""
    families = (family,) if family in _FAMILIES else _FAMILIES
    ok = True
    with _lock:
        for item in families:
            if _run(["ipset", "destroy", _set_name(item)]).returncode != 0:
                ok = False
    return ok


# ------------------------------------------------------------------
# iptables helpers
# ------------------------------------------------------------------

def _log_rule_args(family: int) -> list[str]:
    return ["-m", "set", "--match-set", _set_name(family), "src",
            "-j", "LOG", "--log-prefix", LOG_PREFIX, "--log-level", "4"]


def _drop_rule_args(family: int) -> list[str]:
    return ["-m", "set", "--match-set", _set_name(family), "src", "-j", "DROP"]


def _rule_exists(family: int, args: list[str]) -> bool:
    result = _run([_iptables_bin(family), "-C", IPTABLES_CHAIN, *args])
    return result.returncode == 0


def ensure_iptables_log_rule(family: int = 4) -> bool:
    """Insert the INPUT LOG rule if it doesn't exist yet."""
    args = _log_rule_args(family)
    if _rule_exists(family, args):
        return True
    result = _run([_iptables_bin(family), "-I", IPTABLES_CHAIN, "1", *args])
    return result.returncode == 0


def remove_iptables_log_rule(family: int = 4) -> bool:
    """Remove the INPUT LOG rule."""
    args = _log_rule_args(family)
    if not _rule_exists(family, args):
        return True
    result = _run([_iptables_bin(family), "-D", IPTABLES_CHAIN, *args])
    return result.returncode == 0


def ensure_iptables_drop_rule(family: int = 4) -> bool:
    """Insert the INPUT DROP rule if it doesn't exist yet."""
    args = _drop_rule_args(family)
    if _rule_exists(family, args):
        return True
    result = _run([_iptables_bin(family), "-I", IPTABLES_CHAIN, "1", *args])
    return result.returncode == 0


def remove_iptables_drop_rule(family: int = 4) -> bool:
    """Remove the INPUT DROP rule."""
    args = _drop_rule_args(family)
    if not _rule_exists(family, args):
        return True
    result = _run([_iptables_bin(family), "-D", IPTABLES_CHAIN, *args])
    return result.returncode == 0


def ensure_iptables_rule(family: int = 4) -> bool:
    """Insert LOG + DROP rules. LOG inserted first so it matches before DROP."""
    ensure_iptables_drop_rule(family)
    ensure_iptables_log_rule(family)
    return True


def remove_iptables_rule(family: int | None = None) -> bool:
    """Remove both LOG and DROP rules."""
    families = (family,) if family in _FAMILIES else _FAMILIES
    for item in families:
        remove_iptables_log_rule(item)
        remove_iptables_drop_rule(item)
    return True


# ------------------------------------------------------------------
# Combined helpers
# ------------------------------------------------------------------

def initialise() -> bool:
    """Create the IPv4 ipset + iptables rule (call once at startup).

    The IPv6 set is left until a v6 address is blocked, so hosts that never
    see v6 traffic do not gain an empty set and unused ip6tables rules.
    """
    ok = ensure_ipset(4)
    if ok:
        ok = ensure_iptables_rule(4)
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
