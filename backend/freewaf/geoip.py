from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path


DEFAULT_DBIP_BASE_URL = "https://download.db-ip.com/free"
DEFAULT_GEOIP_DB_FILE = "/var/lib/freewaf/geoip/dbip-country-lite.csv.gz"
DEFAULT_LOOKBACK_MONTHS = 4
DEFAULT_TIMEOUT_SECONDS = 30
COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")


class GeoIpInstallError(RuntimeError):
    pass


def candidate_months(today: date | datetime | None = None, lookback_months: int = DEFAULT_LOOKBACK_MONTHS) -> list[str]:
    if lookback_months < 1:
        raise ValueError("lookback_months must be at least 1")
    if today is None:
        today = datetime.now(timezone.utc).date()
    elif isinstance(today, datetime):
        today = today.date()

    months = []
    year = today.year
    month = today.month
    for offset in range(lookback_months):
        candidate_month = month - offset
        candidate_year = year
        while candidate_month <= 0:
            candidate_month += 12
            candidate_year -= 1
        months.append(f"{candidate_year:04d}-{candidate_month:02d}")
    return months


def dbip_country_lite_url(month: str, base_url: str = DEFAULT_DBIP_BASE_URL) -> str:
    return f"{base_url.rstrip('/')}/dbip-country-lite-{month}.csv.gz"


def validate_dbip_country_csv(path: str | Path) -> bool:
    try:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as source:
            for row in csv.reader(source):
                if len(row) < 3:
                    continue
                try:
                    start_address = ipaddress.ip_address(row[0].strip())
                    end_address = ipaddress.ip_address(row[1].strip())
                except ValueError:
                    continue
                if start_address.version != end_address.version or int(start_address) > int(end_address):
                    continue
                code = str(row[2] or "").strip().upper()
                if COUNTRY_CODE_RE.fullmatch(code):
                    return True
    except (OSError, EOFError, UnicodeDecodeError, gzip.BadGzipFile, csv.Error):
        return False
    return False


def download_file(url: str, destination: str | Path, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "FreeWAF GeoIP updater"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        with Path(destination).open("wb") as target:
            shutil.copyfileobj(response, target)


def install_dbip_country_lite(
    target: str | Path = DEFAULT_GEOIP_DB_FILE,
    *,
    base_url: str = DEFAULT_DBIP_BASE_URL,
    lookback_months: int = DEFAULT_LOOKBACK_MONTHS,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    keep_existing: bool = True,
    today: date | datetime | None = None,
) -> dict:
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    errors = []

    for month in candidate_months(today, lookback_months):
        url = dbip_country_lite_url(month, base_url)
        fd, temporary_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=str(target.parent))
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            download_file(url, temporary, timeout=timeout)
            if not validate_dbip_country_csv(temporary):
                errors.append(f"{url}: invalid database")
                continue
            temporary.chmod(0o644)
            os.replace(temporary, target)
            target.with_suffix(target.suffix + ".source").write_text(url + "\n", encoding="utf-8")
            return {"ok": True, "target": str(target), "url": url, "keptExisting": False}
        except (OSError, urllib.error.URLError) as error:
            errors.append(f"{url}: {error}")
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    if keep_existing and target.exists() and validate_dbip_country_csv(target):
        return {"ok": True, "target": str(target), "url": "", "keptExisting": True}

    detail = "; ".join(errors[-lookback_months:]) if errors else "no candidate URLs were attempted"
    raise GeoIpInstallError(f"Unable to install a valid DB-IP country database: {detail}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install and validate the FreeWAF GeoIP database.")
    parser.add_argument("command", choices=["install", "validate"])
    parser.add_argument("--target", default=os.environ.get("GEOIP_DB_FILE", DEFAULT_GEOIP_DB_FILE))
    parser.add_argument("--base-url", default=os.environ.get("FREEWAF_GEOIP_BASE_URL", DEFAULT_DBIP_BASE_URL))
    parser.add_argument("--lookback-months", type=int, default=int(os.environ.get("FREEWAF_GEOIP_LOOKBACK_MONTHS", DEFAULT_LOOKBACK_MONTHS)))
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("FREEWAF_GEOIP_TIMEOUT", DEFAULT_TIMEOUT_SECONDS)))
    args = parser.parse_args(argv)

    if args.command == "validate":
        return 0 if validate_dbip_country_csv(args.target) else 1

    try:
        result = install_dbip_country_lite(
            args.target,
            base_url=args.base_url,
            lookback_months=args.lookback_months,
            timeout=args.timeout,
        )
    except GeoIpInstallError as error:
        print(error)
        return 1

    if result["keptExisting"]:
        print(f"Keeping existing GeoIP database at {result['target']}")
    else:
        print(f"Installed GeoIP database from {result['url']} to {result['target']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
