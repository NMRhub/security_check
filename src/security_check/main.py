#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "requests",
# ]
# ///
"""
Ubuntu Kernel CVE Checker
Queries CVE status for the currently running kernel
"""

import argparse
import logging
import subprocess
import sys
from collections import defaultdict

import requests

logger = logging.getLogger(__name__)

# Ubuntu CVE severity hierarchy (highest to lowest)
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Untriaged"]

SEVERITY_COLORS = {
    "Critical":   "\033[1;91m",  # Bold bright red
    "High":       "\033[91m",    # Bright red
    "Medium":     "\033[93m",    # Yellow
    "Low":        "\033[94m",    # Blue
    "Negligible": "\033[92m",    # Green
    "Untriaged":  "\033[90m",    # Dark gray
}
RESET = "\033[0m"


def hyperlink(url, text):
    """Render a terminal hyperlink using ANSI OSC 8 escape sequences."""
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"


def cve_url(cve_id):
    return f"https://ubuntu.com/security/{cve_id}"


def get_kernel_info():
    """Get current kernel version and installed kernel packages."""
    try:
        kernel_release = subprocess.check_output(["uname", "-r"], text=True).strip()
        dpkg_output = subprocess.check_output(["dpkg", "-l"], text=True)

        kernel_packages = []
        for line in dpkg_output.split("\n"):
            if "linux-image" in line and kernel_release in line:
                parts = line.split()
                if len(parts) >= 3:
                    kernel_packages.append({"name": parts[1], "version": parts[2]})

        return {"release": kernel_release, "packages": kernel_packages}
    except Exception:
        logger.exception("Error getting kernel info")
        return None


def get_ubuntu_version():
    """Read Ubuntu version from /etc/os-release."""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("VERSION_ID"):
                    return line.split("=")[1].strip().strip('"')
    except Exception:
        logger.exception("Error getting Ubuntu version")
    return None


_CVE_PAGE_SIZE = 20  # Ubuntu API maximum per request


def fetch_kernel_cves(limit=100):
    """Fetch CVEs for the linux kernel package from the Ubuntu CVE API.

    Paginates in batches of up to 20 (API maximum) until *limit* CVEs are
    collected or the server reports no more results.
    """
    url = "https://ubuntu.com/security/cves.json"
    headers = {"User-Agent": "ubuntu-kernel-cve-checker/1.0"}
    cves = []
    offset = 0

    while len(cves) < limit:
        batch = min(_CVE_PAGE_SIZE, limit - len(cves))
        params = {"package": "linux", "limit": batch, "offset": offset}
        try:
            response = requests.get(url, params=params, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            page = data.get("cves", [])
            if not page:
                break
            cves.extend(page)
            if len(page) < batch:
                break  # last page
            offset += batch
        except Exception:
            logger.exception("Error fetching kernel CVEs (offset=%d)", offset)
            break

    return cves


def classify_cves(cves):
    """Group CVEs by Ubuntu severity priority."""
    by_severity = defaultdict(list)
    for cve in cves:
        raw = cve.get("priority", "untriaged")
        priority = raw.capitalize()
        if priority not in SEVERITY_ORDER:
            priority = "Untriaged"
        by_severity[priority].append(cve)
    return by_severity


def check_ubuntu_cves(kernel_info, args):
    """Fetch and display Ubuntu kernel CVEs grouped by severity."""
    print("\n" + "=" * 70)
    print("UBUNTU KERNEL CVE STATUS CHECK")
    print("=" * 70)

    ubuntu_ver = get_ubuntu_version()
    print(f"\nCurrent Kernel : {kernel_info['release']}")
    print(f"Ubuntu Version : {ubuntu_ver or 'unknown'}")

    if kernel_info["packages"]:
        print("\nInstalled Kernel Packages:")
        for pkg in kernel_info["packages"]:
            print(f"  - {pkg['name']}: {pkg['version']}")

    print("\n" + "-" * 70)
    print(f"Fetching up to {args.limit} Ubuntu kernel CVEs...")
    print("-" * 70)

    cves = fetch_kernel_cves(limit=args.limit)
    if not cves:
        print("\nNo CVE data retrieved.")
        return

    by_severity = classify_cves(cves)
    total = sum(len(v) for v in by_severity.values())
    print(f"\nFound {total} CVEs for linux kernel\n")

    for severity in SEVERITY_ORDER:
        cve_list = by_severity.get(severity, [])
        if not cve_list:
            continue

        color = SEVERITY_COLORS[severity]
        print(f"{color}{'─' * 70}")
        print(f"  {severity.upper()}  ({len(cve_list)} CVE{'s' if len(cve_list) != 1 else ''})")
        print(f"{'─' * 70}{RESET}")

        for cve in cve_list:
            cve_id = cve.get("id", "Unknown")
            description = cve.get("description", "No description available").strip()
            published = cve.get("published", "")
            date_str = published[:10] if published else "N/A"

            link = hyperlink(cve_url(cve_id), cve_id)
            snippet = description[:120] + ("..." if len(description) > 120 else "")
            print(f"\n  {color}{link}{RESET}  [{date_str}]")
            print(f"  {snippet}")

    print()


def check_reboot_required():
    """Check whether a reboot is required."""
    print("\n" + "-" * 70)
    print("Reboot Status")
    print("-" * 70)

    try:
        with open("/var/run/reboot-required"):
            print("\n  *** REBOOT REQUIRED ***")

        try:
            with open("/var/run/reboot-required.pkgs") as f:
                packages = [p for p in f.read().strip().split("\n") if p]
                print(f"\n  Packages requiring reboot ({len(packages)}):")
                for pkg in packages[:10]:
                    print(f"    - {pkg}")
                if len(packages) > 10:
                    print(f"    ... and {len(packages) - 10} more")
        except FileNotFoundError:
            pass
        except Exception:
            logger.exception("Error reading reboot-required.pkgs")

    except FileNotFoundError:
        print("\n  No reboot currently required")
    except Exception:
        logger.exception("Error checking reboot-required")


def check_security_updates():
    """Check for available security updates via apt."""
    print("\n" + "-" * 70)
    print("Available Security Updates")
    print("-" * 70)

    try:
        print("\n  Updating package lists...")
        subprocess.run(
            ["sudo", "apt", "update", "-qq"],
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        logger.exception("apt update failed")
        return
    except Exception:
        logger.exception("Unexpected error running apt update")
        return

    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
        )

        security_updates = [
            line
            for line in result.stdout.split("\n")
            if line and ("security" in line.lower() or "linux-image" in line)
        ]

        if security_updates:
            print(f"\n  {len(security_updates)} security-related update(s) available:")
            for update in security_updates[:15]:
                print(f"    {update}")
            if len(security_updates) > 15:
                print(f"    ... and {len(security_updates) - 15} more")
        else:
            print("\n  No security updates currently available")

    except Exception:
        logger.exception("Error parsing apt output")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Check Ubuntu kernel CVE status using the Ubuntu security API"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        metavar="N",
        help="Maximum number of CVEs to fetch (default: 100)",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity (default: WARNING)",
    )
    parser.add_argument(
        "--skip-updates",
        action="store_true",
        help="Skip the apt security updates check (avoids sudo)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s: %(message)s",
    )

    print("\nChecking kernel CVE status...\n")

    kernel_info = get_kernel_info()
    if not kernel_info:
        logger.error("Could not retrieve kernel information")
        sys.exit(1)

    check_ubuntu_cves(kernel_info, args)
    check_reboot_required()

    if not args.skip_updates:
        check_security_updates()

    print("\n" + "=" * 70)
    print("Recommendations")
    print("=" * 70)
    cve_link = hyperlink("https://ubuntu.com/security/cves", "ubuntu.com/security/cves")
    print(f"""
  1. Patch Critical and High CVEs as a priority
  2. If reboot is required, schedule a maintenance window
  3. Apply updates:  sudo apt update && sudo apt upgrade
  4. Full CVE list:  {cve_link}
""")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
