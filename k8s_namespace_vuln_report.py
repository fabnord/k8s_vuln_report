#!/usr/bin/env python3
"""Kubernetes Namespace Container Vulnerability Report

Queries CrowdStrike Falcon for container image vulnerabilities grouped by
Kubernetes namespace. Uses KubernetesProtection to enumerate running containers
and ContainerVulnerabilities to retrieve CVE details, producing a per-namespace
summary with severity breakdown and affected image inventory.

API Scopes Required:
    Kubernetes Protection     - READ
    Container Vulnerabilities - READ
"""
import csv
import datetime
import json
import sys
from argparse import ArgumentParser, RawTextHelpFormatter

try:
    from falconpy import ContainerVulnerabilities, KubernetesProtection
except ImportError as e:
    raise SystemExit(
        "This script requires crowdstrike-falconpy.\n"
        "Install with: pip install crowdstrike-falconpy"
    ) from e

from core import (
    SEVERITY_LEVELS,
    SEVERITY_ORDER,
    assemble_report,
    fetch_all_containers,
    fetch_vulns_parallel,
    group_containers_by_namespace,
)
from falconpy_auth import get_falcon_credentials


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = ArgumentParser(
        description=__doc__,
        formatter_class=RawTextHelpFormatter
    )
    parser.add_argument("-k", "--client_id", default=None,
                        help="Falcon API Client ID (overrides config/env)")
    parser.add_argument("-s", "--client_secret", default=None,
                        help="Falcon API Client Secret (overrides config/env)")
    parser.add_argument("-b", "--base_url", default=None,
                        help="Falcon cloud region (us1, us2, eu1, usgov1, usgov2)")
    parser.add_argument("-p", "--profile", default="default",
                        help="Credential profile from ~/.falconpy/credentials")
    parser.add_argument("-m", "--member_cid", default=None,
                        help="Member CID for MSSP/Flight Control")
    parser.add_argument("--namespace", default=None,
                        help="Limit report to a specific Kubernetes namespace")
    parser.add_argument("--cluster", default=None,
                        help="Limit report to a specific cluster name")
    parser.add_argument("--severity", default=None,
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Include only vulnerabilities at or above this severity")
    parser.add_argument("--min-vulns", type=int, default=0,
                        help="Skip images with fewer than this many vulnerabilities")
    parser.add_argument("--output-json", default=None, metavar="FILE",
                        help="Write full JSON report to FILE")
    parser.add_argument("--output-csv", default=None, metavar="FILE",
                        help="Write flat CSV (one row per CVE) to FILE")
    parser.add_argument("--all-containers", action="store_true",
                        help="Include stopped/terminated containers (default: running only)")
    parser.add_argument("--page-size", type=int, default=500,
                        help="Records per API page for container queries (default: 500)")
    parser.add_argument("--no-console", action="store_true",
                        help="Suppress console output (useful with --output-* flags)")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[32m",
    "UNKNOWN":  "\033[90m",
}
RESET = "\033[0m"


def _badge(sev: str) -> str:
    return f"{COLORS.get(sev.upper(), '')}{sev}{RESET}"


def print_console_report(report: dict, severity_threshold: str):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print()
    print("=" * 80)
    print(f"  Kubernetes Container Vulnerability Report  |  {ts}")
    if severity_threshold:
        print(f"  Severity filter: >= {severity_threshold}")
    print("=" * 80)

    if not report:
        print("\n  No vulnerabilities found matching the criteria.\n")
        return

    def ns_sort_key(item):
        sc = item[1].get("severity_counts", {})
        return (-sc.get("CRITICAL", 0), -sc.get("HIGH", 0),
                -sc.get("MEDIUM", 0), item[0])

    grand = {}

    for ns, ns_data in sorted(report.items(), key=ns_sort_key):
        sc    = ns_data.get("severity_counts", {})
        total = ns_data.get("total_cves", 0)
        crit  = sc.get("CRITICAL", 0)
        high  = sc.get("HIGH", 0)
        med   = sc.get("MEDIUM", 0)
        low   = sc.get("LOW", 0)

        for sev, cnt in sc.items():
            grand[sev] = grand.get(sev, 0) + cnt

        print()
        print(f"  NAMESPACE: {ns}")
        print(f"  {'─' * 60}")
        print(f"  Containers: {ns_data['container_count']}"
              f"  |  Images: {ns_data['image_count']}"
              f"  |  Total CVEs: {total}")
        print(f"  {_badge('CRITICAL')}:{crit}  "
              f"{_badge('HIGH')}:{high}  "
              f"{_badge('MEDIUM')}:{med}  "
              f"{_badge('LOW')}:{low}")

        for img_ref, img_data in sorted(
            ns_data.get("images", {}).items(),
            key=lambda x: -x[1].get("severity_counts", {}).get("CRITICAL", 0)
        ):
            vulns = img_data.get("vulnerabilities", [])
            if not vulns:
                continue
            isc = img_data.get("severity_counts", {})
            print()
            print(f"    Image : {img_ref}")
            print(f"    CVEs  : {len(vulns)}   "
                  f"C:{isc.get('CRITICAL',0)} "
                  f"H:{isc.get('HIGH',0)} "
                  f"M:{isc.get('MEDIUM',0)} "
                  f"L:{isc.get('LOW',0)}")
            for v in vulns[:15]:
                fix  = " [fix available]" if v.get("fix_available") else ""
                exp  = " [EXPLOITED]" if v.get("exploit_found") else ""
                line = (f"      {v['cve_id']:<22} "
                        f"{_badge(v['severity']):<12} "
                        f"CVSS:{v['cvss_score']:>4.1f}{fix}{exp}")
                print(line)
            if len(vulns) > 15:
                print(f"      … {len(vulns) - 15} more (use --output-json or --output-csv)")

    print()
    print("=" * 80)
    print("  GRAND TOTALS")
    print(f"  Namespaces : {len(report)}")
    for sev in SEVERITY_LEVELS:
        cnt = grand.get(sev, 0)
        if cnt:
            print(f"  {_badge(sev):<20}: {cnt}")
    print("=" * 80)
    print()


def write_json_report(report: dict, path: str):
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"JSON report written to: {path}")


def write_csv_report(report: dict, path: str):
    fieldnames = [
        "namespace", "image", "image_digest",
        "cve_id", "severity", "cvss_score", "cps_rating",
        "fix_available", "exploit_found", "exploited_status",
        "published_date", "description",
    ]
    rows = []
    for ns, ns_data in report.items():
        for img_ref, img_data in ns_data.get("images", {}).items():
            for v in img_data.get("vulnerabilities", []):
                rows.append({
                    "namespace":        ns,
                    "image":            img_ref,
                    "image_digest":     img_data.get("image_digest", ""),
                    "cve_id":           v["cve_id"],
                    "severity":         v["severity"],
                    "cvss_score":       v["cvss_score"],
                    "cps_rating":       v.get("cps_rating", ""),
                    "fix_available":    v.get("fix_available", ""),
                    "exploit_found":    v.get("exploit_found", ""),
                    "exploited_status": v.get("exploited_status", ""),
                    "published_date":   v.get("published_date", ""),
                    "description":      v.get("description", ""),
                })

    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV report written to: {path}  ({len(rows)} rows)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    creds = get_falcon_credentials(
        profile=args.profile,
        client_id=args.client_id,
        client_secret=args.client_secret,
        base_url=args.base_url,
    )

    k8s = KubernetesProtection(
        client_id=creds["client_id"],
        client_secret=creds["client_secret"],
        base_url=creds["base_url"],
        member_cid=args.member_cid,
    )
    cv = ContainerVulnerabilities(auth_object=k8s)

    fql_parts = ["image_has_been_assessed:true", "image_vulnerability_count:>0"]
    if not args.all_containers:
        fql_parts.append("running_status:true")
    if args.namespace:
        fql_parts.append(f"namespace:'{args.namespace}'")
    if args.cluster:
        fql_parts.append(f"cluster_name:'{args.cluster}'")
    container_fql = "+".join(fql_parts)

    print("\nFetching containers …")
    print(f"  Filter : {container_fql}")
    containers = fetch_all_containers(k8s, container_fql, args.page_size)
    print(f"  Found  : {len(containers)} container records")

    if not containers:
        print("No containers found. Check your filter or confirm KAC sensors are reporting.")
        sys.exit(0)

    print("Fetching vulnerability details …")
    ns_image_map = group_containers_by_namespace(containers)
    total_images = sum(len(imgs) for imgs in ns_image_map.values())

    def _cli_progress(done: int, total: int):
        if done % 10 == 0 or done == total:
            print(f"  Fetching vulns: {done}/{total} images …", end="\r", flush=True)

    vuln_cache = fetch_vulns_parallel(cv, ns_image_map, progress_cb=_cli_progress)
    print()  # newline after progress line

    report = assemble_report(ns_image_map, vuln_cache, args.severity, args.min_vulns)

    if not args.no_console:
        print_console_report(report, args.severity)

    if args.output_json:
        write_json_report(report, args.output_json)

    if args.output_csv:
        write_csv_report(report, args.output_csv)


if __name__ == "__main__":
    main()
