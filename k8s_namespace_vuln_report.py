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
import os
import sys
import csv
import json
import datetime
from argparse import ArgumentParser, RawTextHelpFormatter
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from falconpy import ContainerVulnerabilities, KubernetesProtection
except ImportError as e:
    raise SystemExit(
        "This script requires crowdstrike-falconpy.\n"
        "Install with: pip install crowdstrike-falconpy"
    ) from e

from falconpy_auth import get_falcon_credentials

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "NONE": 5}
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


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
# API helpers
# ---------------------------------------------------------------------------

def fetch_all_containers(k8s: KubernetesProtection, fql_filter: str,
                         page_size: int) -> list:
    """Page through all containers matching the FQL filter."""
    containers = []
    offset = 0

    while True:
        resp = k8s.read_containers_combined(
            filter=fql_filter or None,
            limit=page_size,
            offset=offset,
            sort="namespace.asc"
        )
        if resp["status_code"] not in (200, 201):
            errors = resp["body"].get("errors", [])
            raise SystemExit(
                f"KubernetesProtection API error {resp['status_code']}: {errors}"
            )

        resources = resp["body"].get("resources") or []
        containers.extend(resources)

        pagination = resp["body"].get("meta", {}).get("pagination", {})
        total = pagination.get("total", 0)

        if not resources or len(containers) >= total:
            break
        offset += page_size

    return containers


def fetch_vulns_for_container(cv: ContainerVulnerabilities, container_id: str,
                               severity_threshold: str) -> list:
    """Fetch all vulnerabilities for a container_id, optionally filtered by severity."""
    vulns = []
    offset = 0

    fql = f"container_id:'{container_id}'"
    if severity_threshold:
        fql += f"+severity:'{severity_threshold}'"

    while True:
        resp = cv.read_combined_vulnerabilities(
            filter=fql,
            limit=100,
            offset=offset,
            sort="cvss_score.desc"
        )
        if resp["status_code"] not in (200, 201):
            # Non-fatal: container may not have vuln data yet
            break

        resources = resp["body"].get("resources") or []
        vulns.extend(resources)

        pagination = resp["body"].get("meta", {}).get("pagination", {})
        total = pagination.get("total", 0)

        if not resources or len(vulns) >= total:
            break
        offset += 100

    return vulns


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def build_image_ref(container: dict) -> str:
    """Build a human-readable image reference string."""
    reg  = container.get("image_registry", "").rstrip("/")
    repo = container.get("image_repository", "")
    tag  = container.get("image_tag") or "latest"
    if reg and repo:
        return f"{reg}/{repo}:{tag}"
    if repo:
        return f"{repo}:{tag}"
    return container.get("image_digest", "<unknown>")[:40]


def build_report(containers: list, cv: ContainerVulnerabilities,
                 severity_threshold: str, min_vulns: int) -> dict:
    """
    Build the full per-namespace vulnerability report.

    Strategy:
    - Group containers by namespace
    - Within each namespace, deduplicate images by image_digest
    - For each unique image, use one representative container_id to fetch CVEs
    - Aggregate severity counts at namespace and image level
    """
    threshold_idx = SEVERITY_ORDER.get(severity_threshold, 99) if severity_threshold else 99

    # Group containers: namespace -> image_digest -> list of containers
    ns_image_map: dict[str, dict[str, dict]] = defaultdict(dict)

    for c in containers:
        ns      = c.get("namespace") or "<no-namespace>"
        digest  = c.get("image_digest") or ""
        key     = digest or build_image_ref(c)  # fallback if no digest

        if key not in ns_image_map[ns]:
            ns_image_map[ns][key] = {
                "image_ref":    build_image_ref(c),
                "image_digest": digest,
                "container_id": c.get("container_id", ""),  # representative container
                "vuln_count_reported": c.get("image_vulnerability_count", 0),
                "container_count": 0,
            }
        ns_image_map[ns][key]["container_count"] += 1

    total_images = sum(len(imgs) for imgs in ns_image_map.values())
    processed    = 0
    report       = {}

    # Flatten all images for parallel fetching
    all_tasks = [
        (ns, dk, meta)
        for ns, imgs in ns_image_map.items()
        for dk, meta in imgs.items()
    ]

    # Fetch all vulnerabilities in parallel
    vuln_cache: dict[tuple, list] = {}
    with ThreadPoolExecutor(max_workers=20) as pool:
        future_map = {
            pool.submit(fetch_vulns_for_container, cv, meta["container_id"], severity_threshold): (ns, dk, meta)
            for ns, dk, meta in all_tasks
        }
        for future in as_completed(future_map):
            ns_key, dk, meta = future_map[future]
            vuln_cache[(ns_key, dk)] = future.result()
            processed += 1
            if processed % 10 == 0 or processed == total_images:
                print(f"  Fetching vulns: {processed}/{total_images} images …", end="\r", flush=True)
    print()  # newline after progress line

    for ns, images in sorted(ns_image_map.items()):
        ns_entry = {
            "namespace":       ns,
            "container_count": sum(img["container_count"] for img in images.values()),
            "image_count":     len(images),
            "severity_counts": defaultdict(int),
            "total_cves":      0,
            "images":          {},
        }

        for digest_key, img_meta in images.items():
            container_id = img_meta["container_id"]
            raw_vulns    = vuln_cache.get((ns, digest_key), [])

            # Filter and normalise
            vulns = []
            sev_counts: dict[str, int] = defaultdict(int)
            for v in raw_vulns:
                sev = (v.get("severity") or "UNKNOWN").upper()
                if SEVERITY_ORDER.get(sev, 99) > threshold_idx:
                    continue
                cve_id = v.get("cve_id", "N/A")
                desc   = v.get("description") or ""
                entry  = {
                    "cve_id":           cve_id,
                    "severity":         sev,
                    "cvss_score":       v.get("cvss_score") or 0.0,
                    "cps_rating":       v.get("cps_current_rating") or "",
                    "fix_available":    bool(v.get("remediation_available")),
                    "exploit_found":    bool(v.get("exploit_found")),
                    "exploited_status": v.get("exploited_status_string") or "",
                    "published_date":   v.get("published_date") or "",
                    "description":      desc[:200] + ("…" if len(desc) > 200 else ""),
                }
                vulns.append(entry)
                sev_counts[sev] += 1
                ns_entry["severity_counts"][sev] += 1

            if min_vulns and len(vulns) < min_vulns:
                continue

            ns_entry["total_cves"] += len(vulns)
            ns_entry["images"][img_meta["image_ref"]] = {
                "image_digest":          img_meta["image_digest"],
                "container_count":       img_meta["container_count"],
                "vuln_count_sensor":     img_meta["vuln_count_reported"],
                "vuln_count_fetched":    len(vulns),
                "severity_counts":       dict(sev_counts),
                "vulnerabilities":       vulns,
            }

        ns_entry["severity_counts"] = dict(ns_entry["severity_counts"])
        if ns_entry["total_cves"] > 0 or not min_vulns:
            report[ns] = ns_entry

    return report


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

    grand = defaultdict(int)

    for ns, ns_data in sorted(report.items(), key=ns_sort_key):
        sc   = ns_data.get("severity_counts", {})
        total = ns_data.get("total_cves", 0)
        crit = sc.get("CRITICAL", 0)
        high = sc.get("HIGH", 0)
        med  = sc.get("MEDIUM", 0)
        low  = sc.get("LOW", 0)

        for sev, cnt in sc.items():
            grand[sev] += cnt

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
                    "namespace":       ns,
                    "image":           img_ref,
                    "image_digest":    img_data.get("image_digest", ""),
                    "cve_id":          v["cve_id"],
                    "severity":        v["severity"],
                    "cvss_score":      v["cvss_score"],
                    "cps_rating":      v.get("cps_rating", ""),
                    "fix_available":   v.get("fix_available", ""),
                    "exploit_found":   v.get("exploit_found", ""),
                    "exploited_status": v.get("exploited_status", ""),
                    "published_date":  v.get("published_date", ""),
                    "description":     v.get("description", ""),
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
        base_url=args.base_url
    )

    k8s = KubernetesProtection(
        client_id=creds["client_id"],
        client_secret=creds["client_secret"],
        base_url=creds["base_url"],
        member_cid=args.member_cid
    )
    cv = ContainerVulnerabilities(auth_object=k8s)

    # ── Container filter ────────────────────────────────────────────────────
    fql_parts = ["image_has_been_assessed:true", "image_vulnerability_count:>0"]
    if not args.all_containers:
        fql_parts.append("running_status:true")
    if args.namespace:
        fql_parts.append(f"namespace:'{args.namespace}'")
    if args.cluster:
        fql_parts.append(f"cluster_name:'{args.cluster}'")
    container_fql = "+".join(fql_parts)

    print(f"\nFetching containers …")
    print(f"  Filter : {container_fql}")
    containers = fetch_all_containers(k8s, container_fql, args.page_size)
    print(f"  Found  : {len(containers)} container records")

    if not containers:
        print("No containers found. Check your filter or confirm KAC sensors are reporting.")
        sys.exit(0)

    # ── Build report ─────────────────────────────────────────────────────────
    print("Fetching vulnerability details …")
    report = build_report(containers, cv, args.severity, args.min_vulns)

    # ── Output ───────────────────────────────────────────────────────────────
    if not args.no_console:
        print_console_report(report, args.severity)

    if args.output_json:
        write_json_report(report, args.output_json)

    if args.output_csv:
        write_csv_report(report, args.output_csv)


if __name__ == "__main__":
    main()
