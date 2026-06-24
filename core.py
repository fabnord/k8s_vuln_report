"""Shared core logic for k8s vulnerability report generation.

Both the CLI (k8s_namespace_vuln_report.py) and the web server (server.py) use
these functions. Keep all data-fetch and assembly logic here to avoid drift.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from falconpy import ContainerVulnerabilities, KubernetesProtection

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "NONE": 5}
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
VULN_DESC_MAX_LEN = 300


class RateLimitError(Exception):
    """Raised when the Falcon API returns HTTP 429 (rate limit exceeded)."""


def build_image_ref(c: dict) -> str:
    reg  = (c.get("image_registry") or "").rstrip("/")
    repo = c.get("image_repository") or ""
    tag  = c.get("image_tag") or "latest"
    if reg and repo:
        return f"{reg}/{repo}:{tag}"
    if repo:
        return f"{repo}:{tag}"
    return (c.get("image_digest") or "<unknown>")[:40]


def fetch_all_containers(k8s: KubernetesProtection, fql_filter: str,
                         page_size: int = 500) -> list[dict]:
    """Page through all containers matching the FQL filter."""
    containers: list[dict] = []
    offset = 0
    while True:
        resp = k8s.read_containers_combined(
            filter=fql_filter or None,
            limit=page_size,
            offset=offset,
            sort="namespace.asc",
        )
        if resp["status_code"] not in (200, 201):
            errors = resp["body"].get("errors", [])
            raise RuntimeError(
                f"KubernetesProtection API error {resp['status_code']}: {errors}"
            )
        resources = resp["body"].get("resources") or []
        containers.extend(resources)
        total = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        if not resources or len(containers) >= total:
            break
        offset += page_size
    return containers


def fetch_all_clusters(k8s: KubernetesProtection, page_size: int = 500) -> list[dict]:
    """Page through all clusters."""
    clusters: list[dict] = []
    offset = 0
    while True:
        r = k8s.read_clusters_combined(limit=page_size, offset=offset)
        if r["status_code"] not in (200, 201):
            break
        resources = r["body"].get("resources") or []
        clusters.extend(resources)
        total = r["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        if not resources or len(clusters) >= total:
            break
        offset += page_size
    return clusters


def fetch_vulns_for_container(cv: ContainerVulnerabilities,
                               container_id: str) -> list[dict]:
    """Fetch all vulnerabilities for a container_id (no server-side severity filter).

    Severity filtering is done post-fetch so that ">= HIGH" correctly includes
    CRITICAL — the Falcon FQL severity filter returns only the exact level named,
    not all levels at or above it.
    """
    vulns: list[dict] = []
    offset = 0
    fql = f"container_id:'{container_id}'"
    while True:
        resp = cv.read_combined_vulnerabilities(
            filter=fql,
            limit=100,
            offset=offset,
            sort="cvss_score.desc",
        )
        if resp["status_code"] == 429:
            raise RateLimitError(
                f"Falcon API rate limit exceeded while fetching vulns for {container_id}. "
                "The report may be incomplete."
            )
        if resp["status_code"] not in (200, 201):
            break
        resources = resp["body"].get("resources") or []
        vulns.extend(resources)
        total = resp["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        if not resources or len(vulns) >= total:
            break
        offset += 100
    return vulns


def group_containers_by_namespace(containers: list[dict]) -> dict[str, dict[str, dict]]:
    """Return namespace -> digest_key -> image_metadata."""
    ns_image_map: dict[str, dict[str, dict]] = defaultdict(dict)
    for c in containers:
        ns     = c.get("namespace") or "<no-namespace>"
        digest = c.get("image_digest") or ""
        key    = digest or build_image_ref(c)
        if key not in ns_image_map[ns]:
            ns_image_map[ns][key] = {
                "image_ref":           build_image_ref(c),
                "image_digest":        digest,
                "container_id":        c.get("container_id", ""),
                "vuln_count_reported": c.get("image_vulnerability_count", 0),
                "container_count":     0,
                "cluster_name":        c.get("cluster_name", ""),
            }
        ns_image_map[ns][key]["container_count"] += 1
    return ns_image_map


def fetch_vulns_parallel(
    cv: ContainerVulnerabilities,
    ns_image_map: dict[str, dict[str, dict]],
    progress_cb: Callable[[int, int], None] | None = None,
    max_workers: int = 20,
) -> tuple[dict[tuple, list[dict]], int]:
    """Fetch vulns for all images in parallel.

    Returns (vuln_cache, rate_limited_count) where vuln_cache maps
    (ns, digest_key) -> vuln list and rate_limited_count is the number
    of images skipped due to HTTP 429 responses.
    """
    all_tasks = [
        (ns, dk, meta)
        for ns, imgs in ns_image_map.items()
        for dk, meta in imgs.items()
    ]
    total = len(all_tasks)
    vuln_cache: dict[tuple, list[dict]] = {}
    processed = 0
    rate_limited = 0

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(fetch_vulns_for_container, cv, meta["container_id"]): (ns, dk, meta)
            for ns, dk, meta in all_tasks
        }
        for future in as_completed(future_map):
            ns_key, dk, meta = future_map[future]
            try:
                vuln_cache[(ns_key, dk)] = future.result()
            except RateLimitError as exc:
                print(f"  Warning: {exc}", file=sys.stderr)
                vuln_cache[(ns_key, dk)] = []
                rate_limited += 1
            except Exception as exc:
                print(
                    f"  Warning: failed to fetch vulns for {meta['container_id']}: {exc}",
                    file=sys.stderr,
                )
                vuln_cache[(ns_key, dk)] = []
            processed += 1
            if progress_cb:
                progress_cb(processed, total)

    return vuln_cache, rate_limited


def assemble_report(
    ns_image_map: dict[str, dict[str, dict]],
    vuln_cache: dict[tuple, list[dict]],
    severity_threshold: str | None,
    min_vulns: int = 0,
) -> dict:
    """Build the final report dict from pre-fetched vuln data."""
    threshold_idx = SEVERITY_ORDER.get(severity_threshold, 99) if severity_threshold else 99
    report: dict = {}

    for ns, images in sorted(ns_image_map.items()):
        ns_entry: dict = {
            "namespace":       ns,
            "container_count": sum(img["container_count"] for img in images.values()),
            "image_count":     len(images),
            "severity_counts": defaultdict(int),
            "total_cves":      0,
            "images":          {},
        }

        for digest_key, img_meta in images.items():
            raw_vulns = vuln_cache.get((ns, digest_key), [])

            vulns: list[dict] = []
            sev_counts: dict[str, int] = defaultdict(int)
            for v in raw_vulns:
                sev = (v.get("severity") or "UNKNOWN").upper()
                if SEVERITY_ORDER.get(sev, 99) > threshold_idx:
                    continue
                desc = v.get("description") or ""
                entry = {
                    "cve_id":           v.get("cve_id", "N/A"),
                    "severity":         sev,
                    "cvss_score":       v.get("cvss_score") or 0.0,
                    "cps_rating":       v.get("cps_current_rating") or "",
                    "fix_available":    bool(v.get("remediation_available")),
                    "exploit_found":    bool(v.get("exploit_found")),
                    "exploited_status": v.get("exploited_status_string") or "",
                    "published_date":   v.get("published_date") or "",
                    "description":      desc[:VULN_DESC_MAX_LEN] + ("…" if len(desc) > VULN_DESC_MAX_LEN else ""),
                }
                vulns.append(entry)
                sev_counts[sev] += 1
                ns_entry["severity_counts"][sev] += 1

            if min_vulns and len(vulns) < min_vulns:
                continue

            ns_entry["total_cves"] += len(vulns)
            ns_entry["images"][img_meta["image_ref"]] = {
                "image_digest":       img_meta["image_digest"],
                "container_count":    img_meta["container_count"],
                "cluster_name":       img_meta["cluster_name"],
                "vuln_count_sensor":  img_meta["vuln_count_reported"],
                "vuln_count_fetched": len(vulns),
                "severity_counts":    dict(sev_counts),
                "vulnerabilities":    vulns,
            }

        ns_entry["severity_counts"] = dict(ns_entry["severity_counts"])
        if ns_entry["total_cves"] > 0 or not min_vulns:
            report[ns] = ns_entry

    return report
