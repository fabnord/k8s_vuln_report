#!/usr/bin/env python3
"""Local API server for the K8s Vulnerability Report dashboard.

Serves index.html and proxies requests to the CrowdStrike Falcon API.
Vulnerability report generation streams progress via Server-Sent Events.

Usage:
    python3 server.py
    python3 server.py --port 8080
    python3 server.py --client_id ID --client_secret SECRET --base_url us1
"""
import json
import os
import sys
import time
from argparse import ArgumentParser, RawTextHelpFormatter
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from flask import Flask, Response, jsonify, request, send_from_directory
except ImportError:
    raise SystemExit("Flask is required.\nInstall with: pip install flask")

try:
    from falconpy import ContainerVulnerabilities, KubernetesProtection
except ImportError:
    raise SystemExit("crowdstrike-falconpy is required.\nInstall with: pip install crowdstrike-falconpy")

from falconpy_auth import get_falcon_credentials

app = Flask(__name__, static_folder=".")

# ── Globals set at startup ─────────────────────────────────────────────────
_creds: dict = {}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


# ── Falcon client factory ──────────────────────────────────────────────────

def make_k8s() -> KubernetesProtection:
    return KubernetesProtection(
        client_id=_creds["client_id"],
        client_secret=_creds["client_secret"],
        base_url=_creds["base_url"],
    )


# ── API helpers (same logic as the CLI script) ─────────────────────────────

def fetch_all_clusters(k8s: KubernetesProtection) -> list[dict]:
    clusters, offset = [], 0
    while True:
        r = k8s.read_clusters_combined(limit=500, offset=offset)
        if r["status_code"] not in (200, 201):
            break
        resources = r["body"].get("resources") or []
        clusters.extend(resources)
        total = r["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        if not resources or len(clusters) >= total:
            break
        offset += 500
    return clusters


def fetch_all_containers(k8s: KubernetesProtection, fql: str, page_size: int = 500) -> list[dict]:
    containers, offset = [], 0
    while True:
        r = k8s.read_containers_combined(
            filter=fql or None, limit=page_size, offset=offset, sort="namespace.asc"
        )
        if r["status_code"] not in (200, 201):
            errors = r["body"].get("errors", [])
            raise RuntimeError(f"KubernetesProtection error {r['status_code']}: {errors}")
        resources = r["body"].get("resources") or []
        containers.extend(resources)
        total = r["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        if not resources or len(containers) >= total:
            break
        offset += page_size
    return containers


def fetch_vulns_for_container(cv: ContainerVulnerabilities, container_id: str,
                               severity: str | None) -> list[dict]:
    vulns, offset = [], 0
    fql = f"container_id:'{container_id}'"
    if severity:
        fql += f"+severity:'{severity}'"
    while True:
        r = cv.read_combined_vulnerabilities(
            filter=fql, limit=100, offset=offset, sort="cvss_score.desc"
        )
        if r["status_code"] not in (200, 201):
            break
        resources = r["body"].get("resources") or []
        vulns.extend(resources)
        total = r["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        if not resources or len(vulns) >= total:
            break
        offset += 100
    return vulns


def build_image_ref(c: dict) -> str:
    reg  = (c.get("image_registry") or "").rstrip("/")
    repo = c.get("image_repository") or ""
    tag  = c.get("image_tag") or "latest"
    if reg and repo:
        return f"{reg}/{repo}:{tag}"
    if repo:
        return f"{repo}:{tag}"
    return (c.get("image_digest") or "<unknown>")[:40]


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/clusters")
def api_clusters():
    """Return sorted list of cluster names."""
    try:
        k8s = make_k8s()
        clusters = fetch_all_clusters(k8s)
        names = sorted({c["cluster_name"] for c in clusters if c.get("cluster_name")})
        return jsonify(names)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/namespaces")
def api_namespaces():
    """Return sorted list of namespaces, optionally filtered by cluster."""
    cluster = request.args.get("cluster", "").strip()
    all_containers = request.args.get("all_containers", "false").lower() == "true"
    try:
        k8s = make_k8s()
        parts = []
        if not all_containers:
            parts.append("running_status:true")
        if cluster:
            parts.append(f"cluster_name:'{cluster}'")
        fql = "+".join(parts) if parts else None

        # One page is enough to collect namespace names
        r = k8s.read_containers_combined(filter=fql, limit=500, sort="namespace.asc")
        resources = r["body"].get("resources") or []

        # May need more pages if >500 containers
        total = r["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        offset = 500
        while offset < total:
            r2 = k8s.read_containers_combined(filter=fql, limit=500, offset=offset)
            resources.extend(r2["body"].get("resources") or [])
            offset += 500

        namespaces = sorted({c.get("namespace", "") for c in resources if c.get("namespace")})
        return jsonify(namespaces)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/report")
def api_report():
    """Stream vulnerability report as Server-Sent Events.

    Query params:
      cluster          — filter by cluster name
      namespace        — filter by namespace
      severity         — CRITICAL | HIGH | MEDIUM | LOW
      all_containers   — true | false (default false = running only)
    """
    cluster       = request.args.get("cluster", "").strip()
    namespace     = request.args.get("namespace", "").strip()
    severity      = request.args.get("severity", "").strip().upper() or None
    all_containers = request.args.get("all_containers", "false").lower() == "true"

    threshold_idx = SEVERITY_ORDER.get(severity, 99) if severity else 99

    def generate():
        def sse(event: str, data):
            return f"event: {event}\ndata: {json.dumps(data)}\n\n"

        try:
            k8s = make_k8s()
            cv  = ContainerVulnerabilities(auth_object=k8s)

            # Build container FQL
            parts = ["image_has_been_assessed:true", "image_vulnerability_count:>0"]
            if not all_containers:
                parts.append("running_status:true")
            if cluster:
                parts.append(f"cluster_name:'{cluster}'")
            if namespace:
                parts.append(f"namespace:'{namespace}'")
            fql = "+".join(parts)

            yield sse("status", {"msg": f"Fetching containers…", "fql": fql})

            containers = fetch_all_containers(k8s, fql)
            yield sse("status", {"msg": f"Found {len(containers)} container records. Deduplicating images…"})

            if not containers:
                yield sse("done", {"report": {}})
                return

            # Group: namespace → image_digest → metadata
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

            total_images = sum(len(v) for v in ns_image_map.values())
            yield sse("status", {"msg": f"Fetching vulnerabilities for {total_images} unique images…", "total": total_images})

            # Flatten all images across namespaces for parallel fetching
            all_tasks = [
                (ns, dk, meta)
                for ns, imgs in ns_image_map.items()
                for dk, meta in imgs.items()
            ]

            # Fetch all vulnerabilities in parallel
            vuln_cache: dict[tuple, list] = {}
            processed = 0
            with ThreadPoolExecutor(max_workers=20) as pool:
                future_map = {
                    pool.submit(fetch_vulns_for_container, cv, meta["container_id"], severity): (ns, dk, meta)
                    for ns, dk, meta in all_tasks
                }
                for future in as_completed(future_map):
                    ns_key, dk, meta = future_map[future]
                    vuln_cache[(ns_key, dk)] = future.result()
                    processed += 1
                    if processed % 5 == 0 or processed == total_images:
                        yield sse("progress", {"done": processed, "total": total_images})

            # Assemble report from cached results
            report: dict = {}

            for ns, images in sorted(ns_image_map.items()):
                ns_entry = {
                    "namespace":       ns,
                    "container_count": sum(i["container_count"] for i in images.values()),
                    "image_count":     len(images),
                    "severity_counts": defaultdict(int),
                    "total_cves":      0,
                    "images":          {},
                }

                for digest_key, img_meta in images.items():
                    raw_vulns = vuln_cache.get((ns, digest_key), [])

                    vulns = []
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
                            "description":      desc[:300] + ("…" if len(desc) > 300 else ""),
                        }
                        vulns.append(entry)
                        sev_counts[sev] += 1
                        ns_entry["severity_counts"][sev] += 1

                    if vulns:
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
                if ns_entry["total_cves"] > 0:
                    report[ns] = ns_entry

            yield sse("done", {"report": report})

        except Exception as e:
            yield sse("error", {"msg": str(e)})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Entry point ────────────────────────────────────────────────────────────

def parse_args():
    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("-k", "--client_id",     default=None)
    parser.add_argument("-s", "--client_secret",  default=None)
    parser.add_argument("-b", "--base_url",       default=None,
                        help="Cloud region: us1, us2, eu1, usgov1, usgov2")
    parser.add_argument("-p", "--profile",        default="default")
    parser.add_argument("--port",  type=int, default=5000)
    parser.add_argument("--host",  default="127.0.0.1")
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    _creds = get_falcon_credentials(
        profile=args.profile,
        client_id=args.client_id,
        client_secret=args.client_secret,
        base_url=args.base_url,
    )
    print(f"  Falcon API  : {_creds['base_url']}")
    print(f"  Client ID   : {_creds['client_id'][:8]}…")
    print(f"  Dashboard   : http://{args.host}:{args.port}/")
    print()
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
