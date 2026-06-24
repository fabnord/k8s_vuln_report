#!/usr/bin/env python3
"""Local API server for the K8s Vulnerability Report dashboard.

Serves index.html and proxies requests to the CrowdStrike Falcon API.
Vulnerability report generation streams progress via Server-Sent Events.

Usage:
    python3 server.py
    python3 server.py --port 8080
    python3 server.py --client_id ID --client_secret SECRET --base_url us1

Debug mode:
    Set DEV_MODE=1 in the environment to enable Flask debug mode.
    WARNING: This enables the Werkzeug interactive debugger which exposes a
    Python REPL in the browser. Never use DEV_MODE=1 on a shared or
    network-accessible machine.
"""
import json
import logging
import os
import re
from argparse import ArgumentParser, RawTextHelpFormatter

try:
    from flask import Flask, Response, jsonify, request, send_from_directory
except ImportError:
    raise SystemExit("Flask is required.\nInstall with: pip install flask")

try:
    from falconpy import ContainerVulnerabilities, KubernetesProtection
except ImportError:
    raise SystemExit("crowdstrike-falconpy is required.\nInstall with: pip install crowdstrike-falconpy")

from concurrent.futures import ThreadPoolExecutor, as_completed

from core import (
    RateLimitError,
    assemble_report,
    fetch_all_clusters,
    fetch_all_containers,
    fetch_vulns_for_container,
    group_containers_by_namespace,
)
from falconpy_auth import get_falcon_credentials

log = logging.getLogger(__name__)

app = Flask(__name__, static_folder=".")

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9_.:\-/]{1,256}$')

_GENERIC_API_ERROR = "API error — check server logs for details."


# ── Security headers ───────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["Referrer-Policy"]        = "no-referrer"
    # Tight CSP: page only loads local resources (no inline scripts/styles
    # beyond what is already inline in index.html, which uses nonces via
    # the meta tag). Adjust if you add external resources.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self';"
    )
    return response


# ── Credential management ──────────────────────────────────────────────────

def init_app(client_id: str, client_secret: str, base_url: str) -> None:
    app.config["FALCON_CLIENT_ID"]     = client_id
    app.config["FALCON_CLIENT_SECRET"] = client_secret
    app.config["FALCON_BASE_URL"]      = base_url


def make_k8s() -> KubernetesProtection:
    cfg = app.config
    if not cfg.get("FALCON_CLIENT_ID"):
        raise RuntimeError(
            "Falcon credentials not initialised. Call init_app() before serving requests."
        )
    return KubernetesProtection(
        client_id=cfg["FALCON_CLIENT_ID"],
        client_secret=cfg["FALCON_CLIENT_SECRET"],
        base_url=cfg["FALCON_BASE_URL"],
    )


# ── Input validation ───────────────────────────────────────────────────────

def _validate_identifier(value: str, param_name: str) -> str:
    """Raise ValueError if value is unsafe to embed in an FQL string."""
    if not _IDENTIFIER_RE.match(value):
        raise ValueError(f"Invalid characters in {param_name!r}: {value!r}")
    return value


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
    except Exception:
        log.exception("Error in /api/clusters")
        return jsonify({"error": _GENERIC_API_ERROR}), 500


@app.route("/api/namespaces")
def api_namespaces():
    """Return sorted list of namespaces, optionally filtered by cluster."""
    cluster        = request.args.get("cluster", "").strip()
    all_containers = request.args.get("all_containers", "false").lower() == "true"

    if cluster:
        try:
            _validate_identifier(cluster, "cluster")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    try:
        k8s = make_k8s()
        parts = []
        if not all_containers:
            parts.append("running_status:true")
        if cluster:
            parts.append(f"cluster_name:'{cluster}'")
        fql = "+".join(parts) if parts else ""

        containers = fetch_all_containers(k8s, fql)
        namespaces = sorted({c.get("namespace", "") for c in containers if c.get("namespace")})
        return jsonify(namespaces)
    except Exception:
        log.exception("Error in /api/namespaces")
        return jsonify({"error": _GENERIC_API_ERROR}), 500


@app.route("/api/report")
def api_report():
    """Stream vulnerability report as Server-Sent Events.

    Query params:
      cluster          — filter by cluster name
      namespace        — filter by namespace
      severity         — CRITICAL | HIGH | MEDIUM | LOW
      all_containers   — true | false (default false = running only)
    """
    cluster        = request.args.get("cluster", "").strip()
    namespace      = request.args.get("namespace", "").strip()
    severity       = request.args.get("severity", "").strip().upper() or None
    all_containers = request.args.get("all_containers", "false").lower() == "true"

    if severity and severity not in _VALID_SEVERITIES:
        return jsonify({"error": f"Invalid severity: {severity}"}), 400
    for val, name in ((cluster, "cluster"), (namespace, "namespace")):
        if val:
            try:
                _validate_identifier(val, name)
            except ValueError as e:
                return jsonify({"error": str(e)}), 400

    def generate():
        def sse(event: str, data) -> str:
            return f"event: {event}\ndata: {json.dumps(data)}\n\n"

        try:
            k8s = make_k8s()
            cv  = ContainerVulnerabilities(auth_object=k8s)

            parts = ["image_has_been_assessed:true", "image_vulnerability_count:>0"]
            if not all_containers:
                parts.append("running_status:true")
            if cluster:
                parts.append(f"cluster_name:'{cluster}'")
            if namespace:
                parts.append(f"namespace:'{namespace}'")
            fql = "+".join(parts)

            yield sse("status", {"msg": "Fetching containers…", "fql": fql})

            containers = fetch_all_containers(k8s, fql)
            yield sse("status", {"msg": f"Found {len(containers)} container records. Deduplicating images…"})

            if not containers:
                yield sse("done", {"report": {}})
                return

            ns_image_map = group_containers_by_namespace(containers)
            total_images = sum(len(v) for v in ns_image_map.values())
            yield sse("status", {"msg": f"Fetching vulnerabilities for {total_images} unique images…",
                                 "total": total_images})

            all_tasks = [
                (ns, dk, meta)
                for ns, imgs in ns_image_map.items()
                for dk, meta in imgs.items()
            ]
            vuln_cache: dict = {}
            processed    = 0
            rate_limited = 0
            with ThreadPoolExecutor(max_workers=20) as pool:
                future_map = {
                    pool.submit(fetch_vulns_for_container, cv, meta["container_id"]): (ns, dk, meta)
                    for ns, dk, meta in all_tasks
                }
                for future in as_completed(future_map):
                    ns_key, dk, meta = future_map[future]
                    try:
                        vuln_cache[(ns_key, dk)] = future.result()
                    except RateLimitError:
                        vuln_cache[(ns_key, dk)] = []
                        rate_limited += 1
                    except Exception:
                        log.exception("Failed to fetch vulns for %s", meta["container_id"])
                        vuln_cache[(ns_key, dk)] = []
                    processed += 1
                    if processed % 5 == 0 or processed == total_images:
                        yield sse("progress", {"done": processed, "total": total_images})

            if rate_limited:
                yield sse("status", {
                    "msg": f"Warning: {rate_limited} image(s) skipped due to API rate limiting — report may be incomplete.",
                    "warning": True,
                })

            report = assemble_report(ns_image_map, vuln_cache, severity)
            yield sse("done", {"report": report})

        except Exception:
            log.exception("Unhandled error in /api/report SSE stream")
            yield sse("error", {"msg": _GENERIC_API_ERROR})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Entry point ────────────────────────────────────────────────────────────

def parse_args():
    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("-k", "--client_id",    default=None)
    parser.add_argument("-s", "--client_secret", default=None)
    parser.add_argument("-b", "--base_url",      default=None,
                        help="Cloud region: us1, us2, eu1, usgov1, usgov2")
    parser.add_argument("-p", "--profile",       default="default")
    parser.add_argument("--port",  type=int, default=5000)
    parser.add_argument("--host",  default="127.0.0.1")
    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    debug = os.environ.get("DEV_MODE", "").strip() == "1"
    if debug:
        import sys
        print(
            "\n  *** DEV_MODE=1: Werkzeug interactive debugger is ENABLED ***\n"
            "  *** Anyone with browser access can execute arbitrary code.  ***\n"
            "  *** Never use this on a shared or network-accessible host.  ***\n",
            file=sys.stderr,
        )

    args = parse_args()
    creds = get_falcon_credentials(
        profile=args.profile,
        client_id=args.client_id,
        client_secret=args.client_secret,
        base_url=args.base_url,
    )
    init_app(creds["client_id"], creds["client_secret"], creds["base_url"])
    print(f"  Falcon API  : {creds['base_url']}")
    print(f"  Client ID   : {creds['client_id'][:8]}…")
    print(f"  Dashboard   : http://{args.host}:{args.port}/")
    print()
    app.run(host=args.host, port=args.port, debug=debug, threaded=True)
