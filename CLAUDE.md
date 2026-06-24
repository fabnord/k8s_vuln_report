# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

**Setup** (uses `uv` for environment management):
```bash
uv sync          # install dependencies into .venv
```

**Run the web dashboard:**
```bash
uv run python server.py
# or with explicit credentials:
uv run python server.py --client_id ID --client_secret SECRET --base_url us1
```

**Run the CLI script:**
```bash
uv run python k8s_namespace_vuln_report.py
uv run python k8s_namespace_vuln_report.py --severity HIGH --namespace kube-system
uv run python k8s_namespace_vuln_report.py --output-csv report.csv --no-console
```

There are no tests or linting configured.

## Architecture

This project has two entry points sharing a common core module:

1. **`k8s_namespace_vuln_report.py`** — CLI tool that prints a console report and optionally writes JSON/CSV files. Self-contained with its own `main()`.

2. **`server.py`** — Flask web server that serves `index.html` (a single-file SPA) and exposes three API routes:
   - `GET /api/clusters` — list cluster names
   - `GET /api/namespaces` — list namespaces (optionally filtered by cluster)
   - `GET /api/report` — streams the vulnerability report as **Server-Sent Events** (SSE), emitting `status`, `progress`, and `done` events. The final `done` event carries the complete JSON report.

3. **`core.py`** — shared data-fetch and report-assembly logic used by both entry points: `fetch_all_containers`, `fetch_all_clusters`, `fetch_vulns_for_container`, `group_containers_by_namespace`, `fetch_vulns_parallel`, `assemble_report`, `build_image_ref`. All changes to the report logic belong here.

4. **`falconpy_auth.py`** — shared credential resolution: CLI args → `~/.falconpy/credentials` (INI, supports named profiles) → env vars (`FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`).

5. **`index.html`** — single-file frontend (~1500 lines of vanilla JS + CSS). Connects to the SSE stream, renders namespaces as collapsible sections with per-image CVE tables, supports dark/light theme toggle and client-side filtering.

### Core data flow (same in both entry points)

1. Query `KubernetesProtection.read_containers_combined` with FQL filter (`image_has_been_assessed:true+image_vulnerability_count:>0+running_status:true`, plus optional cluster/namespace).
2. Deduplicate containers by `image_digest` within each namespace — one representative `container_id` per unique image.
3. Fetch CVE details from `ContainerVulnerabilities.read_combined_vulnerabilities` for each unique image in parallel (`ThreadPoolExecutor`, 20 workers).
4. Assemble the report dict: `namespace → images → vulnerabilities`, with severity counts at each level.

The `server.py` version yields SSE progress events during step 3 so the UI can show a live progress bar.

### Severity filtering

The `--severity` / `severity` query param is applied **post-fetch** only. All CVEs are fetched from the API without a server-side severity FQL filter, then `SEVERITY_ORDER` (`CRITICAL:0 … LOW:3`) is used to drop entries below the threshold. This ensures `--severity HIGH` correctly returns both HIGH and CRITICAL CVEs — a server-side `+severity:'HIGH'` FQL filter would return only exactly-HIGH results, missing CRITICAL.

### Credentials

Required API scopes: **Kubernetes Protection — Read** and **Container Vulnerabilities — Read**. The Falcon Kubernetes Admission Controller (KAC) must be deployed in target clusters. Supports MSSP/Flight Control via `--member_cid` (CLI only).
