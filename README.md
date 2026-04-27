# k8s_namespace_vuln_report.py

Reports container image vulnerabilities from CrowdStrike Falcon, grouped by Kubernetes namespace. For each namespace it shows affected images, CVE IDs, CVSS scores, severity, fix availability, and exploit status.

## Requirements

- Python 3.9+
- `crowdstrike-falconpy` package
- CrowdStrike Falcon API credentials with the following scopes:
  - **Kubernetes Protection** — Read
  - **Container Vulnerabilities** — Read
- Falcon Kubernetes Admission Controller (KAC) deployed in the target clusters

Install the dependency:

```bash
pip install crowdstrike-falconpy
```

## Credentials

The script resolves credentials in this priority order:

1. `--client_id` / `--client_secret` CLI flags
2. `~/.falconpy/credentials` file (INI format)
3. `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` environment variables

**Credentials file format** (`~/.falconpy/credentials`):

```ini
[default]
client_id     = your_client_id_here
client_secret = your_client_secret_here
base_url      = us1
```

Multiple named profiles are supported — select one with `--profile`.

**Cloud regions:**

| Value    | Cloud                          |
|----------|--------------------------------|
| `us1`    | US-1 (default)                 |
| `us2`    | US-2                           |
| `eu1`    | EU-1                           |
| `usgov1` | US Gov 1                       |
| `usgov2` | US Gov 2                       |

## Usage

```
python3 k8s_namespace_vuln_report.py [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `-k`, `--client_id` | Falcon API Client ID |
| `-s`, `--client_secret` | Falcon API Client Secret |
| `-b`, `--base_url` | Cloud region (e.g. `us1`, `eu1`) |
| `-p`, `--profile` | Credential profile from `~/.falconpy/credentials` (default: `default`) |
| `-m`, `--member_cid` | Child CID for MSSP / Flight Control |
| `--namespace` | Limit report to one Kubernetes namespace |
| `--cluster` | Limit report to one cluster name |
| `--severity` | Only include CVEs at or above this level: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--min-vulns` | Skip images with fewer than N vulnerabilities |
| `--all-containers` | Include stopped/terminated containers (default: running only) |
| `--output-json FILE` | Write the full report to a JSON file |
| `--output-csv FILE` | Write a flat CVE-per-row CSV to a file |
| `--no-console` | Suppress the console report (useful when writing files only) |
| `--page-size` | API page size for container queries (default: `500`) |

## Examples

**Full report across all namespaces:**

```bash
python3 k8s_namespace_vuln_report.py
```

**Critical and high CVEs only:**

```bash
python3 k8s_namespace_vuln_report.py --severity HIGH
```

**Single namespace:**

```bash
python3 k8s_namespace_vuln_report.py --namespace kube-system
```

**Single cluster, export to CSV:**

```bash
python3 k8s_namespace_vuln_report.py --cluster prod-cluster --output-csv report.csv
```

**Include stopped containers, export JSON only:**

```bash
python3 k8s_namespace_vuln_report.py --all-containers --no-console --output-json report.json
```

**MSSP — run against a child tenant:**

```bash
python3 k8s_namespace_vuln_report.py --member_cid <child_cid>
```

**Non-default credential profile:**

```bash
python3 k8s_namespace_vuln_report.py --profile production
```

## Output

### Console

Namespaces are sorted by vulnerability severity (most critical first). Each namespace shows a summary line followed by a per-image breakdown:

```
================================================================================
  Kubernetes Container Vulnerability Report  |  2026-04-27 15:07:31 UTC
  Severity filter: >= HIGH
================================================================================

  NAMESPACE: kube-system
  ────────────────────────────────────────────────────────────
  Containers: 389  |  Images: 44  |  Total CVEs: 312
  CRITICAL:3  HIGH:309  MEDIUM:0  LOW:0

    Image : registry.example.com/myapp:v1.2.3
    CVEs  : 12   C:3 H:9 M:0 L:0
      CVE-2026-12345         CRITICAL  CVSS: 9.8 [fix available] [EXPLOITED]
      CVE-2025-99999         HIGH      CVSS: 8.1 [fix available]
      ...
```

The console report caps output at 15 CVEs per image. Use `--output-csv` or `--output-json` to see all.

### CSV

One row per CVE. Columns:

| Column | Description |
|--------|-------------|
| `namespace` | Kubernetes namespace |
| `image` | Full image reference (`registry/repository:tag`) |
| `image_digest` | SHA-256 content digest |
| `cve_id` | CVE identifier |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `cvss_score` | CVSS numeric score |
| `cps_rating` | CrowdStrike CPS rating |
| `fix_available` | `True` / `False` |
| `exploit_found` | `True` / `False` |
| `exploited_status` | e.g. `Unproven`, `Weaponized`, `Active` |
| `published_date` | CVE publication date (UTC) |
| `description` | CVE description (truncated at 200 chars) |

### JSON

Structured report keyed by namespace. Each namespace contains:

```json
{
  "kube-system": {
    "namespace": "kube-system",
    "container_count": 389,
    "image_count": 44,
    "total_cves": 312,
    "severity_counts": { "CRITICAL": 3, "HIGH": 309 },
    "images": {
      "registry.example.com/myapp:v1.2.3": {
        "image_digest": "sha256:abc123...",
        "container_count": 5,
        "vuln_count_sensor": 12,
        "vuln_count_fetched": 12,
        "severity_counts": { "CRITICAL": 3, "HIGH": 9 },
        "vulnerabilities": [
          {
            "cve_id": "CVE-2026-12345",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "cps_rating": "Critical",
            "fix_available": true,
            "exploit_found": true,
            "exploited_status": "Active",
            "published_date": "2026-01-15T00:00:00Z",
            "description": "..."
          }
        ]
      }
    }
  }
}
```

## How It Works

1. **Container discovery** — queries `KubernetesProtection` for containers that have been image-assessed and have at least one known vulnerability. By default only running containers are included.
2. **Image deduplication** — within each namespace, containers sharing the same `image_digest` are collapsed into a single image entry, avoiding redundant API calls.
3. **Vulnerability lookup** — for each unique image, CVE details are fetched from `ContainerVulnerabilities` using the `container_id` as the join key, with full pagination.
4. **Report assembly** — results are aggregated by namespace and sorted by severity count (CRITICAL → HIGH → MEDIUM → LOW → alphabetical).
