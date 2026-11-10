# Python HIDS Engine (v4) - Query Rules

A Host-based Intrusion Detection System (HIDS) detection engine powered by **Python**, **pySigma**, and **OpenSearch**. The engine translates Sigma detection rules into OpenSearch Lucene queries to evaluate security events and generate actionable threat alerts.

---

## 📌 Architecture Overview

```
                          ┌───────────────────────────┐
                          │   Sigma Detection Rules   │
                          │   (Atomic & Correlation)  │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
┌─────────────────────────┐    ┌──────────────────┐
│ Windows Event Datasets  │───>│  pySigma Parser  │
│ (JSONL / Sysmon / etc.) │    │   & Translator   │
└───────────┬─────────────┘    └────────┬─────────┘
            │                           │
            │ (Bulk Ingestion)          │ (Lucene DSL Queries)
            ▼                           ▼
┌─────────────────────────────────────────────────────┐
│                 OpenSearch 2.18.0                   │
│  - windows-events: Stored event logs                │
│  - hids-alerts:    Generated security alerts        │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│                 Alert Output Engine                 │
│  - Local timestamped JSONL alert logs (data/alerts) │
│  - Direct buffering & indexing into OpenSearch      │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

- **Sigma Rule Translation**: Leverages `pySigma` and `pySigma-backend-opensearch` to dynamically translate Sigma rules into optimized OpenSearch Query DSL.
- **Dual Schema Support**:
  - **Native**: Direct matching against raw Windows / Sysmon / Mordor logs (`EventID`, `Image`, `CommandLine`).
  - **ECS (Elastic Common Schema)**: Field mapping pipeline transforming fields into standard ECS format (`winlog.event_id`, `process.executable`, `process.command_line`).
- **Atomic & Correlation Rules**:
  - **Atomic Rules**: Single-event query searches with configurable time ranges.
  - **Correlation Rules**: Aggregation-based threshold searches detecting multi-event patterns over time spans.
- **High-Performance Ingestion**: Streaming JSON parsing with `orjson` and bulk indexing into OpenSearch.
- **OpenSearch Dashboards**: Pre-configured visualization and analysis interface on port `5601`.

---

## 📂 Project Structure

```
hids_v4_query_rules/
├── docker-compose.yml              # OpenSearch & Dashboards setup
├── README.md                       # Project documentation
├── test_atomic_queries.py          # Batch export script for atomic rule queries
├── test_correlation_rules.py       # Batch export script for correlation queries
├── data/
│   ├── alerts/                     # Generated alert JSONL outputs
│   ├── events/                     # Datasets (Sysmon, DCSync, Brute Force, etc.)
│   └── translated_*_queries.json   # Exported Lucene query definitions
├── modules/
│   ├── opensearch/
│   │   └── opensearch.py           # OpenSearch client, bulk ingestion & PIT queries
│   ├── parser/
│   │   ├── alerts.py               # Alert data model & serialization
│   │   ├── config.py / config.json # Configuration loader (OpenSearch settings)
│   │   ├── constants.py            # Global constants & schemas
│   │   ├── correlation_rules.py    # Sigma correlation rule parser
│   │   ├── events.py               # JSONL event parser
│   │   ├── main.py                 # Core CLI entry point
│   │   ├── rules.py                # Sigma atomic rule loader
│   │   └── translator.py           # pySigma AST to OpenSearch Query DSL compiler
│   └── pipelines/
│       └── opensearch_custom.yml   # Custom ECS transformation pipeline
└── rules/
    └── sigma/                      # Sigma detection rule repository (2,400+ rules)
        ├── builtin/                # Windows Security & System rules
        ├── process_creation/       # Process execution detection
        ├── registry/               # Registry manipulation detection
        ├── sysmon/                 # Sysmon-specific rules
        └── correlation/            # Multi-event correlation rules
```

---

## 🛠️ Prerequisites

- **Python**: 3.11+ (recommended 3.12 or 3.13)
- **Docker & Docker Compose**: For running OpenSearch and Dashboards
- **RAM**: Minimum 4 GB recommended (OpenSearch container uses 1-2 GB JVM heap)

### Python Dependencies

Install required Python libraries:
```bash
pip install requests orjson pyyaml sigma-cli pysigma pysigma-backend-opensearch
```

---

## ⚡ Quick Start

### 1. Start OpenSearch Cluster

Start OpenSearch and OpenSearch Dashboards:
```bash
docker compose up -d
```

> **Important**: Wait 15–30 seconds for OpenSearch to finish booting up before sending queries.

Verify OpenSearch status:
```bash
curl http://localhost:9200
```
or via PowerShell:
```powershell
Invoke-RestMethod http://localhost:9200
```

OpenSearch Dashboards will be available at: **http://localhost:5601**

---

### 2. Run the Detection Engine

Execute the HIDS engine using `modules.parser.main`:

```bash
python -m modules.parser.main <rules_dir> <output_dir> [options]
```

#### Example: Ingest Event Log & Run Detection

```powershell
python -m modules.parser.main .\rules\sigma\ .\data\alerts\ `
  --events-index windows-events `
  --timeframe all `
  --schema native `
  --opensearch `
  --ingest-file .\data\events\dsync_detection.jsonl
```

#### Example: Fast Test with Rule Limit

```powershell
python -m modules.parser.main .\rules\sigma\builtin\security\ .\data\alerts\ `
  --events-index windows-events `
  --timeframe all `
  --schema native `
  --opensearch `
  --limit 50
```

---

## ⚙️ CLI Arguments

| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `rules_dir` | Positional | *Required* | Path to the directory containing Sigma YAML rule files. |
| `output_dir` | Positional | *Required* | Path to the directory where JSONL alert files are written. |
| `--opensearch`, `--os` | Flag | `False` | Enables OpenSearch search execution and alert indexing. |
| `--events-index` | String | `windows-events` | Target index containing raw security logs. |
| `--timeframe` | String | `all` | Filter range: `'all'`, `'now-15m'`, `'now-24h'`, `'now-7d'`. |
| `--schema` | Choice | `native` | Target field naming: `native` (raw Windows) or `ecs` (Elastic Common Schema). |
| `--ingest-file` | Path | `None` | Optional `.jsonl` raw log file to ingest into `--events-index` prior to querying. |
| `--limit` | Integer | `None` | Limits execution to the first *N* loaded rules (useful for testing). |

---

## 🔔 Alert Output Format

Alerts are saved in timestamped files under `data/alerts/alerts_<YYYYMMDD_HHMMSS>.jsonl` and mirrored to the `hids-alerts` OpenSearch index.

Example alert document:
```json
{
  "alert_type": "atomic",
  "rule_title": "Uncommon Outbound Kerberos Connection - Security",
  "event_count": 1,
  "rule_id": "eca91c7c-9214-47b9-b4c5-cb1d7e4f2350",
  "rule_level": "medium",
  "source_path": "rules/sigma/builtin/security/win_security_susp_outbound_kerberos_connection.yml",
  "@timestamp": "2020-08-05T06:10:02.780Z",
  "hostname": "MORDORDC.theshire.local",
  "rule_tags": [
    "attack.lateral-movement",
    "attack.credential-access",
    "attack.t1558.003"
  ]
}
```

---

## 🔍 Exporting Translated Rules (Offline Testing)

To inspect how Sigma rules are translated into OpenSearch Query DSL without querying a cluster:

- **Atomic Queries**:
  ```bash
  python test_atomic_queries.py
  ```
  Exports queries to `data/translated_atomic_queries.json`.

- **Correlation Queries**:
  ```bash
  python test_correlation_rules.py
  ```
  Exports correlation definitions to `data/translated_correlation_queries.json`.

---

## ⚠️ Notes & Troubleshooting

1. **OpenSearch Startup Latency**:
   - If you see `RemoteDisconnected` or `Opensearch doesn't respond`, wait ~20 seconds after `docker compose up -d` before executing the script.
2. **`too_many_nested_clauses` (HTTP 500)**:
   - Rules with thousands of clauses (e.g. driver hashes or Mimikatz keywords) may exceed Lucene's clause limit. `maxClauseCount` is configured to `10240` in `docker-compose.yml`. Any rule exceeding this is logged and safely bypassed.
3. **Historical Datasets & Timeframes**:
   - Synthetic or captured attack datasets (like Mordor) usually contain historical timestamps (e.g., from 2020). Always use `--timeframe all` when evaluating pre-recorded event files.
4. **Field Mapping**:
   - Ensure the `--schema` parameter matches your dataset format. For raw Windows Event logs or Mordor datasets, use `--schema native`. For Winlogbeat or ECS-normalized inputs, use `--schema ecs`.
