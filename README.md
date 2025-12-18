# Vulnerability Data Lakehouse

A production-grade ETL pipeline designed to ingest, process, and analyze vulnerability data from multiple external sources. This project follows a **Data Lakehouse** architecture using MongoDB, processing data through **Bronze (Raw)**, **Silver (Cleaned/Enriched)**, and **Gold (Aggregated)** layers.

---

## 🏗 Architecture

### 1. Bronze Layer (Raw Ingestion)
The entry point for all data. Extractors fetch data from APIs or feeds and load it "as-is" into MongoDB. 
**Key Feature:** Supports incremental loading (High Watermark) to only fetch new data.

| Source | Description | Collection Name | Update Strategy |
|--------|-------------|-----------------|-----------------|
| **NVD** | National Vulnerability Database (CVEs) | `nvd_raw` | API (Incremental Key: `lastModified`) |
| **CISA** | Known Exploited Vulnerabilities (KEV) | `cisa_raw` | CSV Feed (Incremental Key: `dateReleased`) |
| **EPSS** | Exploit Prediction Scoring System | `epss_raw` | CSV Feed (Incremental Key: `date`) |
| **ExploitDB** | Archive of public exploits | `exploitdb_raw` | Scraper + CSV (Incremental Key: `date_published`) |
| **Metasploit** | Penetration testing modules | `metasploit_raw` | JSON Feed (Incremental Key: `mod_time`) |

### 2. Silver Layer (Cleaned & Enriched)
Transforms raw data into a standardized schema.
*   **Cleaning:** Fixing missing values, type casting (strings to dates/ints).
*   **Flattening:** e.g., NVD Metrics (`cvssMetricV31`) are flattened to top-level columns.
*   **Enrichment:** Maps source-specific keys to a unified schema.

**Collections:** `nvd_silver`, `cisa_silver`, `epss_silver`, `exploit_silver`, `metasploit_silver`.

### 3. Gold Layer (Aggregated)
The final analytical layer. Contains **5 Collections**:

**Source Mirrors (5):** Precise replicas of Silver data
*   `gold_nvd`, `gold_cisa`, `gold_epss`, `gold_exploit`, `gold_metasploit`
*   Controlled by `gold/mapping_config.py` (configured to pass all columns)

---

### 4. Analytics Layer (Actionable Intelligence)
The final processing stage located in `analytics_stream/`. It transforms Gold records into a **Star Schema** for fast analysis.

*   **Logic-as-Code:** Definitions in `definitions.py` specify scoring weights and field transforms.
*   **Star Schema:** 
    *   `dim_threats`: Reference table for all metadata fields (CISA product, EPSS value, etc).
    *   `dim_vrr`: Reference table for scoring factors and their weights.
    *   `fct_final`: The "Master Fact Table" containing calculated scores for **322,000+ CVEs**.
*   **Performance:** Uses an in-memory caching engine to process the entire dataset in **< 10 seconds**.

---

## 📂 Project Structure

```text
├── vulnerability_pipeline/      # ETL Core (Bronze, Silver, Gold)
├── analytics_stream/            # Analytics Layer (Layer 4)
│   ├── definitions.py           # Scoring weights & Logic definitions
│   ├── init_schema.py           # Validator & Dimension Builder
│   └── calculate_facts.py       # High-speed scoring engine
├── api/                         # FastAPI Deployment
├── terraform/                   # AWS Infrastructure (IaC)
├── csv_handler/                 # Smart CSV Ingestion & Enrichment
│   ├── uploader.py              # Main "Smart" Ingestion Engine
│   └── enricher.py              # Standalone CSV Enrichment Tool
├── scripts/                     # Operational Scripts
│   └── migration/               # Data sync tools (Local -> Atlas)
├── logs/                        # Centralized Log Storage
├── data/                        # Sample input files
├── local_run.sh                 # Unified Control Script (Runner)
└── requirements.txt             # Dependencies
```

---

## 🚀 Getting Started

### Prerequisites
*   Python 3.11+
*   MongoDB (Atlas recommended for analytics performance)

### Installation

1.  **Clone & Enter:**
    ```bash
    cd Vuln_Info
    ```
2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configure Environment:**
    Ensure your `.env` file has the correct MongoDB URI.
    ```ini
    MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/vulnerability_gold
    ```

---

## 🏃 Usage Examples

### 1. Run the ETL Pipeline (Bronze to Gold)
This fetches raw data and mirrors it into the Gold tables.
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator
```

### 2. Initialize Analytics (Dimensions)
Validates that your Gold data matches the code definitions and builds dimensions.
```bash
python3 analytics_stream/init_schema.py
```

### 3. Calculate Risk Scores (Facts)
Runs the optimized scoring engine. Processes ~322k records in seconds.
```bash
python3 analytics_stream/calculate_facts.py
```

---

## 📊 VRR Scoring Logic (Example)
The system uses a weighted formula to calculate the **Vulnerability Risk Rating (VRR)**:

| Factor | Weight | Logic |
|--------|---------|-------|
| **CISA KEV** | +30.0 | If CVE is in CISA Known Exploited list. |
| **ExploitDB** | +10.0 | If a public exploit exists. |
| **Metasploit** | +10.0 | If a Metasploit module is available. |
| **EPSS** | Value * 10 | Probability score (0.0 - 10.0 range). |
| **NVD CVSS** | Score * 0.5 | Half of the base severity score. |

**Resulting Fact Record:**
```json
{
  "cve_id": "CVE-2023-23397",
  "vrr_score": 44.26,
  "threats": {
    "CISA_vendor": "Microsoft",
    "EPSS_value": 0.936,
    "NVD_severity": "Critical"
  }
}
```

### 4. Full Reload (Resetting a Source)
If you need to re-fetch data from scratch (e.g., ExploitDB to get new scraped fields), you must drop the collections.
```bash
# Example: Reset ExploitDB
python3 -c "from vulnerability_pipeline.core.mongo_client import MongoManager; db=MongoManager.get_bronze_db(); db['exploitdb_raw'].drop(); db=MongoManager.get_silver_db(); db['exploit_silver'].drop(); print('Dropped ExploitDB.')"

# Then run pipeline
python3 -m vulnerability_pipeline.pipeline_orchestrator --sources exploit --layer all
```

---

---

---

## 🎯 Smart CSV Ingestion & Enrichment

The system now includes an intelligent CSV handler that automatically transforms raw scanner exports (like Nessus) and enriches them with risk intelligence in real-time.

### 1. Features
*   **Automatic Transformation:** Detects raw Nessus CSVs and maps them to a consistent schema.
*   **Real-time Enrichment:** Fetches `vrr_score`, `threats`, and `weaknesses` (CWEs) from the Gold analytics layer.
*   **Full Data Retention:** Enriches every row in the file (no filtering), even if the risk score is 0.
*   **Clean Reporting:** Generates a prioritized `final_risk_report.json` and `.csv` for every upload.
*   **Audit Trail:** Stores enriched findings in a dedicated MongoDB collection: `vrr_risk_report`.

### 2. How to Run

The easiest way to use the system is through the `./local_run.sh` tool:

**A. Start the API Server:**
```bash
./local_run.sh api
```

**B. Directly Process a CSV (Standalone):**
Process, enrich, and save reports locally without starting the API.
```bash
./local_run.sh process ./data/Nessus.csv
```

**C. Sync Risk Intelligence to Atlas:**
Migrate your local 322k+ risk scores to the cloud for deployment enrichment.
```bash
./local_run.sh sync
```

**D. Full System Refresh (Scoring):**
Recalculate all 322k+ risk scores across all sources.
```bash
./local_run.sh all
```

---

A built-in tool is provided to migrate your local Risk Intelligence records to Atlas. 

**Run Migration via Runner:**
```bash
./local_run.sh sync
```

**Manual Execution (Advanced):**
```bash
# Sync specific risk tables only (Recommended for Free Tier)
python3 scripts/migration/targeted_atlas_sync.py

# Full DB Migration
python3 scripts/migration/copy_local_to_atlas.py --scope all
```

---

---

## 🚀 Deployment & API

The project includes a **FastAPI** backend for triggering analytics via HTTP and is Docker-ready for AWS App Runner.

### 1. Web API
Start the server locally:
```bash
uvicorn api.main:app --reload
```

**Endopint**: `POST /ingest`
- **File**: Upload a `silver_*.csv` file.
- **Form Data (Optional)**: `mongo_uri` (Connect to a specific client DB).

### 2. Docker
Build and run locally:
```bash
docker build -t vuln-backend .
docker run -p 8080:8080 --env-file .env vuln-backend
```

### 3. AWS App Runner (CI/CD)
The `.github/workflows/deploy.yml` pipeline automatically deploys to App Runner.
- **Requires**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` in GitHub Secrets.
- **Target**: Deploys to `vuln-info-backend` service.

---

## 🏗 Infrastructure as Code (Terraform)

Instead of relying on the pipeline to create resources, you can provision them cleanly using Terraform.

### 1. Initialize
```bash
cd terraform
terraform init
```

### 2. Provision
Creates ECR Repo, IAM Roles, and App Runner Service.
```bash
terraform apply
```

### 3. Connect to Pipeline
After provisioning, the GitHub Workflow will detect the existing `vuln-info-backend` service and simply update it with new code.

---

## 🔌 Extensibility Assessment

**Can this code be extended? YES.**

The system uses **Dynamic Discovery** (`pkgutil`). You do **not** need to modify the Orchestrator to add new sources.

### How to Add a New Source (e.g., "GitHub Advisories"):
1.  **Create Folder**: `vulnerability_pipeline/bronze/github_advisories/`
2.  **Implement**:
    *   `extract.py`: Class inheriting `BaseExtractor`. Logic to fetch from GitHub API.
    *   `load.py`: Class inheriting `BaseLoader`. Logic to save to Mongo.
3.  **Expose**: Create `__init__.py` exporting `Extractor`, `Loader`, and `INCREMENTAL_KEY`.
4.  **Run**: `python3 -m vulnerability_pipeline.pipeline_orchestrator`.
    *   *Result*: The orchestrator logs `Discovered Bronze source: github_advisories` and runs it automatically.

---

## ⚖️ Advantages vs Drawbacks

### ✅ Advantages
1.  **Modular & Scalable**: Adding sources touches NO existing code. It's safe and isolated.
2.  **Incremental Intelligence**: The "High Watermark" strategy ensures you don't re-download 20 years of data daily, saving bandwidth and time.
3.  **Data Lakehouse Power**: Storing raw data (Bronze) allows you to fix transformation bugs in Silver *without* re-fetching the original data.
4.  **Rich Data**: Custom scrapers (like ExploitDB) fetch data that isn't available in standard feeds (Screenshots, Verification status).

### ⚠️ Drawbacks
1.  **Initial Load Time**:
    *   NVD (API): Can take 1-2 hours initially due to rate limits.
    *   ExploitDB (Scraper): Scraping 46k pages takes **~12 hours** for a full fresh load (1s/page).
    *   *Mitigation*: Incremental runs take seconds. Use `SAFE_LIMIT` in `extract.py` for testing.
2.  **Scraper Fragility**:
    *   If Exploit-DB changes their HTML structure, the scraper (`extract.py`) will break and return `null` for fields like `verified`.
    *   *Mitigation*: The pipeline won't crash (caught exceptions), but data will be incomplete until code is updated.
3.  **Storage**: Storing both Raw and Silver duplicates data volume. (However, storage is cheap; compute/bandwidth is expensive).

---
*Built with ❤️ for Vulnerability Research.*