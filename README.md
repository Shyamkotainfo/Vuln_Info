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

## 📂 Project Structure

```text
Vuln_Info/
├── vulnerability_pipeline/
│   ├── core/                    # Core framework (Config, DB Connection, Base Classes)
│   ├── bronze/                  # Bronze Layer Plugins
│   │   ├── nvd/                 # NVD Source (extract.py, load.py, __init__.py)
│   │   ├── cisa/                # CISA Source
│   │   ├── exploit/             # ExploitDB Source (Scraper logic here)
│   │   └── ...
│   ├── silver/                  # Silver Layer Plugins
│   │   ├── nvd/                 # NVD Transformation (etl.py)
│   │   └── ...
│   ├── gold/                    # Gold Layer
│   │   ├── mirrors/             # Source mirrors (nvd, cisa, etc.)
│   │   └── mapping_config.py    # Column filters & factor definitions
│   └── pipeline_orchestrator.py # Main entry point (Dynamic Discovery System)
├── requirements.txt             # Dependencies
└── pipeline.log                 # Execution logs
```

---

## 🚀 Getting Started

### Prerequisites
*   Python 3.8+
*   MongoDB (Local `localhost:27017` or Atlas)

### Installation

1.  **Clone & Enter:**
    ```bash
    cd Vuln_Info
    ```
2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configure Environment (Optional):**
    Create `.env` if using a custom MongoDB URI or NVD API Key (Recommended for speed).
    ```ini
    MONGO_URI=mongodb://localhost:27017/
    NVD_API_KEY=your_api_key_here
    ```

---

## 🏃 Usage Examples

The `pipeline_orchestrator` is your main tool. It automatically handles incremental loading.

### 1. Run Everything (Standard Daily Job)
Runs all Bronze extractors, then Silver transformers, then Gold aggregators.
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator
```

### 2. Run Specific Sources
Useful if you only want to update NVD.
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator --sources nvd
```
*Run multiple:*
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator --sources cisa metasploit
```

### 3. Run Specific Layers
If you just want to re-process Silver without re-fetching data (e.g., after changing transformation logic).
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator --layer silver
```
*Run only Bronze:*
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator --layer bronze
```
*Run only Gold:*
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator --layer gold
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

## ☁️ Migrating to Atlas

A built-in tool is provided to migrate your Local data to MongoDB Atlas.

### 1. Setup
Ensure your `.env` file has both URIs:
```ini
LOCAL_MONGO_URI=mongodb://localhost:27017/
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/
```

### 2. Run Migration
Use the `copy_local_to_atlas.py` script.

**Copy All Data:**
```bash
python3 copy_local_to_atlas.py --scope all
```

**Copy Only Gold Layer:**
```bash
python3 copy_local_to_atlas.py --scope gold
```

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