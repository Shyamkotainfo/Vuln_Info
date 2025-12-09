# Vulnerability Data Pipeline

A production-grade ETL pipeline designed to ingest, process, and analyze vulnerability data from multiple external sources. This project follows a **Data Lakehouse** architecture using MongoDB, processing data through Bronze (Raw), Silver (Cleaned), and Gold (Aggregated) layers.

## 🏗 Architecture

The pipeline currently implements the **Bronze Layer** ingestion for the following data sources:

| Source | Description | Collection Name |
|--------|-------------|-----------------|
| **NVD** | National Vulnerability Database CVEs | `nvd_cves_raw` |
| **CISA** | Known Exploited Vulnerabilities (KEV) | `cisa_kev_raw` |
| **EPSS** | Exploit Prediction Scoring System | `epss_scores_raw` |
| **ExploitDB** | Archive of public exploits | `exploitdb_archive_raw` |
| **Metasploit** | Penetration testing modules | `metasploit_modules_raw` |

## 📂 Project Structure

```
Vuln_Info/
├── vulnerability_pipeline/
│   ├── core/                    # Core configuration & utilities
│   │   ├── config.py
│   │   └── mongo_client.py
│   └── datasources/
│       └── external_feeds/      # Data ingestion modules
│           ├── cisa/
│           ├── epss/
│           ├── exploit/
│           ├── metasploit/
│           └── nvd/
├── requirements.txt             # Project dependencies
└── verify_structure.py          # Setup verification script
```

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- MongoDB instance (Local or Atlas)

### Installation

1. **Clone the repository** and navigate to the project root:
   ```bash
   cd Vuln_Info
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration

Create a `.env` file in the root directory if you need to override the default MongoDB URI:

```ini
MONGO_URI=mongodb://localhost:27017/
```

## 🏃 Usage
 
The recommended way to run the pipelines is via the `pipeline_orchestrator.py`. This script handles logging, error tracking, and unified execution.
 
### 1. Run All Pipelines (Full Load)
Fetches all data from scratch (or updates everything).
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator
```
 
### 2. Run All Pipelines (Incremental)
Only fetches data newer than what is currently in the database.
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator --mode incremental
```
 
### 3. Run Specific Sources
You can specify one or more sources to run: `nvd`, `cisa`, `epss`, `exploit`, `metasploit`.
 
**Example: NVD only**
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator --sources nvd
```
 
**Example: CISA and Metasploit (Incremental)**
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator --sources cisa metasploit --mode incremental
```
 
## 📊 Logging
 
Execution logs are saved to `pipeline.log` in the root directory.
- **Console Output**: Shows high-level progress and summaries (e.g., "100 inserted, 50 updated").
- **File Output**: Contains detailed debugging info and timestamps.
 
## 🔍 Verification
 
To verify that the project structure is valid and all dependencies are correctly installed, run:
 
```bash
python3 verify_structure.py
```