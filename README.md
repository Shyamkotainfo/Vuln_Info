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

You can run individual pipelines as modules. Ensure you are in the project root.

### Running Data Ingestion

**NVD Pipeline:**
```bash
python3 -m vulnerability_pipeline.datasources.external_feeds.nvd.nvd_main
```

**CISA KEV Pipeline:**
```bash
python3 -m vulnerability_pipeline.datasources.external_feeds.cisa.cisa_main
```

**EPSS Pipeline:**
```bash
python3 -m vulnerability_pipeline.datasources.external_feeds.epss.epss_main
```

**ExploitDB Pipeline:**
```bash
python3 -m vulnerability_pipeline.datasources.external_feeds.exploit.exploit_main
```

**Metasploit Pipeline:**
```bash
python3 -m vulnerability_pipeline.datasources.external_feeds.metasploit.metasploit_main
```

## 🔍 Verification

To verify that the project structure is valid and all dependencies are correctly installed, run:

```bash
python3 verify_structure.py
```