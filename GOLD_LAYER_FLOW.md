# Gold Layer Pipeline Flow

## What Happens When You Run `--layer gold`

### Phase 1: Gold Mirrors (Silver → Gold Source Tables)
**Duration**: ~1-2 minutes per source

For each source (nvd, cisa, epss, exploit, metasploit):
1. **Read** all documents from Silver collection (e.g., `nvd_silver`)
2. **Filter** columns based on `gold/mapping_config.py`:
   - `include`: Only keep specified columns
   - `exclude`: Drop specified columns
   - `manual`: Add custom static columns
3. **Write** to Gold mirror (e.g., `gold_nvd`)

**Example**: If you have 200K NVD records in Silver, all 200K get copied to `gold_nvd` with filtered columns.

### Phase 2: Gold Aggregates (Gold Mirrors → Dimensional Tables)
**Duration**: ~2-5 minutes total

For each dimensional table (vrr, threats, vulnerabilities, weaknesses):
1. **Read** from configured Gold mirrors
2. **Extract** factors defined in `mapping_config.py`
3. **Transform** into long-format rows:
   - One CVE with 3 factors → 3 rows in dimensional table
4. **Write** to aggregate collection

**Example VRR Transformation**:
```
Input (gold_nvd):
{
  "id": "CVE-2021-44228",
  "metrics_cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]
}

Output (gold_vrr):
[
  {
    "cve_id": "CVE-2021-44228",
    "factor_name": "cvss_v3_score",
    "value": 10.0,
    "category": "Base Severity",
    "static_or_dynamic": "Dynamic",
    "source": "nvd"
  }
]
```

## Current Configuration

### VRR Factors (Risk Calculation)
- **NVD**: `cvss_v3_score`, `cvss_v2_score`
- **EPSS**: `epss_probability`, `epss_percentile`
- **CISA**: `in_kev` (boolean)
- **Exploit**: `exploit_verified` (boolean)

### Threat Factors (Threat Intelligence)
- **CISA**: `kev_listed`
- **EPSS**: `score`
- **Exploit**: `has_public_exploit`
- **Metasploit**: `has_metasploit_module`

### Vulnerability Factors (Metadata)
- **NVD**: `description`, `published_date`, `last_modified`
- **CISA**: `short_description`

### Weakness Factors (CWE)
- **NVD**: `primary_cwe`

## Expected Output (Current Data)

Based on your current Silver data:
- **Gold Mirrors**: 5 collections, ~240K total documents
- **Gold VRR**: ~39K rows (1 row per CVE per factor)
- **Gold Threats**: ~39K rows
- **Gold Vulnerabilities**: ~0 rows (NVD/CISA not in Gold yet)
- **Gold Weaknesses**: ~0 rows (NVD not in Gold yet)

## Next Steps

To populate all Gold tables:
```bash
# Run full pipeline for all sources
python3 -m vulnerability_pipeline.pipeline_orchestrator --layer all
```

This will:
1. Update Bronze (incremental)
2. Update Silver (incremental)
3. **Rebuild Gold** (full sync from Silver)

**Note**: Gold layer always does a full sync because it's fast (no API calls, just MongoDB reads/writes).
