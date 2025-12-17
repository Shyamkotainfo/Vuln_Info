# Analytics Stream: VRR & Threat Intelligence

This directory contains the Dimensional Modeling pipeline for the Vulnerability Risk Rating (VRR) system.

## Architecture

The system uses a **Configuration-Driven Dimensional Model**:

1.  **Definitions (init_schema.py)**:
    *   `dim_vrr`: Defines *which* factors contribute to the score (e.g., "CISA_KEV", "NVD_CVSS_3").
    *   `dim_threats`: Defines *which* attributes are tracked (e.g., "CISA_product", "EPSS_score").
    
2.  **Calculation (calculate_facts.py)**:
    *   Reads the definitions.
    *   Queries `gold_*` collections.
    *   Calculates Scores and Aggregates Metadata.
    *   Populates `fct_final`.

## Collections

### `dim_vrr` (Config)
| Column | Description |
|--------|-------------|
| `category` | Source (CISA, NVD, etc.) |
| `name` | Factor Name (e.g., CISA_KEV) |

### `dim_threats` (Config)
| Column | Description |
|--------|-------------|
| `category` | Source (CISA, ExploitDB, etc.) |
| `name` | Attribute Name (e.g., required_action, platform) |

### `fct_final` (Output)
| Column | Description |
|--------|-------------|
| `cve_id` | Unique Vulnerability ID |
| `vrr_score` | Calculated Risk Score (0-100) |
| `threat_values` | Computed attributes from dim_threats |
| `date_added` | Calculation Timestamp |

## Usage

1.  **Initialize Schema**:
    ```bash
    python3 analytics_stream/init_schema.py
    ```
2.  **Run Calculation**:
    ```bash
    python3 analytics_stream/calculate_facts.py
    ```
