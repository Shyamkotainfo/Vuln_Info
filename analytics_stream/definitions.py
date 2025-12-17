from typing import Any, Dict, List, Optional, Callable

# =============================================================================
# TRANSFORMATION FUNCTIONS
# =============================================================================
# Reusable logic to extract/transform values from Gold Data
def xf_identity(doc: Dict, key: str) -> Any:
    return doc.get(key)

def xf_bool_exists(doc: Dict, key: str = None) -> bool:
    return bool(doc)

def xf_lowercase_in(doc: Dict, key: str, valid_list: List[str]) -> bool:
    val = str(doc.get(key, "")).lower()
    return val in [v.lower() for v in valid_list]

def xf_deep_get_cvss(doc: Dict, key: str = "metrics") -> float:
    try:
        # Custom logic for NVD nested structure
        return float(doc.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0.0))
    except:
        return 0.0

def xf_list_pluck(doc: Dict, key: str, subkey: str) -> List[Any]:
    # E.g. Extracting URLs from references list
    items = doc.get(key, [])
    # Defensive check: items might be strings or dicts
    valid_items = []
    for i in items:
        if isinstance(i, dict):
            val = i.get(subkey)
            if val: valid_items.append(val)
        elif isinstance(i, str) and subkey == "url":
             # Fallback: if it's a string, assume it's the url itself? 
             # Or just ignore str if looking for dict key?
             # Let's assume it might be the URL if it looks like one.
             valid_items.append(i) 
    return valid_items

def xf_cwe_extract(doc: Dict, key: str) -> List[str]:
    # Specific NVD Weakness extraction
    cwes = []
    for w in doc.get(key, []):
        if isinstance(w, dict):
            # Standard NVD Structure
            for desc in w.get("description", []):
                if desc.get("lang") == "en":
                    cwes.append(desc.get("value"))
        elif isinstance(w, str):
            # Flattened/Simple Structure
            cwes.append(w)
    return cwes

# =============================================================================
# DATA SOURCES MAP
# =============================================================================
COLLECTION_MAP = {
    "CISA": "gold_cisa",
    "NVD": "gold_nvd",
    "EPSS": "gold_epss",
    "ExploitDB": "gold_exploit",
    "Metasploit": "gold_metasploit"
}

# =============================================================================
# DIMENSION: THREATS (Metadata Attributes)
# =============================================================================
# Defines columns in the 'threat_values' object.
# Structure: (Category, Name, Source Collection Key, Source Field, Transform Func)
THREAT_DEFINITIONS = [
    # CISA
    {"category": "CISA", "name": "required_action", "source": "CISA", "field": "requiredAction", "transform": xf_identity},
    {"category": "CISA", "name": "known_ransomware_campaign_use", "source": "CISA", "field": "knownRansomwareCampaignUse", "transform": xf_identity},
    {"category": "CISA", "name": "product", "source": "CISA", "field": "product", "transform": xf_identity},
    {"category": "CISA", "name": "vendor_project", "source": "CISA", "field": "vendorProject", "transform": xf_identity},
    
    # EPSS
    {"category": "EPSS", "name": "epss_value", "source": "EPSS", "field": "epss", "transform": xf_identity},
    {"category": "EPSS", "name": "percentile", "source": "EPSS", "field": "percentile", "transform": xf_identity},
    
    # ExploitDB
    {"category": "ExploitDB", "name": "exploit_id", "source": "ExploitDB", "field": "exploit_id", "transform": xf_identity},
    {"category": "ExploitDB", "name": "type", "source": "ExploitDB", "field": "type", "transform": xf_identity},
    {"category": "ExploitDB", "name": "platform", "source": "ExploitDB", "field": "platform", "transform": xf_identity},
    
    # NVD
    {"category": "NVD", "name": "weaknesses", "source": "NVD", "field": "weaknesses", "transform": xf_cwe_extract},
    {"category": "NVD", "name": "references", "source": "NVD", "field": "references", "transform": lambda d, k: xf_list_pluck(d, k, "url")},
    
    # Metasploit
    {"category": "Metasploit", "name": "module_name", "source": "Metasploit", "field": "name", "transform": xf_identity},
    {"category": "Metasploit", "name": "type", "source": "Metasploit", "field": "type", "transform": xf_identity},
    {"category": "Metasploit", "name": "platform", "source": "Metasploit", "field": "platform", "transform": xf_identity},
]

# =============================================================================
# DIMENSION: VRR FACTORS (Scoring Logic)
# =============================================================================
# Defines factors for the Score Calculation.
# Structure: (Category, Name, Weight, Source, Logic Func returning Boolean/Float)
VRR_DEFINITIONS = [
    {
        "category": "CISA", "name": "CISA_KEV", 
        "weight": 30.0, 
        "source": "CISA",
        "logic": lambda doc: xf_bool_exists(doc)  # If record exists in CISA
    },
    {
        "category": "CISA", "name": "CISA_KNOWN_RANSOMWARE_USE", 
        "weight": 20.0, 
        "source": "CISA",
        "logic": lambda doc: xf_lowercase_in(doc, "knownRansomwareCampaignUse", ["Known", "Yes"])
    },
    {
        "category": "EPSS", "name": "EPSS", 
        "weight": 10.0, # Multiplier
        "source": "EPSS",
        "logic": lambda doc: float(doc.get("epss", 0) or 0) # Value * Weight
    },
    {
        "category": "ExploitDB", "name": "EXPLOIT_DB", 
        "weight": 10.0, 
        "source": "ExploitDB",
        "logic": lambda doc: xf_bool_exists(doc)
    },
    {
        "category": "Metasploit", "name": "METASPLOIT", 
        "weight": 10.0, 
        "source": "Metasploit",
        "logic": lambda doc: xf_bool_exists(doc)
    },
    {
        "category": "NVD", "name": "NVD_CVSS_3", 
        "weight": 0.5, # Multiplier (Score / 2)
        "source": "NVD",
        "logic": lambda doc: xf_deep_get_cvss(doc)
    }
]
