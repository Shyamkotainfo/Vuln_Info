from datetime import datetime
from typing import List, Optional, Any
from dataclasses import dataclass, field
import uuid

# --- Dimensions ---

@dataclass
class DimVRR:
    """Vulnerability Master Dimension (Slowly Changing)"""
    vuln_id: str  # CVE ID
    vuln_category: str
    vuln_name: str
    date_added: datetime
    unique_id: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class DimWeakness:
    """Weakness Dimension (1:Many for CVE)"""
    vuln_id: str
    weakness_category: str
    weakness_name: str
    date_added: datetime
    unique_id: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class DimThreat:
    """Threat Dimension (1:Many for CVE)"""
    threat_id: str  # ID from source (e.g. ExploitDB ID)
    threat_category: str
    threat_name: str
    date_added: datetime
    unique_id: str = field(default_factory=lambda: str(uuid.uuid4()))

# --- Fact ---

@dataclass
class FctFinal:
    """Final Fact Table linking Dimensions"""
    cve_id: str
    vrr_score: float
    weakness_id: Optional[str] # FK to DimWeakness.unique_id
    threat_id: Optional[str]   # FK to DimThreat.unique_id
    date_added: datetime
