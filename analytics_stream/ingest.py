import csv
import logging
import ast
from datetime import datetime
from typing import List, Dict, Tuple
from vulnerability_pipeline.core.mongo_client import MongoManager
from analytics_stream.schema_models import DimVRR, DimWeakness, DimThreat, FctFinal

logger = logging.getLogger("analytics.ingest")

class AnalyticsLoader:
    def __init__(self):
        self.db = MongoManager.get_gold_db() # Storing analytics in Gold DB
        self.col_dim_vrr = self.db["dim_vrr"]
        self.col_dim_weakness = self.db["dim_weakness"]
        self.col_dim_threat = self.db["dim_threat"]
        self.col_fct_final = self.db["fct_final"]
        
        # In-memory cache for UUID lookups during run
        self.vrr_cache = {}      # cve_id -> unique_id
        self.weakness_cache = {} # (cve_id, weakness_name) -> unique_id
        self.threat_cache = {}   # threat_id -> unique_id

    def load_file(self, file_path: str):
        logger.info(f"Loading analytics from {file_path}")
        
        # 1. Read Data
        rows = []
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
        
        logger.info(f"Read {len(rows)} rows. Processing Dimensions...")
        
        # 2. Process Dimensions
        self._process_dim_vrr(rows)
        self._process_dim_weakness(rows)
        self._process_dim_threat(rows)
        
        # 3. Process Facts
        logger.info("Processing Fact Table...")
        self._process_facts(rows)
        
        logger.info("Analytics Load Complete.")

    def _get_existing_vrr_ids(self) -> Dict[str, str]:
        """Load existing CVE->UUID map from DB"""
        return {d['vuln_id']: d['unique_id'] for d in self.col_dim_vrr.find({}, {'vuln_id': 1, 'unique_id': 1})}

    def _process_dim_vrr(self, rows):
        """Load DimVRR: One record per CVE"""
        existing_map = self._get_existing_vrr_ids()
        new_records = []
        
        # Update cache with existing
        self.vrr_cache.update(existing_map)
        
        processed_cves = set()

        for row in rows:
            cve_id = row.get('cveID') or row.get('cve_id')
            if not cve_id or cve_id in self.vrr_cache or cve_id in processed_cves:
                continue
            
            # Create New Dim
            dim = DimVRR(
                vuln_id=cve_id,
                vuln_category="General", # Logic to determine category if needed
                vuln_name=row.get('vulnerabilityName', 'Unknown'),
                date_added=self._parse_date(row.get('dateAdded'))
            )
            
            new_records.append(dim.__dict__)
            self.vrr_cache[cve_id] = dim.unique_id
            processed_cves.add(cve_id)
            
        if new_records:
            self.col_dim_vrr.insert_many(new_records)
            logger.info(f"Inserted {len(new_records)} new DimVRR records.")

    def _process_dim_weakness(self, rows):
        """Load DimWeakness: Explode 'cwes' array"""
        # Cache key: (vuln_id, weakness_name)
        # Pre-load existing (Optimized: could build index-based lookup, doing full scan for prototype)
        existing = set()
        for d in self.col_dim_weakness.find({}, {'vuln_id': 1, 'weakness_name': 1}):
            existing.add((d['vuln_id'], d['weakness_name']))
            
        new_records = []
        
        for row in rows:
            cve_id = row.get('cveID') or row.get('cve_id')
            cwes_str = row.get('cwes', '[]')
            try:
                cwes = ast.literal_eval(cwes_str) if cwes_str.startswith('[') else [cwes_str]
            except:
                cwes = []

            for cwe in cwes:
                if (cve_id, cwe) in existing:
                    # Retrieve ID logic missing here for existing facts, but for clean load ok.
                    # For simple prototype, we query DB for ID if needed, 
                    # but for Fact gen we need to know the ID.
                    # Let's simple cache ALL unique_ids for simplicity in this version.
                    continue
                
                dim = DimWeakness(
                    vuln_id=cve_id,
                    weakness_category="CWE",
                    weakness_name=cwe,
                    date_added=self._parse_date(row.get('dateAdded'))
                )
                new_records.append(dim.__dict__)
                existing.add((cve_id, cwe))

        if new_records:
            self.col_dim_weakness.insert_many(new_records)
            logger.info(f"Inserted {len(new_records)} new DimWeakness records.")
            
        # Re-build FULL cache for Fact Generation
        self.weakness_cache = {
            (d['vuln_id'], d['weakness_name']): d['unique_id'] 
            for d in self.col_dim_weakness.find()
        }

    def _process_dim_threat(self, rows):
        """Load DimThreat: Explode threats logic (Source specific mock)"""
        # Mocking logic: Treating 'knownRansomwareCampaignUse' != Unknown as a threat
        # Real logic would depend on 'threats' column in Silver. Assuming it exists or derived.
        
        # Using 'knownRansomwareCampaignUse' as a proxy for a threat for now if 'threats' not in CSV
        pass # User logic said "explode(s.threats)", assuming column exists.
        
        # Simple implementation assuming 'threats' column is list of dicts or strings
        # Adjust based on actual CSV content inspection later.

    def _process_facts(self, rows):
        """Generate FctFinal"""
        msg_buffer = []
        
        for row in rows:
            cve_id = row.get('cveID') or row.get('cve_id')
            date_added = self._parse_date(row.get('dateAdded'))
            
            # VRR Score (Mock or from file)
            vrr_score = float(row.get('vrr_score', 0.0)) 
            
            # Links
            # Weaknesses (Many-to-Many flattened? User star schema implies 1 row per FK combo?)
            # User Model: "fct_final: weakness_id string". 
            # This implies FctFinal grain is (CVE x Weakness x Threat). 
            # If CVE has 2 weaknesses, we get 2 Fact rows? 
            # Re-reading user request: "Grain: 1 row per CVE per date_added"
            # BUT "weakness_id string FK". 
            # If a CVE has multiple weaknesses, a single FK column can't hold them unless grain expands.
            # OR we pick "Primary Weakness".
            # User said "One CVE -> many weaknesses -> 1 row per weakness" for DimWeakness.
            # User said FctFinal has "weakness_id".
            
            # FOR PRESERVING GRAIN "1 row per CVE":
            # We likely pick the FIRST weakness or NULL. 
            # OR the user intends FctFinal to explode.
            # "INSERT INTO fct_final ... LEFT JOIN dim_weakness" -> This creates explosion (1 row per CVE-Weakness pair).
            # So grain becomes CVE + Weakness.
            
            cwes_str = row.get('cwes', '[]')
            try:
                cwes = ast.literal_eval(cwes_str) if cwes_str.startswith('[') else [cwes_str]
            except:
                cwes = []
            
            if not cwes: cwes = [None] # Ensure at least one row
            
            for cwe in cwes:
                weakness_id = self.weakness_cache.get((cve_id, cwe)) if cwe else None
                
                # Similar logic for threats
                threats = [None] # Placeholder
                
                for threat in threats:
                    fact = FctFinal(
                        cve_id=cve_id,
                        vrr_score=vrr_score,
                        weakness_id=weakness_id,
                        threat_id=None, # Placeholder
                        date_added=date_added
                    )
                    
                    # Insert Fact (No caching needed unless deduping facts)
                    self.col_fct_final.insert_one(fact.__dict__)

    def _parse_date(self, date_str):
        if not date_str: return datetime.utcnow()
        try:
            return datetime.fromisoformat(str(date_str).replace('Z', '+00:00'))
        except:
            return datetime.utcnow()
