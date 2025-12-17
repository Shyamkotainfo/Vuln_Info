import pandas as pd
import logging
import datetime
import hashlib
from pymongo import UpdateOne
from vulnerability_pipeline.core.mongo_client import MongoManager
from vulnerability_pipeline.core.config import Config

# Setup Logger
logger = logging.getLogger("CSVProcessor")
logging.basicConfig(level=logging.INFO)

from pymongo import MongoClient
import certifi

# ... imports ...

class CSVProcessor:
    def __init__(self, mongo_uri: str = None):
        if mongo_uri:
            # Custom Connection Logic
            logger.info(f"Connecting to Custom Mongo URI: {mongo_uri[:15]}...")
            is_local = "localhost" in mongo_uri or "127.0.0.1" in mongo_uri
            if is_local:
                logger.info("⚠️ Custom URI: Localhost detected (No TLS).")
                self.client = MongoClient(mongo_uri, serverSelectionTimeoutMS=10000)
            else:
                logger.info("🌍 Custom URI: Atlas/Remote detected (TLS Enabled).")
                self.client = MongoClient(mongo_uri, tls=True, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=10000)
            
            # Assume 'vulnerability_gold' DB for consistency, or extract?
            # User requirement: "uload them in their mongodb".
            # We will default to 'vulnerability_gold' but this could be configurable.
            self.db = self.client[Config.DB_GOLD]
        else:
            # Default System Connection
            logger.info("Using Default System MongoDB Connection.")
            self.client = MongoManager.get_client()
            self.db = self.client[Config.DB_GOLD]
            
        self.collection = self.db["host_findings"]

    def _generate_id(self, host, plugin_id):
        """Generates deterministic ID based on Host and PluginID."""
        raw = f"{host}-{plugin_id}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _transform_nessus(self, df: pd.DataFrame) -> pd.DataFrame:
        """Applies Nessus-specific mapping logic."""
        out = pd.DataFrame()
        
        # Helper to safely get column
        def pick_col(name, default=""):
            return df[name] if name in df.columns else pd.Series([default] * len(df))

        # Mapping Logic
        out["HostFindingsID"] = df.apply(
            lambda r: self._generate_id(
                str(r.get("Host", "")), 
                str(r.get("Plugin ID", ""))
            ), axis=1
        )
        
        out["VRRScore"] = 0.0 # Placeholder
        out["ScannerName"] = "Nessus"
        
        out["ScannerPluginID"] = pick_col("Plugin ID")
        out["VulnerabilityName"] = pick_col("Name")
        out["ScannerReportedSeverity"] = pick_col("Risk")
        out["ScannerSeverity"] = pick_col("CVSS")
        
        # Combine Desc + Synopsis
        desc = pick_col("Description").fillna("")
        synopsis = pick_col("Synopsis").fillna("")
        out["Description"] = (desc + " " + synopsis).str.strip()
        
        # Status: Default to Open if missing/empty
        status_col = pick_col("Status").fillna("")
        out["Status"] = status_col.replace("", "Open")
        out["Port"] = pick_col("Port")
        out["Protocol"] = pick_col("Protocol")
        out["PluginOutput"] = pick_col("Plugin Output") # Might be missing
        out["PossibleSolutions"] = pick_col("Solution")
        out["PossiblePatches"] = pick_col("See Also")
        out["IPAddress"] = pick_col("Host")
        
        # Placeholders
        out["Vulnerabilities"] = "[]"
        out["Weaknesses"] = "[]"
        out["Threat"] = "{}"
        
        return out

    def process_csv(self, file_path: str):
        """
        Reads CSV, sanitizes headers, and upserts to MongoDB.
        """
        try:
            # 1. Read CSV
            df = pd.read_csv(file_path)
            
            # 2. Detect Format & Transform
            # If standard key "Plugin ID" exists but "HostFindingsID" doesn't, assume Nessus Raw
            if "Plugin ID" in df.columns and "HostFindingsID" not in df.columns and "Host Findings ID" not in df.columns:
                logger.info("Detected Raw Nessus Format. Applying Transformation.")
                df = self._transform_nessus(df)
            else:
                # Standard Logic: Sanitize Headers
                df.columns = [c.strip().replace(" ", "").replace("/", "_").replace(".", "") for c in df.columns]
                
                # Check for ID
                if "HostFindingsID" not in df.columns:
                     if "HostFindingsID" not in df.columns:
                        raise ValueError("CSV missing 'Host Findings ID' column.")
            
            # 3. Convert to Dicts
            records = df.to_dict(orient="records")
            
            # 4. Bulk Upsert
            ops = []
            for record in records:
                # Clean NaNs
                clean_record = {k: v for k, v in record.items() if pd.notna(v)}
                clean_record["last_updated"] = datetime.datetime.utcnow()
                
                ops.append(
                    UpdateOne(
                        {"HostFindingsID": clean_record["HostFindingsID"]},
                        {"$set": clean_record},
                        upsert=True
                    )
                )
                
            if ops:
                result = self.collection.bulk_write(ops)
                logger.info(f"Processed {len(ops)} records. Upserted: {result.upserted_count}, Modified: {result.modified_count}")
                return {"status": "success", "processed": len(ops), "upserted": result.upserted_count}
            
            return {"status": "success", "processed": 0}
            
        except Exception as e:
            logger.error(f"Error processing CSV: {e}")
            raise e
