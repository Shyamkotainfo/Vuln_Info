# Vuln_info/csv_handler/uploader.py

import pandas as pd
import logging
import datetime
import hashlib
import os
import json
from pymongo import UpdateOne, MongoClient
import certifi

from vulnerability_pipeline.core.mongo_client import MongoManager
from vulnerability_pipeline.core.config import Config

# -------------------------------------------------------------------
# Logger
# -------------------------------------------------------------------
logger = logging.getLogger("CSVProcessor")
logging.basicConfig(level=logging.INFO)

# -------------------------------------------------------------------
class CSVProcessor:
    def __init__(self, mongo_uri: str = None):
        # 1. Target Database (where data goes)
        if mongo_uri:
            logger.info(f"💾 Target: Custom MongoDB {mongo_uri[:15]}...")
            is_local = "localhost" in mongo_uri or "127.0.0.1" in mongo_uri
            if is_local:
                self.client = MongoClient(mongo_uri, serverSelectionTimeoutMS=10000)
            else:
                self.client = MongoClient(mongo_uri, tls=True, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=10000)
            self.db = self.client[Config.DB_GOLD]
        else:
            logger.info("💾 Target: Default System MongoDB")
            self.client = MongoManager.get_client()
            self.db = self.client[Config.DB_GOLD]

        # 2. Intel Database (where Risk Intel comes from)
        # ALWAYS use system default for Intel lookup to ensure we find the 322k records
        self.intel_client = MongoManager.get_client()
        self.intel_db = self.intel_client[Config.DB_GOLD]
        
        self.collection = self.db["vrr_risk_report"]
        self.raw_collection = self.db["host_findings"]

    # -------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------
    def _generate_id(self, host, plugin_id):
        raw = f"{host}-{plugin_id}"
        return hashlib.md5(raw.encode()).hexdigest()

    @staticmethod
    def _normalize_cves(cve_str):
        return sorted({
            c.strip().upper()
            for c in str(cve_str).split(",")
            if c.strip().upper().startswith("CVE-")
        })

    # -------------------------------------------------------------------
    # Nessus Transformation
    # -------------------------------------------------------------------
    def _transform_nessus(self, df: pd.DataFrame) -> pd.DataFrame:
        logger.info("Transforming Nessus CSV")

        df.columns = [c.strip() for c in df.columns]
        out = pd.DataFrame()

        def pick_col(name, default=""):
            return df[name] if name in df.columns else pd.Series([default] * len(df))

        # ---------------------------------------------------------------
        # 1. Generate HostFindingsID
        # ---------------------------------------------------------------
        out["HostFindingsID"] = df.apply(
            lambda r: self._generate_id(
                str(r.get("Host", "")),
                str(r.get("Plugin ID", ""))
            ),
            axis=1
        )

        # ---------------------------------------------------------------
        # 2. Extract & Normalize CVEs
        # ---------------------------------------------------------------
        cve_col = df["CVE"].fillna("") if "CVE" in df.columns else pd.Series([""] * len(df))

        unique_cves = set()
        for row in cve_col:
            unique_cves.update(self._normalize_cves(row))

        logger.info(f"Found {len(unique_cves)} unique CVEs in CSV")

        # 3. Fetch Risk Intel from fct_final (System Database)
        intel_map = {}
        if unique_cves:
            # Diagnostics: Check if collection exists and has data
            coll_name = "fct_final"
            coll = self.intel_db[coll_name]
            count = coll.count_documents({})
            logger.info(f"🔍 Intel Stats: Collection '{coll_name}' exists in '{self.intel_db.name}' with {count} docs.")
            
            if count == 0:
                logger.warning(f"⚠️  Vulnerability Enrichment Gap: The collection '{coll_name}' is EMPTY in your database '{self.intel_db.name}'. Did you run 'calculate_facts.py'?")

            cursor = coll.find(
                {"cve_id": {"$in": list(unique_cves)}},
                {"_id": 0}
            )
            for doc in cursor:
                intel_map[doc["cve_id"]] = doc
        
        match_count = len(intel_map)
        logger.info(f"Risk Intel found for {match_count}/{len(unique_cves)} CVEs")

        # ---------------------------------------------------------------
        # 4. Enrichment Logic
        # ---------------------------------------------------------------
        def get_risk_data(cve_str):
            cves = self._normalize_cves(cve_str)
            if not cves:
                return 0.0, [], [], {}

            scores = []
            found_cves = set()
            all_cwes = set()
            all_threats = {}

            for cve in cves:
                intel = intel_map.get(cve)
                if not intel:
                    logger.warning(f"⚠️ No Risk Intel found in database for {cve}")
                    continue

                found_cves.add(cve)
                scores.append(intel.get("vrr_score", 0.0))

                threats = intel.get("threats", {})

                # ---- merge threats safely
                for k, v in threats.items():
                    if k not in all_threats:
                        all_threats[k] = set()
                    
                    if isinstance(v, list):
                        all_threats[k].update(v)
                    else:
                        all_threats[k].add(v)

                # ---- extract CWEs (anything containing CWE)
                for val in threats.values():
                    items = val if isinstance(val, list) else [val]
                    for x in items:
                        if isinstance(x, str) and "CWE-" in x:
                            all_cwes.add(x)

            # Convert sets to sorted lists or scalar if single
            final_threats = {}
            for k, v in all_threats.items():
                list_v = sorted(list(v)) if any(isinstance(x, (str, int, float)) for x in v) else list(v)
                final_threats[k] = list_v[0] if len(list_v) == 1 else list_v

            return (
                max(scores) if scores else 0.0,
                sorted(found_cves),
                sorted(all_cwes),
                final_threats
            )

        enrichment = cve_col.apply(get_risk_data)

        out["vrr_score"] = enrichment.apply(lambda x: x[0])
        out["vulnerabilities"] = enrichment.apply(lambda x: x[1])
        out["weaknesses"] = enrichment.apply(lambda x: x[2])
        out["threats"] = enrichment.apply(lambda x: x[3])

        # ---------------------------------------------------------------
        # 5. Standard Nessus Mappings
        # ---------------------------------------------------------------
        out["ScannerName"] = "Nessus"
        out["ScannerPluginID"] = pick_col("Plugin ID")
        out["VulnerabilityName"] = pick_col("Name")
        out["ScannerReportedSeverity"] = pick_col("Risk")
        out["ScannerSeverity"] = pick_col("CVSS")

        out["Description"] = (
            pick_col("Description").fillna("") +
            " " +
            pick_col("Synopsis").fillna("")
        ).str.strip()

        out["Status"] = "Open"
        out["Port"] = pick_col("Port")
        out["Protocol"] = pick_col("Protocol")
        out["PluginOutput"] = pick_col("Plugin Output")
        out["PossibleSolutions"] = pick_col("Solution")
        out["PossiblePatches"] = pick_col("See Also")
        out["IPAddress"] = pick_col("Host")

        # ---------------------------------------------------------------
        # 6. Junk Removal & Clean Reporting
        # ---------------------------------------------------------------
        total_rows = len(out)
        
        # Keeping all rows per user request
        out_clean = out.copy()
        
        # Move Risk Intel to the FRONT of the CSV for easier reading
        cols = out_clean.columns.tolist()
        risk_cols = ["vrr_score", "vulnerabilities", "weaknesses", "IPAddress", "VulnerabilityName", "ScannerReportedSeverity"]
        other_cols = [c for c in cols if c not in risk_cols]
        out_clean = out_clean[risk_cols + other_cols]

        # Save clean reports
        os.makedirs("data", exist_ok=True)
        base_dir = os.getcwd()
        csv_path = os.path.join(base_dir, "data", "final_risk_report.csv")
        json_path = os.path.join(base_dir, "data", "final_risk_report.json")
        
        out_clean.to_csv(csv_path, index=False)
        out_clean.to_json(json_path, orient="records", indent=4)
        
        # Terminal Summary Table
        summary_header = "\n" + "="*80 + "\n🛡️  ENRICHED VULNERABILITY REPORT SUMMARY\n" + "="*80 + "\n"
        summary_body = ""
        if not out_clean.empty:
            df_summary = out_clean[["ScannerPluginID", "vrr_score", "vulnerabilities", "IPAddress"]].head(10)
            summary_body = df_summary.to_string(index=False)
            if len(out_clean) > 10:
                summary_body += f"\n... and {len(out_clean)-10} more rows."
        else:
            summary_body = "No high-risk vulnerabilities found (VRR > 0)."
        
        full_summary = summary_header + summary_body + "\n" + "="*80 + "\n"
        print(full_summary)

        logger.info(f"📄 Clean Risk Report (CSV): {csv_path}")
        logger.info(f"📄 Clean Risk Report (JSON): {json_path}")

        # Store metadata for return
        self.last_report_metadata = {
            "summary": full_summary,
            "csv_path": csv_path,
            "json_path": json_path,
            "total_rows": total_rows
        }

        return out_clean

    # -------------------------------------------------------------------
    # Main CSV Processor
    # -------------------------------------------------------------------
    def process_csv(self, file_path: str):
        try:
            df = pd.read_csv(file_path)

            if "Plugin ID" in df.columns and "HostFindingsID" not in df.columns:
                logger.info("Detected raw Nessus CSV")
                df = self._transform_nessus(df)
            else:
                df.columns = [
                    c.strip().replace(" ", "").replace("/", "_").replace(".", "")
                    for c in df.columns
                ]
                if "HostFindingsID" not in df.columns:
                    raise ValueError("CSV missing HostFindingsID")

            records = df.to_dict(orient="records")

            ops = []
            for record in records:
                clean = {k: v for k, v in record.items() if pd.notna(v)}
                clean["last_updated"] = datetime.datetime.utcnow()

                ops.append(
                    UpdateOne(
                        {"HostFindingsID": clean["HostFindingsID"]},
                        {
                            "$set": clean,
                            "$unset": {
                                "VRRScore": "", 
                                "Threat": "", 
                                "Vulnerabilities": "", 
                                "Weaknesses": ""
                            }
                        },
                        upsert=True
                    )
                )

            if ops:
                result = self.collection.bulk_write(ops)
                logger.info(
                    f"🚀 CLEAN DATA LOADED TO MONGODB (collection: 'vrr_risk_report') | "
                    f"Count: {len(ops)}"
                )

            # Convert to JSON-safe dicts for API response (handles datetimes, NaNs, etc)
            json_safe_records = json.loads(df.to_json(orient="records", date_format="iso"))

            return {
                "status": "success", 
                "processed": len(ops), 
                "collection": "vrr_risk_report",
                "metadata": getattr(self, "last_report_metadata", {}),
                "data": json_safe_records
            }

        except Exception as e:
            logger.error(f"CSV processing failed: {e}")
            raise

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m csv_handler.uploader <csv_file> [mongo_uri]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    custom_uri = sys.argv[2] if len(sys.argv) > 2 else None
    
    processor = CSVProcessor(mongo_uri=custom_uri)
    try:
        processor.process_csv(file_path)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
