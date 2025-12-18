# Vuln_info/csv_handler/enricher.py

import pandas as pd
import os
import logging
from pymongo import MongoClient
from dotenv import load_dotenv
import certifi

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CSVTransformer")

class CSVEnricher:
    def __init__(self, mongo_uri=None):
        load_dotenv()
        self.uri = mongo_uri or os.getenv("MONGO_URI")
        self.db_name = "vulnerability_gold"
        self.client = None
        self.db = None
        self._connect()

    def _connect(self):
        try:
            is_local = "localhost" in self.uri or "127.0.0.1" in self.uri
            if is_local:
                self.client = MongoClient(self.uri)
            else:
                self.client = MongoClient(self.uri, tls=True, tlsCAFile=certifi.where())
            self.db = self.client[self.db_name]
            logger.info(f"Connected to MongoDB: {self.db_name}")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise

    def enrich_csv(self, input_csv_path, output_csv_path=None, cve_column="CVE"):
        """
        Reads a CSV, looks up each CVE in fct_final, and adds vrr_score and threats.
        """
        if not os.path.exists(input_csv_path):
            logger.error(f"Input file not found: {input_csv_path}")
            return None

        # 1. Read Input CSV
        df = pd.read_csv(input_csv_path)
        logger.info(f"Read {len(df)} rows from {input_csv_path}")

        if cve_column not in df.columns:
            # Try to be smart if the user didn't specify the right column
            possible_names = ["CVE", "cve", "CVE ID", "cve_id", "Vulnerability ID"]
            for name in possible_names:
                if name in df.columns:
                    cve_column = name
                    break
            else:
                logger.error(f"Could not find CVE column. Available: {list(df.columns)}")
                return None

        # 2. Extract Unique CVEs for lookup
        unique_cves = df[cve_column].dropna().unique().tolist()
        logger.info(f"Looking up {len(unique_cves)} unique CVEs in database...")

        # 3. Fetch data from fct_final
        # We fetch only what we need to keep it fast
        cursor = self.db.fct_final.find(
            {"cve_id": {"$in": unique_cves}},
            {"cve_id": 1, "vrr_score": 1, "threats": 1, "_id": 0}
        )
        enrichment_data = {doc["cve_id"]: doc for doc in cursor}
        logger.info(f"Found match for {len(enrichment_data)} CVEs.")

        # 4. Apply Enrichment
        def get_score(cve):
            return enrichment_data.get(cve, {}).get("vrr_score", 0.0)

        def get_threats(cve):
            # Flatten threats into a single string for CSV compatibility
            threats_dict = enrichment_data.get(cve, {}).get("threats", {})
            if not threats_dict: return ""
            return "; ".join([f"{k}: {v}" for k, v in threats_dict.items()])

        df["vrr_score"] = df[cve_column].apply(get_score)
        df["threat_intel"] = df[cve_column].apply(get_threats)

        # 5. Output
        if output_csv_path:
            df.to_csv(output_csv_path, index=False)
            logger.info(f"Enriched CSV saved to: {output_csv_path}")
        
        return df

    def upload_to_collection(self, df, collection_name):
        """Uploads the enriched dataframe to a specified collection."""
        if df is None: return
        
        records = df.to_dict(orient="records")
        if not records:
            logger.warning("No records to upload.")
            return

        col = self.db[collection_name]
        # Using insert_many for simplicity, or could use bulk upsert
        col.delete_many({}) # Clear old data if requested or just append? Let's append
        col.insert_many(records)
        logger.info(f"Uploaded {len(records)} enriched records to {collection_name}")

if __name__ == "__main__":
    # Example usage:
    # enricher = CSVEnricher()
    # df = enricher.enrich_csv("data/Nessus 1.csv", "data/Nessus_Enriched.csv", cve_column="CVE")
    # enricher.upload_to_collection(df, "enriched_host_findings")
    pass
