# Vuln_info/analytics_stream/init_schema.py
import os
import datetime
from pymongo import MongoClient
import certifi
from dotenv import load_dotenv
import logging

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("InitSchema")

import logging
import sys

# Setup Path to allow imports from parent/sibling
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analytics_stream.definitions import THREAT_DEFINITIONS, VRR_DEFINITIONS, COLLECTION_MAP

# Load Environment
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

def get_db():
    uri = os.getenv("MONGO_URI")
    if not uri:
        raise RuntimeError("MONGO_URI not found in .env")
        
    # Check for local connection to avoid SSL errors
    is_local = "localhost" in uri or "127.0.0.1" in uri
    
    if is_local:
        client = MongoClient(uri) # No TLS for local
    else:
        client = MongoClient(uri, tls=True, tlsCAFile=certifi.where())

    try:
        # If URI specifies a DB, use it, otherwise explicit Gold
        db = client.get_database()
        if db.name == "test": # Default if not specified
             db = client["vulnerability_gold"]
        logger.info(f"Using database: {db.name}")
        return db
    except:
        logger.info("Using fallback database: vulnerability_gold")
        return client["vulnerability_gold"]

def validate_definitions(db):
    """Checks if defined fields exist in at least one document in Gold collections."""
    logger.info("🔍 Validating definitions against Gold collections...")
    
    errors = []
    
    # Combined check for THREAT and VRR
    all_defs = THREAT_DEFINITIONS + VRR_DEFINITIONS
    
    # Memoize collection field checks to avoid redundant DB hits
    collection_fields = {} # col_name -> set of keys

    for item in all_defs:
        alias = item["source"]
        col_name = COLLECTION_MAP.get(alias)
        field_input = item.get("field")
        if not field_input: continue

        # Handle list of fields (e.g. for NVD metrics)
        fields_to_check = [field_input] if isinstance(field_input, str) else field_input

        for field in fields_to_check:
            if col_name not in collection_fields:
                collection_fields[col_name] = set()

            # Try to find a document that HAS this field to verify it exists in the schema
            sample = db[col_name].find_one({field: {"$exists": True}})
            if sample:
                collection_fields[col_name].add(field)
            else:
                # If even searching for it returns None, it really doesn't exist
                errors.append(f"Field '{field}' (Source: {alias}) missing/empty in ALL records of '{col_name}'")

    if errors:
        logger.error("❌ Schema Validation Failed!")
        for err in errors:
            logger.error(f"  - {err}")
        raise RuntimeError("Configuration Mismatch: Defined fields do not exist in MongoDB Gold tables.")
    
    logger.info("✅ Schema Validation Passed.")

def init_schema():
    db = get_db()
    
    # Run Validation first
    validate_definitions(db)
    
    # ==========================================
    # 1. dim_threats (Reference Definitions)
    # ==========================================
    logger.info("Initializing dim_threats...")
    col_threats = db["dim_threats"]
    col_threats.drop()
    threat_records = []
    for item in THREAT_DEFINITIONS:
        threat_records.append({
            "category": item["category"],
            "name": item["name"],
            "field": item["field"],
            "source_collection": COLLECTION_MAP.get(item["source"]),
            "date_added": datetime.datetime.utcnow()
        })
    
    col_threats.insert_many(threat_records)
    logger.info(f"Inserted {len(threat_records)} records into dim_threats.")

    # ==========================================
    # 2. dim_vrr (Reference Factors)
    # ==========================================
    logger.info("Initializing dim_vrr...")
    col_vrr = db["dim_vrr"]
    col_vrr.drop()
    
    # Load from Config
    vrr_records = []
    for item in VRR_DEFINITIONS:
        vrr_records.append({
            "category": item["category"],
            "name": item["name"],
            "field": item.get("field"),
            "weight": item["weight"], # Store verified weight in DB for transparency
            "source_collection": COLLECTION_MAP.get(item["source"]),
            "date_added": datetime.datetime.utcnow()
        })
    
    col_vrr.insert_many(vrr_records)
    logger.info(f"Inserted {len(vrr_records)} records into dim_vrr.")

    # ==========================================
    # 3. fct_final (Structure Only)
    # ==========================================
    # We don't insert data here yet, just ensure the collection exists/is clean if needed
    # User said "whenever it runs, it will create these tables"
    logger.info("Initializing fct_final...")
    col_final = db["fct_final"]
    
    # Optional: Create Indexes
    col_final.create_index("cve_id")
    col_final.create_index("threat_sk") # If we link back
    
    logger.info("Schema Initialization Complete.")

if __name__ == "__main__":
    init_schema()
