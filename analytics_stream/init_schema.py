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

from analytics_stream.definitions import THREAT_DEFINITIONS, VRR_DEFINITIONS

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

    # Assuming we use the default DB from URI or 'vuln_db'
    try:
        # If URI specifies a DB, use it, otherwise explicit Gold
        db = client.get_database()
        if db.name == "test": # Default if not specified
             return client["vulnerability_gold"]
        return db
    except:
        return client["vulnerability_gold"]

def init_schema():
    db = get_db()
    
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
            "weight": item["weight"], # Store verified weight in DB for transparency
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
