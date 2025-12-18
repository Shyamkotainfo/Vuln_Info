#Vuln_info/analytics_stream/calculate_facts.py

import logging
import os
import sys
import certifi
from datetime import datetime
from pymongo import MongoClient, UpdateOne
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup Path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analytics_stream.definitions import (
    THREAT_DEFINITIONS, VRR_DEFINITIONS, COLLECTION_MAP
)

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(threadName)s - %(message)s')
logger = logging.getLogger("FactCalc")

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

def get_db():
    uri = os.getenv("MONGO_URI")
    if not uri:
        # Fallback or error
        return None
        
    is_local = "localhost" in uri or "127.0.0.1" in uri
    
    if is_local:
        client = MongoClient(uri, maxPoolSize=100) # Ensure pool is large enough for threads
    else:
        client = MongoClient(uri, tls=True, tlsCAFile=certifi.where(), maxPoolSize=100)
    
    try:
        db = client.get_database()
        if db.name == "test": return client["vulnerability_gold"]
        return db
    except:
        return client["vulnerability_gold"]

class FactCalculator:
    def __init__(self, cache: dict):
        self.cache = cache

    def get_cve_data(self, cve_id: str) -> dict:
        """Fetch from memory cache instead of DB"""
        return {
            alias: self.cache.get(alias, {}).get(cve_id, {})
            for alias in COLLECTION_MAP.keys()
        }

    def calculate_score(self, cve_data: dict) -> float:
        score = 0.0
        for rule in VRR_DEFINITIONS:
            source_doc = cve_data.get(rule["source"], {})
            try:
                raw_val = rule["logic"](source_doc)
                if isinstance(raw_val, bool):
                    if raw_val: score += rule["weight"]
                elif isinstance(raw_val, (int, float)):
                    score += raw_val * rule["weight"]
            except Exception:
                continue
        return round(score, 2)

    def extract_threats(self, cve_data: dict) -> dict:
        threats = {}
        for rule in THREAT_DEFINITIONS:
            source_doc = cve_data.get(rule["source"], {})
            key = f"{rule['category']}_{rule['name']}"
            try:
                # Definitions use transform(doc, field)
                val = rule["transform"](source_doc, rule["field"])
                if val: threats[key] = val
            except Exception:
                continue
        return threats

def load_all_metadata(db) -> dict:
    """Pre-load auxiliary collections into memory for O(1) lookup"""
    cache = {}
    
    # CISA
    logger.info("Caching CISA data...")
    cache["CISA"] = {doc["cve_id"]: doc for doc in db.gold_cisa.find() if "cve_id" in doc}
    
    # EPSS
    logger.info("Caching EPSS data (300k+ records)...")
    epss_cache = {}
    count = 0
    for doc in db.gold_epss.find():
        if "cve" in doc:
            epss_cache[doc["cve"]] = doc
            count += 1
            if count % 50000 == 0:
                logger.info(f"  Downloaded {count} EPSS records...")
    cache["EPSS"] = epss_cache
    
    # ExploitDB (codes is a list)
    logger.info("Caching ExploitDB data...")
    xdb = {}
    count = 0
    for doc in db.gold_exploit.find({"codes": {"$exists": True}}):
        for cve in doc.get("codes", []):
            xdb[cve] = doc
        count += 1
        if count % 10000 == 0:
            logger.info(f"  Cached {count} ExploitDB records...")
    cache["ExploitDB"] = xdb
    
    # Metasploit (references is a list)
    logger.info("Caching Metasploit data...")
    msf = {}
    for doc in db.gold_metasploit.find({"references": {"$exists": True}}):
        for ref in doc.get("references", []):
            if ref.startswith("CVE-"):
                msf[ref] = doc
    cache["Metasploit"] = msf
    
    logger.info("Warm-up Complete. Memory cache ready.")
    return cache

def process_batch(nvd_batch, cache, db):
    """Worker function (Thread Safe since it uses shared cache read-only)"""
    calculator = FactCalculator(cache)
    ops = []
    
    for nvd_doc in nvd_batch:
        cve_id = nvd_doc.get("cve_id")
        if not cve_id: continue
        
        # Merge NVD doc into the cve_data mapping
        cve_data = calculator.get_cve_data(cve_id)
        cve_data["NVD"] = nvd_doc
        
        vrr = calculator.calculate_score(cve_data)
        threat_vals = calculator.extract_threats(cve_data)
        
        record = {
            "cve_id": cve_id,
            "vrr_score": vrr,
            "threats": threat_vals,
            "date_added": datetime.utcnow()
        }
        ops.append(record)
    
    if ops:
        db.fct_final.insert_many(ops)
    return len(ops)

def run_optimized():
    db = get_db()
    if db is None:
        logger.error("Could not connect to database.")
        return

    # 1. Warm up cache
    start_time = datetime.now()
    cache = load_all_metadata(db)
    
    # 2. Reset Target
    db.fct_final.drop()
    db.fct_final.create_index("cve_id", unique=True)
    
    # 3. Stream NVD and process in batches
    logger.info("Streaming NVD records...")
    total_processed = 0
    batch = []
    BATCH_SIZE = 5000
    
    # Estimate total for progress
    total_to_do = db.gold_nvd.count_documents({})
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        
        # Use a cursor to avoid loading all 322k NVD docs at once
        cursor = db.gold_nvd.find({})
        
        for doc in cursor:
            batch.append(doc)
            if len(batch) >= BATCH_SIZE:
                futures.append(executor.submit(process_batch, batch, cache, db))
                batch = []
                
                # Housekeeping on futures to avoid memory bloat
                if len(futures) > 20:
                    for f in as_completed(futures):
                        total_processed += f.result()
                        futures.remove(f)
                        if total_processed % 10000 == 0:
                            logger.info(f"Progress: {total_processed}/{total_to_do}")
                        break

        # Final batch
        if batch:
            futures.append(executor.submit(process_batch, batch, cache, db))

        # Wait for remaining
        for f in as_completed(futures):
            total_processed += f.result()
            if total_processed % 10000 == 0:
                logger.info(f"Progress: {total_processed}/{total_to_do}")

    duration = datetime.now() - start_time
    logger.info(f"Optimization Complete! Processed {total_processed} CVEs in {duration.total_seconds():.2f}s")

if __name__ == "__main__":
    run_optimized()
