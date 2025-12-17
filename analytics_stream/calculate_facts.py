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
    def __init__(self, db):
        self.db = db
        # Cache source collections 
        self.sources = {
            alias: self.db[col_name] 
            for alias, col_name in COLLECTION_MAP.items()
        }

    def fetch_cve_data(self, cve_id: str) -> dict:
        data = {}
        for alias, col in self.sources.items():
            query = {"cve_id": cve_id}
            if alias == "CISA": query = {"cveID": cve_id}
            elif alias == "EPSS": query = {"cve": cve_id}
            
            doc = col.find_one(query) or {}
            data[alias] = doc
        return data

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
                val = rule["transform"](source_doc, rule["field"])
                if val: threats[key] = val
            except Exception:
                continue
        return threats

def process_batch(cve_ids, db):
    """Worker function (Thread Safe)"""
    calculator = FactCalculator(db)
    col_final = db.fct_final
    ops = []
    
    for cve in cve_ids:
        cve_data = calculator.fetch_cve_data(cve)
        vrr = calculator.calculate_score(cve_data)
        threat_vals = calculator.extract_threats(cve_data)
        
        record = {
            "cve_id": cve,
            "vrr_score": vrr,
            "threat_values": threat_vals,
            "date_added": datetime.utcnow()
        }
        ops.append(record)
    
    if ops:
        col_final.insert_many(ops)
        
    return len(ops)

def run_parallel():
    # 1. Setup Shared DB 
    db = get_db()
    primary_source = db["gold_nvd"]
    
    logger.info("Fetching CVE list...")
    cve_ids = primary_source.distinct("cve_id")
    total_cves = len(cve_ids)
    logger.info(f"Targeting {total_cves} CVEs.")
    
    # 2. Reset Target
    db.fct_final.drop()
    
    # 3. Batching
    BATCH_SIZE = 1000 # Can handle larger batches with threads
    batches = [cve_ids[i:i + BATCH_SIZE] for i in range(0, total_cves, BATCH_SIZE)]
    logger.info(f"Split into {len(batches)} batches.")
    
    # 4. Thread Execution
    workers = 10 # Threading can support higher concurrency than cores for I/O
    logger.info(f"Starting {workers} threads...")
    
    total_processed = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Submit task with shared DB object (MongoClient is thread safe)
        futures = [executor.submit(process_batch, batch, db) for batch in batches]
        
        for future in as_completed(futures):
            try:
                count = future.result()
                total_processed += count
                if total_processed % 5000 == 0:
                    logger.info(f"Progress: {total_processed}/{total_cves}")
            except Exception as e:
                logger.error(f"Batch failed: {e}")
                
    logger.info("Parallel Fact Calculation Complete.")

if __name__ == "__main__":
    run_parallel()
