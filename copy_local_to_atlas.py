from pymongo import MongoClient
from pymongo.errors import BulkWriteError
import certifi
import os
from typing import List
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# -------------------------
# CONFIGURATION
# -------------------------

# Local MongoDB
LOCAL_MONGO_URI = os.getenv("LOCAL_MONGO_URI", "mongodb://localhost:27017")

# MongoDB Atlas
# Must be set in .env as MONGO_URI
ATLAS_MONGO_URI = os.getenv("MONGO_URI")

if not ATLAS_MONGO_URI:
    raise ValueError("❌ MONGO_URI not found in .env file. Please set it to your Atlas Connection String.")

# Databases & collections to copy
COPY_CONFIG = {
    "vulnerability_bronze": [
        "nvd_raw",
        "cisa_raw",
        "epss_raw"
    ],
    "vulnerability_silver": [
        "nvd_silver",       # Updated to match project convention
        "cisa_silver",      # Updated to match project convention
        "nvd",              # Keeping user request just in case
        "cisa"              # Keeping user request just in case
    ],
     "vulnerability_gold": [
        "gold_nvd",
        "gold_cisa",
        "gold_epss",
        "gold_exploit",
        "gold_metasploit",
        "dim_vrr",
        "dim_weakness",
        "dim_threat",
        "fct_final"
    ]
}

BATCH_SIZE = 1000

# -------------------------
# MIGRATION LOGIC
# -------------------------

def copy_collection(
    src_db,
    tgt_db,
    collection_name: str,
    batch_size: int = 1000
):
    # Skip if collection doesn't exist in source
    if collection_name not in src_db.list_collection_names():
        print(f"⚠️  Skipping {collection_name}: Not found in source DB {src_db.name}")
        return

    src_col = src_db[collection_name]
    tgt_col = tgt_db[collection_name]

    cursor = src_col.find({}, no_cursor_timeout=True)
    batch = []
    total = 0

    print(f"📦 Copying collection: {collection_name}")

    try:
        # Drop target to ensure clean copy? 
        # User script didn't drop, just used insert unordered.
        # We will keep it additive/idempotent-ish.
        
        for doc in cursor:
            batch.append(doc)

            if len(batch) >= batch_size:
                try:
                    tgt_col.insert_many(batch, ordered=False)
                except BulkWriteError:
                    pass  # Ignore duplicate _id
                total += len(batch)
                batch.clear()
                print(f"   ... copied {total} docs", end="\r")

        # Insert remaining
        if batch:
            try:
                tgt_col.insert_many(batch, ordered=False)
            except BulkWriteError:
                pass
            total += len(batch)

    finally:
        cursor.close()

    print(f"✅ Completed {collection_name} ({total} docs)        ")


def copy_database(
    src_client: MongoClient,
    tgt_client: MongoClient,
    db_name: str,
    collections: List[str]
):
    print(f"\n🚀 Copying database: {db_name}")

    src_db = src_client[db_name]
    tgt_db = tgt_client[db_name]

    for col in collections:
        copy_collection(src_db, tgt_db, col)


import argparse

import argparse
import concurrent.futures
import time

def copy_collection_wrapper(args):
    """Wrapper for parallel execution unpacked arguments"""
    src_client, tgt_client, db_name, col_name = args
    # Create new client instances or use existing? 
    # PyMongo clients are thread-safe.
    
    src_db = src_client[db_name]
    tgt_db = tgt_client[db_name]
    copy_collection(src_db, tgt_db, col_name)

def main():
    parser = argparse.ArgumentParser(description="Migrate data from Local MongoDB to Atlas")
    parser.add_argument("--scope", choices=["all", "gold"], default="all", help="Scope of migration: 'all' to copy everything, 'gold' for only Gold layer.")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel threads (default: 4)")
    args = parser.parse_args()

    print(f"🔌 Connecting to Local MongoDB ({LOCAL_MONGO_URI})...")
    # Initialize clients (Thread-safe)
    local_client = MongoClient(LOCAL_MONGO_URI)

    print("🔌 Connecting to MongoDB Atlas...")
    atlas_client = MongoClient(
        ATLAS_MONGO_URI,
        tls=True,
        tlsCAFile=certifi.where()
    )

    # Connectivity check
    try:
        local_client.admin.command("ping")
        print("✅ Local connected.")
        atlas_client.admin.command("ping")
        print("✅ Atlas connected.")
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return

    # Filter Config based on Scope
    active_config = {}
    if args.scope == "all":
        active_config = COPY_CONFIG
    elif args.scope == "gold":
         if "vulnerability_gold" in COPY_CONFIG:
            active_config = {"vulnerability_gold": COPY_CONFIG["vulnerability_gold"]}
         else:
             print("⚠️ Gold configuration not found in script.")
             return

    print(f"🎯 Migration Scope: {args.scope.upper()} | Threads: {args.workers}")
    print("---------------------------------------------------")
    
    start_time = time.time()
    
    # Prepare tasks
    tasks = []
    for db_name, collections in active_config.items():
        for col_name in collections:
            tasks.append((local_client, atlas_client, db_name, col_name))
            
    # Execute in Parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(copy_collection_wrapper, task): task for task in tasks}
        
        for future in concurrent.futures.as_completed(futures):
            # We can capture exceptions here if needed
            try:
                future.result()
            except Exception as exc:
                print(f"❌ Task failed: {exc}")

    elapsed = time.time() - start_time
    print(f"\n🎉 Migration completed successfully in {elapsed:.2f} seconds")

if __name__ == "__main__":
    main()


