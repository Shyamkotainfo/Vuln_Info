import os
import certifi
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# Atlas URI - Ensure this is set correctly in .env
ATLAS_URI = os.getenv("MONGO_URI")
LOCAL_URI = "mongodb://localhost:27017"

if not ATLAS_URI:
    print("❌ ERROR: MONGO_URI not found in .env")
    exit(1)

collections_to_sync = ["dim_vrr", "dim_threats", "fct_final"]
BATCH_SIZE = 2000

def sync_collection(name, local_db, atlas_db):
    if name not in local_db.list_collection_names():
        print(f"⚠️  Skipping {name}: Not found in local DB.")
        return
        
    print(f"📦 Syncing {name}...")
    local_col = local_db[name]
    atlas_col = atlas_db[name]
    
    # Check if data already exists in Atlas (additive/idempotent-ish)
    atlas_count = atlas_col.count_documents({})
    local_count = local_col.count_documents({})
    
    if atlas_count >= local_count:
        print(f"✅ {name} already has {atlas_count} documents in Atlas. Skipping.")
        return

    # Fresh start if it's very small, otherwise continue
    if local_count < 1000:
        atlas_col.drop()
        atlas_count = 0

    cursor = local_col.find().skip(atlas_count)
    batch = []
    processed = atlas_count
    
    print(f"   Continuing from document {processed}...")
    
    for doc in cursor:
        batch.append(doc)
        if len(batch) >= BATCH_SIZE:
            try:
                atlas_col.insert_many(batch, ordered=False)
                processed += len(batch)
                print(f"   ... synced {processed}/{local_count} docs", end="\r")
                batch = []
            except Exception as e:
                print(f"\n❌ Batch insert failed: {e}")
                # We stop on error to avoid messy partial batches
                return

    if batch:
        atlas_col.insert_many(batch, ordered=False)
        processed += len(batch)
        print(f"   ... synced {processed}/{local_count} docs")

    print(f"✅ Finished syncing {name}.")

def main():
    print(f"🔌 Connecting to Local...")
    local_client = MongoClient(LOCAL_URI)
    
    print(f"🔌 Connecting to Atlas...")
    atlas_client = MongoClient(ATLAS_URI, tls=True, tlsCAFile=certifi.where())
    
    try:
        local_client.admin.command('ping')
        atlas_client.admin.command('ping')
        print("✅ Both connected.")
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return

    db_name = "vulnerability_gold"
    local_db = local_client[db_name]
    atlas_db = atlas_client[db_name]

    print("\n🚀 Starting Robust Targeted Sync...")
    for coll_name in collections_to_sync:
        sync_collection(coll_name, local_db, atlas_db)

    print("\n🎉 Targeted Sync Complete!")

if __name__ == "__main__":
    main()
