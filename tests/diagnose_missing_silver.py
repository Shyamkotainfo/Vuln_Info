from vulnerability_pipeline.core.mongo_client import MongoManager

bronze = MongoManager.get_bronze_db()
silver = MongoManager.get_silver_db()

print("=== Finding Missing ExploitDB Records ===\n")

# Get all IDs
bronze_ids = set([str(d['_id']) for d in bronze['exploitdb_raw'].find({}, {'_id': 1})])
silver_ids = set([str(d['_id']) for d in silver['exploit_silver'].find({}, {'_id': 1})])

missing = bronze_ids - silver_ids
print(f"Missing {len(missing)} records in Silver")
print(f"Bronze total: {len(bronze_ids)}")
print(f"Silver total: {len(silver_ids)}\n")

# Sample missing records
sample_missing = list(missing)[:10]
print(f"Sample missing IDs: {sample_missing}\n")

# Check why they're missing
print("Checking Bronze for these records...")
for mid in sample_missing[:5]:
    doc = bronze['exploitdb_raw'].find_one({'_id': mid})
    if doc:
        print(f"\nID {mid}:")
        print(f"  date_published: {doc.get('date_published')}")
        print(f"  description: {doc.get('description', '')[:50]}...")
        print(f"  Has all required fields: id={bool(doc.get('id'))}")
    else:
        print(f"ID {mid}: NOT FOUND in Bronze (shouldn't happen)")

# Check if it's a date issue
print("\n\n=== Checking Date Distribution ===")
old_count = bronze['exploitdb_raw'].count_documents({'date_published': {'$lt': '2025-12-08'}})
new_count = bronze['exploitdb_raw'].count_documents({'date_published': {'$gte': '2025-12-08'}})
print(f"Bronze: Old (<2025-12-08): {old_count}, New (>=2025-12-08): {new_count}")

old_silver = silver['exploit_silver'].count_documents({'date_published': {'$lt': '2025-12-08'}})
new_silver = silver['exploit_silver'].count_documents({'date_published': {'$gte': '2025-12-08'}})
print(f"Silver: Old (<2025-12-08): {old_silver}, New (>=2025-12-08): {new_silver}")
