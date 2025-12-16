from vulnerability_pipeline.core.mongo_client import MongoManager
import pprint

db_bronze = MongoManager.get_bronze_db()
print("=== NVD BRONZE FULL DOC ===")
bronze_doc = db_bronze["nvd_raw"].find_one()
if bronze_doc:
    # Print exclusions to avoid massive output if desc is long
    doc_copy = bronze_doc.copy()
    if 'descriptions' in doc_copy: doc_copy['descriptions'] = "..."
    pprint.pprint(doc_copy)
else:
    print("No Bronze doc found!")
