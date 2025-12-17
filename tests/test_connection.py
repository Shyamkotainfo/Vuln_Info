import os
import certifi
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

uri = os.getenv("MONGO_URI")
print(f"Testing connection to: {uri.split('@')[-1] if uri else 'None'}")

if not uri:
    print("❌ MONGO_URI is missing!")
    exit(1)

try:
    print("Attempting to connect...")
    client = MongoClient(uri, tls=True, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print("✅ Connection successful!")
    
    # List DBs
    print("Databases:", client.list_database_names())
except Exception as e:
    print(f"❌ Connection FAILED: {e}")
