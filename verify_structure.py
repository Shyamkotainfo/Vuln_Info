import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

def verify_imports():
    print("Verifying imports...")
    try:
        from vulnerability_pipeline.core.config import Config
        print("✅ Config imported")
        
        from vulnerability_pipeline.core.mongo_client import MongoManager
        print("✅ MongoManager imported")

        from vulnerability_pipeline.datasources.external_feeds.nvd.nvd_main import run_nvd_pipeline
        print("✅ NVD Pipeline imported")

        from vulnerability_pipeline.datasources.external_feeds.cisa.cisa_main import run_cisa_pipeline
        print("✅ CISA Pipeline imported")
        
        from vulnerability_pipeline.datasources.external_feeds.epss.epss_main import run_epss_pipeline
        print("✅ EPSS Pipeline imported")

        from vulnerability_pipeline.datasources.external_feeds.exploit.exploit_main import run_exploit_pipeline
        print("✅ ExploitDB Pipeline imported")

        from vulnerability_pipeline.datasources.external_feeds.metasploit.metasploit_main import run_metasploit_pipeline
        print("✅ Metasploit Pipeline imported")
        
        print("\nAll modules imported successfully! Structure is valid.")
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")

if __name__ == "__main__":
    verify_imports()
