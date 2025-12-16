import argparse
import logging
import sys
from analytics_stream.ingest import AnalyticsLoader

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("analytics.runner")

def main():
    parser = argparse.ArgumentParser(description="Gold Analytics Loader")
    parser.add_argument("--file", required=True, help="Path to Silver output CSV file")
    
    args = parser.parse_args()
    
    try:
        loader = AnalyticsLoader()
        loader.load_file(args.file)
        logger.info("Successfully completed analytics load.")
    except Exception as e:
        logger.error(f"Failed to load analytics: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
