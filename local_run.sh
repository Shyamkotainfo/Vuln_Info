#!/bin/bash

# =============================================================================
# Local Run Script for Vulnerability Pipeline
# Supports: Command Line (ETL/Analytics) and Web API (Uvicorn)
# =============================================================================

# Colors for logging
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Vulnerability Pipeline Local Runner ===${NC}"

# Function to display help
show_help() {
    echo "Usage: ./local_run.sh [option]"
    echo ""
    echo "Options:"
    echo "  api        Start the FastAPI web server (Uvicorn)"
    echo "  process [file] [uri]  Directly process a CSV (No API needed)"
    echo "  etl        Run the full ETL pipeline (Bronze -> Gold)"
    echo "  analytics  Run Analytics (Init Schema + Calculate Facts)"
    echo "  sync       Sync Risk Intelligence from Local to Atlas"
    echo "  all        Run ETL followed by Analytics"
    echo "  help       Show this help message"
}

case "$1" in
    api)
        echo -e "${GREEN}Starting FastAPI Server on http://localhost:8080...${NC}"
        uvicorn api.main:app --host 0.0.0.0 --port 8080 --reload
        ;;
    process)
        FILE=$2
        URI=$3
        if [ -z "$FILE" ]; then
            echo "Usage: ./local_run.sh process [csv_file] [optional_mongo_uri]"
            exit 1
        fi
        echo -e "${GREEN}Processing CSV: $FILE ...${NC}"
        python3 -m csv_handler.uploader "$FILE" "$URI"
        ;;
    etl)
        echo -e "${GREEN}Running ETL Pipeline (Bronze to Gold)...${NC}"
        python3 -m vulnerability_pipeline.pipeline_orchestrator
        ;;
    analytics)
        echo -e "${GREEN}Initializing Analytics Schema...${NC}"
        python3 analytics_stream/init_schema.py
        echo -e "${GREEN}Calculating Risk Scores (Facts)...${NC}"
        python3 analytics_stream/calculate_facts.py
        ;;
    sync)
        echo -e "${GREEN}Syncing Risk Intelligence to Atlas...${NC}"
        python3 scripts/migration/targeted_atlas_sync.py
        ;;
    all)
        echo -e "${GREEN}Running Full Project Suite...${NC}"
        python3 -m vulnerability_pipeline.pipeline_orchestrator
        python3 analytics_stream/init_schema.py
        python3 analytics_stream/calculate_facts.py
        echo -e "${BLUE}Full run complete!${NC}"
        ;;
    *)
        show_help
        ;;
esac
