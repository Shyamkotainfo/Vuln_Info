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
    echo "  etl        Run the full ETL pipeline (Bronze -> Gold)"
    echo "  analytics  Run Analytics (Init Schema + Calculate Facts)"
    echo "  enrich [in] [out]  Enrich a CSV with Risk Intel (joins with fct_final)"
    echo "  all        Run ETL followed by Analytics"
    echo "  test-upload  [file] [mongo_uri] - Test CSV upload via API"
    echo "  help       Show this help message"
}

case "$1" in
    api)
        echo -e "${GREEN}Starting FastAPI Server on http://localhost:8080...${NC}"
        uvicorn api.main:app --host 0.0.0.0 --port 8080 --reload
        ;;
    test-upload)
        FILE=$2
        URI=$3
        if [ -z "$FILE" ]; then
            echo "Error: Please provide a file path. Example: ./local_run.sh test-upload ./data/Nessus.csv"
            exit 1
        fi
        echo -e "${GREEN}Testing Upload for $FILE...${NC}"
        
        # Call API and capture response
        RESPONSE=$(curl -s -X POST "http://localhost:8080/upload/csv" \
             -H "Content-Type: multipart/form-data" \
             -F "file=@$FILE" \
             -F "mongo_uri=$URI")
        
        # Use Python to pretty print the summary and result
        echo "$RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'metadata' in data and 'summary' in data['metadata']:
        print(data['metadata']['summary'])
    else:
        print(json.dumps(data, indent=4))
except Exception as e:
    print('Error parsing response:', e)
    print(sys.stdin.read())
"
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
    enrich)
        IN=$2
        OUT=$3
        if [ -z "$IN" ]; then
            echo "Usage: ./local_run.sh enrich [input_csv] [output_csv]"
            exit 1
        fi
        echo -e "${GREEN}Enriching CSV with Risk Intelligence...${NC}"
        python3 analytics_stream/run_enrichment.py "$IN" --output "$OUT"
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
