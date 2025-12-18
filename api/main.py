import logging
import uuid

# Setup Logger for API
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("API")

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
import shutil
import os
import tempfile

app = FastAPI()
# ... imports ...

# Removed broken legacy endpoint (analytics_stream.client_processor missing)

from csv_handler.uploader import CSVProcessor

from typing import Optional

def process_host_findings_background(file_path: str, mongo_uri: Optional[str] = None):
    try:
        logger.info(f"Starting Host Findings processing for {file_path}")
        if mongo_uri:
            logger.info(f"Targeting Custom MongoDB: {mongo_uri[:10]}...")
            
        processor = CSVProcessor(mongo_uri=mongo_uri)
        result = processor.process_csv(file_path)
        logger.info(f"Host Findings complete: {result}")
    except Exception as e:
        logger.error(f"Host Findings processing failed: {e}", exc_info=True)
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

@app.post("/upload/csv")
async def upload_host_findings(
    file: UploadFile = File(...),
    mongo_uri: Optional[str] = Form(None)
):
    """
    Ingest Host Findings CSV and return the enriched JSON results.
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are supported")
        
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name
            
        logger.info(f"Processing upload for {file.filename}")
        processor = CSVProcessor(mongo_uri=mongo_uri)
        result = processor.process_csv(tmp_path)
        
        # Clean up temp file
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
            
        return result

    except Exception as e:
        logger.error(f"Upload and processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
