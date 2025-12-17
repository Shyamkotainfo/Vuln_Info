FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies if needed (e.g. git, curl)
# RUN apt-get update && apt-get install -y ...

# Copy requirements first to leverage cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8080

# Command to run the application
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]
