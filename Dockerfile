# Use a slim, stable Python image
FROM python:3.10-slim

# Set working directory inside container
WORKDIR /app

# Copy dependency file first (for Docker cache)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project
COPY . .

# Default command: run the full pipeline
CMD ["python", "main.py"]
