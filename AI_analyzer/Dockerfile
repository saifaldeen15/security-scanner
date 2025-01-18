# AI_analyzer/Dockerfile

# Use Python 3.9 as base image
FROM python:3.9-slim

# Set working directory in container
WORKDIR /app

# Copy requirements file
COPY requirements.txt requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ .

# Expose port
EXPOSE 5001

# Run the application with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "server:app"]