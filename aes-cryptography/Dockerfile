# Use a lightweight Python base image 3.14.0a3-bullseye
FROM python:3.12-slim

# Set a working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy our source code into the image
COPY src/crypto_utils.py src/main.py ./

# When the container starts, by default it will show the help text for main.py
CMD ["python", "src/main.py", "--help"]
