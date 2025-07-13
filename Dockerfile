
# Use official Python runtime as a base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy current directory contents into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port
EXPOSE 5000

# Command to run the app
CMD ["python", "app.py"]

