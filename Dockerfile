# Use official Azure Functions Python base image
FROM mcr.microsoft.com/azure-functions/python:4-python3.10-slim

# Set working directory
WORKDIR /home/site/wwwroot

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy function code
COPY . .

# Expose port (Azure Functions uses 80 in container)
EXPOSE 80

# Environment variables (will be overridden by Azure)
ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true
