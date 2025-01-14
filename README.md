## Defender for Cloud AI Enrichment Tool

This program fetches vulnerability data from Azure Defender for Cloud APIs, enriches it with AI-generated insights, and exports the results to an Excel document for easier analysis and reporting.

## Features

- Fetches vulnerability assessments and metadata from Azure Defender for Cloudm APIs. These are the recommendations that you can see in the Azure portal.
- Combines assessment data and metadata to create enriched vulnerability data.
- Uses OpenAI's GPT-based models to generate detailed descriptions, remediation steps, and context for each vulnerability.
- Exports enriched vulnerabilities to an Excel file for further use.

## Prerequisites

### 1. Azure
- Access to Azure Defender for Cloud APIs.
- This program uses DefaultAzureCredential so you need Azure credentials from your environment (e.g., via `az login`).

### 2. OpenAI API Key
- An active OpenAI API key. You can either:
- Enter the key directly when prompted.
- Set it as an environment variable and provide the variable name when prompted.

### 3. Go Modules
- Install the required Go modules using `go mod tidy`. The main dependencies include:
  - `github.com/Azure/azure-sdk-for-go`
  - `github.com/openai/openai-go`
  - `github.com/xuri/excelize/v2`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/bauerbrett/AzureVulnerabilities
   cd <repository_directory>

## Run Program 
- go run main.go 
or 
- go build -o defender-recommendations