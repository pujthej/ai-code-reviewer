# Automated AI Code Review System for GitHub

Automated Python code review system powered by OpenAI GPT-4 and Azure serverless architecture. Automatically analyzes pull requests and provides intelligent feedback on code quality.

## Features

- **Automatic PR Analysis** - Triggers on PR open, update, or reopen
- **AI-Powered Reviews** - Uses OpenAI GPT-4o-mini for intelligent suggestions
- **Stateful Deduplication** - Cosmos DB prevents duplicate reviews on webhook retries
- **Serverless Architecture** - Pay-per-use with Azure Functions
- **AST-Based Analysis** - Deep Python code understanding via Abstract Syntax Tree parsing

### Tech Stack

- **Azure Functions** - Serverless compute (Python 3.10)
- **Cosmos DB** - NoSQL database for state management
- **OpenAI API** - GPT-4o-mini for code analysis
- **GitHub API** - Webhook integration and PR comments
- **Python AST** - Code parsing and analysis

## What It Checks

Currently analyzes:
- Missing docstrings in functions
- Poor function naming (too short, not snake_case)

*More checks coming soon: security issues, performance patterns, complexity metrics*

## Setup

### Prerequisites

- Azure Account
- GitHub Account
- OpenAI API Key

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ai-code-reviewer.git
cd ai-code-reviewer
```

### 2. Create Azure Resources

**Function App:**
```bash
az functionapp create \
  --resource-group your-rg \
  --consumption-plan-location eastus \
  --runtime python \
  --runtime-version 3.10 \
  --functions-version 4 \
  --name your-function-app-name \
  --storage-account yourstorageaccount
```

**Cosmos DB (Serverless):**
```bash
az cosmosdb create \
  --name your-cosmos-account \
  --resource-group your-rg \
  --locations regionName=eastus \
  --capabilities EnableServerless
```

Create database and container:
- Database: `code-reviews`
- Container: `reviewed-commits`
- Partition Key: `/review_key`

### 3. Configure Environment Variables

```bash
az functionapp config appsettings set \
  --name your-function-app \
  --resource-group your-rg \
  --settings \
    GITHUB_TOKEN="ghp_your_token" \
    OPENAI_API_KEY="sk-your_key" \
    COSMOS_ENDPOINT="https://your-cosmos.documents.azure.com:443/" \
    COSMOS_KEY="your-cosmos-key"
```

### 4. Deploy

```bash
func azure functionapp publish your-function-app-name
```

### 5. Setup GitHub Webhook

1. Go to your repo → **Settings** → **Webhooks** → **Add webhook**
2. **Payload URL:** `https://your-function-app.azurewebsites.net/api/github_webhook`
3. **Content type:** `application/json`
4. **Events:** Select "Pull requests" only
5. **Active:** ✓

## Testing

### Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Start local server
func start

# Test with curl
curl -X POST http://localhost:7071/api/github_webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -d @test_payload.json
```

### Production Testing

1. Create a test PR with Python code
2. Bot should comment automatically
3. Redeliver webhook to test deduplication

## Development

### Project Structure

```
ai-code-reviewer/
├── github_webhook/
│   ├── __init__.py          # Main function code
│   └── function.json        # Function bindings
├── requirements.txt         # Python dependencies
├── host.json               # Function app settings
├── local.settings.json     # Local config (not in git)
└── README.md
```

### Adding New Checks

To add a new code analysis check:

1. Create a new function in `__init__.py`:
```python
def find_security_issues(tree):
    issues = []
    # Your analysis logic
    return issues
```

2. Add to the review pipeline:
```python
issues.extend(find_security_issues(tree))
```

## Troubleshooting

**Bot not commenting?**
- Check Azure Function logs in Application Insights
- Verify webhook is configured correctly
- Ensure all environment variables are set

**Cosmos DB not working?**
- Verify database and container exist
- Check partition key is `/review_key`
- Confirm endpoint and key are correct

**OpenAI errors?**
- Check API key is valid
- Verify you have credits
- Check rate limits
