import azure.functions as func
import logging
import json
import traceback
import requests
import os
import ast
import base64
import hashlib
from datetime import datetime, timezone
from openai import OpenAI


# Initialize clients
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
cosmos_container = None

def init_cosmos_db():
    """Initialize Cosmos DB client."""
    try:
        from azure.cosmos import CosmosClient
        
        endpoint = os.getenv("COSMOS_ENDPOINT")
        key = os.getenv("COSMOS_KEY")
        
        if not endpoint or not key:
            logging.warning("Cosmos DB not configured - deduplication disabled")
            return None
        
        client = CosmosClient(endpoint, key)
        database = client.get_database_client("code-reviews")
        container = database.get_container_client("reviewed-commits")
        
        logging.info("Cosmos DB initialized successfully")
        return container
        
    except Exception as e:
        logging.error(f"Failed to initialize Cosmos DB: {e}")
        return None


def get_review_key(repo: str, pr_number: int, filename: str, commit_sha: str) -> str:
    """Generate unique key for this review."""
    key_string = f"{repo}:{pr_number}:{filename}:{commit_sha}"
    return hashlib.sha256(key_string.encode()).hexdigest()


def was_already_reviewed(review_key: str) -> bool:
    """Check if this exact code was already reviewed."""
    if not cosmos_container:
        return False
    
    try:
        cosmos_container.read_item(item=review_key, partition_key=review_key)
        logging.info(f"✓ Already reviewed: {review_key[:12]}...")
        return True
    except Exception:
        return False


def mark_as_reviewed(review_key: str, metadata: dict):
    """Mark this code as reviewed in Cosmos DB."""
    if not cosmos_container:
        return
    
    try:
        cosmos_container.upsert_item({
            "id": review_key,
            "review_key": review_key,
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
            **metadata
        })
        logging.info(f"Marked as reviewed: {review_key[:12]}...")
    except Exception as e:
        logging.error(f"Failed to save review state: {e}")


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function to handle GitHub webhook events for PR reviews.
    """
    global cosmos_container
    
    # Health check endpoint
    if req.method == "GET":
        status = {
            "status": "healthy",
            "cosmos_configured": bool(os.getenv("COSMOS_ENDPOINT") and os.getenv("COSMOS_KEY")),
            "github_configured": bool(os.getenv("GITHUB_TOKEN")),
            "openai_configured": bool(os.getenv("OPENAI_API_KEY"))
        }
        logging.info(f"Health check: {status}")
        return func.HttpResponse(json.dumps(status), mimetype="application/json")
    
    logging.info('GitHub webhook received')

    try:
        # Initialize Cosmos DB (once per cold start)
        if cosmos_container is None:
            cosmos_container = init_cosmos_db()
        
        # Parse the webhook payload
        payload = req.get_json()
        logging.info(f"Payload keys: {list(payload.keys())}")

        # Check if it's a pull request event
        event_type = req.headers.get('X-GitHub-Event', 'unknown')
        logging.info(f'Event type: {event_type}')
        
        if event_type != 'pull_request':
            logging.info(f'Ignoring non-PR event: {event_type}')
            return func.HttpResponse("Event ignored", status_code=200)

        # Process the PR event
        handle_pr_event(payload)

        return func.HttpResponse("PR review completed", status_code=200)

    except Exception as e:
        logging.error('FUNCTION CRASHED')
        logging.error(traceback.format_exc())
        return func.HttpResponse(
            f"Internal Server Error: {str(e)}",
            status_code=500
        )

# function to get list of files in the PR
def get_pr_files(repo, pr_number):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

# function to get file content at specific ref (branch/commit)
def get_file_content(repo, filepath, ref):
    url = f"https://api.github.com/repos/{repo}/contents/{filepath}?ref={ref}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    response = requests.get(url, headers=headers)
    data = response.json()

    if "content" not in data:
        return None

    content = base64.b64decode(data["content"]).decode("utf-8")
    return content


# parse Python code into AST
def parse_python_code(code: str):
    try:
        return ast.parse(code)
    except SyntaxError:
        return None

# find functions missing docstrings
def find_missing_docstrings(tree):
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if ast.get_docstring(node) is None:
                issues.append({
                    "type": "missing_docstring",
                    "function": node.name,
                    "line": node.lineno
                })
    return issues


# find functions with bad naming conventions
def find_bad_function_names(tree):
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if len(node.name) <= 3 or not node.name.islower() or "_" not in node.name:
                issues.append({
                    "type": "bad_function_name",
                    "function": node.name,
                    "line": node.lineno
                })
    return issues


# post comment to PR
def post_pr_comment(repo, pr_number, body):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    data = {"body": body}
    
    response = requests.post(url, headers=headers, json=data)

    if response.status_code != 201:
        logging.error(f"Failed to post comment: {response.text}")
    else:
        logging.info("✓ Comment posted successfully")


# use OpenAI API to explain the issue
def explain_issue_with_ai(issue, code_snippet):
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    prompt = f"""
You are a senior software engineer doing a code review.

Issue type: {issue['type']}
Function name: {issue['function']}
Line number: {issue['line']}

Code:
{code_snippet}

Explain the issue clearly and suggest a concise improvement.
Do not be verbose.
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=120
    )

    return response.choices[0].message.content


# extract source code of a function from full code
def get_function_source(code, function_name):
    lines = code.split("\n")
    snippet = []
    inside = False

    for line in lines:
        if line.startswith(f"def {function_name}"):
            inside = True
        if inside:
            snippet.append(line)
            if line.strip() == "" and inside:
                break

    return "\n".join(snippet)

# main PR event handler
def handle_pr_event(payload):
    action = payload.get("action")
    logging.info(f"PR action: {action}")
    
    # Ignore non-relevant actions
    if action not in ("opened", "synchronize", "reopened"):
        logging.info(f"Ignoring action: {action}")
        return

    repo = payload["repository"]["full_name"]
    pr_number = payload["pull_request"]["number"]
    branch = payload["pull_request"]["head"]["ref"]
    commit_sha = payload["pull_request"]["head"]["sha"]

    logging.info(f"Processing PR #{pr_number} in {repo}, commit: {commit_sha[:7]}")

    files = get_pr_files(repo, pr_number)
    reviewed_count = 0
    skipped_count = 0

    for file in files:
        filename = file["filename"]

        if not filename.endswith(".py"):
            continue

        # Generate unique key for deduplication
        review_key = get_review_key(repo, pr_number, filename, commit_sha)

        # Check if already reviewed
        if was_already_reviewed(review_key):
            logging.info(f"Skipping {filename} - already reviewed")
            skipped_count += 1
            continue

        logging.info(f"Analyzing {filename}")

        full_code = get_file_content(repo, filename, branch)

        if not full_code:
            logging.warning(f"Skipping {filename}: could not fetch file content")
            continue

        tree = parse_python_code(full_code)

        if not tree:
            logging.warning(f"Skipping {filename}: invalid Python file")
            continue

        issues = []
        issues.extend(find_missing_docstrings(tree))
        issues.extend(find_bad_function_names(tree))

        # Mark as reviewed BEFORE posting (prevent duplicates if comment fails)
        metadata = {
            "repo": repo,
            "pr_number": pr_number,
            "filename": filename,
            "commit_sha": commit_sha,
            "issue_count": len(issues),
            "has_issues": len(issues) > 0
        }
        mark_as_reviewed(review_key, metadata)
        reviewed_count += 1

        if not issues:
            logging.info(f"No issues found in {filename}")
            continue

        ai_lines = [
            f"### AI Code Review for `{filename}`",
            f"*Commit: `{commit_sha[:7]}` • Found {len(issues)} issue(s)*\n"
        ]

        for issue in issues:
            snippet = get_function_source(full_code, issue["function"])
            explanation = explain_issue_with_ai(issue, snippet)

            ai_lines.append(
                f"**`{issue['function']}()` (line {issue['line']})**\n"
                f"{explanation}\n"
            )

        comment_body = "\n".join(ai_lines)
        post_pr_comment(repo, pr_number, comment_body)

    logging.info(f"PR review completed: {reviewed_count} reviewed, {skipped_count} skipped (duplicates)")