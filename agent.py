import os
import json
import zipfile
import tempfile
import boto3
from botocore.exceptions import ClientError
import re
import mimetypes
import streamlit as st
import time

# ------------------------------
# Load secrets from Streamlit
# ------------------------------
AWS_ACCESS_KEY_ID = st.secrets.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = st.secrets.get("AWS_SECRET_ACCESS_KEY")
AWS_REGION = st.secrets.get("AWS_DEFAULT_REGION", "ap-south-1")
BEDROCK_MODEL_ID = st.secrets.get(
    "BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0"
)

# ------------------------------
# Validate region
# ------------------------------
if not re.match(r"^[a-z]{2}-[a-z]+-\d$", AWS_REGION):
    raise ValueError(f"Invalid AWS region: {AWS_REGION}")

# ------------------------------
# Initialize clients
# ------------------------------
session = boto3.Session(
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)
s3_client = session.client("s3")
bedrock_client = session.client("bedrock-runtime")

# ------------------------------
# S3 Utility Functions
# ------------------------------
def validate_website_folder(path: str):
    if not os.path.isdir(path):
        return {"ok": False, "reason": "Not a directory"}

    files = []
    for root, _, filenames in os.walk(path):
        for f in filenames:
            rel = os.path.relpath(os.path.join(root, f), path)
            files.append(rel.replace("\\", "/"))

    has_index = any(f.lower().endswith("index.html") for f in files)
    has_error = any(f.lower().endswith("error.html") or f.lower().endswith("404.html") for f in files)

    return {
        "ok": has_index, 
        "has_index": has_index, 
        "has_error": has_error, 
        "files": files,
        "total_files": len(files)
    }

def is_bucket_name_available(bucket_name: str) -> bool:
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        return False
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            return True
        elif e.response['Error']['Code'] == '403':
            return False
        else:
            raise

def create_bucket(bucket_name: str, region: str = AWS_REGION):
    try:
        if not is_bucket_name_available(bucket_name):
            return {"ok": True, "message": f"Bucket {bucket_name} already exists."}
        if region == "us-east-1":
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        return {"ok": True, "message": f"Bucket {bucket_name} created successfully with public access enabled."}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def get_content_type(filename):
    mimetypes.init()
    content_type, _ = mimetypes.guess_type(filename)
    if content_type is None:
        if filename.endswith('.css'):
            return 'text/css'
        elif filename.endswith('.js'):
            return 'application/javascript'
        elif filename.endswith('.json'):
            return 'application/json'
        elif filename.endswith('.svg'):
            return 'image/svg+xml'
        elif filename.endswith('.html'):
            return 'text/html'
        elif filename.endswith('.txt'):
            return 'text/plain'
        elif filename.endswith('.png'):
            return 'image/png'
        elif filename.endswith('.jpg') or filename.endswith('.jpeg'):
            return 'image/jpeg'
        elif filename.endswith('.gif'):
            return 'image/gif'
        elif filename.endswith('.ico'):
            return 'image/x-icon'
        else:
            return 'binary/octet-stream'
    return content_type

def upload_files(bucket_name: str, folder_path: str):
    uploaded, errors = [], []
    all_files = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            local_path = os.path.join(root, f)
            key = os.path.relpath(local_path, folder_path).replace("\\", "/")
            all_files.append((local_path, key))
    for local_path, key in all_files:
        try:
            content_type = get_content_type(key)
            s3_client.upload_file(
                local_path, 
                bucket_name, 
                key, 
                ExtraArgs={'ContentType': content_type}
            )
            uploaded.append({"file": key, "content_type": content_type})
        except Exception as e:
            errors.append({"file": key, "error": str(e)})
    return {
        "ok": len(errors) == 0,
        "uploaded": uploaded,
        "errors": errors,
        "total_attempted": len(all_files),
        "successful_uploads": len(uploaded),
        "failed_uploads": len(errors)
    }

def list_bucket_contents(bucket_name: str):
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        files = [obj['Key'] for obj in response.get('Contents', [])]
        return {"ok": True, "files": files, "count": len(files)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def enable_static_hosting(bucket_name: str):
    try:
        bucket_contents = list_bucket_contents(bucket_name)
        if not bucket_contents["ok"] or bucket_contents["count"] == 0:
            return {"ok": False, "error": "Bucket is empty or inaccessible."}
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "error.html"},
            },
        )
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*"
                }
            ]
        }
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
        website_url = f"http://{bucket_name}.s3-website.{AWS_REGION}.amazonaws.com"
        return {"ok": True, "website_url": website_url}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def verify_website_url(bucket_name: str):
    try:
        import requests
        website_url = f"http://{bucket_name}.s3-website.{AWS_REGION}.amazonaws.com"
        response = requests.get(website_url, timeout=10)
        return {"ok": True, "status_code": response.status_code, "url": website_url}
    except Exception as e:
        return {"ok": False, "error": str(e), "url": website_url}

# ------------------------------
# Bedrock LLM Helper
# ------------------------------
def call_bedrock_model(prompt, model_id=BEDROCK_MODEL_ID, region=AWS_REGION):
    client = boto3.client("bedrock-runtime", region_name=region)
    if model_id.startswith("anthropic."):
        body = {
            "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
            "max_tokens": 800,
            "temperature": 0.3,
            "anthropic_version": "bedrock-2023-05-31"
        }
    elif model_id.startswith("amazon.titan"):
        body = {
            "inputText": prompt,
            "textGenerationConfig": {"temperature": 0.7, "topP": 0.9, "maxTokenCount": 800}
        }
    else:
        raise ValueError(f"Unsupported Bedrock model: {model_id}")
    response = client.invoke_model(
        modelId=model_id,
        body=json.dumps(body),
        contentType="application/json",
        accept="application/json"
    )
    output = json.loads(response["body"].read())
    if "completion" in output:
        return output["completion"].strip()
    elif "results" in output:
        return output["results"][0]["outputText"].strip()
    elif "content" in output and len(output["content"]) > 0:
        return output["content"][0]["text"].strip()
    return json.dumps(output)

# ------------------------------
# Plan Execution
# ------------------------------
def build_prompt(local_path: str, region: str, user_msg: str) -> str:
    safe_path = json.dumps(local_path.replace("\\", "/"))
    safe_user_msg = json.dumps(user_msg)
    return f"""
You are an autonomous AWS agent that deploys static websites to S3.
Folder path: {safe_path}
AWS region: {region}

Important: Do NOT use ACLs for file uploads. Use bucket policies instead for public access.

Rules:
- Check that the folder has index.html (required) and error.html (optional).
- If index.html missing → stop and warn.
- Plan steps: check bucket, create, upload files, enable hosting, verify URL.

Respond strictly in JSON inside a ```json code block```.

User request: {safe_user_msg}
"""

def execute_plan(plan, local_path, region):
    report = {"ok": True, "steps": [], "website_url": None}
    last_bucket = None
    for step in plan:
        action = step.get("action")
        params = step.get("params", {})
        try:
            if action == "ValidateWebsiteFolder":
                result = validate_website_folder(local_path)
                if not result["has_index"]:
                    result["error"] = "index.html missing — cannot proceed."
                    report["steps"].append({"action": action, "result": result})
                    return report
            elif action == "CheckBucketName":
                name = params.get("bucket_name") or f"website-{int(time.time())}"
                available = is_bucket_name_available(name)
                result = {"available": available, "bucket_name": name}
                last_bucket = name
            elif action == "CreateBucket":
                name = params.get("bucket_name") or last_bucket
                result = create_bucket(name, region)
                last_bucket = name
            elif action == "UploadFiles":
                name = params.get("bucket_name") or last_bucket
                result = upload_files(name, local_path)
            elif action == "EnableStaticHosting":
                name = params.get("bucket_name") or last_bucket
                result = enable_static_hosting(name)
                if result.get("ok"):
                    report["website_url"] = result.get("website_url")
            elif action == "VerifyWebsite":
                name = params.get("bucket_name") or last_bucket
                result = verify_website_url(name)
            else:
                result = {"error": f"Unknown action: {action}"}
                report["ok"] = False
            report["steps"].append({"action": action, "result": result})
        except Exception as e:
            report["ok"] = False
            report["steps"].append({"action": action, "error": str(e)})
            break
    return report

def run_deploy_plan(local_path: str, region: str, user_msg: str):
    prompt = build_prompt(local_path, region, user_msg)
    raw = call_bedrock_model(prompt)
    import re
    match = re.search(r"```json(.*?)```", raw, re.DOTALL)
    raw_json = match.group(1).strip() if match else raw.strip()
    try:
        plan_data = json.loads(raw_json)
    except Exception as e:
        return {"ok": False, "error": f"Invalid JSON from LLM: {e}", "raw": raw}
    plan = plan_data.get("plan", [])
    final_msg = plan_data.get("final_message", "")
    bucket_name = plan_data.get("bucket_name", f"website-{int(time.time())}")
    report = execute_plan(plan, local_path, region)
    report["final_message"] = final_msg
    report["bucket_name"] = bucket_name
    return report

def extract_zip_to_temp(uploaded_file_bytes, filename):
    tmpdir = tempfile.mkdtemp()
    zip_path = os.path.join(tmpdir, filename)
    with open(zip_path, "wb") as f:
        f.write(uploaded_file_bytes)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(tmpdir)
    return tmpdir
