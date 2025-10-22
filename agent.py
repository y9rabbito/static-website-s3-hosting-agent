"""
Autonomous AWS Agent to host a static website on S3 using AWS Bedrock for reasoning.
"""

import os
import json
import tempfile
import zipfile
import mimetypes
import re
import boto3
from botocore.exceptions import ClientError
import streamlit as st
import requests

# ------------------------------
# Load .env / Streamlit secrets
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
# Initialize AWS clients
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
        code = e.response['Error']['Code']
        if code == '404':
            return True
        elif code == '403':
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
        elif filename.endswith(('.jpg', '.jpeg')):
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
            extra_args = {'ContentType': content_type}
            s3_client.upload_file(local_path, bucket_name, key, ExtraArgs=extra_args)
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
    bucket_contents = list_bucket_contents(bucket_name)
    if not bucket_contents["ok"]:
        return {"ok": False, "error": bucket_contents["error"]}
    if bucket_contents["count"] == 0:
        return {"ok": False, "error": "Bucket is empty"}

    s3_client.put_bucket_website(
        Bucket=bucket_name,
        WebsiteConfiguration={
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "error.html"},
        },
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*"
        }]
    }

    try:
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
        policy_status = "Bucket policy set successfully"
    except Exception as e:
        return {"ok": False, "error": str(e)}

    website_url = f"http://{bucket_name}.s3-website.{AWS_REGION}.amazonaws.com"
    return {"ok": True, "website_url": website_url, "bucket_contents": bucket_contents, "policy_status": policy_status}


def check_bucket_public_access(bucket_name: str):
    try:
        public_access = s3_client.get_public_access_block(Bucket=bucket_name)
        config = public_access['PublicAccessBlockConfiguration']
        try:
            s3_client.get_bucket_policy(Bucket=bucket_name)
            has_policy = True
        except:
            has_policy = False
        return {
            "ok": True,
            "is_public": not any(config.values()) and has_policy
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def verify_website_url(bucket_name: str):
    url = f"http://{bucket_name}.s3-website.{AWS_REGION}.amazonaws.com"
    try:
        response = requests.get(url, timeout=10)
        return {
            "ok": True,
            "status_code": response.status_code,
            "is_html": "text/html" in response.headers.get("content-type", ""),
            "url": url
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "url": url}


# ------------------------------
# Bedrock LLM Helper
# ------------------------------
def call_bedrock_model(prompt, model_id=BEDROCK_MODEL_ID, region=AWS_REGION):
    client = boto3.client("bedrock-runtime", region_name=region)
    if model_id.startswith("anthropic."):
        body = {"messages":[{"role":"user","content":[{"type":"text","text":prompt}]}],
                "max_tokens":800,"temperature":0.3,"anthropic_version":"bedrock-2023-05-31"}
    elif model_id.startswith("amazon.titan"):
        body = {"inputText":prompt,"textGenerationConfig":{"temperature":0.7,"topP":0.9,"maxTokenCount":800}}
    else:
        raise ValueError(f"Unsupported Bedrock model: {model_id}")

    try:
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
        else:
            return json.dumps(output)
    except Exception as e:
        raise RuntimeError(f"Bedrock model invocation failed: {e}")


# ------------------------------
# Robust JSON Extraction
# ------------------------------
def extract_json_from_llm(raw_text: str):
    raw_text = raw_text.replace("```json", "").replace("```", "").strip()
    stack = []
    start_idx = None
    for i, c in enumerate(raw_text):
        if c == "{":
            if not stack:
                start_idx = i
            stack.append("{")
        elif c == "}":
            if stack:
                stack.pop()
                if not stack and start_idx is not None:
                    candidate = raw_text[start_idx:i+1]
                    try:
                        return json.loads(candidate)
                    except:
                        continue
    raise ValueError("No valid JSON object found in LLM output")


# ------------------------------
# Plan Execution
# ------------------------------
def execute_plan(plan, local_path, region):
    report = {"ok": True, "steps": [], "website_url": None}
    last_bucket = None
    for step in plan:
        action = step.get("action")
        params = step.get("params", {})
        result = None
        try:
            if action == "ValidateWebsiteFolder":
                result = validate_website_folder(local_path)
                if not result["has_index"]:
                    report["ok"] = False
                    result["error"] = "index.html missing — cannot proceed."
                    report["steps"].append({"action": action, "result": result})
                    return report
            elif action == "CheckBucketName":
                name = params.get("bucket_name") or last_bucket
                result = {"available": is_bucket_name_available(name), "bucket_name": name}
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
                if result["ok"]:
                    report["website_url"] = result["website_url"]
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


def build_prompt(local_path: str, region: str, user_msg: str) -> str:
    safe_path = local_path.replace("\\", "/")
    return f"""
You are an autonomous AWS agent that deploys static websites to S3.
Folder path: {safe_path}
AWS region: {region}

Important: Do NOT use ACLs for file uploads. Use bucket policies instead for public access.

Rules:
- Check that the folder has index.html (required) and error.html (optional).
- If index.html missing → stop and warn.
- If available → plan steps:
  1. Check bucket name availability.
  2. Create the bucket and disable public access blocks.
  3. Upload files WITHOUT ACLs (just set ContentType).
  4. Enable static website hosting with proper bucket policy (not ACLs).
  5. Verify the website URL.

Extract bucket name from user message if specified, otherwise suggest one.
Respond strictly in JSON.
User request: {user_msg}
"""


def run_deploy_plan(local_path: str, region: str, user_msg: str):
    prompt = build_prompt(local_path, region, user_msg)
    raw = call_bedrock_model(prompt)
    try:
        plan_data = extract_json_from_llm(raw)
    except Exception as e:
        return {"ok": False, "error": f"Invalid JSON from LLM: {e}", "raw": raw}

    plan = plan_data.get("plan", [])
    final_msg = plan_data.get("final_message", "")
    bucket_name = plan_data.get("bucket_name", "")
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
