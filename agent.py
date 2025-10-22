# agent.py

import os
import json
import zipfile
import tempfile
import boto3
from botocore.exceptions import ClientError
import mimetypes
import re
import streamlit as st

# ------------------------------
# Load AWS secrets from Streamlit
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
        return {"ok": True, "message": f"Bucket {bucket_name} created with public access enabled."}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def get_content_type(filename):
    mimetypes.init()
    content_type, _ = mimetypes.guess_type(filename)
    if content_type is None:
        ext_map = {
            ".css": "text/css",
            ".js": "application/javascript",
            ".json": "application/json",
            ".svg": "image/svg+xml",
            ".html": "text/html",
            ".txt": "text/plain",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".ico": "image/x-icon"
        }
        for ext, ctype in ext_map.items():
            if filename.endswith(ext):
                return ctype
        return "binary/octet-stream"
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
            s3_client.upload_file(local_path, bucket_name, key, ExtraArgs={"ContentType": content_type})
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
    contents = list_bucket_contents(bucket_name)
    if not contents["ok"] or contents["count"] == 0:
        return {"ok": False, "error": "Bucket is empty or inaccessible"}
    s3_client.put_bucket_website(
        Bucket=bucket_name,
        WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}, "ErrorDocument": {"Key": "error.html"}}
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket_name}/*"}]
    }
    s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    website_url = f"http://{bucket_name}.s3-website.{AWS_REGION}.amazonaws.com"
    return {"ok": True, "website_url": website_url, "bucket_contents": contents}

def verify_website_url(bucket_name: str):
    import requests
    url = f"http://{bucket_name}.s3-website.{AWS_REGION}.amazonaws.com"
    try:
        response = requests.get(url, timeout=10)
        return {"ok": True, "status_code": response.status_code, "url": url}
    except Exception as e:
        return {"ok": False, "error": str(e), "url": url}

# ------------------------------
# LLM / Bedrock helpers
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
        body = {"inputText": prompt, "textGenerationConfig": {"temperature": 0.7, "topP": 0.9, "maxTokenCount": 800}}
    else:
        raise ValueError(f"Unsupported Bedrock model: {model_id}")
    response = client.invoke_model(modelId=model_id, body=json.dumps(body), contentType="application/json", accept="application/json")
    output = json.loads(response["body"].read())
    if "completion" in output: return output["completion"].strip()
    if "results" in output: return output["results"][0]["outputText"].strip()
    if "content" in output and len(output["content"]) > 0: return output["content"][0]["text"].strip()
    return json.dumps(output)

def extract_json_from_llm(raw_text: str):
    raw_text = raw_text.replace("```json", "").replace("```", "")
    matches = re.findall(r"\{.*\}", raw_text, re.DOTALL)
    for m in matches:
        try: return json.loads(m)
        except json.JSONDecodeError: continue
    raise ValueError("No valid JSON object found in LLM output")

# ------------------------------
# Deployment plan executor
# ------------------------------
def execute_plan(plan, local_path, region):
    report = {"ok": True, "steps": [], "website_url": None}
    last_bucket = None
    for step in plan:
        action = step.get("action")
        params = step.get("params", {})
        name = params.get("bucket_name") or last_bucket
        result = None
        try:
            if action == "ValidateWebsiteFolder":
                result = validate_website_folder(local_path)
                if not result["has_index"]:
                    result["error"] = "index.html missing"
                    report["steps"].append({"action": action, "result": result})
                    report["ok"] = False
                    return report
            elif action == "CheckBucketName":
                available = is_bucket_name_available(name)
                result = {"available": available, "bucket_name": name}
            elif action == "CreateBucket":
                result = create_bucket(name, region)
            elif action == "UploadFiles":
                result = upload_files(name, local_path)
            elif action == "EnableStaticHosting":
                result = enable_static_hosting(name)
                if result["ok"]: report["website_url"] = result["website_url"]
            elif action == "VerifyWebsite":
                result = verify_website_url(name)
            else:
                result = {"error": f"Unknown action: {action}"}
                report["ok"] = False
            last_bucket = name
            report["steps"].append({"action": action, "result": result})
        except Exception as e:
            report["steps"].append({"action": action, "error": str(e)})
            report["ok"] = False
            break
    return report

def build_prompt(local_path: str, region: str, user_msg: str) -> str:
    safe_path = local_path.replace("\\", "/")
    return f"""
You are an autonomous AWS agent that deploys static websites to S3.
Folder path: {safe_path}
AWS region: {region}

Important: Respond strictly in JSON only.

User request: {user_msg}
"""

def run_deploy_plan(local_path: str, region: str, user_msg: str):
    prompt = build_prompt(local_path, region, user_msg)
    raw_output = call_bedrock_model(prompt)
    try:
        plan_data = extract_json_from_llm(raw_output)
    except ValueError as e:
        return {"ok": False, "error": f"Invalid JSON from LLM: {e}", "raw": raw_output}
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
    with open(zip_path, "wb") as f: f.write(uploaded_file_bytes)
    with zipfile.ZipFile(zip_path, "r") as z: z.extractall(tmpdir)
    return tmpdir
