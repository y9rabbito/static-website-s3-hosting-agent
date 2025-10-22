"""
agent.py

Autonomous AWS Agent to host a static website on S3 using AWS Bedrock for reasoning.
"""

import json
import os
import zipfile
import tempfile
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import re
import mimetypes
import streamlit as st

# ------------------------------
# Load .env
# ------------------------------
load_dotenv()

AWS_ACCESS_KEY_ID = st.secrets.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = st.secrets.get("AWS_SECRET_ACCESS_KEY")
AWS_REGION = st.secrets.get("AWS_DEFAULT_REGION", "us-east-1")
BEDROCK_MODEL_ID = st.secrets.get(
    "BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0"
)

# ------------------------------
# Validate .env
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
    """Validate the website folder and list all files"""
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
        # If we get a 404, bucket doesn't exist
        if e.response['Error']['Code'] == '404':
            return True
        # If we get a 403, bucket exists but we don't have permission
        elif e.response['Error']['Code'] == '403':
            return False
        else:
            raise


def create_bucket(bucket_name: str, region: str = AWS_REGION):
    try:
        # Check if bucket already exists
        if not is_bucket_name_available(bucket_name):
            return {"ok": True, "message": f"Bucket {bucket_name} already exists."}
        
        if region == "us-east-1":
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        
        # Disable Block Public Access to allow public read for static website
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
    """Get proper MIME type for file"""
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
    """Upload all files from folder to S3 bucket WITHOUT ACLs"""
    uploaded, errors = [], []
    
    print(f"DEBUG: Starting upload from {folder_path} to bucket {bucket_name}")
    
    # List all files to be uploaded
    all_files = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            local_path = os.path.join(root, f)
            key = os.path.relpath(local_path, folder_path).replace("\\", "/")
            all_files.append((local_path, key))
    
    print(f"DEBUG: Found {len(all_files)} files to upload: {[f[1] for f in all_files]}")
    
    for local_path, key in all_files:
        try:
            content_type = get_content_type(key)
            
            # Upload WITHOUT ACL - we'll use bucket policy for public access
            extra_args = {
                'ContentType': content_type
                # REMOVED: 'ACL': 'public-read' - This causes "bucket doesn't allow ACLs" error
            }
            
            print(f"DEBUG: Uploading {key} with content-type {content_type}")
            
            s3_client.upload_file(
                local_path, 
                bucket_name, 
                key, 
                ExtraArgs=extra_args
            )
            uploaded.append({"file": key, "content_type": content_type})
            print(f"DEBUG: Successfully uploaded {key}")
            
        except Exception as e:
            error_msg = f"Failed to upload {key}: {str(e)}"
            print(f"ERROR: {error_msg}")
            errors.append({"file": key, "error": error_msg})
    
    # Verify upload by listing bucket contents
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        bucket_files = [obj['Key'] for obj in response.get('Contents', [])]
        print(f"DEBUG: Bucket now contains {len(bucket_files)} files: {bucket_files}")
    except Exception as e:
        print(f"DEBUG: Could not list bucket contents: {e}")
    
    return {
        "ok": len(errors) == 0, 
        "uploaded": uploaded, 
        "errors": errors,
        "total_attempted": len(all_files),
        "successful_uploads": len(uploaded),
        "failed_uploads": len(errors)
    }


def list_bucket_contents(bucket_name: str):
    """List all files in the bucket for verification"""
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        files = [obj['Key'] for obj in response.get('Contents', [])]
        return {"ok": True, "files": files, "count": len(files)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def enable_static_hosting(bucket_name: str):
    """Enable static website hosting and set bucket policy for public access"""
    try:
        # First, verify bucket exists and has files
        bucket_contents = list_bucket_contents(bucket_name)
        if not bucket_contents["ok"]:
            return {"ok": False, "error": f"Cannot enable hosting: {bucket_contents['error']}"}
        
        if bucket_contents["count"] == 0:
            return {"ok": False, "error": "Cannot enable hosting: Bucket is empty"}
        
        # Enable static website hosting
        s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "error.html"},
            },
        )
        
        # Set bucket policy for public read access (this replaces ACLs)
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
        
        try:
            s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
            policy_status = "Bucket policy set successfully"
        except Exception as policy_error:
            return {"ok": False, "error": f"Failed to set bucket policy: {str(policy_error)}"}
        
        # Get the proper website URL
        website_url = f"http://{bucket_name}.s3-website.{AWS_REGION}.amazonaws.com"
        
        return {
            "ok": True, 
            "website_url": website_url,
            "bucket_contents": bucket_contents,
            "policy_status": policy_status,
            "note": "Use the website URL (not the S3 object URL) to view your site"
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_bucket_public_access(bucket_name: str):
    """Check if the bucket has public access enabled"""
    try:
        # Check public access block configuration
        public_access = s3_client.get_public_access_block(Bucket=bucket_name)
        public_access_config = public_access['PublicAccessBlockConfiguration']
        
        # Check bucket policy
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            has_policy = True
        except:
            has_policy = False
            
        return {
            "ok": True,
            "public_access_block": public_access_config,
            "has_bucket_policy": has_policy,
            "is_public": (
                not public_access_config['BlockPublicAcls'] and
                not public_access_config['IgnorePublicAcls'] and
                not public_access_config['BlockPublicPolicy'] and
                not public_access_config['RestrictPublicBuckets'] and
                has_policy
            )
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def verify_website_url(bucket_name: str):
    """Verify that the website URL is accessible and returns proper content"""
    try:
        import requests
        website_url = f"http://{bucket_name}.s3-website.{AWS_REGION}.amazonaws.com"
        
        response = requests.get(website_url, timeout=10)
        return {
            "ok": True,
            "status_code": response.status_code,
            "content_type": response.headers.get('content-type', ''),
            "is_html": 'text/html' in response.headers.get('content-type', ''),
            "url": website_url
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "url": website_url
        }


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
# Plan Execution
# ------------------------------
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
Respond **strictly in JSON** inside a ```json code block```.
Do NOT include explanations outside the JSON block.

Example JSON format:
```json
{{
  "plan": [
    {{"action":"ValidateWebsiteFolder","params":{{"path":"{safe_path}"}}}},
    {{"action":"CheckBucketName","params":{{"bucket_name":"my-bucket"}}}},
    {{"action":"CreateBucket","params":{{"bucket_name":"my-bucket"}}}},
    {{"action":"UploadFiles","params":{{"bucket_name":"my-bucket"}}}},
    {{"action":"EnableStaticHosting","params":{{"bucket_name":"my-bucket"}}}},
    {{"action":"VerifyWebsite","params":{{"bucket_name":"my-bucket"}}}}
  ],
  "final_message": "Website deployment completed successfully!",
  "bucket_name": "my-bucket"
}}

User request: {user_msg}
"""


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
                print(f"DEBUG: Folder validation result: {result}")
                if not result["has_index"]:
                    report["ok"] = False
                    result["error"] = "index.html missing — cannot proceed."
                    report["steps"].append({"action": action, "result": result})
                    return report

            elif action == "CheckBucketName":
                name = params.get("bucket_name") or last_bucket
                available = is_bucket_name_available(name)
                result = {"available": available, "bucket_name": name}
                last_bucket = name
                print(f"DEBUG: Bucket name check: {name} available: {available}")

            elif action == "CreateBucket":
                name = params.get("bucket_name") or last_bucket
                result = create_bucket(name, region)
                last_bucket = name
                print(f"DEBUG: Create bucket result: {result}")

            elif action == "UploadFiles":
                name = params.get("bucket_name") or last_bucket
                result = upload_files(name, local_path)
                print(f"DEBUG: Upload files result: {result}")

            elif action == "ListBucketContents":
                name = params.get("bucket_name") or last_bucket
                result = list_bucket_contents(name)
                print(f"DEBUG: Bucket contents: {result}")

            elif action == "EnableStaticHosting":
                name = params.get("bucket_name") or last_bucket
                result = enable_static_hosting(name)
                if result["ok"]:
                    report["website_url"] = result["website_url"]
                print(f"DEBUG: Enable hosting result: {result}")

            elif action == "CheckPublicAccess":
                name = params.get("bucket_name") or last_bucket
                result = check_bucket_public_access(name)
                print(f"DEBUG: Public access check: {result}")

            elif action == "VerifyWebsite":
                name = params.get("bucket_name") or last_bucket
                result = verify_website_url(name)
                print(f"DEBUG: Verify website result: {result}")

            else:
                result = {"error": f"Unknown action: {action}"}
                report["ok"] = False

            report["steps"].append({"action": action, "result": result})

        except Exception as e:
            report["ok"] = False
            report["steps"].append({"action": action, "error": str(e)})
            print(f"ERROR in step {action}: {e}")
            break

    return report


def run_deploy_plan(local_path: str, region: str, user_msg: str):
    prompt = build_prompt(local_path, region, user_msg)
    raw = call_bedrock_model(prompt)
    try:
        if "```" in raw:
            raw = raw.split("```json")[-1].split("```")[0].strip()
        plan_data = json.loads(raw)
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
    
    # Debug: List extracted files
    print(f"DEBUG: Extracted files to {tmpdir}")
    for root, dirs, files in os.walk(tmpdir):
        for file in files:
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, tmpdir)
            print(f"DEBUG: Extracted: {rel_path}")
    
    return tmpdir
