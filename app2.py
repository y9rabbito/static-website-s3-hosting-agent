# app_simple.py

import streamlit as st
from agent import extract_zip_to_temp, run_deploy_plan, call_bedrock_model

# ------------------------------
# Streamlit state
# ------------------------------
if "messages" not in st.session_state: st.session_state.messages = []
if "extracted_path" not in st.session_state: st.session_state.extracted_path = None

st.title("AWS S3 Hosting Agent")

# ------------------------------
# File upload
# ------------------------------
uploaded_zip = st.file_uploader("Upload your static website (ZIP)", type=["zip"])
if uploaded_zip and not st.session_state.extracted_path:
    st.session_state.extracted_path = extract_zip_to_temp(uploaded_zip.read(), uploaded_zip.name)
    st.success(f"Extracted {uploaded_zip.name} to temp folder")

# ------------------------------
# User input / deployment
# ------------------------------
user_input = st.text_input("Type your message or deployment command:")

if user_input:
    st.session_state.messages.append(f"User: {user_input}")
    deployment_keywords = ["host", "deploy", "upload to s3", "publish", "launch website"]

    if any(k in user_input.lower() for k in deployment_keywords):
        if not st.session_state.extracted_path:
            bot_response = "Please upload a ZIP website first!"
        else:
            with st.spinner("Deploying website..."):
                deploy_result = run_deploy_plan(st.session_state.extracted_path, region="ap-south-1", user_msg=user_input)
            if deploy_result.get("ok"):
                url = deploy_result.get("website_url", "URL not available")
                bot_response = f"Website deployed successfully! {url}"
            else:
                bot_response = f"Deployment failed. {deploy_result.get('error', 'Unknown error')}"
    else:
        try:
            bot_response = call_bedrock_model(user_input)
        except Exception as e:
            bot_response = f"Sorry, I couldn't process your request. ({e})"

    st.session_state.messages.append(bot_response)

# ------------------------------
# Display conversation
# ------------------------------
st.markdown("### Conversation")
for msg in st.session_state.messages:
    st.text(msg)
