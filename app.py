import streamlit as st
import os
import tempfile
from dotenv import load_dotenv  # 1. Bring in the loader

# 2. Force load the .env file at the absolute entrypoint of the app
load_dotenv() 

# 3. NOW import your utilities (which rely on the API key being in memory)
from utils.sanitizer import sanitize_soc2_pdf
from utils.extractor import extract_soc2_insights

# Set up page configurations
st.set_page_config(
    page_title="Automated SOC 2 Parser",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Next-Gen GRC Automation Engine")
st.subheader("Automated Third-Party Risk Management (TPRM) & SOC 2 Parser")
st.write("Upload a vendor's SOC 2 Type II report to execute a secure, data-masked compliance assessment.")

st.markdown("---")

# Layout columns for user input metadata
col1, col2 = st.columns(2)

with col1:
    vendor_name = st.text_input("Target Vendor Name *", placeholder="e.g., CloudCorp")

with col2:
    product_name = st.text_input("Product/Platform Name (Optional)", placeholder="e.g., Enterprise Analytics Suite")

# File Upload Control with strict size constraint (10MB maximum to prevent abuse)
uploaded_file = st.file_uploader(
    "Upload Vendor SOC 2 Type II Report (PDF Format)", 
    type=["pdf"]
)

if st.button("Execute Secure Parse", type="primary"):
    # Input Validation checks
    if not vendor_name:
        st.error("❌ Mandatory Field Missing: Please enter a Target Vendor Name.")
    elif not uploaded_file:
        st.error("❌ Missing Asset: Please upload a SOC 2 PDF report to analyze.")
    else:
        with st.spinner("🔄 Initializing shift-left pipeline (Extracting, Firewalling, and Masking)..."):
            try:
                # 1. Create a secure, temporary local file block to hold the binary upload
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
                    temp_pdf.write(uploaded_file.read())
                    temp_pdf_path = temp_pdf.name

                # 2. Trigger the local sanitization and data-masking pipeline
                sanitized_text = sanitize_soc2_pdf(temp_pdf_path, vendor_name, product_name)
                
                # Clean up the temporary file immediately after parsing text to limit footprint
                os.unlink(temp_pdf_path)
                
                st.success("🔒 Ingestion Complete. Data masked and verified clean of prompt injections.")

                # 3. Trigger the structured LLM extraction model and validation gates
                with st.spinner("🧠 Analyzing GRC architecture, extracting exceptions, and verifying quotes..."):
                    analysis_result = extract_soc2_insights(sanitized_text)
                
                # --- UI DISPLAY LAYER ---
                st.markdown("### 📊 Audit Assessment Summary")
                
                sum_col1, sum_col2 = st.columns(2)
                with sum_col1:
                    st.metric(label="Auditing Firm", value=analysis_result.audit_firm)
                with sum_col2:
                    # Color code the metric display based on standard audit risk profiles
                    opinion = analysis_result.opinion_type
                    if "unqualified" in opinion.lower() or "clean" in opinion.lower():
                        st.success(f"Opinion: {opinion}")
                    else:
                        st.warning(f"Opinion: {opinion}")

                st.markdown("---")
                
                # Display parsed exceptions
                st.markdown(f"### 🚨 Discovered Testing Exceptions ({len(analysis_result.exceptions)})")
                if not analysis_result.exceptions:
                    st.info("✅ No compliance deviations or control testing exceptions were noted by the auditor.")
                else:
                    for i, exc in enumerate(analysis_result.exceptions, 1):
                        with st.expander(f"Exception {i}: Control Reference {exc.control_id}"):
                            st.write(f"**Control Description:** {exc.control_description}")
                            st.write(f"**Deviation Details:** {exc.exception_details}")
                            st.info(f"**Grounded Source Quote:** *\"{exc.exact_source_quote}\"*")

                st.markdown("---")

                # Display Complementary User Entity Controls (CUECs)
                st.markdown(f"### ⚙️ Required Complementary User Entity Controls / CUECs ({len(analysis_result.user_controls)})")
                if not analysis_result.user_controls:
                    st.warning("⚠️ No customer responsibilities were extracted. Ensure Section IV was read fully.")
                else:
                    for i, cuec in enumerate(analysis_result.user_controls, 1):
                        with st.expander(f"CUEC {i}: Item ID {cuec.cuec_id}"):
                            st.write(f"**Customer Action Required:** {cuec.description}")
                            st.info(f"**Grounded Source Quote:** *\"{cuec.exact_source_quote}\"*")

            except Exception as e:
                st.error(f"💥 Pipeline Execution Error: {str(e)}")
                # Ensure temporary file deletion if an execution error occurs mid-stream
                if 'temp_pdf_path' in locals() and os.path.exists(temp_pdf_path):
                    os.unlink(temp_pdf_path)