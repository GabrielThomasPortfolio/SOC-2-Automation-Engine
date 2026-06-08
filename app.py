import streamlit as st
import os
import tempfile
from dotenv import load_dotenv

load_dotenv()

from utils.sanitizer import sanitize_soc2_pdf
from utils.extractor import extract_soc2_insights

st.set_page_config(page_title="Automated SOC 2 Parser", page_icon="🛡️", layout="wide")

st.title("🛡️ Next-Gen GRC Automation Engine")
st.subheader("Automated Third-Party Risk Management (TPRM) & SOC 2 Parser")
st.write("Secure, data-masked compliance assessment interface.")

st.markdown("---")

# Fix Gap 3: Initialize session state parameters to protect data metrics from reset cycles
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "processing_complete" not in st.session_state:
    st.session_state.processing_complete = False

col1, col2 = st.columns(2)
with col1:
    vendor_name = st.text_input("Target Vendor Name *", placeholder="e.g., CloudCorp")
with col2:
    product_name = st.text_input("Product/Platform Name (Optional)", placeholder="e.g., Enterprise Suite")

uploaded_file = st.file_uploader("Upload Vendor SOC 2 Type II Report (PDF Format)", type=["pdf"])

if st.button("Execute Secure Parse", type="primary"):
    # Fix Q5: Enforce script halting via st.stop() immediately following input failure events
    if not vendor_name:
        st.error("❌ Mandatory Field Missing: Please enter a Target Vendor Name.")
        st.stop()
    if not uploaded_file:
        st.error("❌ Missing Asset: Please upload a valid SOC 2 PDF report.")
        st.stop()

    # Fix Bug 2: Operationalize the 10MB file size ceiling check
    if uploaded_file.size > 10 * 1024 * 1024:
        st.error("❌ File Boundary Breach: The uploaded report exceeds the maximum 10MB constraint profile.")
        st.stop()

    with st.spinner("🔄 Initializing shift-left pipeline (Extracting, Firewalling, and Masking)..."):
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
                temp_pdf.write(uploaded_file.read())
                temp_pdf_path = temp_pdf.name

            # Process masking rules safely
            sanitized_text = sanitize_soc2_pdf(temp_pdf_path, vendor_name, product_name)
            os.unlink(temp_pdf_path)

            with st.spinner("🧠 Analyzing GRC architecture and validating schema compliance..."):
                # Store the structured object in state so it persists across interactions
                st.session_state.analysis_result = extract_soc2_insights(sanitized_text)
                st.session_state.processing_complete = True

        except Exception as pipeline_error:
            st.error(f"💥 Pipeline Execution Aborted: {str(pipeline_error)}")
            if 'temp_pdf_path' in locals() and os.path.exists(temp_pdf_path):
                os.unlink(temp_pdf_path)
            st.stop()

# --- RUNTIME PERSISTENT INTERFACE RENDERING LAYER ---
if st.session_state.processing_complete and st.session_state.analysis_result:
    analysis = st.session_state.analysis_result
    
    st.success("🔒 Extraction pipeline processed cleanly. Verification metrics rendered below.")
    st.markdown("### 📊 Audit Assessment Summary")
    
    sum_col1, sum_col2 = st.columns(2)
    with sum_col1:
        st.metric(label="Auditing Firm", value=analysis.audit_firm)
    with sum_col2:
        opinion = analysis.opinion_type
        if "unqualified" in opinion.lower() or "clean" in opinion.lower():
            st.success(f"Opinion Status: {opinion}")
        else:
            st.warning(f"Opinion Status: {opinion}")

    st.markdown("---")
    
    st.markdown(f"### 🚨 Discovered Testing Exceptions ({len(analysis.exceptions)})")
    if not analysis.exceptions:
        st.info("✅ No compliance deviations or control testing exceptions were noted by the auditor.")
    else:
        for i, exc in enumerate(analysis.exceptions, 1):
            with st.expander(f"Exception {i}: Control Reference {exc.control_id}"):
                st.write(f"**Control Description:** {exc.control_description}")
                st.write(f"**Deviation Details:** {exc.exception_details}")
                st.info(f"**Grounded Source Quote:** *\"{exc.exact_source_quote}\"*")

    st.markdown("---")

    st.markdown(f"### ⚙️ Required Complementary User Entity Controls / CUECs ({len(analysis.user_controls)})")
    if not analysis.user_controls:
        st.warning("⚠️ No customer responsibilities were extracted.")
    else:
        for i, cuec in enumerate(analysis.user_controls, 1):
            with st.expander(f"CUEC {i}: Item ID {cuec.cuec_id}"):
                st.write(f"**Customer Action Required:** {cuec.description}")
                st.info(f"**Grounded Source Quote:** *\"{cuec.exact_source_quote}\"*")