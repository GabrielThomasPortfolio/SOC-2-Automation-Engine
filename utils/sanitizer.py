import re
import os
import sys
import pdfplumber

def check_prompt_injection_firewall(text):
    """
    ADVERSARIAL INPUT FIREWALL
    Scans extracted PDF text for malicious structural overrides or jailbreak phrases.
    """
    adversarial_patterns = [
        r"ignore\s+(?:all\s+)?previous\s+instructions",
        r"override\s+(?:the\s+)?system",
        r"disregard\s+(?:all\s+)?prior\s+guidelines",
        r"you\s+are\s+no\s+longer\s+an\s+ai",
        r"bypass\s+(?:the\s+)?compliance\s+checks",
        r"output\s+only\s+the\s+word\s+compliant",
        r"force\s+evaluation\s+to\s+pass"
    ]
    
    text_clean = text.lower()
    for pattern in adversarial_patterns:
        if re.search(pattern, text_clean):
            return True, pattern
            
    return False, None

def clean_patterns(text):
    """MASKS STANDARD INFRASTRUCTURE AND PII FOUND IN AUDIT REPORTS"""
    # Emails
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    text = re.sub(email_pattern, '[REDACTED_EMAIL_ADDRESS]', text)
    
    # IP Addresses
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    text = re.sub(ip_pattern, '[INTERNAL_IP_ADDRESS]', text)
    
    # Internal System Paths (Linux/Windows structures often leak in Section III)
    text = re.sub(r'(/[a-zA-Z0-9_-]+){3,}', '[INTERNAL_SYSTEM_PATH]', text)
    text = re.sub(r'[a-zA-Z]:\\(?:[a-zA-Z0-9_-]+\\)+', '[INTERNAL_SYSTEM_PATH]', text)
    return text

def clean_dynamic_keywords(text, vendor_name, product_name=None):
    """DYNAMICALLY MASKS TARGET VENDOR IDENTIFIERS AT RUNTIME"""
    dynamic_markers = {vendor_name: "[TARGET_VENDOR_NAME]"}
    if product_name:
        dynamic_markers[product_name] = "[TARGET_PRODUCT_PLATFORM]"
        
    for keyword, placeholder in dynamic_markers.items():
        if keyword:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            text = pattern.sub(placeholder, text)
    return text

def sanitize_soc2_pdf(pdf_path, vendor_name, product_name=None):
    """INGESTS A SOC 2 PDF, EXTRACTS TEXT, SANITIZES, AND RETURNS CLEAN TEXT"""
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"Could not locate PDF at {pdf_path}")
        
    print(f"🔒 Opening raw SOC 2 PDF: '{pdf_path}'")
    raw_text_chunks = []
    
    # Extract layout-aware text with pdfplumber
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                raw_text_chunks.append(text)
                
    full_raw_text = "\n".join(raw_text_chunks)
    
    # --- FIREWALL PASS ---
    is_compromised, caught_pattern = check_prompt_injection_firewall(full_raw_text)
    if is_compromised:
        print(f"🚨 CRITICAL ADVERSARIAL OVERRIDE DETECTED ON INGESTION")
        sys.exit("Pipeline terminated: Security risk state detected in document body.")
        
    # --- DATA MASKING ROUTINES ---
    print("🛡️ Text verified. Executing patterns and dynamic corporate masking...")
    scrubbed_text = clean_patterns(full_raw_text)
    final_safe_text = clean_dynamic_keywords(scrubbed_text, vendor_name, product_name)
    
    return final_safe_text