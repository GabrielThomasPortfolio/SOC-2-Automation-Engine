import re
import pdfplumber
from typing import Optional

def sanitize_soc2_pdf(pdf_path: str, vendor_name: str, product_name: Optional[str] = None) -> str:
    """
    Ingests a raw SOC 2 PDF report, applies optimized layout extraction tolerances,
    screens for adversarial injection states, and masks internal architecture markers.
    """
    full_raw_text = ""
    
    # Open the document using pdfplumber with enhanced reading grid configurations
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            # Fix Gap 4: Use explicit tolerances to prevent multi-column cell text interleaving
            text = page.extract_text(x_tolerance=3, y_tolerance=3)
            if text:
                full_raw_text += text + "\n"

    # Fix Gap 2: Guard against scanned or image-only documents lacking an OCR text layer
    if not full_raw_text.strip():
        raise ValueError(
            "No text layer could be extracted from this document. "
            "The PDF may be scanned or image-based. Optical Character Recognition (OCR) is not currently supported."
        )

    # --- INJECTION FIREWALL LAYER ---
    injection_patterns = [
        r"(?i)ignore (all )?prior instructions",
        r"(?i)system prompt bypass",
        r"(?i)override original compliance controls",
        r"(?i)disregard (all |any |previous |prior )?instructions",
        r"(?i)you are now( operating as| a)?",
        r"(?i)new (system |base |core )?instructions",
        r"(?i)act as (if you are|an? )",
        r"(?i)jailbreak",
        r"(?i)do not follow",
        r"(?i)forget (all |your |previous )?instructions"
    ]
    
    for pattern in injection_patterns:
        if re.search(pattern, full_raw_text):
            # Fix Bug 1: Raise a catchable ValueError instead of executing a fatal sys.exit()
            raise ValueError("Adversarial security risk state detected in document body. Pipeline execution terminated.")

    # --- DYNAMIC MASKING LAYER ---
    sanitized_text = full_raw_text.replace(vendor_name, "[TARGET_VENDOR_MASK]")
    if product_name:
        sanitized_text = sanitized_text.replace(product_name, "[TARGET_PRODUCT_MASK]")

    # Mask High-Risk Structural Infrastructure Patterns (IPs, Emails)
    sanitized_text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[INTERNAL_IP_ADDRESS]', sanitized_text)
    sanitized_text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL_ADDRESS]', sanitized_text)
    sanitized_text = re.sub(r'\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b', '[REDACTED_PHONE_NUMBER]', sanitized_text)

    return sanitized_text