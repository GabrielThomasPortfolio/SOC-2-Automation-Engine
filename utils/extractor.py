import os
from typing import List, Optional
from pydantic import BaseModel, Field
import instructor
from openai import OpenAI
from dotenv import load_dotenv

# Load variables from our secure .env file
load_dotenv()

# Initialize the Instructor-wrapped client for structured JSON enforcement
client = instructor.from_openai(OpenAI(api_key=os.getenv("OPENAI_API_KEY")))

# --- PYDANTIC SCHEMAS (Defining our exact output structure) ---

class SOC2Exception(BaseModel):
    """Schema for a single control failure or exception noted by the auditor."""
    control_id: str = Field(description="The TSC control ID, e.g., CC6.1, CC7.2, or table reference.")
    control_description: str = Field(description="A brief description of the control that experienced an issue.")
    exception_details: str = Field(description="The precise details of the failure or deviation noted by the auditor.")
    exact_source_quote: str = Field(description="The EXACT verbatim text string from the document showing this exception.")

class ComplementaryUserControl(BaseModel):
    """Schema for a control requirement the customer must implement (CUEC)."""
    cuec_id: str = Field(description="The identifier or number for the user control requirement.")
    description: str = Field(description="The specific security action the customer must take to satisfy this control.")
    exact_source_quote: str = Field(description="The EXACT verbatim text string from the document showing this requirement.")

class SOC2ReportAnalysis(BaseModel):
    """The master schema representing the final audited output."""
    audit_firm: str = Field(description="The accounting/auditing firm that signed off on the report.")
    opinion_type: str = Field(description="The auditor's opinion: Unqualified (Clean), Qualified (Modified), Adverse, or Disclaimer.")
    exceptions: List[SOC2Exception] = Field(default=[], description="List of all exceptions discovered in the report.")
    user_controls: List[ComplementaryUserControl] = Field(default=[], description="List of all Complementary User Entity Controls (CUECs) required.")


# --- GROUNDING & VALIDATION LAYER ---

import re

def verify_quote_grounding(quote: str, raw_text: str) -> bool:
    """
    ALPHANUMERIC VALIDATION GATE
    Verifies that the LLM's extracted sequence of words exists inside the source document,
    completely ignoring layout artifacts like line breaks, hyphens, punctuation, and spaces.
    """
    if not quote or quote.strip() == "":
        return False
        
    # 1. Regex to strip out any custom bracketed security tags first
    tag_pattern = r'\[[A-Z0-9_]+\]'
    normalized_quote = re.sub(tag_pattern, '', quote)
    normalized_raw = re.sub(tag_pattern, '', raw_text)
    
    # 2. Strip ALL non-alphanumeric characters and force lowercase
    # This turns "nexuscore\nsystems.com" and "nexuscore-systems.com" both into "nexuscoresystemscom"
    clean_quote = re.sub(r'[^a-zA-Z0-9]', '', normalized_quote).lower()
    clean_raw = re.sub(r'[^a-zA-Z0-9]', '', normalized_raw).lower()
    
    # 3. Execute the sequence containment check
    return clean_quote in clean_raw


# --- CORE EXTRACTION ENGINE ---

def extract_soc2_insights(sanitized_text: str) -> SOC2ReportAnalysis:
    """
    Passes sanitized text to the LLM and enforces structural schema output.
    Applies a deterministic post-extraction verification gate to clear out hallucinations.
    """
    print("🧠 Initiating structured extraction via Instructor...")
    
    # Using gpt-4o-mini as a high-performance, cost-efficient parser
    extracted_data: SOC2ReportAnalysis = client.chat.completions.create(
        model="gpt-4o-mini",
        response_model=SOC2ReportAnalysis,
        temperature=0.0, # Lock down creativity to maximize deterministic extraction
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an expert technical GRC auditor specializing in third-party risk management (TPRM).\n"
                    "Your task is to analyze the provided sanitized text of a SOC 2 Type II report.\n"
                    "Extract the audit firm, the overall opinion type, all testing exceptions/failures, and all Complementary User Entity Controls (CUECs).\n"
                    "CRITICAL: The 'exact_source_quote' field MUST be copied verbatim from the text. Do not summarize or alter the quote."
                )
            },
            {
                "role": "user",
                "content": f"Sanitized SOC 2 Document Text:\n\n{sanitized_text}"
            }
        ]
    )

    # --- Shift-Left Output Validation Gate ---
    print("🛡️ Guardrail Check: Validating LLM quotes against source text...")
    
    # Validate exceptions
    validated_exceptions = []
    for exc in extracted_data.exceptions:
        if verify_quote_grounding(exc.exact_source_quote, sanitized_text):
            validated_exceptions.append(exc)
        else:
            print(f"⚠️ Hallucination Alert: Dropped ungrounded exception quote -> '{exc.exact_source_quote[:40]}...'")

    # Validate CUECs
    validated_cuecs = []
    for cuec in extracted_data.user_controls:
        if verify_quote_grounding(cuec.exact_source_quote, sanitized_text):
            validated_cuecs.append(cuec)
        else:
            print(f"⚠️ Hallucination Alert: Dropped ungrounded CUEC quote -> '{cuec.exact_source_quote[:40]}...'")

    # Override the object data with the verified, grounded datasets
    extracted_data.exceptions = validated_exceptions
    extracted_data.user_controls = validated_cuecs

    return extracted_data