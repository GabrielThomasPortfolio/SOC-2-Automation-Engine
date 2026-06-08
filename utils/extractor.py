import os
import re
from typing import List
from pydantic import BaseModel, Field
import instructor
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# --- PYDANTIC SCHEMAS ---
class SOC2Exception(BaseModel):
    control_id: str = Field(description="The TSC control ID, e.g., CC6.1, CC7.2, or table reference.")
    control_description: str = Field(description="A brief description of the control that experienced an issue.")
    exception_details: str = Field(description="The precise details of the failure or deviation noted by the auditor.")
    exact_source_quote: str = Field(description="The EXACT verbatim text string from the document showing this exception.")

class ComplementaryUserControl(BaseModel):
    cuec_id: str = Field(description="The identifier or number for the user control requirement.")
    description: str = Field(description="The specific security action the customer must take to satisfy this control.")
    exact_source_quote: str = Field(description="The EXACT verbatim text string from the document showing this requirement.")

class SOC2ReportAnalysis(BaseModel):
    audit_firm: str = Field(description="The accounting/auditing firm that signed off on the report.")
    opinion_type: str = Field(description="The auditor's opinion: Unqualified (Clean), Qualified (Modified), Adverse, or Disclaimer.")
    exceptions: List[SOC2Exception] = Field(default=[], description="List of all exceptions discovered in the report.")
    user_controls: List[ComplementaryUserControl] = Field(default=[], description="List of all Complementary User Entity Controls (CUECs) required.")


# --- RESILIENT TEXT GROUNDING CHECK ---
def verify_quote_grounding(quote: str, raw_text: str) -> bool:
    if not quote or quote.strip() == "":
        return False
        
    tag_pattern = r'\[[A-Z0-9_]+\]'
    normalized_quote = re.sub(tag_pattern, '', quote)
    normalized_raw = re.sub(tag_pattern, '', raw_text)
    
    clean_quote = re.sub(r'[^a-zA-Z0-9]', '', normalized_quote).lower()
    clean_raw = re.sub(r'[^a-zA-Z0-9]', '', normalized_raw).lower()
    
    return clean_quote in clean_raw


# --- CORE PROCESSING INTERFACE ---
def extract_soc2_insights(sanitized_text: str) -> SOC2ReportAnalysis:
    """Runs structural extraction safely with localized context protections."""
    
    # Initialize the OpenAI client lazily inside the runtime thread
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise EnvironmentError("Missing Authentication: The OPENAI_API_KEY environment variable is not configured.")
        
    client = instructor.from_openai(OpenAI(api_key=api_key))

    extracted_data: SOC2ReportAnalysis = client.chat.completions.create(
        model="gpt-4o-mini",
        response_model=SOC2ReportAnalysis,
        temperature=0.0,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an expert technical GRC auditor specializing in third-party risk management (TPRM).\n"
                    "Analyze the provided text of a SOC 2 report and map the targets into your strict structured response schema.\n"
                    "CRITICAL: The 'exact_source_quote' field must be extracted completely verbatim. Do not summarize strings."
                )
            },
            {
                "role": "user",
                "content": f"Sanitized SOC 2 Document Text:\n\n{sanitized_text}"
            }
        ]
    )

    # Validate output allocations against the grounding matrix
    validated_exceptions = [exc for exc in extracted_data.exceptions if verify_quote_grounding(exc.exact_source_quote, sanitized_text)]
    validated_cuecs = [cuec for cuec in extracted_data.user_controls if verify_quote_grounding(cuec.exact_source_quote, sanitized_text)]

    extracted_data.exceptions = validated_exceptions
    extracted_data.user_controls = validated_cuecs

    return extracted_data