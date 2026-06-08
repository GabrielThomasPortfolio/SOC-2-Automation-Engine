import pytest
from utils.extractor import verify_quote_grounding

def test_perfect_quote_grounding_alignment():
    """Asserts that an exact verbatim matching string passes the grounding gate cleanly."""
    raw_text = "The auditor noted that logical access parameters were fully operational across all clusters."
    quote = "logical access parameters were fully operational"
    
    assert verify_quote_grounding(quote, raw_text) is True

def test_alphanumeric_line_break_resilience():
    """Verifies that the grounding engine is completely blind to PDF layout word-wrapping artifacts."""
    # Simulating a nasty layout text break across columns
    raw_text = "Please notify security via email (offboarding@nexuscore\nsystems.com) immediately."
    # The LLM outputs a clean, healed string token
    llm_quote = "email (offboarding@nexuscore-systems.com)"
    
    assert verify_quote_grounding(llm_quote, raw_text) is True

def test_hallucination_interception():
    """Asserts that if the LLM subtly alters, changes terms, or invents details, it fails validation."""
    raw_text = "Testing identified three instances where engineer privileges lacked management ticket approval."
    fabricated_llm_quote = "Testing identified twenty instances where engineers lacked approvals."
    
    assert verify_quote_grounding(fabricated_llm_quote, raw_text) is False