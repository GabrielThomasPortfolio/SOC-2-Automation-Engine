# 🛡️ Secure Automated SOC 2 Parsing & TPRM Engine

A production-grade, privacy-first automation tool designed to accelerate Third-Party Risk Management (TPRM) workflows. This engine processes unstructured SOC 2 Type II PDF reports, executes a local "shift-left" data-masking pipeline, extracts structured auditing insights via a validated LLM schema, and programmatically eliminates hallucinations.

## 🏗️ Architectural Guardrails

Unlike standard LLM implementations, this engine enforces strict data-minimization and security boundaries before any data leaves the local machine:

1. **Shift-Left Data Masking (`utils/sanitizer.py`):** A local, deterministic regex firewall strips high-risk network indicators (Internal IP addresses), sensitive URLs, system paths, and specific PII strings before data egress to cloud APIs.
2. **Structured JSON Enforcement (`utils/extractor.py`):** Uses Pydantic schemas via the `instructor` library to force the LLM to map messy audit prose into precise, predictable object structures (Audit Firm, Opinion Type, Testing Exceptions, and CUECs).
3. **Alphanumeric Grounding Filter:** A post-extraction validation gate cross-references the LLM's cited source quotes against the sanitized document text, automatically dropping ungrounded or hallucinated entries while remaining resilient to PDF layout word-wrapping artifacts.

---

## 🛠️ Tech Stack & Dependencies

* **Frontend:** Streamlit
* **Orchestration & Validation:** Pydantic, Instructor (OpenAI)
* **Text Extraction:** pdfplumber
* **Environment Management:** python-dotenv

---

## 🚀 Local Deployment Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/GabrielThomasPortfolio/SOC-2-Automation-Engine.git](https://github.com/GabrielThomasPortfolio/SOC-2-Automation-Engine.git)
   cd SOC-2-Automation-Engine
Configure your environment variables:
Create a secure .env file in the root directory:

Code snippet
OPENAI_API_KEY=sk-proj-your-restricted-key-here
Install dependencies and launch:


python -m venv venv
source venv/bin/activate  # On Windows use: .\venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py