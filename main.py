# main.py
# The core backend application for Guardian Shield

import os
import subprocess
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import httpx
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Initialize the FastAPI application
app = FastAPI(
    title="Guardian Shield API",
    description="The AI-powered backend for the Guardian Shield cybersecurity platform.",
    version="0.2.0-godmode",
)

# --- Pydantic Models ---
# Define the structure of the data we expect in requests and responses

class ScanRequest(BaseModel):
    """The request model for initiating a new scan."""
    url: str

class FindingDetail(BaseModel):
    """A detailed, AI-analyzed finding."""
    title: str
    severity: str
    what_it_is: str = Field(..., description="A one-sentence explanation in plain English.")
    business_impact: str = Field(..., description="The potential business impact (e.g., data loss, reputation damage).")
    how_to_fix: str
    threat_level: str = Field(..., description="Current real-world threat level (e.g., 'Actively Exploited', 'Potential Target').")


class ScanResult(BaseModel):
    """The response model for returning the simplified AI report."""
    verdict: str
    summary: str
    findings: list[FindingDetail]

# --- API Endpoints ---

@app.get("/", tags=["Status"])
async def read_root():
    """A simple endpoint to check if the API is running."""
    return {"status": "Guardian Shield API is running"}


@app.post("/scan", response_model=ScanResult, tags=["Scanning"])
async def create_scan(request: ScanRequest):
    """
    The main endpoint to initiate a security scan on a given URL.
    This is where the core logic will reside.
    """
    target_url = request.url
    print(f"Received scan request for URL: {target_url}")

    # --- Phase 1: Run Security Scanners (The "Checker") ---
    # This now calls a function that runs REAL security tools.
    try:
        raw_scan_data = run_scanners(target_url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running security scanners: {e}")

    # --- Phase 2: Get AI Validation (The "Validator") ---
    # Send the real, raw data to the Gemini API for god-level analysis.
    try:
        ai_report = await get_ai_validation(raw_scan_data)
        return ai_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting AI validation: {e}")


# --- Helper Functions ---

def run_scanners(url: str) -> dict:
    """
    Runs real command-line security tools and returns their combined output.
    NOTE: This requires the tools (e.g., Nuclei) to be installed on the server
    where this Python application is running.
    """
    print(f"Starting real scanners for {url}...")
    combined_results = {"vulnerabilities": []}

    # --- Run Nuclei Scanner ---
    # Nuclei is a powerful vulnerability scanner.
    try:
        # The command to run Nuclei and get JSON output
        command = ["nuclei", "-u", url, "-json", "-silent"]
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300) # 5-minute timeout

        # Nuclei outputs JSON objects line by line, so we parse each line
        for line in result.stdout.strip().split('\n'):
            if line:
                scan_item = json.loads(line)
                # We simplify the output to a common format for the AI
                finding = {
                    "tool": "Nuclei",
                    "id": scan_item.get("template-id"),
                    "name": scan_item.get("info", {}).get("name"),
                    "severity": scan_item.get("info", {}).get("severity", "info").upper(),
                    "description": scan_item.get("info", {}).get("description"),
                    "matched-at": scan_item.get("matched-at")
                }
                combined_results["vulnerabilities"].append(finding)
    except FileNotFoundError:
        raise RuntimeError("The 'nuclei' command was not found. Please ensure Nuclei is installed and in the system's PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Nuclei scan failed: {e.stderr}")
        # Don't raise an error, just means no results or a scan error
    except Exception as e:
        print(f"An unexpected error occurred while running Nuclei: {e}")

    # --- Placeholder for other scanners (e.g., Trivy for container images) ---
    # You would add more subprocess calls here to run other tools.

    if not combined_results["vulnerabilities"]:
         return {"vulnerabilities": [{"id": "CLEAN-SCAN", "name": "No issues found", "severity": "INFO", "description": "Initial scan found no immediate issues."}]}

    return combined_results


async def get_ai_validation(scan_data: dict) -> dict:
    """
    Sends the raw scan data to the Gemini API for "god-level" analysis and returns the structured JSON report.
    """
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY not found in environment variables.")

    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_api_key}"

    # This is the "God Mode" prompt. It asks the AI to think on a much deeper level.
    prompt = f"""
        You are "Guardian Oracle", a world-class cybersecurity strategist and threat analyst. You are not just a translator; you are an intelligence engine. Your analysis is sharp, business-focused, and considers the global threat landscape.

        You will receive a JSON object containing raw vulnerability data from multiple security scanners. Your task is to perform a holistic threat analysis and generate a strategic, actionable intelligence report in JSON format.

        Here is the raw scan data:
        {json.dumps(scan_data, indent=2)}

        Perform the following actions with expert precision:
        1.  **Correlate Findings:** Analyze all findings together. Do any vulnerabilities chain together to create a more severe risk?
        2.  **Assess Business Impact:** Move beyond technical descriptions. What is the tangible business risk? (e.g., "Complete customer data loss," "Website defacement and reputation damage," "Minor operational disruption").
        3.  **Evaluate Real-World Threat Level:** For each major finding, determine its current threat level based on your knowledge of active exploits. Use terms like 'Actively Exploited in the Wild', 'High-Profile Target', 'Opportunistic Target', or 'Low / Theoretical'.
        4.  **Determine Overall Verdict:** Based on the highest severity and threat level, issue a verdict: "GREEN" (safe), "YELLOW" (caution advised), or "RED" (critical risk).
        5.  **Generate Actionable Fixes:** Provide clear, prioritized steps for remediation. The advice should be practical for a small team or solo founder.
        6.  **Create a Strategic Summary:** Write a concise, executive-level summary of the application's security posture.

        Your final output MUST be a single, valid JSON object following the Pydantic model structure below. Do not add any text before or after the JSON object.

        {{
            "verdict": "GREEN" | "YELLOW" | "RED",
            "summary": "A strategic, executive-level summary of the security posture.",
            "findings": [
                {{
                    "title": "A simple, human-readable name for the issue.",
                    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
                    "what_it_is": "A one-sentence explanation in plain English.",
                    "business_impact": "The potential, tangible business impact.",
                    "how_to_fix": "A simple, actionable step-by-step guide with code snippets if applicable.",
                    "threat_level": "The real-world exploitability status."
                }}
            ]
        }}
    """

    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json"}
    }

    async with httpx.AsyncClient(timeout=90.0) as client:
        response = await client.post(api_url, json=payload)
        response.raise_for_status()
        result = response.json()

    try:
        json_text = result["candidates"][0]["content"]["parts"][0]["text"]
        # Use Pydantic to validate the AI's output against our model
        return ScanResult.model_validate_json(json_text)
    except (KeyError, IndexError, TypeError, Exception) as e:
        print(f"Error parsing or validating Gemini response: {e}")
        print(f"Full Gemini response: {result}")
        raise HTTPException(status_code=500, detail="Failed to parse or validate the AI's response.")

# To run this application:
# 1. Install Nuclei on your system: https://nuclei.projectdiscovery.io/
# 2. Install the dependencies: pip install -r requirements.txt
# 3. Create a file named .env and add your Gemini API key: GEMINI_API_KEY="your_api_key_here"
# 4. Start the server: uvicorn main:app --reload
