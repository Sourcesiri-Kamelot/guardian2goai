# main.py
# The core backend application for Guardian Shield

import os
import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Initialize the FastAPI application
app = FastAPI(
    title="Guardian Shield API",
    description="The AI-powered backend for the Guardian Shield cybersecurity platform.",
    version="0.1.0",
)

# --- Pydantic Models ---
# Define the structure of the data we expect in requests and responses

class ScanRequest(BaseModel):
    """The request model for initiating a new scan."""
    url: str

class ScanResult(BaseModel):
    """The response model for returning the simplified AI report."""
    verdict: str
    summary: str
    findings: list

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
    # In the MVP, we will use mock data. In the full version, we would
    # call command-line tools like Nuclei and Trivy here.
    try:
        # raw_scan_data = run_scanners(target_url) # Placeholder for real function
        raw_scan_data = get_mock_vulnerabilities() # Using mock data for now
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running security scanners: {e}")

    # --- Phase 2: Get AI Validation (The "Validator") ---
    # Send the raw data to the Gemini API for analysis.
    try:
        ai_report = await get_ai_validation(raw_scan_data)
        return ai_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting AI validation: {e}")


# --- Helper Functions ---

def run_scanners(url: str) -> dict:
    """
    A placeholder function to simulate running command-line security tools.
    This function would use Python's 'subprocess' module to execute tools
    like 'nuclei -u {url} -json' and parse their output.
    """
    # Example using subprocess (commented out for MVP):
    # command = ["nuclei", "-u", url, "-json"]
    # result = subprocess.run(command, capture_output=True, text=True, check=True)
    # nuclei_output = json.loads(result.stdout)
    # return {"nuclei": nuclei_output}
    print(f"Simulating scanners for {url}...")
    # This would return a complex JSON object in a real scenario
    return get_mock_vulnerabilities()


def get_mock_vulnerabilities() -> dict:
    """Provides mock vulnerability data for the MVP."""
    return {
        "vulnerabilities": [
            { "id": "CVE-2021-34527", "packageName": "old-image-library", "version": "1.2.3", "severity": "CRITICAL", "description": "Remote Code Execution vulnerability in image processing component." },
            { "id": "NUCLEI-MEDIUM-1", "checkName": "missing-hsts-header", "severity": "MEDIUM", "description": "The Strict-Transport-Security (HSTS) header is not set." },
            { "id": "NUCLEI-LOW-1", "checkName": "server-version-exposed", "severity": "LOW", "description": "The server is exposing its version number in the 'Server' header (nginx/1.18.0)." }
        ]
    }


async def get_ai_validation(scan_data: dict) -> dict:
    """

    Sends the raw scan data to the Gemini API and returns the structured JSON report.
    """
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY not found in environment variables.")

    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_api_key}"

    prompt = f"""
        You are "Guardian Shield AI", a cybersecurity analyst expert who explains complex security issues to non-technical founders. Your tone is calm, reassuring, and helpful, not alarming. You will receive a JSON object containing raw vulnerability data from a security scan. Your task is to analyze this data and generate a JSON response with a clear, simple report.
        Here is the raw scan data:
        {scan_data}
        Based on this data, perform the following actions:
        1. Determine an overall verdict: "GREEN" (no critical/high risks), "YELLOW" (medium/low risks only), or "RED" (at least one critical/high risk).
        2. For each vulnerability, create a simplified finding object containing:
            - "title": A simple, human-readable name for the issue.
            - "what_it_is": A one-sentence explanation in plain English.
            - "why_it_matters": A one-sentence explanation of the real-world risk.
            - "how_to_fix": A simple, actionable step-by-step guide. If it involves code, provide a small, clear snippet.
            - "severity": The original severity level (CRITICAL, HIGH, MEDIUM, LOW).
        Your final output MUST be a single, valid JSON object with the following structure:
        {{ "verdict": "GREEN" | "YELLOW" | "RED", "summary": "A one-sentence summary of the overall security posture.", "findings": [ {{ "title": "...", "what_it_is": "...", "why_it_matters": "...", "how_to_fix": "...", "severity": "..." }} ] }}
    """

    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json"}
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(api_url, json=payload)
        response.raise_for_status() # Will raise an exception for 4xx/5xx responses
        result = response.json()

    try:
        json_text = result["candidates"][0]["content"]["parts"][0]["text"]
        return ScanResult.model_validate_json(json_text)
    except (KeyError, IndexError, TypeError) as e:
        print(f"Error parsing Gemini response: {e}")
        print(f"Full Gemini response: {result}")
        raise HTTPException(status_code=500, detail="Failed to parse AI response.")

# To run this application:
# 1. Install the dependencies: pip install -r requirements.txt
# 2. Create a file named .env and add your Gemini API key: GEMINI_API_KEY="your_api_key_here"
# 3. Start the server: uvicorn main:app --reload
