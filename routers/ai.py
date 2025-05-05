import json
import logging
import os
import re
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException
import google.generativeai as genai
from pydantic import BaseModel

from tools.parser import fix_regex_pattern, parse_log_file

load_dotenv()
api_key=os.getenv("GOOGLE_API_KEY")
genai.configure(api_key=api_key)

model = genai.GenerativeModel('gemini-2.0-flash')
router = APIRouter(tags = ["ai"])
logger = logging.getLogger(__name__)
@router.get("/ai/{prompt}")
async def generate_text(prompt: str):
    """Generates text using the Gemini API."""
    try:
        response = model.generate_content(prompt)
        return {"generated_text": response.text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class LogRequest(BaseModel):
    rows: str  # Ensure this is a string to receive the log data properly

@router.post("/ai/get_log_pattern")
async def generate_pattern(request: LogRequest):
    """Génère un regex pattern pour parser un fichier de logs."""

    prompt = f"""
    I have a log file, and I need a regex pattern (log_pattern) to parse its entries in Python. Below are the first 10 lines:

    {request.rows}

    - Use **named capture groups** like `(?P<group_name>...)` with the following exact group names if they are exist:
    - `ip`: The client IP address
    - `timestamp`: The date and time
    - `method`: The HTTP request method
    - `url`: The requested path or URL
    - `status`: The HTTP status code
    - `response_size`: The size of the response
    - `referer`: The referrer URL (optional)
    - `user_agent`: The user agent string
    - `protocol`: The protocol (optional, can be null)
    - `src_port`: The source port (optional, can be null)
    - `dest_port`: The destination port (optional, can be null)
    - `message`: An optional message field (can be null)
    - `level`: The log level (optional, can be null)
    - `component`: The log component (optional, can be null)
    - `log_id`: The log ID (optional, can be null)
    - `remote_logname`: The remote log name (optional, can be null)
    - `user`: The user (optional, can be null)
    - `request`: The request (optional, can be null)
    - `pid`: The process ID (optional, can be null)
    - `tid`: The thread ID (optional, can be null)
    - `module`: The module (optional, can be null)
    - `event_id`: The event ID (optional, can be null)
    - `entry_type`: The entry type (optional, can be null)
    - `provider_name`: The provider name (optional, can be null)
    - `computer_name`: The computer name (optional, can be null)
    - `task_display_name`: The task display name (optional, can be null)
    - `level_display_name`: The level display name (optional, can be null)
    - `account_name`: The account name (optional, can be null)
    - `run_as_user`: The user running the request (optional, can be null)
    - `hostname`: The hostname (optional, can be null)

    - **Return JSON format only**:
    ```json
    {{
        "regex_pattern": "Your generated regex pattern here"
    }}
    ```
    """

    try:
        # Ensure request is valid
        if not request.rows or not request.rows.strip():
            logger.error("Log rows are empty or missing.")
            raise HTTPException(status_code=422, detail="Log rows cannot be empty.")

        # Get AI response
        response = model.generate_content(prompt)

        # Validate AI response
        if not response or not hasattr(response, "text") or not response.text.strip():
            logger.error("Invalid response from AI model")
            raise HTTPException(status_code=500, detail="AI model response is invalid.")

        response_text = response.text.strip()

        # 🔥 Fix: Remove ```json ... ``` wrapper
        if response_text.startswith("```json"):
            response_text = response_text[7:]  # Remove leading ```json
        if response_text.endswith("```"):
            response_text = response_text[:-3]  # Remove trailing ```

        # Parse JSON response
        try:
            response_json = json.loads(response_text)
            regex_pattern = response_json.get("regex_pattern", "").strip()
            if not regex_pattern:
                logger.error("Regex pattern not found in AI response.")
                raise ValueError("Regex pattern is missing in the response.")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {str(e)}")
            raise HTTPException(status_code=500, detail="AI response is not valid JSON.")

        # Validate regex pattern
        try:
            compiled_regex = re.compile(regex_pattern)
        except re.error as e:
            logger.error(f"Invalid regex pattern: {str(e)}")
            raise HTTPException(status_code=500, detail="Generated regex pattern is invalid.")

        # Log line for testing
        log_line = request.rows.split('\n')[0]

        # Test regex match
        match = compiled_regex.match(log_line)
        match_groups = match.groupdict() if match else None
        fixed_pattern = fix_regex_pattern(regex_pattern)
        parsed_rows = parse_log_file(request.rows, fixed_pattern)
        return {"regex_pattern": fixed_pattern, "match_groups": match_groups,"rows":parsed_rows}

    except HTTPException as e:
        logger.error(f"HTTP Exception: {e.detail}")
        raise e
    except Exception as e:
        logger.exception("Error occurred while generating log pattern.")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")