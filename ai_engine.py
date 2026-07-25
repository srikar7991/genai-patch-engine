import re
import requests

OLLAMA_GENERATE_URL = "http://localhost:11434/api/generate"
MODEL = "codellama:7b"


def generate_remediation_script(cve_id: str, description: str, target_os: str) -> str:
    prompt = f"""You are a security remediation assistant. Generate a shell script to remediate the following vulnerability.

CVE ID: {cve_id}
Target OS: {target_os}
Description: {description}

STRICT OUTPUT RULES (mandatory):
- Output ONLY executable shell code (bash/sh). No markdown, no code fences, no explanations.
- Do NOT include comments, prose, or labels before or after the script.
- The first character of your response must be valid shell (e.g. #!/bin/bash or a command).
- Use only safe, targeted remediation commands appropriate for {target_os}.
- Do NOT use destructive commands (no rm -rf /, mkfs, dd against disks, fork bombs, etc.).

Respond with the script body only."""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
    }

    response = requests.post(OLLAMA_GENERATE_URL, json=payload, timeout=120)
    response.raise_for_status()
    data = response.json()
    raw_script = data.get("response", "").strip()

    # --- PYTHON SANITIZATION GUARDRAIL ---
    # Removes ```bash, ```sh, or closing ``` tags if the LLM included them
    clean_script = re.sub(r"^```(?:bash|sh)?\n?", "", raw_script, flags=re.IGNORECASE)
    clean_script = re.sub(r"\n?```$", "", clean_script).strip()

    return clean_script