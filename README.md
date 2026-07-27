# GenAI Patch Engine

A lightweight FastAPI service that turns vulnerability context (CVE ID, description, target OS) into **reviewable shell remediation scripts** using a **local** large language model. It is built for teams and lab environments that **do not** rely on a SIEM or centralized detection pipeline to drive patching workflows.

Instead of correlating alerts from Splunk, Elastic SIEM, or QRadar, callers submit structured vulnerability data over HTTP. The engine prompts [Ollama](https://ollama.com/) (`codellama:7b`), returns executable shell output, and runs a static safety scan before the response leaves the API.

---

## Architecture overview

### Why “non-SIEM”?

Enterprise patch orchestration often assumes:

- Detections normalized in a SIEM
- Ticketing tied to alert IDs and asset inventory from the same platform
- Playbooks triggered by correlation rules

**GenAI Patch Engine** takes a simpler path suitable for:

- Homelabs, air-gapped networks, and edge sites without SIEM licensing
- Red-team / blue-team exercises where you already know the CVE and OS
- CI or internal tools that ingest advisories (NVD, vendor bulletins) and need draft remediation scripts
- Prototyping “human-in-the-loop” patch suggestions before wiring a full SOAR stack

You provide **explicit inputs** (`cve_id`, `description`, `target_os`). The service does not ingest logs, agents, or SIEM exports.

### Design principles

| Layer | Responsibility |
|--------|----------------|
| **API (`main.py`)** | Validates payloads, orchestrates generation and safety audit, returns JSON |
| **AI engine (`ai_engine.py`)** | Builds a strict prompt and calls Ollama locally—no cloud API keys |
| **Security (`security.py`)** | Regex-based guardrails on generated shell; flags destructive patterns |

Generation is **assistive**, not autonomous: operators should review `script` and `safety.warnings` before running anything on production systems.

### ASCII architecture flow

```
                    Non-SIEM clients
              (curl, scripts, portals, CI)
                           |
                           |  POST /generate-patch
                           |  { cve_id, description, target_os }
                           v
                 +---------------------+
                 |   FastAPI (main.py) |
                 |   Pydantic validate |
                 +----------+----------+
                            |
              +-------------+-------------+
              |                           |
              v                           v
   +--------------------+      +----------------------+
   |  ai_engine.py      |      |  (after generation)  |
   |  build strict      |      |  security.py         |
   |  shell-only prompt |      |  inspect_script_     |
   +---------+----------+      |  safety()            |
             |                 +----------+-----------+
             | POST JSON                  |
             v                            |
   +--------------------+                |
   |  Ollama            |                |
   |  localhost:11434   |                |
   |  codellama:7b      |                |
   +---------+----------+                |
             |                            |
             |  raw shell text            |
             +------------+---------------+
                          |
                          v
                 +---------------------+
                 |  JSON response      |
                 |  script + safety    |
                 +---------------------+
                          |
                          v
                 Human review / optional
                 execution on target host
```

### Request lifecycle

1. Client sends a `VulnerabilityPayload` JSON body.
2. `generate_remediation_script()` calls Ollama’s `/api/generate` with rules that forbid markdown and commentary—**shell only**.
3. `inspect_script_safety()` scans the model output for known-dangerous constructs (e.g. `rm -rf /`, `mkfs`, fork bombs).
4. The API returns the script plus `is_safe` and a `warnings` list. A failed Ollama call yields HTTP **502**.

---

## Project structure

```
genai-patch-engine/
├── main.py          # FastAPI app and routes
├── ai_engine.py     # Ollama integration and prompting
├── security.py      # Static script safety inspection
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Prerequisites

- **Python 3.10+** (3.12 recommended)
- **[Ollama](https://ollama.com/download)** running locally
- Model pulled: `codellama:7b`

```bash
ollama pull codellama:7b
ollama serve   # default: http://localhost:11434
```

---

## Local setup

### 1. Clone and enter the repository

```bash
git clone <your-repo-url> genai-patch-engine
cd genai-patch-engine
```

### 2. Create a virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Start Ollama (if not already running)

Ensure `http://localhost:11434` is reachable and `codellama:7b` is available:

```bash
curl http://localhost:11434/api/tags
```

### 4. Run the API

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

- Health check: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- Interactive docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## API reference

### `GET /`

Health check.

**Response**

```json
{
  "status": "ok"
}
```

### `POST /generate-patch`

Generate a remediation shell script and safety report.

**Request body** (`application/json`)

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| `cve_id` | string | yes | CVE identifier (e.g. `CVE-2024-1234`) |
| `description` | string | yes | Human-readable vulnerability context |
| `target_os` | string | yes | Target platform (e.g. `Ubuntu 22.04`, `RHEL 9`) |

**Success response** (`200`)

| Field | Type | Description |
|--------|------|-------------|
| `cve_id` | string | Echo of request |
| `target_os` | string | Echo of request |
| `script` | string | Model-generated shell |
| `safety` | object | `{ "is_safe": boolean, "warnings": string[] }` |

**Error responses**

- `422` — Validation error (missing or empty fields)
- `502` — Ollama unreachable, model error, or other AI engine failure

---

## Sample JSON requests

### Ubuntu OpenSSL advisory (example)

**Request**

```bash
curl -s -X POST http://127.0.0.1:8000/generate-patch \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-XXXX",
    "description": "OpenSSL buffer overrun in TLS handshake; upgrade openssl/libssl packages to vendor-fixed versions and restart affected services.",
    "target_os": "Ubuntu 22.04 LTS"
  }'
```

**Example response shape**

```json
{
  "cve_id": "CVE-2024-XXXX",
  "target_os": "Ubuntu 22.04 LTS",
  "script": "#!/bin/bash\napt-get update && apt-get install -y --only-upgrade openssl libssl3\nsystemctl restart nginx || true",
  "safety": {
    "is_safe": true,
    "warnings": []
  }
}
```

*(Actual `script` content depends on the model; always verify before execution.)*

### RHEL / dnf-style context

```json
{
  "cve_id": "CVE-2023-YYYY",
  "description": "Privilege escalation in kernel module foo; apply latest kernel security update and reboot if required.",
  "target_os": "RHEL 9"
}
```

### Minimal payload (field names only)

```json
{
  "cve_id": "CVE-2021-44228",
  "description": "Log4Shell: remove vulnerable log4j JARs or upgrade to 2.17.1+ on Java applications.",
  "target_os": "Debian 12"
}
```

### Health check

```bash
curl -s http://127.0.0.1:8000/
```

---

## Safety inspection

`security.py` flags patterns including (non-exhaustive):

- Recursive delete of root (`rm -rf /` variants)
- `mkfs` and destructive `dd` to block devices
- Fork bombs
- Forced shutdown/reboot commands
- `chmod -R 777 /`
- `curl … | sh` / `wget … | sh`

When `is_safe` is `false`, treat the script as **blocked for automated use** until manually reviewed or regenerated.

The prompt also instructs the model to avoid destructive commands; the scanner is a **second line of defense**, not a guarantee of correctness or completeness.

---

## Configuration

| Setting | Location | Default |
|---------|----------|---------|
| Ollama URL | `ai_engine.py` → `OLLAMA_GENERATE_URL` | `http://localhost:11434/api/generate` |
| Model | `ai_engine.py` → `MODEL` | `codellama:7b` |
| Generate timeout | `ai_engine.py` | 120 seconds |

To use another local model, change `MODEL` and `ollama pull` the tag you need.

---

## Limitations and disclaimer

- LLM output can be **wrong**, incomplete, or unsafe despite prompts and scanning.
- This project does **not** replace vendor patches, change management, or SIEM-driven incident response.
- Run generated scripts only in isolated environments after human review.
- No authentication is built into the API; do not expose it to untrusted networks without a reverse proxy, TLS, and access controls.

---

## License

:)
