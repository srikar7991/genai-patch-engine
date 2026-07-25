from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from ai_engine import generate_remediation_script
from security import inspect_script_safety

app = FastAPI(title="GenAI Patch Engine")


class VulnerabilityPayload(BaseModel):
    cve_id: str = Field(..., min_length=1, description="CVE identifier")
    description: str = Field(..., min_length=1, description="Vulnerability description")
    target_os: str = Field(..., min_length=1, description="Target operating system")


@app.get("/")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/generate-patch")
def generate_patch(payload: VulnerabilityPayload) -> dict:
    try:
        script = generate_remediation_script(
            cve_id=payload.cve_id,
            description=payload.description,
            target_os=payload.target_os,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI engine error: {exc}") from exc

    safety = inspect_script_safety(script)

    return {
        "cve_id": payload.cve_id,
        "target_os": payload.target_os,
        "script": script,
        "safety": safety,
    }
