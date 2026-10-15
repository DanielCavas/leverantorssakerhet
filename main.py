"""
Leverantörssäkerhetsbedömning – FastAPI application.
Scans vendor websites and evaluates them against K1–K4 classification requirements.
"""

from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from classification import CLASSIFICATION_LEVELS, REQUIREMENTS, get_cumulative_requirements
from scanner import scan_vendor

app = FastAPI(title="Leverantörssäkerhetsbedömning", version="1.0.0")

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class ScanRequest(BaseModel):
    url: str
    level: str  # K1, K2, K3, K4


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/levels")
async def get_levels():
    levels = []
    for key, val in CLASSIFICATION_LEVELS.items():
        reqs = get_cumulative_requirements(key)
        levels.append({
            "id": key,
            "name": val["name"],
            "description": val["description"],
            "requirement_count": len(reqs),
        })
    return JSONResponse(levels)


@app.get("/api/requirements/{level}")
async def get_requirements(level: str):
    if level not in CLASSIFICATION_LEVELS:
        return JSONResponse({"error": "Invalid level"}, status_code=400)
    reqs = get_cumulative_requirements(level)
    return JSONResponse([asdict(r) for r in reqs])


@app.post("/api/scan")
async def perform_scan(req: ScanRequest):
    if req.level not in CLASSIFICATION_LEVELS:
        return JSONResponse({"error": "Invalid classification level"}, status_code=400)
    if not req.url.strip():
        return JSONResponse({"error": "URL is required"}, status_code=400)

    result = await scan_vendor(req.url.strip(), req.level)
    return JSONResponse(asdict(result))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
