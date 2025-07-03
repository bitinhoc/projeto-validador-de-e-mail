from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List
import asyncio
from app.validador_email import EmailValidatorAsync, generate_localparts

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

class EmailInput(BaseModel):
    first: str
    middle: str = ""
    last: str = ""
    extras: List[str] = []
    domain: str
    light_mode: bool = False

@app.post("/validate")
async def validate_emails(data: EmailInput):
    localparts = generate_localparts(data.first, data.middle, data.last, data.extras)
    emails = [f"{lp}@{data.domain}" for lp in localparts]
    validator = EmailValidatorAsync(data.domain, concurrency=10, light_mode=data.light_mode)
    results = await asyncio.gather(*(validator.validate(e) for e in emails))
    confirmed = [e for e, ok, _ in results if ok]

    return {
        "confirmed": confirmed,
        "total_tested": len(results),
        "catch_all": await validator.is_catch_all()
    }

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return FileResponse("static/index.html")
