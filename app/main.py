from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import time
import os

from app.logger import log_request
from app.firewall import firewall_check
from app.api import router as api_router

app = FastAPI(docs_url=None, redoc_url=None)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.include_router(api_router, prefix="/internal")


@app.middleware("http")
async def honeypot_middleware(request: Request, call_next):
    start = time.time()
    path = request.url.path

    # skip logging for dashboard, internal API, and static files
    if path == "/" or path.startswith("/internal") or path.startswith("/static"):
        return await call_next(request)

    body = await request.body()

    fw_result = await firewall_check(request)
    if fw_result["blocked"]:
        await log_request(request, body, blocked=True, block_reason=fw_result["reason"])
        return Response(
            content="403 Forbidden",
            status_code=403,
            media_type="text/plain"
        )

    response = await call_next(request)
    duration_ms = round((time.time() - start) * 1000, 2)
    await log_request(request, body, blocked=False, duration_ms=duration_ms)
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


# fake router registered last so it never intercepts / or /internal
from app.fake_endpoints import router as fake_router
app.include_router(fake_router)
