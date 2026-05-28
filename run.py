import asyncio
import uvicorn
import os
from app.logger import init_db


async def startup():
    await init_db()
    print("[honeypot] DB initialized")


if __name__ == "__main__":
    asyncio.run(startup())
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
    )
