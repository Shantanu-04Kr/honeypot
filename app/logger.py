import aiosqlite
import json
import os
from datetime import datetime, timezone
from fastapi import Request
import httpx

DB_PATH = os.getenv("DB_PATH", "logs/honeypot.db")

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS attacks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    ip           TEXT NOT NULL,
    country      TEXT,
    city         TEXT,
    isp          TEXT,
    is_proxy     INTEGER DEFAULT 0,
    is_tor       INTEGER DEFAULT 0,
    method       TEXT,
    path         TEXT,
    query_string TEXT,
    headers      TEXT,
    payload      TEXT,
    user_agent   TEXT,
    attack_type  TEXT,
    severity     TEXT,
    ai_summary   TEXT,
    firewall     TEXT DEFAULT 'off',
    blocked      INTEGER DEFAULT 0,
    block_reason TEXT,
    duration_ms  REAL
)
"""


async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_TABLE)
        await db.commit()


async def get_geo(ip: str) -> dict:
    # Skip for private/loopback IPs
    if ip in ("127.0.0.1", "::1") or ip.startswith("192.168.") or ip.startswith("10."):
        return {"country": "Local", "city": "Local", "isp": "Local", "proxy": False, "tor": False}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,proxy,hosting,query")
            if r.status_code == 200:
                d = r.json()
                return {
                    "country": d.get("country", "Unknown"),
                    "city": d.get("city", "Unknown"),
                    "isp": d.get("isp", "Unknown"),
                    "proxy": d.get("proxy", False),
                    "tor": d.get("hosting", False),
                }
    except Exception:
        pass
    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "proxy": False, "tor": False}


async def log_request(
    request: Request,
    body: bytes,
    blocked: bool = False,
    block_reason: str = None,
    duration_ms: float = None
):
    ip = request.headers.get("x-forwarded-for", request.client.host).split(",")[0].strip()
    geo = await get_geo(ip)
    firewall_state = os.getenv("FIREWALL_ENABLED", "off")

    payload_str = ""
    try:
        payload_str = body.decode("utf-8", errors="replace")[:2000]
    except Exception:
        pass

    headers_dict = dict(request.headers)
    headers_dict.pop("cookie", None)  # don't log cookies

    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "is_proxy": int(geo["proxy"]),
        "is_tor": int(geo["tor"]),
        "method": request.method,
        "path": request.url.path,
        "query_string": str(request.query_params),
        "headers": json.dumps(headers_dict),
        "payload": payload_str,
        "user_agent": request.headers.get("user-agent", ""),
        "firewall": firewall_state,
        "blocked": int(blocked),
        "block_reason": block_reason,
        "duration_ms": duration_ms,
    }

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO attacks
            (timestamp, ip, country, city, isp, is_proxy, is_tor,
             method, path, query_string, headers, payload, user_agent,
             firewall, blocked, block_reason, duration_ms)
            VALUES
            (:timestamp, :ip, :country, :city, :isp, :is_proxy, :is_tor,
             :method, :path, :query_string, :headers, :payload, :user_agent,
             :firewall, :blocked, :block_reason, :duration_ms)
        """, row)
        await db.commit()
