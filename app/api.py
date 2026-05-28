import aiosqlite
import os
import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.ai_agent import analyze_attack
from app.firewall import add_to_blocklist, remove_from_blocklist, load_blocklist
from app.logger import DB_PATH

router = APIRouter()


# ── Attacks feed ─────────────────────────────────────────────────────────────

@router.get("/attacks")
async def get_attacks(limit: int = 50, offset: int = 0):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM attacks ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ) as cursor:
            rows = await cursor.fetchall()
    return JSONResponse([dict(r) for r in rows])


@router.get("/attacks/{attack_id}")
async def get_attack(attack_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM attacks WHERE id=?", (attack_id,)) as cursor:
            row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return JSONResponse(dict(row))


@router.get("/stats")
async def get_stats():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        total = (await (await db.execute("SELECT COUNT(*) as c FROM attacks")).fetchone())["c"]
        blocked = (await (await db.execute("SELECT COUNT(*) as c FROM attacks WHERE blocked=1")).fetchone())["c"]
        unique_ips = (await (await db.execute("SELECT COUNT(DISTINCT ip) as c FROM attacks")).fetchone())["c"]

        async with db.execute(
            "SELECT attack_type, COUNT(*) as cnt FROM attacks WHERE attack_type IS NOT NULL GROUP BY attack_type ORDER BY cnt DESC LIMIT 10"
        ) as cur:
            attack_types = [dict(r) for r in await cur.fetchall()]

        async with db.execute(
            "SELECT country, COUNT(*) as cnt FROM attacks GROUP BY country ORDER BY cnt DESC LIMIT 10"
        ) as cur:
            top_countries = [dict(r) for r in await cur.fetchall()]

        async with db.execute(
            "SELECT ip, COUNT(*) as cnt FROM attacks GROUP BY ip ORDER BY cnt DESC LIMIT 10"
        ) as cur:
            top_ips = [dict(r) for r in await cur.fetchall()]

        async with db.execute(
            "SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt FROM attacks GROUP BY hour ORDER BY hour"
        ) as cur:
            by_hour = [dict(r) for r in await cur.fetchall()]

    return JSONResponse({
        "total": total,
        "blocked": blocked,
        "unique_ips": unique_ips,
        "attack_types": attack_types,
        "top_countries": top_countries,
        "top_ips": top_ips,
        "by_hour": by_hour,
    })


# ── AI Analysis ──────────────────────────────────────────────────────────────

@router.post("/analyze/{attack_id}")
async def analyze_single(attack_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM attacks WHERE id=?", (attack_id,)) as cursor:
            row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Attack not found")

    result = await analyze_attack(dict(row))

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE attacks SET attack_type=?, severity=?, ai_summary=? WHERE id=?",
            (result["attack_type"], result["severity"], result["summary"], attack_id)
        )
        await db.commit()

    # Auto-add to blocklist if AI recommends blocking and firewall is on
    if result.get("recommend_block") and os.getenv("FIREWALL_ENABLED", "off") == "on":
        await add_to_blocklist(dict(row)["ip"])

    return JSONResponse(result)


@router.post("/analyze-batch")
async def analyze_batch(limit: int = 20):
    """Analyze the most recent unanalyzed attacks."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM attacks WHERE attack_type IS NULL ORDER BY id DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = [dict(r) for r in await cursor.fetchall()]

    results = []
    for row in rows:
        result = await analyze_attack(row)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE attacks SET attack_type=?, severity=?, ai_summary=? WHERE id=?",
                (result["attack_type"], result["severity"], result["summary"], row["id"])
            )
            await db.commit()
        results.append({"id": row["id"], **result})

    return JSONResponse({"analyzed": len(results), "results": results})


# ── Firewall control ──────────────────────────────────────────────────────────

class FirewallToggle(BaseModel):
    enabled: bool


@router.post("/firewall/toggle")
async def toggle_firewall(body: FirewallToggle):
    # In production on Railway, this sets the in-process env var
    # For persistence across restarts, set FIREWALL_ENABLED in Railway env vars
    os.environ["FIREWALL_ENABLED"] = "on" if body.enabled else "off"
    return JSONResponse({"firewall": os.getenv("FIREWALL_ENABLED")})


@router.get("/firewall/status")
async def firewall_status():
    blocklist = load_blocklist()
    return JSONResponse({
        "enabled": os.getenv("FIREWALL_ENABLED", "off") == "on",
        "blocked_ips": list(blocklist),
        "blocked_count": len(blocklist),
    })


class IPAction(BaseModel):
    ip: str


@router.post("/firewall/block")
async def block_ip(body: IPAction):
    await add_to_blocklist(body.ip)
    return JSONResponse({"blocked": body.ip})


@router.post("/firewall/unblock")
async def unblock_ip(body: IPAction):
    await remove_from_blocklist(body.ip)
    return JSONResponse({"unblocked": body.ip})
