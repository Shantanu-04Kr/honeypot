import os
import json
import httpx
from datetime import datetime, timezone

ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")

ANALYSIS_PROMPT = """You are a cybersecurity analyst. Analyze this HTTP request captured by a honeypot server.

Request details:
- IP: {ip} | Country: {country} | City: {city} | ISP: {isp}
- Is Proxy/VPN: {is_proxy} | Is Hosting/Tor: {is_tor}
- Method: {method} | Path: {path}
- Query string: {query_string}
- User-Agent: {user_agent}
- Payload (first 500 chars): {payload}
- Headers (partial): {headers}

Respond ONLY with a valid JSON object, no markdown, no explanation:
{{
  "attack_type": "<one of: SQL Injection, XSS, Path Traversal, Brute Force, Reconnaissance, RCE Attempt, Credential Stuffing, Directory Enumeration, API Abuse, Web Scraping, Vulnerability Scan, Unknown>",
  "severity": "<critical|high|medium|low>",
  "confidence": "<high|medium|low>",
  "attacker_intent": "<one sentence>",
  "indicators": ["<indicator 1>", "<indicator 2>"],
  "recommend_block": <true|false>,
  "summary": "<2 sentence plain English summary>"
}}"""

async def analyze_with_claude(prompt: str) -> dict:
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5",
                "max_tokens": 600,
                "messages": [{"role": "user", "content": prompt}],
            }
        )
        print(f"[AI] Claude status: {r.status_code}")
        print(f"[AI] Claude response: {r.text[:300]}")
        r.raise_for_status()
        data = r.json()
        text = data["content"][0]["text"].strip()
        return json.loads(text)



async def analyze_with_openai(prompt: str) -> dict:
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini-2024-07-18",
                "max_tokens": 600,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "user", "content": prompt}],
            }
        )
        r.raise_for_status()
        data = r.json()
        return json.loads(data["choices"][0]["message"]["content"])


async def analyze_attack(attack_row: dict) -> dict:
    """Analyze a single attack log entry. Tries Claude first, falls back to OpenAI."""
    headers_preview = {}
    try:
        h = json.loads(attack_row.get("headers", "{}"))
        # Only show a few key headers to keep prompt short
        for k in ["user-agent", "content-type", "accept", "referer", "origin"]:
            if k in h:
                headers_preview[k] = h[k]
    except Exception:
        pass

    prompt = ANALYSIS_PROMPT.format(
        ip=attack_row.get("ip", ""),
        country=attack_row.get("country", "Unknown"),
        city=attack_row.get("city", "Unknown"),
        isp=attack_row.get("isp", "Unknown"),
        is_proxy=bool(attack_row.get("is_proxy", 0)),
        is_tor=bool(attack_row.get("is_tor", 0)),
        method=attack_row.get("method", "GET"),
        path=attack_row.get("path", "/"),
        query_string=attack_row.get("query_string", ""),
        user_agent=attack_row.get("user_agent", ""),
        payload=(attack_row.get("payload", "") or "")[:500],
        headers=json.dumps(headers_preview),
    )

    result = None

    # Try Claude first
    if ANTHROPIC_KEY:
        try:
            result = await analyze_with_claude(prompt)
        except Exception as e:
            print(f"[AI] Claude failed: {e}")

    # Fall back to OpenAI
    if result is None and OPENAI_KEY:
        try:
            result = await analyze_with_openai(prompt)
        except Exception as e:
            print(f"[AI] OpenAI failed: {e}")

    if result is None:
        result = {
            "attack_type": "Unknown",
            "severity": "low",
            "confidence": "low",
            "attacker_intent": "Could not analyze",
            "indicators": [],
            "recommend_block": False,
            "summary": "AI analysis unavailable. Check API keys.",
        }

    return result
