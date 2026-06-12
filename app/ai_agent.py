import os
import json
import httpx

GROQ_KEY = os.getenv("GROQ_API_KEY", "")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")

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


def build_prompt(attack_row: dict) -> str:
    headers_preview = {}
    try:
        h = json.loads(attack_row.get("headers", "{}"))
        for k in ["user-agent", "content-type", "accept", "referer", "origin"]:
            if k in h:
                headers_preview[k] = h[k]
    except Exception:
        pass

    return ANALYSIS_PROMPT.format(
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


async def analyze_with_groq(prompt: str) -> dict:
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.1-8b-instant",
                "max_tokens": 600,
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity analyst. Always respond with valid JSON only. No markdown, no explanation, just the JSON object."},
                    {"role": "user", "content": prompt}
                ],
            }
        )
        r.raise_for_status()
        data = r.json()
        text = data["choices"][0]["message"]["content"].strip()
        # Strip markdown code blocks if model adds them
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())


async def analyze_attack(attack_row: dict) -> dict:
    prompt = build_prompt(attack_row)
    result = None

    if GROQ_KEY:
        try:
            result = await analyze_with_groq(prompt)
            print(f"[AI] Groq analysis OK: {result.get('attack_type')}")
        except Exception as e:
            print(f"[AI] Groq failed: {e}")

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
