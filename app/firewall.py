import os
import re
import json
from fastapi import Request

# Loaded from blocklist file — updated by AI agent
BLOCKLIST_PATH = os.getenv("BLOCKLIST_PATH", "logs/blocklist.json")

# Common attack patterns (SQLi, XSS, path traversal, shell injection)
ATTACK_PATTERNS = [
    re.compile(r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b)", re.IGNORECASE),
    re.compile(r"(<script|javascript:|onerror=|onload=)", re.IGNORECASE),
    re.compile(r"(\.\.\/|\.\.\\|%2e%2e%2f)", re.IGNORECASE),
    re.compile(r"(\bexec\b|\beval\b|\bsystem\b|\bpassthru\b)", re.IGNORECASE),
    re.compile(r"(\bor\b\s+\d+=\d+|\band\b\s+\d+=\d+)", re.IGNORECASE),
    re.compile(r"(;|\||&&)\s*(ls|cat|wget|curl|bash|sh|nc)\b", re.IGNORECASE),
    re.compile(r"(\bDROP\b|\bTRUNCATE\b|\bDELETE\b.*\bFROM\b)", re.IGNORECASE),
]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster",
    "gobuster", "wfuzz", "burpsuite", "acunetix", "nessus", "openvas",
    "python-requests/2.2", "go-http-client/1.1",
]


def load_blocklist() -> set:
    try:
        if os.path.exists(BLOCKLIST_PATH):
            with open(BLOCKLIST_PATH) as f:
                data = json.load(f)
                return set(data.get("ips", []))
    except Exception:
        pass
    return set()


def save_blocklist(ips: set):
    os.makedirs(os.path.dirname(BLOCKLIST_PATH), exist_ok=True)
    with open(BLOCKLIST_PATH, "w") as f:
        json.dump({"ips": list(ips)}, f, indent=2)


async def firewall_check(request: Request) -> dict:
    """Returns {"blocked": bool, "reason": str | None}"""

    firewall_on = os.getenv("FIREWALL_ENABLED", "off").lower() == "on"
    if not firewall_on:
        return {"blocked": False, "reason": None}

    ip = request.headers.get("x-forwarded-for", request.client.host).split(",")[0].strip()

    # 1. Check IP blocklist
    blocklist = load_blocklist()
    if ip in blocklist:
        return {"blocked": True, "reason": f"IP {ip} is in blocklist"}

    user_agent = request.headers.get("user-agent", "").lower()

    # 2. Check suspicious user agents
    for ua in SUSPICIOUS_USER_AGENTS:
        if ua.lower() in user_agent:
            return {"blocked": True, "reason": f"Suspicious user-agent: {ua}"}

    # 3. Check URL path for attack patterns
    full_url = str(request.url)
    for pattern in ATTACK_PATTERNS:
        if pattern.search(full_url):
            return {"blocked": True, "reason": f"Attack pattern detected in URL: {pattern.pattern[:40]}"}

    return {"blocked": False, "reason": None}


async def add_to_blocklist(ip: str):
    blocklist = load_blocklist()
    blocklist.add(ip)
    save_blocklist(blocklist)


async def remove_from_blocklist(ip: str):
    blocklist = load_blocklist()
    blocklist.discard(ip)
    save_blocklist(blocklist)
