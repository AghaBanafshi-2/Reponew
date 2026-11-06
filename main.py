import asyncio
import json
import os
import hashlib
import secrets
import time
import aiofiles
from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("helloworld")

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title="helloworld", docs_url=None, redoc_url=None)

# ── Persistence ───────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "hw_state.json"
SECRET_FILE = DATA_DIR / "hw_secret.key"
SNI_FILE = Path(__file__).parent / "sni.txt"
SAVE_LOCK = asyncio.Lock()

def _load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if SECRET_FILE.exists():
            existing = SECRET_FILE.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        new_secret = secrets.token_urlsafe(32)
        SECRET_FILE.write_text(new_secret, encoding="utf-8")
        return new_secret
    except Exception as e:
        logger.warning(f"Could not persist SECRET_KEY: {e}")
        return secrets.token_urlsafe(32)

def _load_sni_list() -> list[str]:
    try:
        if SNI_FILE.exists():
            lines = SNI_FILE.read_text(encoding="utf-8").splitlines()
            return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    except Exception as e:
        logger.warning(f"Could not load sni.txt: {e}")
    return ["www.microsoft.com", "cdn.jsdelivr.net", "google.com"]

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": _load_or_create_secret(),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
    "fake_sni": os.environ.get("FAKE_SNI", "").strip(),
    "cipher_suites": os.environ.get(
        "CIPHER_SUITES",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
        "TLS_RSA_WITH_AES_128_GCM_SHA256:"
        "TLS_RSA_WITH_AES_256_GCM_SHA384:"
        "TLS_RSA_WITH_AES_128_CBC_SHA:"
        "TLS_RSA_WITH_AES_256_CBC_SHA"
    ).strip(),
    "sni_list": _load_sni_list(),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

async def load_state():
    global LINKS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = await f.read()
            data = json.loads(raw)
            LINKS.update(data.get("links", {}))
            logger.info(f"State loaded: {len(LINKS)} links")
    except Exception as e:
        logger.warning(f"Could not load state: {e}")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "links": dict(LINKS),
                "saved_at": datetime.now().isoformat(),
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.warning(f"Could not save state: {e}")

# ── In-memory state ───────────────────────────────────────────────────────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
activity_logs: deque = deque(maxlen=200)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

PROTOCOLS = ("vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one")
DEFAULT_PROTOCOL = "vless-ws"
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "unsafe")
DEFAULT_FINGERPRINT = "chrome"
DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
    "xhttp-stream-one": "h2,http/1.1",
}
DEFAULT_PORT = 443
MIN_PORT, MAX_PORT = 1, 65535
DEFAULT_SPEED_LIMIT = 0
SUBS: dict = {}

def log_activity(kind: str, message: str, level: str = "info"):
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    await load_state()
    await ensure_default_link()
    await log_startup_link()
    log_activity("system", "started", "ok")
    logger.info(f"helloworld started on port {CONFIG['port']}")
    logger.info(f"sni.txt loaded: {len(CONFIG['sni_list'])} domains")

@app.on_event("shutdown")
async def shutdown():
    await save_state()
    if http_client:
        await http_client.aclose()

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_host(request: Request | None = None) -> str:
    if request is not None:
        h = request.headers.get("x-forwarded-host") or request.headers.get("host")
        if h:
            h = h.split(":")[0]
            CONFIG["host"] = h
            return h
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])

def generate_uuid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)

def _build_params(uid, host, protocol, fp, alpn_val, sni_val, extra=None):
    if protocol == "vless-ws":
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": f"/ws/{uid}",
            "sni": sni_val,
            "fp": fp,
            "alpn": alpn_val,
        }
    else:
        mode = protocol.replace("xhttp-", "")
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": f"/xhttp-siz10/{mode}/{uid}",
            "sni": sni_val,
            "fp": fp,
            "alpn": alpn_val,
        }
    if extra:
        params.update(extra)
    return params

def generate_vless_link(
    uuid: str,
    host: str,
    remark: str = "hw",
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str | None = None,
    alpn: str | None = None,
    port: int | None = None,
    fake_sni: str | None = None,
) -> str:
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip() or DEFAULT_FINGERPRINT
    if fp not in FINGERPRINTS:
        fp = DEFAULT_FINGERPRINT
    alpn_val = (alpn or "").strip() or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")
    port_val = port or DEFAULT_PORT
    if not (MIN_PORT <= port_val <= MAX_PORT):
        port_val = DEFAULT_PORT
    sni_val = fake_sni or CONFIG.get("fake_sni") or host
    params = _build_params(uuid, host, protocol, fp, alpn_val, sni_val)
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:{port_val}?{query}#{quote(remark)}"

def generate_vless_link_patt(uuid: str, host: str, sni: str = "", remark: str = "hw-patt") -> str:
    """PattNG link: fp=unsafe + finalMask + cipher suites."""
    sni_val = sni or CONFIG.get("fake_sni") or host
    params = _build_params(
        uuid, host, "vless-ws", "unsafe", "http/1.1", sni_val,
        extra={
            "fm": "tlshello",
            "cs": CONFIG.get("cipher_suites", ""),
        },
    )
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:443?{query}#{quote(remark)}"

def vless_link_for_link(link: dict, uid: str, host: str) -> str:
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    return generate_vless_link(
        uid, host,
        remark=f"hw-{link.get('label','')}",
        protocol=proto,
        fingerprint=link.get("fingerprint"),
        alpn=link.get("alpn"),
        port=link.get("port"),
    )

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False

def is_link_allowed(link: dict | None) -> bool:
    if link is None:
        return False
    if not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True

def unique_ips_for_uuid(uuid: str) -> set:
    return {c.get("ip") for c in connections.values() if c.get("uuid") == uuid and c.get("ip")}

def is_ip_allowed(link: dict | None, uuid: str, ip: str) -> bool:
    if link is None:
        return False
    limit = int(link.get("ip_limit", 0) or 0)
    if limit <= 0:
        return True
    ips = unique_ips_for_uuid(uuid)
    if ip in ips:
        return True
    return len(ips) < limit

def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"

# ── Default link ──────────────────────────────────────────────────────────────
_default_link_created = False

async def ensure_default_link():
    global _default_link_created
    if _default_link_created:
        return
    async with LINKS_LOCK:
        if not any(l.get("is_default") for l in LINKS.values()):
            uid = hashlib.sha256(f"default{CONFIG['secret']}".encode()).hexdigest()
            uid = f"{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}-{uid[20:32]}"
            if uid not in LINKS:
                LINKS[uid] = {
                    "label": "default",
                    "limit_bytes": 0,
                    "used_bytes": 0,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "expires_at": None,
                    "note": "",
                    "is_default": True,
                    "protocol": DEFAULT_PROTOCOL,
                    "fingerprint": DEFAULT_FINGERPRINT,
                    "alpn": "",
                    "port": DEFAULT_PORT,
                    "ip_limit": 0,
                    "speed_limit_bytes": DEFAULT_SPEED_LIMIT,
                }
                asyncio.create_task(save_state())
                logger.info(f"default link created: {uid}")
        _default_link_created = True

async def log_startup_link():
    """Print two links in Deploy Logs: standard (with FAKE_SNI) + PattNG."""
    host = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip()
    if not host:
        host = CONFIG["host"]

    async with LINKS_LOCK:
        target_uid = None
        target_link = None
        for uid, link in LINKS.items():
            if is_link_allowed(link):
                target_uid = uid
                target_link = link
                break

    if not target_uid:
        logger.warning("no active link found for logging")
        return

    # Standard link (uses FAKE_SNI if set)
    vless_simple = vless_link_for_link(target_link, target_uid, host)

    # PattNG link (fp=unsafe + fm + cs, also uses FAKE_SNI if set)
    vless_patt = generate_vless_link_patt(
        target_uid, host,
        sni=CONFIG.get("fake_sni", ""),
        remark="hw-patt",
    )

    logger.info("=" * 78)
    logger.info("🔗 Standard link (v2rayNG / v2rayN):")
    logger.info(vless_simple)
    logger.info("-" * 78)
    logger.info("🔗 PattNG link (fp=unsafe + finalMask + cipher suites):")
    logger.info(vless_patt)
    logger.info("-" * 78)
    logger.info(f"🌐 FAKE_SNI: {CONFIG['fake_sni'] or '(not set — using host as sni)'}")
    logger.info(f"📄 SNI list loaded: {len(CONFIG['sni_list'])} domains from sni.txt")
    logger.info("=" * 78)

# ── Basic endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"status": "ok"}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ── Subscription (single link) ────────────────────────────────────────────────
@app.get("/sub/{uuid}")
async def subscription_single(uuid: str, request: Request):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="not found")
    host = get_host(request)
    vless = vless_link_for_link(link, uuid, host)
    content = base64.b64encode(vless.encode()).decode()
    return Response(content=content, media_type="text/plain")

# ── /get/config — for GitHub Pages (custom SNI) ───────────────────────────────
@app.get("/get/config")
async def get_config(request: Request, sni: str = ""):
    sni = (sni or "").strip()
    if not sni:
        raise HTTPException(status_code=400, detail="sni is required")
    if len(sni) > 253 or not all(c.isalnum() or c in ".-_" for c in sni):
        raise HTTPException(status_code=400, detail="invalid sni")

    host = get_host(request)
    async with LINKS_LOCK:
        target_uid = None
        target_link = None
        for uid, link in LINKS.items():
            if is_link_allowed(link):
                target_uid = uid
                target_link = link
                break

    if not target_uid:
        raise HTTPException(status_code=404, detail="no active config")

    standard = generate_vless_link(
        target_uid, host,
        remark=f"hw-{sni}",
        protocol=target_link.get("protocol", DEFAULT_PROTOCOL),
        fingerprint=target_link.get("fingerprint", DEFAULT_FINGERPRINT),
        alpn=target_link.get("alpn"),
        port=target_link.get("port"),
        fake_sni=sni,
    )
    patt = generate_vless_link_patt(target_uid, host, sni=sni, remark=f"hw-patt-{sni}")

    return {
        "standard": standard,
        "patt": patt,
        "sni": sni,
        "uuid": target_uid,
        "host": host,
    }

# ── Tunnel ────────────────────────────────────────────────────────────────────
from relay_vless import websocket_tunnel
app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], log_level="info", workers=1)
