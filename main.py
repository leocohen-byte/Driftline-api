from fastapi import FastAPI, HTTPException, Header, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
import time, os, random, hashlib, secrets
from datetime import datetime

app = FastAPI(title="Driftline API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DEMO_KEY_ALPHA = "dk_alpha_marketplace_001"
DEMO_KEY_BETA = "dk_beta_marketplace_002"

users_store = {}
api_keys = {DEMO_KEY_ALPHA: "AlphaMarket", DEMO_KEY_BETA: "BetaExchange"}
tenant_data = {}

def init_tenant(key):
    if key not in tenant_data:
        tenant_data[key] = {"events": {}, "scores": {}, "flagged": []}

def get_tenant(x_api_key: str = Header(None)):
    if not x_api_key or x_api_key not in api_keys:
        raise HTTPException(status_code=401, detail="Invalid or missing API key. Pass X-API-Key header.")
    init_tenant(x_api_key)
    return x_api_key

def compute_risk(user_id, key):
    ev = tenant_data[key]["events"].get(user_id, [])
    if not ev:
        return 0, [], "low", "No action required"
    now = time.time()
    recent = [e for e in ev if now - e["ts"] < 3600]
    s = 0
    f = []
    mc = len(recent)
    if mc > 30:
        f.append("Sent " + str(mc) + " messages in 1 hour")
        s += 35
    elif mc > 15:
        f.append("High message volume: " + str(mc) + " msg/hr")
        s += 18
    uc = len(set(e["cid"] for e in recent))
    if uc > 20:
        f.append("Opened " + str(uc) + " simultaneous conversations")
        s += 30
    elif uc > 10:
        f.append("High conversation count: " + str(uc))
        s += 15
    speeds = [e.get("reply_speed", 0) for e in recent if e.get("reply_speed")]
    if speeds and sum(speeds)/len(speeds) < 3:
        f.append("Bot-like reply speed: avg " + str(round(sum(speeds)/len(speeds), 1)) + "s")
        s += 20
    s = min(s, 99)
    if s >= 75: return s, f, "critical", "Suspend account immediately"
    elif s >= 55: return s, f, "high", "Limit messaging and verify identity"
    elif s >= 35: return s, f, "medium", "Monitor closely"
    return s, f, "low", "No action required"

def seed():
    for key in [DEMO_KEY_ALPHA, DEMO_KEY_BETA]:
        init_tenant(key)
    now = time.time()
    demo_users = [
        ("scammer_001", 45, True, 1.5),
        ("scammer_002", 38, True, 2.0),
        ("scammer_003", 52, True, 1.2),
        ("user_medium_01", 22, False, 45.0),
        ("user_normal_01", 5, False, 180.0),
    ]
    for uid, mc, bad, speed in demo_users:
        tenant_data[DEMO_KEY_ALPHA]["events"][uid] = []
        bt = now - random.randint(1800, 7200)
        cvs = ["c" + str(random.randint(1000, 9999)) for _ in range(random.randint(10, 25))]
        for _ in range(mc):
            bt += random.uniform(0.5, 3) if bad else random.uniform(30, 300)
            tenant_data[DEMO_KEY_ALPHA]["events"][uid].append({
                "ts": bt, "cid": random.choice(cvs),
                "platform": "driftline", "reply_speed": speed + random.uniform(-0.5, 0.5)
            })
        sc, fl, lv, rc = compute_risk(uid, DEMO_KEY_ALPHA)
        d = {"user_id": uid, "platform": "driftline", "risk_score": round(sc, 2),
             "risk_level": lv, "flags": fl, "flag_reason": fl[0] if fl else None,
             "recommendation": rc, "analyzed_at": datetime.utcnow().isoformat(), "total_messages": mc}
        tenant_data[DEMO_KEY_ALPHA]["scores"][uid] = d
        if sc >= 35:
            tenant_data[DEMO_KEY_ALPHA]["flagged"].append(d)

seed()

@app.get("/")
def root():
    return {"product": "Driftline", "version": "2.0.0", "status": "operational", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.post("/register")
def register(email: str = Query(...), password: str = Query(...), marketplace: str = Query(...)):
    if not email or not password or not marketplace:
        raise HTTPException(400, "email, password, and marketplace are required")
    if email in users_store:
        raise HTTPException(409, "Account already exists with this email")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    api_key = "dk_" + secrets.token_hex(16)
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    users_store[email] = {"email": email, "password": pw_hash, "marketplace": marketplace, "api_key": api_key, "created_at": datetime.utcnow().isoformat()}
    api_keys[api_key] = marketplace
    init_tenant(api_key)
    return {"success": True, "email": email, "marketplace": marketplace, "api_key": api_key, "message": "Account created. Save your API key — it won't be shown again."}

@app.post("/login")
def login(email: str = Query(...), password: str = Query(...)):
    if not email or not password:
        raise HTTPException(400, "email and password are required")
    user = users_store.get(email)
    if not user:
        raise HTTPException(401, "Invalid email or password")
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if pw_hash != user["password"]:
        raise HTTPException(401, "Invalid email or password")
    return {"success": True, "email": email, "marketplace": user["marketplace"], "api_key": user["api_key"]}

@app.post("/event")
def ingest_event(
    user_id: str = Query(...),
    platform: str = Query(...),
    conversation_id: str = Query(...),
    timestamp: float = Query(None),
    message_length: int = Query(None),
    reply_speed: float = Query(None),
    api_key: str = Depends(get_tenant)
):
    ts = timestamp or time.time()
    if user_id not in tenant_data[api_key]["events"]:
        tenant_data[api_key]["events"][user_id] = []
    tenant_data[api_key]["events"][user_id].append({
        "ts": ts, "cid": conversation_id, "platform": platform,
        "message_length": message_length, "reply_speed": reply_speed
    })
    sc, fl, lv, rc = compute_risk(user_id, api_key)
    d = {"user_id": user_id, "platform": platform, "risk_score": round(sc, 2),
         "risk_level": lv, "flags": fl, "flag_reason": fl[0] if fl else None,
         "recommendation": rc, "analyzed_at": datetime.utcnow().isoformat(),
         "total_messages": len(tenant_data[api_key]["events"][user_id])}
    tenant_data[api_key]["scores"][user_id] = d
    if sc >= 35:
        existing = next((a for a in tenant_data[api_key]["flagged"] if a["user_id"] == user_id), None)
        if existing:
            existing.update(d)
        else:
            tenant_data[api_key]["flagged"].insert(0, d)
    return d

@app.get("/flagged")
def get_flagged(limit: int = Query(50), level: str = Query(None), api_key: str = Depends(get_tenant)):
    accounts = tenant_data[api_key]["flagged"].copy()
    if level:
        accounts = [a for a in accounts if a.get("risk_level") == level]
    accounts.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "marketplace": api_keys[api_key],
        "total_flagged": len(accounts),
        "results": accounts[:limit],
        "critical": len([a for a in accounts if a["risk_level"] == "critical"]),
        "high": len([a for a in accounts if a["risk_level"] == "high"]),
        "medium": len([a for a in accounts if a["risk_level"] == "medium"]),
    }

@app.get("/stats")
def get_stats(api_key: str = Depends(get_tenant)):
    total = len(tenant_data[api_key]["events"])
    flagged = len(tenant_data[api_key]["flagged"])
    return {
        "marketplace": api_keys[api_key],
        "total_scanned": total,
        "total_flagged": flagged,
        "critical": len([a for a in tenant_data[api_key]["flagged"] if a["risk_level"] == "critical"]),
        "high": len([a for a in tenant_data[api_key]["flagged"] if a["risk_level"] == "high"]),
        "medium": len([a for a in tenant_data[api_key]["flagged"] if a["risk_level"] == "medium"]),
        "flag_rate": round(flagged / max(total, 1) * 100, 1),
    }

@app.get("/score/{user_id}")
def get_score(user_id: str, api_key: str = Depends(get_tenant)):
    score = tenant_data[api_key]["scores"].get(user_id)
    if not score:
        raise HTTPException(404, "User not found")
    return score

@app.delete("/account/{user_id}")
def clear_account(user_id: str, action: str = Query("reviewed"), api_key: str = Depends(get_tenant)):
    tenant_data[api_key]["flagged"] = [a for a in tenant_data[api_key]["flagged"] if a["user_id"] != user_id]
    if user_id in tenant_data[api_key]["scores"]:
        tenant_data[api_key]["scores"][user_id]["status"] = action
    if user_id in tenant_data[api_key]["events"]:
        del tenant_data[api_key]["events"][user_id]
    return {"user_id": user_id, "action": action, "status": "success"}
