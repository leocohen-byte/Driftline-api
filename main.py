from fastapi import FastAPI, HTTPException, Header, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
import time, os, random, hashlib, secrets
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="Driftline API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DATABASE_URL = os.environ.get("DATABASE_URL", "")

def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            marketplace TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            tier TEXT DEFAULT 'free',
            events_this_month INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id SERIAL PRIMARY KEY,
            api_key TEXT NOT NULL,
            user_id TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            timestamp FLOAT NOT NULL,
            reply_speed FLOAT,
            message_length INTEGER,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS flagged_accounts (
            id SERIAL PRIMARY KEY,
            api_key TEXT NOT NULL,
            user_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            risk_score FLOAT NOT NULL,
            risk_level TEXT NOT NULL,
            flag_reason TEXT,
            flags TEXT,
            recommendation TEXT,
            total_messages INTEGER DEFAULT 0,
            analyzed_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(api_key, user_id)
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

try:
    init_db()
    print("Database initialized successfully")
except Exception as e:
    print("Database init error:", e)

DEMO_KEY_ALPHA = "dk_alpha_marketplace_001"
DEMO_KEY_BETA = "dk_beta_marketplace_002"
DEMO_KEYS = {DEMO_KEY_ALPHA: "AlphaMarket", DEMO_KEY_BETA: "BetaExchange"}

def get_tenant(x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key. Pass X-API-Key header.")
    if x_api_key in DEMO_KEYS:
        return x_api_key
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT api_key FROM users WHERE api_key = %s", (x_api_key,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if not result:
            raise HTTPException(status_code=401, detail="Invalid or missing API key. Pass X-API-Key header.")
        return x_api_key
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or missing API key. Pass X-API-Key header.")

def get_marketplace_name(api_key: str) -> str:
    if api_key in DEMO_KEYS:
        return DEMO_KEYS[api_key]
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT marketplace FROM users WHERE api_key = %s", (api_key,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        return result["marketplace"] if result else "Unknown"
    except Exception:
        return "Unknown"

def compute_risk(user_id: str, api_key: str):
    try:
        conn = get_db()
        cur = conn.cursor()
        now = time.time()
        hour_ago = now - 3600
        cur.execute("""
            SELECT conversation_id, reply_speed, timestamp
            FROM events
            WHERE api_key = %s AND user_id = %s AND timestamp > %s
            ORDER BY timestamp DESC
        """, (api_key, user_id, hour_ago))
        recent = cur.fetchall()
        cur.close()
        conn.close()
    except Exception:
        recent = []

    if not recent:
        return 0, [], "low", "No action required"

    s = 0
    f = []
    mc = len(recent)
    if mc > 30:
        f.append("Sent " + str(mc) + " messages in 1 hour")
        s += 35
    elif mc > 15:
        f.append("High message volume: " + str(mc) + " msg/hr")
        s += 18

    convos = set(e["conversation_id"] for e in recent)
    uc = len(convos)
    if uc > 20:
        f.append("Opened " + str(uc) + " simultaneous conversations")
        s += 30
    elif uc > 10:
        f.append("High conversation count: " + str(uc))
        s += 15

    speeds = [e["reply_speed"] for e in recent if e["reply_speed"] and e["reply_speed"] > 0]
    if speeds and sum(speeds) / len(speeds) < 3:
        f.append("Bot-like reply speed: avg " + str(round(sum(speeds) / len(speeds), 1)) + "s")
        s += 20

    s = min(s, 99)
    if s >= 75: return s, f, "critical", "Suspend account immediately"
    elif s >= 55: return s, f, "high", "Limit messaging and verify identity"
    elif s >= 35: return s, f, "medium", "Monitor closely"
    return s, f, "low", "No action required"

def seed_demo_data():
    demo_users = [
        ("scammer_001", 45, 1.5),
        ("scammer_002", 38, 2.0),
        ("scammer_003", 52, 1.2),
        ("user_medium_01", 22, 45.0),
        ("user_normal_01", 5, 180.0),
    ]
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM events WHERE api_key = %s", (DEMO_KEY_ALPHA,))
        count = cur.fetchone()["c"]
        if count > 0:
            cur.close()
            conn.close()
            return
        now = time.time()
        for uid, mc, speed in demo_users:
            bt = now - random.randint(1800, 7200)
            cvs = ["c" + str(random.randint(1000, 9999)) for _ in range(random.randint(10, 25))]
            for _ in range(mc):
                bt += random.uniform(0.5, 3) if speed < 10 else random.uniform(30, 300)
                cur.execute("""
                    INSERT INTO events (api_key, user_id, conversation_id, platform, timestamp, reply_speed)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (DEMO_KEY_ALPHA, uid, random.choice(cvs), "driftline", bt, speed + random.uniform(-0.5, 0.5)))
        conn.commit()
        for uid, mc, speed in demo_users:
            sc, fl, lv, rc = compute_risk(uid, DEMO_KEY_ALPHA)
            if sc >= 35:
                cur.execute("""
                    INSERT INTO flagged_accounts (api_key, user_id, platform, risk_score, risk_level, flag_reason, flags, recommendation, total_messages)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (api_key, user_id) DO UPDATE SET
                        risk_score = EXCLUDED.risk_score,
                        risk_level = EXCLUDED.risk_level,
                        flag_reason = EXCLUDED.flag_reason,
                        flags = EXCLUDED.flags,
                        recommendation = EXCLUDED.recommendation,
                        total_messages = EXCLUDED.total_messages,
                        analyzed_at = NOW()
                """, (DEMO_KEY_ALPHA, uid, "driftline", sc, lv, fl[0] if fl else None, str(fl), rc, mc))
        conn.commit()
        cur.close()
        conn.close()
        print("Demo data seeded successfully")
    except Exception as e:
        print("Seed error:", e)

try:
    seed_demo_data()
except Exception as e:
    print("Seed failed:", e)

@app.get("/")
def root():
    return {"product": "Driftline", "version": "2.0.0", "status": "operational", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.get("/debug-db")
def debug_db():
    import os
    db_url = os.environ.get("DATABASE_URL", "NOT SET")
    # Mask password for security
    if db_url and "@" in db_url:
        parts = db_url.split("@")
        masked = parts[0].split(":")[0] + ":****@" + parts[1]
    else:
        masked = db_url
    return {"DATABASE_URL": masked, "set": db_url != "NOT SET"}

@app.post("/register")
def register(email: str = Query(...), password: str = Query(...), marketplace: str = Query(...)):
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    api_key = "dk_" + secrets.token_hex(16)
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (email, password_hash, marketplace, api_key)
            VALUES (%s, %s, %s, %s)
        """, (email, pw_hash, marketplace, api_key))
        conn.commit()
        cur.close()
        conn.close()
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(409, "An account with this email already exists")
    except Exception as e:
        raise HTTPException(500, "Registration failed: " + str(e))
    return {"success": True, "email": email, "marketplace": marketplace, "api_key": api_key}

@app.post("/login")
def login(email: str = Query(...), password: str = Query(...)):
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s AND password_hash = %s", (email, pw_hash))
        user = cur.fetchone()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(500, "Login failed: " + str(e))
    if not user:
        raise HTTPException(401, "Invalid email or password")
    return {"success": True, "email": user["email"], "marketplace": user["marketplace"], "api_key": user["api_key"]}

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
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events (api_key, user_id, conversation_id, platform, timestamp, reply_speed, message_length)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (api_key, user_id, conversation_id, platform, ts, reply_speed, message_length))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(500, "Failed to store event: " + str(e))

    sc, fl, lv, rc = compute_risk(user_id, api_key)

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM events WHERE api_key = %s AND user_id = %s", (api_key, user_id))
        total = cur.fetchone()["c"]
        if sc >= 35:
            cur.execute("""
                INSERT INTO flagged_accounts (api_key, user_id, platform, risk_score, risk_level, flag_reason, flags, recommendation, total_messages)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (api_key, user_id) DO UPDATE SET
                    risk_score = EXCLUDED.risk_score,
                    risk_level = EXCLUDED.risk_level,
                    flag_reason = EXCLUDED.flag_reason,
                    flags = EXCLUDED.flags,
                    recommendation = EXCLUDED.recommendation,
                    total_messages = EXCLUDED.total_messages,
                    analyzed_at = NOW()
            """, (api_key, user_id, platform, sc, lv, fl[0] if fl else None, str(fl), rc, total))
            conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass

    return {
        "user_id": user_id, "platform": platform,
        "risk_score": round(sc, 2), "risk_level": lv,
        "flags": fl, "flag_reason": fl[0] if fl else None,
        "recommendation": rc, "analyzed_at": datetime.utcnow().isoformat()
    }

@app.get("/flagged")
def get_flagged(limit: int = Query(50), level: str = Query(None), api_key: str = Depends(get_tenant)):
    try:
        conn = get_db()
        cur = conn.cursor()
        if level:
            cur.execute("""
                SELECT * FROM flagged_accounts
                WHERE api_key = %s AND risk_level = %s
                ORDER BY risk_score DESC LIMIT %s
            """, (api_key, level, limit))
        else:
            cur.execute("""
                SELECT * FROM flagged_accounts
                WHERE api_key = %s
                ORDER BY risk_score DESC LIMIT %s
            """, (api_key, limit))
        accounts = cur.fetchall()
        cur.execute("SELECT COUNT(*) as c FROM flagged_accounts WHERE api_key = %s", (api_key,))
        total = cur.fetchone()["c"]
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(500, "Failed to fetch flagged accounts: " + str(e))

    results = []
    for a in accounts:
        results.append({
            "user_id": a["user_id"], "platform": a["platform"],
            "risk_score": float(a["risk_score"]), "risk_level": a["risk_level"],
            "flag_reason": a["flag_reason"], "recommendation": a["recommendation"],
            "total_messages": a["total_messages"],
            "analyzed_at": a["analyzed_at"].isoformat() if a["analyzed_at"] else None
        })

    return {
        "marketplace": get_marketplace_name(api_key),
        "total_flagged": total,
        "results": results,
        "critical": len([a for a in results if a["risk_level"] == "critical"]),
        "high": len([a for a in results if a["risk_level"] == "high"]),
        "medium": len([a for a in results if a["risk_level"] == "medium"]),
    }

@app.get("/stats")
def get_stats(api_key: str = Depends(get_tenant)):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(DISTINCT user_id) as c FROM events WHERE api_key = %s", (api_key,))
        total = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM flagged_accounts WHERE api_key = %s", (api_key,))
        flagged = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM flagged_accounts WHERE api_key = %s AND risk_level = 'critical'", (api_key,))
        critical = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM flagged_accounts WHERE api_key = %s AND risk_level = 'high'", (api_key,))
        high = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM flagged_accounts WHERE api_key = %s AND risk_level = 'medium'", (api_key,))
        medium = cur.fetchone()["c"]
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(500, "Failed to fetch stats: " + str(e))

    return {
        "marketplace": get_marketplace_name(api_key),
        "total_scanned": total,
        "total_flagged": flagged,
        "critical": critical, "high": high, "medium": medium,
        "flag_rate": round(flagged / max(total, 1) * 100, 1)
    }

@app.get("/score/{user_id}")
def get_score(user_id: str, api_key: str = Depends(get_tenant)):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM flagged_accounts WHERE api_key = %s AND user_id = %s", (api_key, user_id))
        result = cur.fetchone()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(500, str(e))
    if not result:
        sc, fl, lv, rc = compute_risk(user_id, api_key)
        return {"user_id": user_id, "risk_score": sc, "risk_level": lv, "flags": fl, "recommendation": rc}
    return {
        "user_id": result["user_id"], "risk_score": float(result["risk_score"]),
        "risk_level": result["risk_level"], "flag_reason": result["flag_reason"],
        "recommendation": result["recommendation"]
    }

@app.delete("/account/{user_id}")
def clear_account(user_id: str, action: str = Query("reviewed"), api_key: str = Depends(get_tenant)):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM flagged_accounts WHERE api_key = %s AND user_id = %s", (api_key, user_id))
        cur.execute("DELETE FROM events WHERE api_key = %s AND user_id = %s", (api_key, user_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(500, str(e))
    return {"user_id": user_id, "action": action, "status": "success"}
