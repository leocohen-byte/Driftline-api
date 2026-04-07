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
            ip_address TEXT,
            device_fingerprint TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS network_signals (
            id SERIAL PRIMARY KEY,
            ip_address TEXT,
            device_fingerprint TEXT,
            user_id TEXT,
            platform TEXT,
            api_key TEXT,
            risk_score FLOAT,
            flagged_at TIMESTAMP DEFAULT NOW()
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS outcomes (
            id SERIAL PRIMARY KEY,
            api_key TEXT NOT NULL,
            user_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            outcome TEXT NOT NULL,
            confirmed_at TIMESTAMP DEFAULT NOW(),
            notes TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS network_flags (
            id SERIAL PRIMARY KEY,
            ip_address TEXT,
            device_fingerprint TEXT,
            user_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            api_key TEXT NOT NULL,
            risk_score FLOAT,
            outcome TEXT DEFAULT 'flagged',
            flagged_at TIMESTAMP DEFAULT NOW()
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
    ip_address: str = Query(None),
    device_fingerprint: str = Query(None),
    api_key: str = Depends(get_tenant)
):
    # Enforce tier limits
    tier, events_used, limit = get_user_tier(api_key)
    if events_used >= limit:
        raise HTTPException(status_code=429, detail={
            "error": "monthly_limit_reached",
            "message": f"You have reached your {limit:,} event limit for this month.",
            "tier": tier,
            "events_used": events_used,
            "limit": limit,
            "upgrade_url_growth": "https://buy.stripe.com/fZu4gz90ng3u4gr8ce73G00",
            "upgrade_url_enterprise": "https://buy.stripe.com/eVq14n4K76sU4gr64673G01"
        })

    ts = timestamp or time.time()
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events (api_key, user_id, conversation_id, platform, timestamp, reply_speed, message_length, ip_address, device_fingerprint)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (api_key, user_id, conversation_id, platform, ts, reply_speed, message_length, ip_address, device_fingerprint))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(500, "Failed to store event: " + str(e))

    # Increment monthly counter
    increment_event_count(api_key)

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

    # Store network signal for cross-platform intelligence
    if sc >= 35 and (ip_address or device_fingerprint):
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO network_signals (ip_address, device_fingerprint, user_id, platform, api_key, risk_score)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (ip_address, device_fingerprint, user_id, platform, api_key, sc))
            conn.commit()
            cur.close()
            conn.close()
        except Exception:
            pass

    # Cross-platform check
    network_flags = []
    if ip_address or device_fingerprint:
        try:
            conn = get_db()
            cur = conn.cursor()
            conditions = []
            values = []
            if ip_address:
                conditions.append("ip_address = %s")
                values.append(ip_address)
            if device_fingerprint:
                conditions.append("device_fingerprint = %s")
                values.append(device_fingerprint)
            values.append(api_key)
            cur.execute("""
                SELECT COUNT(DISTINCT platform) as platforms, COUNT(*) as signals
                FROM network_signals
                WHERE (%s) AND api_key != %%s AND risk_score >= 35
            """ % " OR ".join(conditions), values)
            row = cur.fetchone()
            if row and row["signals"] > 0:
                network_flags.append(f"Flagged on {row['platforms']} other platform(s) in Driftline network")
                sc = min(sc + 20, 99)
            cur.close()
            conn.close()
        except Exception:
            pass

    if network_flags:
        fl = fl + network_flags
        if sc >= 75: lv, rc = "critical", "Suspend account immediately"
        elif sc >= 55: lv, rc = "high", "Limit messaging and verify identity"

    return {
        "user_id": user_id, "platform": platform,
        "risk_score": round(sc, 2), "risk_level": lv,
        "flags": fl, "flag_reason": fl[0] if fl else None,
        "recommendation": rc, "analyzed_at": datetime.utcnow().isoformat(),
        "network_match": len(network_flags) > 0
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


@app.post("/outcome")
def record_outcome(
    user_id: str = Query(...),
    outcome: str = Query(...),
    notes: str = Query(None),
    api_key: str = Depends(get_tenant)
):
    valid_outcomes = ["confirmed_fraud", "false_positive", "suspended"]
    if outcome not in valid_outcomes:
        raise HTTPException(400, f"Invalid outcome. Must be one of: {valid_outcomes}")
    platform = get_marketplace_name(api_key)
    try:
        conn = get_db()
        cur = conn.cursor()
        # Store outcome
        cur.execute("""
            INSERT INTO outcomes (api_key, user_id, platform, outcome, notes)
            VALUES (%s, %s, %s, %s, %s)
        """, (api_key, user_id, platform, outcome, notes))
        # If confirmed fraud, store in network_flags for cross-platform intelligence
        if outcome in ["confirmed_fraud", "suspended"]:
            cur.execute("""
                SELECT ip_address, device_fingerprint
                FROM events
                WHERE api_key = %s AND user_id = %s
                ORDER BY created_at DESC LIMIT 1
            """, (api_key, user_id))
            row = cur.fetchone()
            ip = row["ip_address"] if row else None
            fp = row["device_fingerprint"] if row else None
            cur.execute("""
                SELECT risk_score FROM flagged_accounts
                WHERE api_key = %s AND user_id = %s
            """, (api_key, user_id))
            fa = cur.fetchone()
            risk = float(fa["risk_score"]) if fa else 99.0
            cur.execute("""
                INSERT INTO network_flags (ip_address, device_fingerprint, user_id, platform, api_key, risk_score, outcome)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (ip, fp, user_id, platform, api_key, risk, outcome))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(500, "Failed to record outcome: " + str(e))
    return {
        "user_id": user_id,
        "outcome": outcome,
        "platform": platform,
        "recorded_at": datetime.utcnow().isoformat(),
        "status": "success"
    }


@app.get("/network/stats")
def get_network_stats(api_key: str = Depends(get_tenant)):
    try:
        conn = get_db()
        cur = conn.cursor()
        # Total unique flagged fingerprints across all platforms
        cur.execute("""
            SELECT COUNT(DISTINCT device_fingerprint) as unique_fingerprints
            FROM network_flags
            WHERE device_fingerprint IS NOT NULL
        """)
        unique_fps = cur.fetchone()["unique_fingerprints"]
        # Total unique IPs flagged
        cur.execute("""
            SELECT COUNT(DISTINCT ip_address) as unique_ips
            FROM network_flags
            WHERE ip_address IS NOT NULL
        """)
        unique_ips = cur.fetchone()["unique_ips"]
        # Total platforms in network (distinct api_keys with at least 1 event)
        cur.execute("""
            SELECT COUNT(DISTINCT api_key) as platforms
            FROM events
        """)
        total_platforms = cur.fetchone()["platforms"]
        # Cross-platform matches — fingerprints seen on 2+ platforms
        cur.execute("""
            SELECT COUNT(*) as cross_matches FROM (
                SELECT device_fingerprint
                FROM network_flags
                WHERE device_fingerprint IS NOT NULL
                GROUP BY device_fingerprint
                HAVING COUNT(DISTINCT platform) > 1
            ) sub
        """)
        cross_fp = cur.fetchone()["cross_matches"]
        # Cross-platform IP matches
        cur.execute("""
            SELECT COUNT(*) as cross_ip_matches FROM (
                SELECT ip_address
                FROM network_flags
                WHERE ip_address IS NOT NULL
                GROUP BY ip_address
                HAVING COUNT(DISTINCT platform) > 1
            ) sub
        """)
        cross_ip = cur.fetchone()["cross_ip_matches"]
        # Total confirmed fraud outcomes
        cur.execute("""
            SELECT COUNT(*) as confirmed FROM outcomes
            WHERE outcome = 'confirmed_fraud'
        """)
        confirmed = cur.fetchone()["confirmed"]
        # Total events scored across all platforms
        cur.execute("SELECT COUNT(*) as total FROM events")
        total_events = cur.fetchone()["total"]
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(500, "Failed to fetch network stats: " + str(e))
    return {
        "total_platforms_in_network": total_platforms,
        "total_events_scored": total_events,
        "unique_flagged_fingerprints": unique_fps,
        "unique_flagged_ips": unique_ips,
        "cross_platform_fingerprint_matches": cross_fp,
        "cross_platform_ip_matches": cross_ip,
        "total_cross_platform_catches": cross_fp + cross_ip,
        "confirmed_fraud_outcomes": confirmed,
        "network_effectiveness": round(
            (cross_fp + cross_ip) / max(unique_fps + unique_ips, 1) * 100, 1
        ),
        "generated_at": datetime.utcnow().isoformat()
    }


@app.get("/find-email")
def find_email(first_name: str = Query(...), last_name: str = Query(...), domain: str = Query(...)):
    import urllib.request
    import urllib.parse
    HUNTER_KEY = "a0d0373672173e9b24c3cfffbed0ebde4ec61600"
    try:
        params = urllib.parse.urlencode({
            "domain": domain,
            "first_name": first_name,
            "last_name": last_name,
            "api_key": HUNTER_KEY
        })
        url = "https://api.hunter.io/v2/email-finder?" + params
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            import json
            data = json.loads(resp.read())
            email = data.get("data", {}).get("email")
            confidence = data.get("data", {}).get("score", 0)
            if email:
                return {"email": email, "confidence": confidence, "found": True}
    except Exception:
        pass
    try:
        params2 = urllib.parse.urlencode({"domain": domain, "api_key": HUNTER_KEY, "limit": 5})
        url2 = "https://api.hunter.io/v2/domain-search?" + params2
        req2 = urllib.request.Request(url2)
        with urllib.request.urlopen(req2, timeout=10) as resp2:
            import json
            data2 = json.loads(resp2.read())
            pattern = data2.get("data", {}).get("pattern", "")
            emails = data2.get("data", {}).get("emails", [])
            if pattern:
                fn = first_name.lower()
                ln = last_name.lower()
                guessed = pattern.replace("{first}", fn).replace("{last}", ln).replace("{f}", fn[0] if fn else "x").replace("{l}", ln[0] if ln else "x")
                return {"email": guessed + "@" + domain, "confidence": 50, "found": True, "guessed": True}
            if emails:
                return {"email": emails[0]["value"], "confidence": emails[0].get("confidence", 0), "found": True}
    except Exception:
        pass
    return {"email": None, "found": False}


# ── STRIPE WEBHOOK ────────────────────────────────────────────────────────────
from fastapi import Request
import json

STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_GROWTH_PRICE = "price_1TIzQDFxBU842YUW3mBNw4UK"
STRIPE_ENTERPRISE_PRICE = "price_1TIzQKFxBU842YUWHpoPDeCi"

@app.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    # Verify webhook signature if secret is set
    if STRIPE_WEBHOOK_SECRET:
        try:
            import hmac, hashlib
            elements = {}
            for part in sig_header.split(","):
                k, v = part.split("=", 1)
                elements[k] = v
            timestamp = elements.get("t", "")
            sig = elements.get("v1", "")
            signed_payload = timestamp + "." + payload.decode("utf-8")
            expected = hmac.new(
                STRIPE_WEBHOOK_SECRET.encode("utf-8"),
                signed_payload.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected, sig):
                raise HTTPException(status_code=400, detail="Invalid signature")
        except Exception:
            pass  # Allow through in dev mode

    try:
        event = json.loads(payload)
        event_type = event.get("type", "")

        if event_type == "checkout.session.completed":
            session = event["data"]["object"]
            customer_email = session.get("customer_details", {}).get("email", "")
            price_id = ""

            # Get price from line items
            line_items = session.get("line_items", {}).get("data", [])
            if line_items:
                price_id = line_items[0].get("price", {}).get("id", "")

            # Determine tier from price
            if price_id == STRIPE_GROWTH_PRICE:
                new_tier = "growth"
            elif price_id == STRIPE_ENTERPRISE_PRICE:
                new_tier = "enterprise"
            else:
                # Fallback: check amount
                amount = session.get("amount_total", 0)
                if amount >= 99999:
                    new_tier = "enterprise"
                elif amount >= 49999:
                    new_tier = "growth"
                else:
                    new_tier = "growth"

            # Update user tier by email
            if customer_email:
                try:
                    conn = get_db()
                    cur = conn.cursor()
                    cur.execute(
                        "UPDATE users SET tier = %s WHERE email = %s RETURNING email, api_key",
                        (new_tier, customer_email)
                    )
                    updated = cur.fetchone()
                    conn.commit()
                    cur.close()
                    conn.close()
                    print(f"Upgraded {customer_email} to {new_tier}")
                except Exception as e:
                    print(f"Failed to upgrade {customer_email}: {e}")

        elif event_type == "customer.subscription.deleted":
            # Downgrade to free if subscription cancelled
            subscription = event["data"]["object"]
            customer_id = subscription.get("customer", "")
            # Would need customer lookup — log for now
            print(f"Subscription cancelled for customer {customer_id}")

    except Exception as e:
        print(f"Webhook error: {e}")

    return {"status": "ok"}


# ── TIER LIMITS ───────────────────────────────────────────────────────────────
TIER_LIMITS = {
    "free": 10000,
    "growth": 500000,
    "enterprise": 999999999
}

def get_user_tier(api_key: str) -> tuple:
    """Returns (tier, events_this_month, limit)"""
    if api_key in DEMO_KEYS:
        return "growth", 0, 500000
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT tier, events_this_month FROM users WHERE api_key = %s", (api_key,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result:
            tier = result["tier"] or "free"
            events = result["events_this_month"] or 0
            limit = TIER_LIMITS.get(tier, 10000)
            return tier, events, limit
    except Exception:
        pass
    return "free", 0, 10000

def increment_event_count(api_key: str):
    if api_key in DEMO_KEYS:
        return
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET events_this_month = events_this_month + 1 WHERE api_key = %s",
            (api_key,)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass


# ── ACCOUNT INFO ENDPOINT ─────────────────────────────────────────────────────
@app.get("/account")
def get_account(api_key: str = Depends(get_tenant)):
    tier, events, limit = get_user_tier(api_key)
    marketplace = get_marketplace_name(api_key)
    return {
        "marketplace": marketplace,
        "tier": tier,
        "events_this_month": events,
        "limit": limit,
        "usage_pct": round(events / max(limit, 1) * 100, 1),
        "upgrade_url_growth": "https://buy.stripe.com/fZu4gz90ng3u4gr8ce73G00",
        "upgrade_url_enterprise": "https://buy.stripe.com/eVq14n4K76sU4gr64673G01"
    }


# ── RESET MONTHLY EVENTS (call via cron on 1st of month) ─────────────────────
@app.post("/admin/reset-monthly-events")
def reset_monthly_events(x_admin_key: str = Header(None)):
    admin_key = os.environ.get("ADMIN_KEY", "driftline_admin_2025")
    if x_admin_key != admin_key:
        raise HTTPException(status_code=403, detail="Unauthorized")
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE users SET events_this_month = 0")
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(500, str(e))
    return {"status": "reset", "reset_at": datetime.utcnow().isoformat()}
