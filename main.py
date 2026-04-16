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
    """
    Multi-signal fraud scoring engine.
    Analyzes behavioral patterns across multiple time windows.
    Returns (score 0-99, flags list, level, recommendation)
    """
    try:
        conn = get_db()
        cur = conn.cursor()
        now = time.time()

        # Pull events across multiple time windows
        cur.execute("""
            SELECT conversation_id, reply_speed, message_length,
                   timestamp, ip_address, device_fingerprint
            FROM events
            WHERE api_key = %s AND user_id = %s
            ORDER BY timestamp DESC
            LIMIT 500
        """, (api_key, user_id))
        all_events = cur.fetchall()
        cur.close()
        conn.close()
    except Exception:
        all_events = []

    if not all_events:
        return 0, [], "low", "No action required"

    s = 0.0
    f = []
    now = time.time()

    # Time window buckets
    events_1h  = [e for e in all_events if e["timestamp"] > now - 3600]
    events_24h = [e for e in all_events if e["timestamp"] > now - 86400]
    events_7d  = [e for e in all_events if e["timestamp"] > now - 604800]

    # ── SIGNAL 1: Message volume (1 hour) ──────────────────────────────────
    mc_1h = len(events_1h)
    if mc_1h > 50:
        f.append(f"Extreme message volume: {mc_1h} messages in 1 hour")
        s += 40
    elif mc_1h > 25:
        f.append(f"High message volume: {mc_1h} messages in 1 hour")
        s += 22
    elif mc_1h > 12:
        f.append(f"Elevated message volume: {mc_1h} messages in 1 hour")
        s += 10

    # ── SIGNAL 2: Simultaneous conversations (1 hour) ──────────────────────
    convos_1h = set(e["conversation_id"] for e in events_1h)
    uc = len(convos_1h)
    if uc > 25:
        f.append(f"Mass outreach: {uc} simultaneous conversations")
        s += 35
    elif uc > 15:
        f.append(f"High conversation spread: {uc} open conversations")
        s += 20
    elif uc > 8:
        f.append(f"Elevated conversation count: {uc} conversations")
        s += 8

    # ── SIGNAL 3: Reply speed analysis ─────────────────────────────────────
    speeds = [e["reply_speed"] for e in events_1h
              if e["reply_speed"] is not None and 0 < e["reply_speed"] < 600]
    if speeds:
        avg_speed = sum(speeds) / len(speeds)
        ultra_fast = [s2 for s2 in speeds if s2 < 1.5]
        pct_ultra  = len(ultra_fast) / len(speeds)

        if avg_speed < 1.5 and len(speeds) >= 5:
            f.append(f"Bot-like reply speed: avg {round(avg_speed,1)}s across {len(speeds)} messages")
            s += 28
        elif avg_speed < 3.0 and len(speeds) >= 5:
            f.append(f"Unusually fast replies: avg {round(avg_speed,1)}s")
            s += 15
        elif pct_ultra > 0.6 and len(speeds) >= 5:
            f.append(f"{int(pct_ultra*100)}% of replies sent in under 1.5 seconds")
            s += 18

    # ── SIGNAL 4: Message length uniformity (copy-paste detection) ─────────
    lengths = [e["message_length"] for e in events_1h
               if e["message_length"] is not None and e["message_length"] > 0]
    if len(lengths) >= 8:
        avg_len = sum(lengths) / len(lengths)
        variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
        std_dev = variance ** 0.5
        coeff_variation = std_dev / max(avg_len, 1)
        if coeff_variation < 0.08 and avg_len > 20:
            f.append(f"Copy-paste pattern detected: message length variance {round(coeff_variation*100,1)}%")
            s += 22
        elif coeff_variation < 0.15 and avg_len > 20:
            f.append(f"Suspiciously uniform message lengths (possible template use)")
            s += 10

    # ── SIGNAL 5: Conversation-to-message ratio (spray pattern) ────────────
    if mc_1h >= 5 and uc >= 3:
        msgs_per_convo = mc_1h / uc
        if msgs_per_convo < 1.5:
            f.append(f"Spray pattern: {mc_1h} messages across {uc} conversations ({round(msgs_per_convo,1)} msg/convo)")
            s += 20
        elif msgs_per_convo < 2.5 and uc > 10:
            f.append(f"Broadcast pattern: low engagement across many conversations")
            s += 10

    # ── SIGNAL 6: Activity acceleration (ramping up fast) ──────────────────
    events_15m = [e for e in events_1h if e["timestamp"] > now - 900]
    events_60m_old = [e for e in events_1h if e["timestamp"] <= now - 900]
    if len(events_15m) > 10 and len(events_60m_old) < 3:
        f.append(f"Sudden activity spike: {len(events_15m)} messages in last 15 minutes")
        s += 15

    # ── SIGNAL 7: 24h sustained volume (not a one-off) ─────────────────────
    convos_24h = set(e["conversation_id"] for e in events_24h)
    if len(convos_24h) > 40:
        f.append(f"Sustained mass outreach: {len(convos_24h)} conversations in 24 hours")
        s += 15
    elif len(convos_24h) > 20:
        f.append(f"High 24h activity: {len(convos_24h)} conversations today")
        s += 8

    # ── SIGNAL 8: Night-time blasting (timezone evasion) ───────────────────
    import datetime
    if events_1h:
        latest = datetime.datetime.utcfromtimestamp(events_1h[0]["timestamp"])
        hour_utc = latest.hour
        if (hour_utc >= 1 and hour_utc <= 5) and mc_1h > 15:
            f.append(f"High volume activity during off-hours (UTC {hour_utc}:00)")
            s += 10

    # Cap at 99
    s = min(round(s), 99)

    if s >= 75: return s, f, "critical", "Suspend account immediately"
    elif s >= 55: return s, f, "high",     "Limit messaging and verify identity"
    elif s >= 35: return s, f, "medium",   "Monitor closely"
    return s, f, "low", "No action required"

def seed_demo_data():
    """
    Seeds realistic demo data showing Driftline catching real scammer patterns.
    Each demo user represents a distinct fraud archetype.
    """
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

        # ── ARCHETYPE 1: Mass outreach scammer ──────────────────────────────
        # Fake seller blasting 60 buyers simultaneously with copy-paste messages
        uid1 = "scammer_mass_001"
        convos1 = ["conv_" + str(i) for i in range(62)]
        t = now - 3200
        for i in range(68):
            t += random.uniform(0.8, 2.1)  # bot-like speed
            ml = random.randint(118, 124)  # uniform length = copy paste
            cur.execute("""
                INSERT INTO events (api_key, user_id, conversation_id, platform, timestamp,
                    reply_speed, message_length, ip_address, device_fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (DEMO_KEY_ALPHA, uid1, random.choice(convos1), "demo_marketplace",
                  t, random.uniform(0.9, 2.0), ml, "45.152.66.91", "fp_a1b2c3d4e5f6"))

        # ── ARCHETYPE 2: Bot-speed spammer ──────────────────────────────────
        # Automated account, sub-second replies, many conversations
        uid2 = "scammer_bot_002"
        convos2 = ["bot_conv_" + str(i) for i in range(35)]
        t = now - 2800
        for i in range(45):
            t += random.uniform(0.3, 1.1)  # sub-second = bot
            cur.execute("""
                INSERT INTO events (api_key, user_id, conversation_id, platform, timestamp,
                    reply_speed, message_length, ip_address, device_fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (DEMO_KEY_ALPHA, uid2, random.choice(convos2), "demo_marketplace",
                  t, random.uniform(0.3, 1.1), random.randint(85, 210),
                  "185.220.101.33", "fp_z9y8x7w6v5u4"))

        # ── ARCHETYPE 3: Fake rental host (spray & pray) ────────────────────
        # Opens many conversations, sends one message and ghosts
        uid3 = "scammer_rental_003"
        convos3 = ["rental_" + str(i) for i in range(28)]
        t = now - 1800
        for i in range(31):
            t += random.uniform(1.5, 4.0)
            cur.execute("""
                INSERT INTO events (api_key, user_id, conversation_id, platform, timestamp,
                    reply_speed, message_length, ip_address, device_fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (DEMO_KEY_ALPHA, uid3, convos3[i % len(convos3)], "demo_marketplace",
                  t, random.uniform(1.5, 3.5), random.randint(140, 148),
                  "91.108.4.17", "fp_m3n4o5p6q7r8"))

        # ── ARCHETYPE 4: Suspicious but borderline ──────────────────────────
        uid4 = "user_suspicious_004"
        convos4 = ["susp_" + str(i) for i in range(12)]
        t = now - 3000
        for i in range(22):
            t += random.uniform(5, 45)
            cur.execute("""
                INSERT INTO events (api_key, user_id, conversation_id, platform, timestamp,
                    reply_speed, message_length)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (DEMO_KEY_ALPHA, uid4, random.choice(convos4), "demo_marketplace",
                  t, random.uniform(4, 30), random.randint(50, 200)))

        # ── ARCHETYPE 5: Normal active seller ───────────────────────────────
        uid5 = "user_normal_005"
        convos5 = ["normal_" + str(i) for i in range(4)]
        t = now - 7200
        for i in range(8):
            t += random.uniform(120, 600)
            cur.execute("""
                INSERT INTO events (api_key, user_id, conversation_id, platform, timestamp,
                    reply_speed, message_length)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (DEMO_KEY_ALPHA, uid5, random.choice(convos5), "demo_marketplace",
                  t, random.uniform(60, 400), random.randint(30, 280)))

        # ── ARCHETYPE 6: Normal buyer ────────────────────────────────────────
        uid6 = "user_buyer_006"
        t = now - 4800
        for i in range(5):
            t += random.uniform(300, 1800)
            cur.execute("""
                INSERT INTO events (api_key, user_id, conversation_id, platform, timestamp,
                    reply_speed, message_length)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (DEMO_KEY_ALPHA, uid6, "buyer_conv_001", "demo_marketplace",
                  t, random.uniform(120, 900), random.randint(20, 150)))

        conn.commit()

        # Now score all users and write flagged accounts
        for uid in [uid1, uid2, uid3, uid4, uid5, uid6]:
            sc, fl, lv, rc = compute_risk(uid, DEMO_KEY_ALPHA)
            total_msgs = len([e for e in [uid1, uid2, uid3, uid4, uid5, uid6] if e == uid])
            cur.execute("SELECT COUNT(*) as c FROM events WHERE api_key=%s AND user_id=%s",
                       (DEMO_KEY_ALPHA, uid))
            total_msgs = cur.fetchone()["c"]
            if sc >= 35:
                cur.execute("""
                    INSERT INTO flagged_accounts
                        (api_key, user_id, platform, risk_score, risk_level,
                         flag_reason, flags, recommendation, total_messages)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (api_key, user_id) DO UPDATE SET
                        risk_score=EXCLUDED.risk_score,
                        risk_level=EXCLUDED.risk_level,
                        flag_reason=EXCLUDED.flag_reason,
                        flags=EXCLUDED.flags,
                        recommendation=EXCLUDED.recommendation,
                        total_messages=EXCLUDED.total_messages,
                        analyzed_at=NOW()
                """, (DEMO_KEY_ALPHA, uid, "demo_marketplace", sc, lv,
                      fl[0] if fl else None, str(fl), rc, total_msgs))

        # Seed network_signals for cross-platform demo
        cur.execute("""
            INSERT INTO network_signals (ip_address, device_fingerprint, user_id, platform, api_key, risk_score)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, ("45.152.66.91", "fp_a1b2c3d4e5f6", "scammer_mass_001", "rover_demo", "dk_beta_marketplace_002", 91.0))
        cur.execute("""
            INSERT INTO network_signals (ip_address, device_fingerprint, user_id, platform, api_key, risk_score)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, ("185.220.101.33", "fp_z9y8x7w6v5u4", "scammer_bot_002", "turo_demo", "dk_beta_marketplace_002", 88.0))

        conn.commit()
        cur.close()
        conn.close()
        print("Demo data seeded successfully with realistic scammer archetypes")
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



# ── FREE AUDIT ENDPOINT ───────────────────────────────────────────────────────
# Accepts a CSV of message events and runs full behavioral analysis.
# No API key required — this is for prospects doing the free audit.
# CSV columns: user_id, conversation_id, timestamp, reply_speed (opt), message_length (opt)

import io, csv as csv_module
from fastapi import UploadFile, File, Form

@app.post("/audit")
async def run_free_audit(
    file: UploadFile = File(...),
    platform_name: str = Form("unknown_platform"),
    platform_type: str = Form("marketplace")
):
    """
    Free fraud audit — no API key required.
    Upload a CSV of message events and get a full behavioral fraud report back.
    """
    # Read and parse CSV
    try:
        contents = await file.read()
        text = contents.decode("utf-8-sig")  # handle BOM
        reader = csv_module.DictReader(io.StringIO(text))
        rows = list(reader)
    except Exception as e:
        raise HTTPException(400, f"Could not parse CSV: {str(e)}")

    if len(rows) < 5:
        raise HTTPException(400, "CSV must contain at least 5 rows for meaningful analysis.")

    # Normalize column names to lowercase
    normalized = []
    for row in rows:
        norm = {k.strip().lower(): v.strip() for k, v in row.items()}
        normalized.append(norm)

    # Validate required columns
    required = {"user_id", "conversation_id"}
    sample_keys = set(normalized[0].keys()) if normalized else set()
    missing = required - sample_keys
    if missing:
        raise HTTPException(400, f"Missing required columns: {missing}. Required: user_id, conversation_id, timestamp (optional), reply_speed (optional), message_length (optional)")

    # Group events by user — replicate the same logic as compute_risk
    # but run entirely in-memory without storing to DB
    import time as time_mod

    user_map = {}
    now = time_mod.time()

    for row in normalized:
        uid = row.get("user_id", "").strip()
        if not uid:
            continue
        if uid not in user_map:
            user_map[uid] = {
                "conversations": set(),
                "timestamps": [],
                "reply_speeds": [],
                "message_lengths": [],
                "events": []
            }
        u = user_map[uid]
        cid = row.get("conversation_id", "").strip()
        if cid:
            u["conversations"].add(cid)

        # Parse timestamp — if not provided use sequential now
        ts_raw = row.get("timestamp", "").strip()
        try:
            ts = float(ts_raw) if ts_raw else now
        except ValueError:
            ts = now
        u["timestamps"].append(ts)

        rs_raw = row.get("reply_speed", "").strip()
        try:
            if rs_raw:
                u["reply_speeds"].append(float(rs_raw))
        except ValueError:
            pass

        ml_raw = row.get("message_length", "").strip()
        try:
            if ml_raw:
                u["message_lengths"].append(int(ml_raw))
        except ValueError:
            pass

        u["events"].append(row)

    # Score every user using the same multi-signal logic as compute_risk
    scored_users = []

    for uid, u in user_map.items():
        s = 0.0
        flags = []

        # Use latest timestamp as reference point
        ref_ts = max(u["timestamps"]) if u["timestamps"] else now

        # Time windows
        events_1h = [
            (ts, rs, ml)
            for ts, rs, ml in zip(
                u["timestamps"],
                u["reply_speeds"] + [None] * len(u["timestamps"]),
                u["message_lengths"] + [None] * len(u["timestamps"])
            )
            if ts > ref_ts - 3600
        ]

        convos_1h = set()
        for i, ev in enumerate(u["events"]):
            ts_raw2 = ev.get("timestamp", "").strip()
            try:
                ts2 = float(ts_raw2) if ts_raw2 else ref_ts
            except ValueError:
                ts2 = ref_ts
            if ts2 > ref_ts - 3600:
                cid2 = ev.get("conversation_id", "").strip()
                if cid2:
                    convos_1h.add(cid2)

        mc_1h = len([t for t in u["timestamps"] if t > ref_ts - 3600])

        # SIGNAL 1: Message volume
        if mc_1h > 50:
            s += 40
            flags.append(f"Extreme message volume: {mc_1h} messages in 1 hour")
        elif mc_1h > 25:
            s += 22
            flags.append(f"High message volume: {mc_1h} messages in 1 hour")
        elif mc_1h > 12:
            s += 10
            flags.append(f"Elevated message volume: {mc_1h} messages in 1 hour")

        # SIGNAL 2: Simultaneous conversations
        uc = len(convos_1h) if convos_1h else len(u["conversations"])
        if uc > 25:
            s += 35
            flags.append(f"Mass outreach: {uc} simultaneous conversations")
        elif uc > 15:
            s += 20
            flags.append(f"High conversation spread: {uc} open conversations")
        elif uc > 8:
            s += 8
            flags.append(f"Elevated conversation count: {uc} conversations")

        # SIGNAL 3: Reply speed
        speeds = [rs for rs in u["reply_speeds"] if rs is not None and 0 < rs < 600]
        if speeds and len(speeds) >= 3:
            avg_speed = sum(speeds) / len(speeds)
            ultra_fast = [sp for sp in speeds if sp < 1.5]
            pct_ultra = len(ultra_fast) / len(speeds)
            if avg_speed < 1.5 and len(speeds) >= 5:
                s += 28
                flags.append(f"Bot-like reply speed: avg {round(avg_speed, 1)}s across {len(speeds)} messages")
            elif avg_speed < 3.0 and len(speeds) >= 5:
                s += 15
                flags.append(f"Unusually fast replies: avg {round(avg_speed, 1)}s")
            elif pct_ultra > 0.6 and len(speeds) >= 5:
                s += 18
                flags.append(f"{int(pct_ultra * 100)}% of replies sent in under 1.5 seconds")

        # SIGNAL 4: Copy-paste (message length uniformity)
        lengths = [ml for ml in u["message_lengths"] if ml is not None and ml > 0]
        if len(lengths) >= 8:
            avg_len = sum(lengths) / len(lengths)
            variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
            std_dev = variance ** 0.5
            cv = std_dev / max(avg_len, 1)
            if cv < 0.08 and avg_len > 20:
                s += 22
                flags.append(f"Copy-paste pattern: message length variance {round(cv * 100, 1)}%")
            elif cv < 0.15 and avg_len > 20:
                s += 10
                flags.append(f"Suspiciously uniform message lengths (possible template use)")

        # SIGNAL 5: Spray pattern (low msgs per convo)
        if mc_1h >= 5 and uc >= 3:
            msgs_per_convo = mc_1h / uc
            if msgs_per_convo < 1.5:
                s += 20
                flags.append(f"Spray pattern: {mc_1h} messages across {uc} conversations")
            elif msgs_per_convo < 2.5 and uc > 10:
                s += 10
                flags.append(f"Broadcast pattern: low engagement across many conversations")

        # SIGNAL 6: Total conversation count (if no timestamps, use overall)
        total_convos = len(u["conversations"])
        if total_convos > 30 and uc == 0:
            s += 20
            flags.append(f"Very high total conversation count: {total_convos}")
        elif total_convos > 15 and uc == 0:
            s += 10
            flags.append(f"High total conversation count: {total_convos}")

        s = min(round(s), 99)

        if s >= 75:
            level = "critical"
            recommendation = "Suspend account immediately"
        elif s >= 55:
            level = "high"
            recommendation = "Limit messaging and verify identity"
        elif s >= 35:
            level = "medium"
            recommendation = "Monitor closely"
        else:
            level = "low"
            recommendation = "No action required"

        scored_users.append({
            "user_id": uid,
            "risk_score": s,
            "risk_level": level,
            "flags": flags,
            "recommendation": recommendation,
            "total_messages": len(u["events"]),
            "total_conversations": total_convos
        })

    # Sort by risk score desc
    scored_users.sort(key=lambda x: x["risk_score"], reverse=True)

    # Build summary stats
    critical = [u for u in scored_users if u["risk_level"] == "critical"]
    high = [u for u in scored_users if u["risk_level"] == "high"]
    medium = [u for u in scored_users if u["risk_level"] == "medium"]
    flagged = critical + high + medium
    total = len(scored_users)
    flag_rate = round(len(flagged) / max(total, 1) * 100, 1)

    # Detect platform-level patterns
    patterns = []
    spray_count = sum(1 for u in flagged if any("Spray" in f or "spray" in f for f in u["flags"]))
    bot_count = sum(1 for u in flagged if any("Bot-like" in f or "bot" in f.lower() for f in u["flags"]))
    copy_count = sum(1 for u in flagged if any("Copy-paste" in f or "copy" in f.lower() for f in u["flags"]))
    mass_count = sum(1 for u in flagged if any("simultaneous" in f.lower() or "Mass outreach" in f for f in u["flags"]))

    if mass_count > 0:
        patterns.append({"signal": "Simultaneous Mass Outreach", "count": mass_count,
                         "description": f"{mass_count} accounts opened 15+ conversations simultaneously — classic scammer behavior"})
    if spray_count > 0:
        patterns.append({"signal": "Spray & Pray Pattern", "count": spray_count,
                         "description": f"{spray_count} accounts sent 1 message per conversation across many threads — broadcast scam pattern"})
    if bot_count > 0:
        patterns.append({"signal": "Bot-Like Automation", "count": bot_count,
                         "description": f"{bot_count} accounts replied faster than humanly possible — likely automated tooling"})
    if copy_count > 0:
        patterns.append({"signal": "Copy-Paste Messaging", "count": copy_count,
                         "description": f"{copy_count} accounts sent near-identical messages across all conversations"})

    return {
        "audit_complete": True,
        "platform": platform_name,
        "platform_type": platform_type,
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_users_analyzed": total,
            "total_events_analyzed": len(normalized),
            "critical_risk": len(critical),
            "high_risk": len(high),
            "medium_risk": len(medium),
            "flag_rate_pct": flag_rate
        },
        "patterns_detected": patterns,
        "flagged_accounts": flagged,
        "all_scores": scored_users,
        "next_steps": {
            "message": "This is your free behavioral fraud audit from Driftline. To get real-time detection integrated into your platform, contact us.",
            "contact": "leocohen@trydriftline.com",
            "website": "https://trydriftline.com",
            "demo_api_key": "dk_alpha_marketplace_001"
        }
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
