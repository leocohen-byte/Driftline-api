"""
Driftline — Marketplace Fraud Detection API
Production-ready FastAPI application
"""

import os
import uuid
import time
import math
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Driftline Fraud Detection API",
    description="Real-time marketplace fraud detection via behavioural risk scoring.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory multi-tenant store
# ---------------------------------------------------------------------------

# tenant_data[api_key] = {
#   "users": {
#       user_id: {
#           "events": [ {ts, event_type, metadata} ],
#           "reply_speeds": [seconds, ...],   # seconds between send/reply pairs
#           "conversation_ids": set(),
#           "flagged": bool,
#           "flag_reason": str | None,
#           "created_at": float,
#       }
#   }
# }

tenant_data: dict[str, dict] = {}

# API key → marketplace name
api_keys: dict[str, str] = {}

# ---------------------------------------------------------------------------
# Demo seed data
# ---------------------------------------------------------------------------

DEMO_KEY_ALPHA = "dk_alpha_marketplace_001"
DEMO_KEY_BETA  = "dk_beta_marketplace_002"

api_keys[DEMO_KEY_ALPHA] = "AlphaMarket"
api_keys[DEMO_KEY_BETA]  = "BetaExchange"

def _init_tenant(api_key: str):
    if api_key not in tenant_data:
        tenant_data[api_key] = {"users": {}}

def _init_user(api_key: str, user_id: str):
    _init_tenant(api_key)
    if user_id not in tenant_data[api_key]["users"]:
        tenant_data[api_key]["users"][user_id] = {
            "events": [],
            "reply_speeds": [],
            "conversation_ids": set(),
            "flagged": False,
            "flag_reason": None,
            "created_at": time.time(),
        }

def _seed():
    now = time.time()

    # --- AlphaMarket seed ---
    _init_tenant(DEMO_KEY_ALPHA)

    # Normal user
    _init_user(DEMO_KEY_ALPHA, "user_normal_01")
    u = tenant_data[DEMO_KEY_ALPHA]["users"]["user_normal_01"]
    for i in range(5):
        u["events"].append({"ts": now - (3600 * i), "event_type": "message_sent", "metadata": {}})
        u["reply_speeds"].append(180 + i * 30)   # 3-5 min reply times
        u["conversation_ids"].add(f"conv_{i}")

    # Suspicious spammer
    _init_user(DEMO_KEY_ALPHA, "user_spammer_88")
    u = tenant_data[DEMO_KEY_ALPHA]["users"]["user_spammer_88"]
    for i in range(60):
        u["events"].append({"ts": now - (60 * i), "event_type": "message_sent", "metadata": {}})
        u["reply_speeds"].append(2)               # instant replies — bot-like
        u["conversation_ids"].add(f"conv_spam_{i}")
    u["flagged"] = True
    u["flag_reason"] = "Automated flagging: high message frequency + bot-like reply speed"

    # Moderate-risk user
    _init_user(DEMO_KEY_ALPHA, "user_medium_42")
    u = tenant_data[DEMO_KEY_ALPHA]["users"]["user_medium_42"]
    for i in range(20):
        u["events"].append({"ts": now - (300 * i), "event_type": "message_sent", "metadata": {}})
        u["reply_speeds"].append(10 + i)
        u["conversation_ids"].add(f"conv_med_{i % 8}")

    # --- BetaExchange seed ---
    _init_tenant(DEMO_KEY_BETA)
    _init_user(DEMO_KEY_BETA, "beta_user_001")
    u = tenant_data[DEMO_KEY_BETA]["users"]["beta_user_001"]
    for i in range(3):
        u["events"].append({"ts": now - (7200 * i), "event_type": "message_sent", "metadata": {}})
        u["reply_speeds"].append(600)
        u["conversation_ids"].add(f"bconv_{i}")

_seed()

# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

def get_tenant(x_api_key: Optional[str] = Header(default=None)) -> str:
    if not x_api_key or x_api_key not in api_keys:
        raise HTTPException(status_code=401, detail="Invalid or missing API key. Pass X-API-Key header.")
    return x_api_key

# ---------------------------------------------------------------------------
# Risk scoring engine
# ---------------------------------------------------------------------------

def compute_risk_score(user: dict) -> dict:
    """
    Score 0–100 built from three behavioural signals:

    1. Message frequency  — messages per hour over last 24 h  (weight 40%)
    2. Reply speed        — median reply time in seconds       (weight 35%)
    3. Conversation count — unique conversations               (weight 25%)

    Each component is normalised to 0–100 via a sigmoid-like curve,
    then blended. Scores ≥ 70 are considered HIGH risk.
    """
    events = user["events"]
    reply_speeds = user["reply_speeds"]
    conversation_ids = user["conversation_ids"]
    now = time.time()

    # --- component 1: message frequency ---
    window = 24 * 3600
    recent_msgs = [e for e in events if now - e["ts"] <= window]
    msgs_per_hour = len(recent_msgs) / 24.0
    # sigmoid: saturates at ~20 msg/hr → score 100
    freq_score = 100 * (1 - math.exp(-msgs_per_hour / 5))

    # --- component 2: reply speed (lower = more suspicious) ---
    if reply_speeds:
        median_speed = sorted(reply_speeds)[len(reply_speeds) // 2]
        # <5 s → near 100; >600 s (10 min) → near 0
        speed_score = 100 * math.exp(-median_speed / 60)
    else:
        speed_score = 0

    # --- component 3: conversation breadth ---
    convo_count = len(conversation_ids)
    # sigmoid: saturates at ~50 conversations
    convo_score = 100 * (1 - math.exp(-convo_count / 15))

    # --- blend ---
    risk = 0.40 * freq_score + 0.35 * speed_score + 0.25 * convo_score
    risk = round(min(100, max(0, risk)), 2)

    level = "low"
    if risk >= 70:
        level = "high"
    elif risk >= 40:
        level = "medium"

    return {
        "score": risk,
        "level": level,
        "components": {
            "message_frequency": round(freq_score, 2),
            "reply_speed": round(speed_score, 2),
            "conversation_breadth": round(convo_score, 2),
        },
        "signals": {
            "messages_last_24h": len(recent_msgs),
            "msgs_per_hour": round(msgs_per_hour, 2),
            "median_reply_seconds": round(sorted(reply_speeds)[len(reply_speeds) // 2], 2) if reply_speeds else None,
            "unique_conversations": convo_count,
        },
    }

def maybe_auto_flag(api_key: str, user_id: str):
    """Auto-flag users whose risk score crosses 70."""
    user = tenant_data[api_key]["users"][user_id]
    result = compute_risk_score(user)
    if result["score"] >= 70 and not user["flagged"]:
        user["flagged"] = True
        user["flag_reason"] = (
            f"Auto-flagged: risk score {result['score']} "
            f"(freq={result['components']['message_frequency']}, "
            f"speed={result['components']['reply_speed']}, "
            f"convo={result['components']['conversation_breadth']})"
        )

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
def health():
    """Liveness check — no auth required."""
    return {
        "status": "ok",
        "service": "driftline",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenants": len(tenant_data),
    }


@app.post("/event", tags=["Events"])
def post_event(
    user_id: str = Query(..., description="Marketplace user identifier"),
    event_type: str = Query(..., description="Type of event: message_sent | reply_sent | listing_created | offer_made"),
    conversation_id: Optional[str] = Query(default=None, description="Conversation / thread ID"),
    reply_to_ts: Optional[float] = Query(default=None, description="Unix timestamp of the original message being replied to (used to compute reply speed)"),
    metadata: Optional[str] = Query(default=None, description="Optional JSON string for extra context"),
    api_key: str = Depends(get_tenant),
):
    """
    Record a user behaviour event. Triggers automatic risk re-evaluation
    and will flag users whose score crosses 70.
    """
    _init_user(api_key, user_id)
    user = tenant_data[api_key]["users"][user_id]
    now = time.time()

    event = {
        "ts": now,
        "event_type": event_type,
        "metadata": {"raw": metadata} if metadata else {},
    }
    user["events"].append(event)

    if conversation_id:
        user["conversation_ids"].add(conversation_id)

    if reply_to_ts and event_type == "reply_sent":
        speed = max(0, now - reply_to_ts)
        user["reply_speeds"].append(speed)

    maybe_auto_flag(api_key, user_id)

    score_data = compute_risk_score(user)

    return {
        "accepted": True,
        "user_id": user_id,
        "event_type": event_type,
        "risk_score": score_data["score"],
        "risk_level": score_data["level"],
        "flagged": user["flagged"],
    }


@app.get("/score/{user_id}", tags=["Risk"])
def get_score(
    user_id: str,
    api_key: str = Depends(get_tenant),
):
    """Return detailed risk score breakdown for a user."""
    _init_tenant(api_key)
    users = tenant_data[api_key]["users"]
    if user_id not in users:
        raise HTTPException(status_code=404, detail=f"User '{user_id}' not found for this tenant.")

    user = users[user_id]
    score_data = compute_risk_score(user)
    return {
        "user_id": user_id,
        "marketplace": api_keys[api_key],
        "flagged": user["flagged"],
        "flag_reason": user["flag_reason"],
        "account_age_hours": round((time.time() - user["created_at"]) / 3600, 1),
        **score_data,
    }


@app.get("/flagged", tags=["Risk"])
def get_flagged(
    min_score: float = Query(default=0, description="Only return users with risk score ≥ this value"),
    limit: int = Query(default=50, le=500, description="Max results to return"),
    api_key: str = Depends(get_tenant),
):
    """List all flagged users for this marketplace, ordered by descending risk score."""
    _init_tenant(api_key)
    users = tenant_data[api_key]["users"]

    results = []
    for uid, user in users.items():
        if not user["flagged"]:
            continue
        score_data = compute_risk_score(user)
        if score_data["score"] < min_score:
            continue
        results.append({
            "user_id": uid,
            "risk_score": score_data["score"],
            "risk_level": score_data["level"],
            "flag_reason": user["flag_reason"],
            "signals": score_data["signals"],
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return {
        "marketplace": api_keys[api_key],
        "total_flagged": len(results),
        "results": results[:limit],
    }


@app.get("/stats", tags=["Analytics"])
def get_stats(api_key: str = Depends(get_tenant)):
    """Aggregate statistics for the marketplace tenant."""
    _init_tenant(api_key)
    users = tenant_data[api_key]["users"]

    total_users = len(users)
    flagged_count = sum(1 for u in users.values() if u["flagged"])
    total_events = sum(len(u["events"]) for u in users.values())

    score_buckets = {"low": 0, "medium": 0, "high": 0}
    all_scores = []
    for user in users.values():
        s = compute_risk_score(user)
        score_buckets[s["level"]] += 1
        all_scores.append(s["score"])

    avg_score = round(sum(all_scores) / len(all_scores), 2) if all_scores else 0

    return {
        "marketplace": api_keys[api_key],
        "total_users": total_users,
        "flagged_users": flagged_count,
        "flag_rate_pct": round(100 * flagged_count / total_users, 1) if total_users else 0,
        "total_events_recorded": total_events,
        "average_risk_score": avg_score,
        "risk_distribution": score_buckets,
    }


@app.delete("/account/{user_id}", tags=["Account"])
def delete_account(
    user_id: str,
    api_key: str = Depends(get_tenant),
):
    """Permanently delete a user's data from this marketplace tenant (GDPR erasure)."""
    _init_tenant(api_key)
    users = tenant_data[api_key]["users"]
    if user_id not in users:
        raise HTTPException(status_code=404, detail=f"User '{user_id}' not found for this tenant.")

    del users[user_id]
    return {
        "deleted": True,
        "user_id": user_id,
        "marketplace": api_keys[api_key],
        "message": "All data associated with this user has been erased.",
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
