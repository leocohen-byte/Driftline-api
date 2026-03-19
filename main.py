import os
import random
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Driftline", description="Marketplace Fraud Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Demo seed data ---
accounts = {
    "scammer_001": {"user_id": "scammer_001", "risk_score": 97, "flag": "critical", "reason": "Rapid listings + payment disputes"},
    "scammer_002": {"user_id": "scammer_002", "risk_score": 94, "flag": "critical", "reason": "Multiple refund requests in 24h"},
    "scammer_003": {"user_id": "scammer_003", "risk_score": 91, "flag": "critical", "reason": "Velocity spike + new account"},
    "medium_001":  {"user_id": "medium_001",  "risk_score": 58, "flag": "medium",   "reason": "Unusual login location"},
    "medium_002":  {"user_id": "medium_002",  "risk_score": 51, "flag": "medium",   "reason": "Mismatched shipping patterns"},
}

total_scanned = len(accounts)


# --- Helpers ---
def score_event(message: str, sender_id: str) -> int:
    risk = 0
    fraud_signals = [
        "venmo", "zelle", "cashapp", "cash app", "wire transfer",
        "off platform", "whatsapp", "telegram", "gift card",
        "too good to be true", "deal", "discount", "urgent",
        "limited time", "send me", "outside", "bypass",
    ]
    msg_lower = message.lower()
    for signal in fraud_signals:
        if signal in msg_lower:
            risk += 18

    if sender_id in accounts:
        existing = accounts[sender_id]["risk_score"]
        risk = min(100, (risk + existing) // 2 + random.randint(0, 5))
    else:
        risk = min(100, risk + random.randint(5, 20))

    return risk


def flag_level(score: int) -> str:
    if score >= 80:
        return "critical"
    elif score >= 45:
        return "medium"
    return "low"


# --- Endpoints ---

@app.get("/")
def root():
    return {"status": "ok", "service": "Driftline", "version": "1.0.0"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/flagged")
def get_flagged():
    flagged = [v for v in accounts.values() if v["flag"] in ("critical", "medium")]
    flagged_sorted = sorted(flagged, key=lambda x: x["risk_score"], reverse=True)
    return {"flagged_accounts": flagged_sorted, "count": len(flagged_sorted)}


@app.get("/stats")
def get_stats():
    flagged_count = sum(1 for v in accounts.values() if v["flag"] in ("critical", "medium"))
    flag_rate = round(flagged_count / total_scanned * 100, 1) if total_scanned > 0 else 0
    return {
        "total_scanned": total_scanned,
        "total_flagged": flagged_count,
        "flag_rate_percent": flag_rate,
    }


@app.get("/score/{user_id}")
def get_score(user_id: str):
    if user_id not in accounts:
        raise HTTPException(status_code=404, detail=f"User '{user_id}' not found")
    account = accounts[user_id]
    return {
        "user_id": user_id,
        "risk_score": account["risk_score"],
        "flag": account["flag"],
        "reason": account["reason"],
    }


@app.delete("/account/{user_id}")
def delete_account(user_id: str):
    if user_id not in accounts:
        raise HTTPException(status_code=404, detail=f"User '{user_id}' not found")
    del accounts[user_id]
    return {"status": "cleared", "user_id": user_id}


@app.post("/event")
def ingest_event(
    sender_id: str = Query(..., description="ID of the message sender"),
    message: str = Query(..., description="Message content to analyse"),
    listing_id: str = Query(None, description="Optional listing ID"),
):
    global total_scanned

    risk_score = score_event(message, sender_id)
    flag = flag_level(risk_score)

    if sender_id not in accounts:
        total_scanned += 1

    accounts[sender_id] = {
        "user_id": sender_id,
        "risk_score": risk_score,
        "flag": flag,
        "reason": f"Flagged via message event{' on listing ' + listing_id if listing_id else ''}",
    }

    return {
        "user_id": sender_id,
        "risk_score": risk_score,
        "flag": flag,
        "listing_id": listing_id,
        "action": "flagged" if flag != "low" else "cleared",
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
