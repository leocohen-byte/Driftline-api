from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import time
from datetime import datetime
import os

app = FastAPI(
title=“Driftline API”,
description=“Early scammer detection for online marketplaces”,
version=“1.0.0”
)

app.add_middleware(
CORSMiddleware,
allow_origins=[”*”],
allow_methods=[”*”],
allow_headers=[”*”],
)

events_store = {}
scores_store = {}
flagged_accounts = []

class MessageEvent(BaseModel):
user_id: str
platform: str
timestamp: Optional[float] = None
conversation_id: str
message_length: Optional[int] = None
is_new_conversation: Optional[bool] = False

class BulkEvents(BaseModel):
events: List[MessageEvent]

class ScoreResponse(BaseModel):
user_id: str
risk_score: int
risk_level: str
flags: List[str]
recommendation: str
analyzed_at: str
total_messages: Optional[int] = 0
platform: Optional[str] = “”

def compute_risk_score(user_id: str) -> dict:
events = events_store.get(user_id, [])
if not events:
return {“score”: 0, “flags”: [], “level”: “low”, “recommendation”: “No action required”}

```
now = time.time()
recent = [e for e in events if now - e["timestamp"] < 3600]
flags = []
score = 0

msg_count = len(recent)
if msg_count > 30:
    flags.append("Sent " + str(msg_count) + " messages in the last hour")
    score += 35
elif msg_count > 15:
    flags.append("High message volume: " + str(msg_count) + " messages/hour")
    score += 18

unique_convos = len(set(e["conversation_id"] for e in recent))
if unique_convos > 20:
    flags.append("Opened " + str(unique_convos) + " simultaneous conversations")
    score += 30
elif unique_convos > 10:
    flags.append("Unusually high conversation count: " + str(unique_convos))
    score += 15

convo_times = {}
for e in sorted(events, key=lambda x: x["timestamp"]):
    cid = e["conversation_id"]
    if cid not in convo_times:
        convo_times[cid] = []
    convo_times[cid].append(e["timestamp"])

fast_replies = 0
for times in convo_times.values():
    if len(times) > 1:
        gaps = [times[i+1]-times[i] for i in range(len(times)-1)]
        avg_gap = sum(gaps)/len(gaps)
        if avg_gap < 2:
            fast_replies += 1

if fast_replies > 5:
    flags.append("Bot-like reply speed in " + str(fast_replies) + " conversations")
    score += 25
elif fast_replies > 2:
    flags.append("Unusually fast replies in " + str(fast_replies) + " conversations")
    score += 12

first_seen = min(e["timestamp"] for e in events)
account_age_hours = (now - first_seen) / 3600
if account_age_hours < 24 and len(events) > 20:
    flags.append("New account (" + str(int(account_age_hours)) + "h old) with high activity")
    score += 20

very_recent = [e for e in events if now - e["timestamp"] < 300]
if len(very_recent) > 10:
    flags.append("Activity spike: " + str(len(very_recent)) + " messages in last 5 minutes")
    score += 15

score = min(score, 99)

if score >= 75:
    level = "critical"
    recommendation = "Suspend account pending manual review"
elif score >= 55:
    level = "high"
    recommendation = "Limit messaging and send verification request"
elif score >= 35:
    level = "medium"
    recommendation = "Monitor closely - flag for review"
else:
    level = "low"
    recommendation = "No action required"

return {"score": score, "flags": flags, "level": level, "recommendation": recommendation}
```

@app.get(”/”)
def root():
return {“product”: “Driftline”, “version”: “1.0.0”, “status”: “operational”}

@app.get(”/health”)
def health():
return {“status”: “ok”, “timestamp”: datetime.utcnow().isoformat()}

@app.post(”/event”)
def ingest_event(event: MessageEvent):
ts = event.timestamp or time.time()
if event.user_id not in events_store:
events_store[event.user_id] = []
events_store[event.user_id].append({
“timestamp”: ts,
“conversation_id”: event.conversation_id,
“platform”: event.platform,
“message_length”: event.message_length,
“is_new_conversation”: event.is_new_conversation,
})
result = compute_risk_score(event.user_id)
score_data = {
“user_id”: event.user_id,
“platform”: event.platform,
“risk_score”: result[“score”],
“risk_level”: result[“level”],
“flags”: result[“flags”],
“recommendation”: result[“recommendation”],
“analyzed_at”: datetime.utcnow().isoformat(),
“total_messages”: len(events_store[event.user_id]),
}
scores_store[event.user_id] = score_data
if result[“score”] >= 35:
existing = next((a for a in flagged_accounts if a[“user_id”] == event.user_id), None)
if existing:
existing.update(score_data)
else:
flagged_accounts.insert(0, score_data)
if len(flagged_accounts) > 100:
flagged_accounts.pop()
return score_data

@app.get(”/flagged”)
def get_flagged(platform: Optional[str] = None, level: Optional[str] = None, limit: int = 50):
accounts = flagged_accounts.copy()
if platform:
accounts = [a for a in accounts if a.get(“platform”) == platform]
if level:
accounts = [a for a in accounts if a.get(“risk_level”) == level]
return {
“total”: len(accounts),
“accounts”: accounts[:limit],
“critical”: len([a for a in accounts if a[“risk_level”] == “critical”]),
“high”: len([a for a in accounts if a[“risk_level”] == “high”]),
“medium”: len([a for a in accounts if a[“risk_level”] == “medium”]),
}

@app.get(”/score/{user_id}”)
def get_score(user_id: str):
if user_id not in scores_store:
raise HTTPException(status_code=404, detail=“User not found”)
return scores_store[user_id]

@app.delete(”/account/{user_id}”)
def clear_account(user_id: str, action: str = “reviewed”):
global flagged_accounts
flagged_accounts = [a for a in flagged_accounts if a[“user_id”] != user_id]
if user_id in scores_store:
scores_store[user_id][“status”] = action
if user_id in events_store:
del events_store[user_id]
return {“user_id”: user_id, “action”: action, “status”: “success”}

@app.get(”/stats”)
def get_stats(platform: Optional[str] = None):
accounts = flagged_accounts
if platform:
accounts = [a for a in accounts if a.get(“platform”) == platform]
total_scanned = len(scores_store)
return {
“total_scanned”: total_scanned,
“total_flagged”: len(accounts),
“critical”: len([a for a in accounts if a[“risk_level”] == “critical”]),
“high”: len([a for a in accounts if a[“risk_level”] == “high”]),
“medium”: len([a for a in accounts if a[“risk_level”] == “medium”]),
“flag_rate”: round(len(accounts) / max(total_scanned, 1) * 100, 1),
}

def seed_demo_data():
import random
demo_users = [
(“scammer_001”, 45, True),
(“scammer_002”, 38, True),
(“scammer_003”, 52, True),
(“suspicious_004”, 22, False),
(“suspicious_005”, 18, False),
]
now = time.time()
for user_id, msg_count, is_scammer in demo_users:
events_store[user_id] = []
base_time = now - random.randint(1800, 7200)
convos = [“conv_” + str(random.randint(1000, 9999)) for _ in range(random.randint(10, 30))]
for i in range(msg_count):
gap = random.uniform(0.5, 3) if is_scammer else random.uniform(30, 300)
base_time += gap
events_store[user_id].append({
“timestamp”: base_time,
“conversation_id”: random.choice(convos),
“platform”: “bark”,
“message_length”: random.randint(20, 200),
“is_new_conversation”: random.random() < 0.3,
})
result = compute_risk_score(user_id)
score_data = {
“user_id”: user_id,
“platform”: “bark”,
“risk_score”: result[“score”],
“risk_level”: result[“level”],
“flags”: result[“flags”],
“recommendation”: result[“recommendation”],
“analyzed_at”: datetime.utcnow().isoformat(),
“total_messages”: msg_count,
}
scores_store[user_id] = score_data
if result[“score”] >= 35:
flagged_accounts.append(score_data)

seed_demo_data()

if **name** == “**main**”:
import uvicorn
port = int(os.environ.get(“PORT”, 8000))
uvicorn.run(app, host=“0.0.0.0”, port=port)
