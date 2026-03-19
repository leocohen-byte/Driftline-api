from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import time, os, random
from datetime import datetime

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=[”*”], allow_methods=[”*”], allow_headers=[”*”])

events = {}
scores = {}
flagged = []

def risk(uid):
ev = events.get(uid, [])
if not ev: return 0, [], “low”, “No action required”
now = time.time()
recent = [e for e in ev if now - e[“ts”] < 3600]
s = 0
f = []
mc = len(recent)
if mc > 30:
f.append(“Sent “ + str(mc) + “ messages in 1 hour”)
s += 35
elif mc > 15:
f.append(“High volume: “ + str(mc) + “ msg/hr”)
s += 18
uc = len(set(e[“cid”] for e in recent))
if uc > 20:
f.append(“Opened “ + str(uc) + “ conversations”)
s += 30
elif uc > 10:
f.append(“High conversation count: “ + str(uc))
s += 15
s = min(s, 99)
if s >= 75: return s, f, “critical”, “Suspend account”
elif s >= 55: return s, f, “high”, “Limit messaging”
elif s >= 35: return s, f, “medium”, “Monitor closely”
return s, f, “low”, “No action required”

def seed():
users = [(“scammer_001”,45,True),(“scammer_002”,38,True),(“scammer_003”,52,True),(“user_004”,12,False)]
now = time.time()
for uid, mc, bad in users:
events[uid] = []
bt = now - random.randint(1800,7200)
cvs = [“c”+str(random.randint(1000,9999)) for _ in range(15)]
for _ in range(mc):
bt += random.uniform(0.5,3) if bad else random.uniform(30,300)
events[uid].append({“ts”:bt,“cid”:random.choice(cvs),“platform”:“driftline”})
sc,fl,lv,rc = risk(uid)
d = {“user_id”:uid,“platform”:“driftline”,“risk_score”:sc,“risk_level”:lv,“flags”:fl,“recommendation”:rc,“analyzed_at”:datetime.utcnow().isoformat(),“total_messages”:mc}
scores[uid] = d
if sc >= 35: flagged.append(d)

seed()

@app.get(”/”)
def root(): return {“product”:“Driftline”,“version”:“2.0.0”,“status”:“operational”}

@app.get(”/health”)
def health(): return {“status”:“ok”,“timestamp”:datetime.utcnow().isoformat()}

@app.get(”/flagged”)
def get_flagged(platform: str = None, level: str = None, limit: int = 50):
acc = flagged.copy()
if platform: acc = [a for a in acc if a.get(“platform”) == platform]
if level: acc = [a for a in acc if a.get(“risk_level”) == level]
return {“total”:len(acc),“accounts”:acc[:limit],“critical”:len([a for a in acc if a[“risk_level”]==“critical”]),“high”:len([a for a in acc if a[“risk_level”]==“high”]),“medium”:len([a for a in acc if a[“risk_level”]==“medium”])}

@app.get(”/stats”)
def get_stats(): return {“total_scanned”:len(scores),“total_flagged”:len(flagged),“critical”:len([a for a in flagged if a[“risk_level”]==“critical”]),“high”:len([a for a in flagged if a[“risk_level”]==“high”]),“medium”:len([a for a in flagged if a[“risk_level”]==“medium”]),“flag_rate”:round(len(flagged)/max(len(scores),1)*100,1)}

@app.get(”/score/{user_id}”)
def get_score(user_id: str):
if user_id not in scores: raise HTTPException(404, “User not found”)
return scores[user_id]

@app.delete(”/account/{user_id}”)
def clear_account(user_id: str, action: str = “reviewed”):
global flagged
flagged = [a for a in flagged if a[“user_id”] != user_id]
if user_id in scores: scores[user_id][“status”] = action
if user_id in events: del events[user_id]
return {“user_id”:user_id,“action”:action,“status”:“success”}