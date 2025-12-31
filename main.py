import asyncio
import json
import os
import time
import hashlib
import base64
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from threading import Thread

# --- START OF FLASK KEEP-ALIVE ---
from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "Bot is running! This page keeps Render awake."

def run_web():
    # Render assigns a port in the environment variable PORT
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)

def keep_alive():
    t = Thread(target=run_web)
    t.start()
# --- END OF FLASK KEEP-ALIVE ---

import httpx
import jwt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ================= CONFIG =================
REQUEST_TIMEOUT = 30
SALT = "j8n5HxYA0ZVF"
ENCRYPTION_KEY = "6fbJwIfT6ibAkZo1VVKlKVl8M2Vb7GSs"

FAIRBID_BURST = int(os.getenv("FAIRBID_BURST", "1"))
FAIRBID_DELAY = float(os.getenv("FAIRBID_DELAY", "0"))

GLOBAL_CONCURRENCY = int(os.getenv("GLOBAL_CONCURRENCY", "0")) or None
FAIRBID_SEMAPHORE = asyncio.Semaphore(GLOBAL_CONCURRENCY) if GLOBAL_CONCURRENCY else None

# ================= ACCOUNTS =================
ACCOUNTS = [
    {
        "NAME": "cashthug",
        "JSON_URL": "https://gist.githubusercontent.com/immu-cyber/81eeab5a36add37068ce19a206d9efca/raw/12c2b5bcaf5e551c97b4d92d45806ecc8a40cf93/Cashthug.json",
        "FIREBASE_KEY": "AIzaSyDArVb852ZEA9s4bV9NozW0-lVmX1UtsIg",
        "PROJECT_ID": "quiz-cash-d2b1f",
        "REFRESH_TOKEN": "AMf-vBweQYZnVSw89cwzEwOPw-XZR2m4z8Kbccd4WKSW-HjEDkiYdY2iKDSVmwpjQ22yCGbyA_wHbodYruvN1YXJLX2h0HyJnWKqgoCsJTru0MiDGdnJWCJ5GmyTCN5mlse9YmalkgQyDQmBn9JinYEBYcdnPbM3xJBgU4h1rMOZAUOlZr3lLGO7oJCylNwGbnbrHI4mVYWOW_eyA0poIjPBw5dx6JBEhs6-GTcGGF918IQtk227Ibk8uQ14MyjjJaZ08q4a5adQXLoN6OTRh9mJehAP1AalNP7Gq7YailNKICjgq8n_spLWRG1gh-nMTbpMSXgUFqTFhE0vx8gP9_-FiIblGbljvs2G2PZ0rMA5rtlfPxdNShi-iS7YOJ1a-IsNsxJtDO-t13AMd8GGOsjWvhuWcrsnzTC1RP3XoZZvYZGPz0DmYv8",
        "BASE_URL": "https://fairbid.inner-active.mobi/simpleM2M/fyberMediation",
        "SPOT_ID": "2238090"
    },
    {
        "NAME": "cashmonkey",
        "JSON_URL": "https://gist.githubusercontent.com/immu-cyber/4317a1fa5892d8e6b185441c88e44017/raw/1953e2d3edc21a1dcfcfade1039a4552c92acb70/Cashmonkey.json",
        "FIREBASE_KEY": "AIzaSyA80VcSTBCCc2eK5urAdPuVFDWo1F9gAds",
        "PROJECT_ID": "cash-monkey-1df41",
        "REFRESH_TOKEN": "AMf-vBx9QLJQy5UvyqJNxsKNgpC2hjZkKIzKNbcFNlcOZJnxUWiN-puI4VGs50_5TJHaS0YMYPFP37U35hLx5nM0LHoInyJuxNC8q-bnhcB6RVzF7wtMmNA8JP5o-ZmoqFG9zbxzWMuOmBWjGN5k_BFzvpwfnJ68q24pMkTvhikYClu9wXmYZNiqiLaYU0f3QxQHnR0wOL1bwp5h2MSIj4MDwIbrE55_tzuaM7OheWlRJtKv1YxvZk_03o0_yOeM3ETbNAzbMxy2jxUPo8pS5FMNi_DD2mxaxxn78Ue-MSh6hg4LgvG9pUuOY5HKOmJVvGp46Ri-SQZrki7cft6O59omswGctDy4w0iDXV_EwjX0McNuO9wQnGxe0fBYnQ3-dz8c_DBetr8PV7AvICv8bSbFdocHz7zprAKFmVp5s7XEtTS9YAstoAj4RRd1xqFmuyC6_N9JVLbs",
        "BASE_URL": "https://fairbid.inner-active.mobi/simpleM2M/fyberMediation",
        "SPOT_ID": "2052854"
    },
    {
        "NAME": "Cashmafia",
        "JSON_URL": "https://gist.githubusercontent.com/immu-cyber/1641798decfced43de3d9545fc58665e/raw/49c618a4616c74266eeae332a08394c5efb35ebb/Cashmafia.json",
        "FIREBASE_KEY": "AIzaSyCxoB5Kk1AEQt5c6CHsC-XVdNaxr4nu8Es",
        "PROJECT_ID": "cash-mafia-5ae03",
        "REFRESH_TOKEN": "AMf-vBxQg_EIstOlGSLpVAbUnUsZpTgMDXBut0v_WraHO87-4PyTGkJqwVzmC1DLadsmPWnjqDfU3CLDSbSrXaUPAc-WveIaUS3b5yaNgIGshMOtOxPjpzburHt2jTbM_XTuZSrNOSPV_0SGEBJiVv2o5e6GaqXdKCAbYEByyaQgXdg8GXTIK2LoRnB2vcMg06pI_b4UWdNqIeNiNTej4bB74cS5ceIECdHVI-YqTbUU9b3Em6_YkdNV8hrBlr359vVyDuBQ4oo1LW_Ipt2fs1ajANES7l6u_UuSWdg-xmj6mez1Exmg5UlHcFOm9VDLt2g5ub1pHyrncZxFAo-VW6BIuK8sFtm7kYArPQKsOu0gNRLNMSeJmoTXCpGQM3cW1o0hiZaGitGEzkvgGZjRCnx-TI_KHBG3dryWNL84GswZ7uX5z28Dz-4",
        "BASE_URL": "https://fairbid.inner-active.mobi/simpleM2M/fyberMediation",
        "SPOT_ID": "2398650"
    },
    {
        "NAME": "Puzzlemaster",
        "JSON_URL": "https://gist.githubusercontent.com/immu-cyber/61225fb8a37d4b1f5b94fa793e1ae411/raw/12304b37c48f27f4cb55145348f7691b6af4db25/Puzzlemaster.json",
        "FIREBASE_KEY": "AIzaSyCF-M9WFi6IsTIn7G3hzG_nIi3rWA3XD6o",
        "PROJECT_ID": "puzzle-master-51426",
        "REFRESH_TOKEN": "3_AS3qfwLO5n30nDs73Zo4n-H-7Uux9BcHDShpW4tl-lixgAmirtrPBUeSBmw3deLnP3xg9CaHMQVrhoe7o66-NqXTpWhDjSVs-MeLXM4DNYSoC0Y",
        "BASE_URL": "https://fairbid.inner-active.mobi/simpleM2M/fyberMediation",
        "SPOT_ID": "2555632"
    },
     {
        "NAME": "Tap&Earn",
        "JSON_URL": "https://gist.githubusercontent.com/immu-cyber/ec4a4eec1a864cfe81b14bfd8a6416f5/raw/cae93130695a01783fdaf2b609fecd9157a50f95/Tapandearn.json",
        "FIREBASE_KEY": "AIzaSyAkSwrPZkuDYUGWU65NAVtbidYzE5ydIJ4",
        "PROJECT_ID": "cash-rhino",
        "REFRESH_TOKEN": "AMf-vBx23oc67bAU59HjdCEvQKDDPhEolhXNKdFdi3hFrEJYa93j5umrpdQDZRt2QrFadqIlZ2kArpt0i-3VCtv9Mf_QPQ-A6Q8ecIdoT3nMOGj7ibWnSQw80SLsWT4X0oIuxX-BFwucv_0yftW_rVeR1YAS12jd2CHkqGkKzjzYB0WqRAqjRmWzV4fYkF1AJ7F-2p1GtDCQ6DNOvAGSezm6H0MDigBWM1NwpVrt21smhyaymX8wtl3EpgLdmo7O6gqg97hj6CrSVZeXAk5O-jXGJAkkzL0770Q91lJ-H2cTjE_8MfsCIrflP2i4qSiWWB08fJwgBmGdlH11WS3NqAze4injLDG9xhzwjZfdKs2pn5hlzBV8BtzKWV36Kf9PWmulRXF-eRAhyBJ7--Zq8QJJp5vDaFpunjbOY2FgUr5S-aRh_0IHsdU",
        "BASE_URL": "https://fairbid.inner-active.mobi/simpleM2M/fyberMediation",
        "SPOT_ID": "2555632"
    },
]

# ================= HELPERS =================
def log(name: str, msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{name}] {msg}", flush=True)

async def create_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        http2=True,
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=100),
        headers={"User-Agent": "Mozilla/5.0 (Android)"}
    )

async def load_config(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    r = await client.get(url)
    r.raise_for_status()
    j = r.json()
    return {
        "user_id": j["client_params"]["publisher_supplied_user_id"],
        "payload": json.dumps(j, separators=(",", ":"))
    }

async def get_id_token(
    client: httpx.AsyncClient,
    firebase_key: str,
    refresh_token: str
) -> tuple[str, str, int]:
    url = f"https://securetoken.googleapis.com/v1/token?key={firebase_key}"
    r = await client.post(
        url,
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    r.raise_for_status()
    j = r.json()
    return j["id_token"], j["user_id"], int(j["expires_in"])

class TokenManager:
    def __init__(self, firebase_key: str, refresh_token: str):
        self.firebase_key = firebase_key
        self.refresh_token = refresh_token
        self.token: Optional[str] = None
        self.uid: Optional[str] = None
        self._lock = asyncio.Lock()

    async def get(self, client: httpx.AsyncClient) -> tuple[str, str]:
        async with self._lock:
            now = time.time()
            needs_refresh = True

            if self.token:
                try:
                    payload = jwt.decode(
                        self.token,
                        options={"verify_signature": False}
                    )
                    exp = payload.get("exp", 0)
                    if exp > now + 120:  # ≥2 min margin
                        needs_refresh = False
                except Exception:
                    pass

            if needs_refresh:
                log("TokenManager", f"🔄 Refreshing token for account")
                self.token, self.uid, _ = await get_id_token(
                    client, self.firebase_key, self.refresh_token
                )
                try:
                    payload = jwt.decode(self.token, options={"verify_signature": False})
                    exp_dt = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                    log("TokenManager", f"✅ New token valid until {exp_dt.strftime('%Y-%m-%d %H:%M:%S')}")
                except Exception:
                    pass

            assert self.token and self.uid
            return self.token, self.uid

def build_hash_payload(user_id: str, url: str) -> str:
    now = int(time.time())
    ts = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    raw = f"{url}{ts}{SALT}"
    h = hashlib.sha512(raw.encode()).hexdigest()
    return json.dumps({"user_id": user_id, "timestamp": now, "hash_value": h}, separators=(",", ":"))

def encrypt_offer(offer_id: str) -> Dict[str, Any]:
    key = hashlib.sha256(ENCRYPTION_KEY.encode()).digest()
    raw = json.dumps({"offerId": offer_id}, separators=(",", ":")).encode()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(raw, AES.block_size))
    return {
        "data": {
            "data": base64.b64encode(encrypted).decode()
        }
    }

async def call_with_auth_retry(client: httpx.AsyncClient, method: str, url: str, token: str, **kwargs):
    for attempt in range(2):
        req = getattr(client, method)
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        try:
            r = await req(url, headers=headers, **kwargs)
            if r.status_code == 401 and attempt == 0:
                continue
            r.raise_for_status()
            return r
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 and attempt == 0:
                continue
            raise
    raise httpx.HTTPStatusError("Auth failed after refresh", request=None, response=None)

async def get_super_offer(
    client: httpx.AsyncClient,
    token: str,
    project_id: str,
    uid: str
) -> Optional[Dict[str, Any]]:
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/users/{uid}:runQuery"
    query = {
        "structuredQuery": {
            "from": [{"collectionId": "superOffers"}],
            "where": {
                "fieldFilter": {
                    "field": {"fieldPath": "status"},
                    "op": "NOT_EQUAL",
                    "value": {"stringValue": "COMPLETED"}
                }
            },
            "limit": 1
        }
    }
    r = await call_with_auth_retry(client, "post", url, token, json=query)
    for item in r.json():
        if "document" in item:
            f = item["document"]["fields"]
            return {
                "offerId": f["offerId"]["stringValue"],
                "fees": int(f["fees"]["integerValue"])
            }
    return None

async def get_boosts(
    client: httpx.AsyncClient,
    token: str,
    project_id: str,
    uid: str
) -> int:
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/users/{uid}?mask.fieldPaths=boosts"
    r = await call_with_auth_retry(client, "get", url, token)
    doc = r.json()
    return int(doc.get("fields", {}).get("boosts", {}).get("integerValue", 0))

async def run_fairbid(client: httpx.AsyncClient, acc: Dict[str, Any], cfg: Dict[str, Any]) -> None:
    if FAIRBID_SEMAPHORE:
        async with FAIRBID_SEMAPHORE:
            await _run_fairbid_impl(client, acc, cfg)
    else:
        await _run_fairbid_impl(client, acc, cfg)

async def _run_fairbid_impl(client: httpx.AsyncClient, acc: Dict[str, Any], cfg: Dict[str, Any]) -> None:
    try:
        url = f"{acc['BASE_URL']}?spotId={acc['SPOT_ID']}"
        r = await client.post(url, content=cfg["payload"])
        r.raise_for_status()
        text = r.text

        tasks = []
        if 'impression":"' in text:
            imp_url = text.split('impression":"')[1].split('"')[0]
            tasks.append(client.get(imp_url))
        if 'completion":"' in text:
            comp_url = text.split('completion":"')[1].split('"')[0]
            payload = build_hash_payload(cfg["user_id"], comp_url)
            tasks.append(client.post(comp_url, content=payload))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    except Exception as e:
        log(acc["NAME"], f"❌ FairBid error: {e}")

async def call_fn(
    client: httpx.AsyncClient,
    token: str,
    project_id: str,
    name: str,
    offer_id: str
) -> Dict[str, Any]:
    url = f"https://us-central1-{project_id}.cloudfunctions.net/{name}"
    r = await call_with_auth_retry(client, "post", url, token, json=encrypt_offer(offer_id))
    return r.json()

async def bot_loop(acc: Dict[str, Any]) -> None:
    client = await create_client()
    try:
        cfg = await load_config(client, acc["JSON_URL"])
        tm = TokenManager(acc["FIREBASE_KEY"], acc["REFRESH_TOKEN"])
        log(acc["NAME"], "🟢 STARTED")

        while True:
            try:
                token, uid = await tm.get(client)
                offer = await get_super_offer(client, token, acc["PROJECT_ID"], uid)
                if not offer:
                    await asyncio.sleep(5)
                    continue

                log(acc["NAME"], f"🎯 OFFER FOUND | ID={offer['offerId']} | FEES={offer['fees']}")
                target = offer["fees"] + 1

                while True:
                    boosts = await get_boosts(client, token, acc["PROJECT_ID"], uid)
                    log(acc["NAME"], f"⚡ BOOSTS {boosts}/{target}")
                    if boosts >= target:
                        break
                    log(acc["NAME"], f"🌀 Running FairBid burst ×{FAIRBID_BURST}...")
                    await asyncio.gather(
                        *(run_fairbid(client, acc, cfg) for _ in range(FAIRBID_BURST)),
                        return_exceptions=True
                    )
                    if FAIRBID_DELAY > 0:
                        await asyncio.sleep(FAIRBID_DELAY)

                unlock = await call_fn(client, token, acc["PROJECT_ID"], "superOffer_unlock", offer["offerId"])
                status = unlock.get("status", "OK")
                log(acc["NAME"], f"🔓 UNLOCK → {status}")

                claim = await call_fn(client, token, acc["PROJECT_ID"], "superOffer_claim", offer["offerId"])
                reward = claim.get("reward", "??")
                log(acc["NAME"], f"🏆 CLAIM → {reward}")

                await asyncio.sleep(3)

            except Exception as e:
                log(acc["NAME"], f"💥 Inner loop error: {e}")
                await asyncio.sleep(10)

    except Exception as e:
        log(acc["NAME"], f"🚨 Bot crashed: {e}")
    finally:
        await client.aclose()

async def main() -> None:
    log("SYSTEM", f"🚀 Bot started | Accounts: {len(ACCOUNTS)} | Burst: {FAIRBID_BURST} | Delay: {FAIRBID_DELAY}s")
    if GLOBAL_CONCURRENCY:
        log("SYSTEM", f"⚠️ Global concurrency limited to {GLOBAL_CONCURRENCY} FairBid requests")
    
    try:
        await asyncio.gather(*(bot_loop(acc) for acc in ACCOUNTS), return_exceptions=True)
    except KeyboardInterrupt:
        log("SYSTEM", "🛑 Interrupt received — shutting down...")
    except Exception as e:
        log("SYSTEM", f"🔥 Fatal error: {e}")

if __name__ == "__main__":
    # Start the "fake" web server in a separate thread
    keep_alive()
    # Start the async bot loop
    asyncio.run(main())