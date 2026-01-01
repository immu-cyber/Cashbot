import asyncio
import json
import os
import time
import hashlib
import base64
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from aiohttp import web  # Web server for 24/7 hosting

# ================= CONFIGURATION =================
# Server Config
PORT = int(os.getenv("PORT", 10000))

# App Config
REQUEST_TIMEOUT = 30
SALT = "j8n5HxYA0ZVF"
ENCRYPTION_KEY = "6fbJwIfT6ibAkZo1VVKlKVl8M2Vb7GSs"

FAIRBID_BURST = int(os.getenv("FAIRBID_BURST", "1"))
FAIRBID_DELAY = float(os.getenv("FAIRBID_DELAY", "0"))
GLOBAL_CONCURRENCY = int(os.getenv("GLOBAL_CONCURRENCY", "0")) or None
FAIRBID_SEMAPHORE = asyncio.Semaphore(GLOBAL_CONCURRENCY) if GLOBAL_CONCURRENCY else None

# Global Stats for Web Server
_stats = {
    "start_time": time.time(),
    "total_boosts": 0,
    "status": "Initializing",
    "active_accounts": 0
}

# ================= ACCOUNTS LIST =================
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

# ================= HELPERS & CRYPTO =================
def log(name: str, msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{name}] {msg}", flush=True)

async def create_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        http2=True,
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=100),
        headers={"User-Agent": "Mozilla/5.0 (Android)"},
        verify=False
    )

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
    return {"data": {"data": base64.b64encode(encrypted).decode()}}

# ================= TOKEN MANAGER =================
class TokenManager:
    def __init__(self, firebase_key: str, refresh_token: str):
        self.firebase_key = firebase_key
        self.refresh_token = refresh_token
        self.token: Optional[str] = None
        self.uid: Optional[str] = None
        self.expiry = 0
        self._lock = asyncio.Lock()

    async def get(self, client: httpx.AsyncClient) -> tuple[str, str]:
        async with self._lock:
            if not self.token or time.time() >= self.expiry:
                url = f"https://securetoken.googleapis.com/v1/token?key={self.firebase_key}"
                try:
                    r = await client.post(
                        url,
                        data={"grant_type": "refresh_token", "refresh_token": self.refresh_token},
                        headers={"Content-Type": "application/x-www-form-urlencoded"}
                    )
                    r.raise_for_status()
                    j = r.json()
                    self.token = j["id_token"]
                    self.uid = j["user_id"]
                    # Expire 60 seconds before actual expiry to be safe
                    self.expiry = time.time() + int(j["expires_in"]) - 60
                    log("TokenManager", f"🔄 Auth Refreshed for {self.uid}")
                except Exception as e:
                    log("TokenManager", f"❌ Auth Failed: {e}")
                    raise e
            return self.token, self.uid

# ================= API & BOT LOGIC =================
async def load_config(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    r = await client.get(url)
    r.raise_for_status()
    j = r.json()
    return {
        "user_id": j["client_params"]["publisher_supplied_user_id"],
        "payload": json.dumps(j, separators=(",", ":"))
    }

async def call_with_auth_retry(client: httpx.AsyncClient, method: str, url: str, token: str, **kwargs):
    headers = kwargs.pop("headers", {})
    headers["Authorization"] = f"Bearer {token}"
    r = await getattr(client, method)(url, headers=headers, **kwargs)
    r.raise_for_status()
    return r

async def get_super_offer(client, token, project_id, uid):
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
    data = r.json()
    if data and "document" in data[0]:
        f = data[0]["document"]["fields"]
        return {"offerId": f["offerId"]["stringValue"], "fees": int(f.get("fees", {}).get("integerValue", 0))}
    return None

async def get_boosts(client, token, project_id, uid):
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/users/{uid}?mask.fieldPaths=boosts"
    r = await call_with_auth_retry(client, "get", url, token)
    return int(r.json().get("fields", {}).get("boosts", {}).get("integerValue", 0))

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
        text = r.text

        tasks = []
        if 'impression":"' in text:
            imp_url = text.split('impression":"')[1].split('"')[0]
            tasks.append(client.get(imp_url))
        
        if 'completion":"' in text:
            comp_url = text.split('completion":"')[1].split('"')[0]
            payload = build_hash_payload(cfg["user_id"], comp_url)
            tasks.append(client.post(comp_url, content=payload))
            _stats["total_boosts"] += 1  # Increment global stats

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    except Exception:
        pass

async def call_fn(client, token, project_id, name, offer_id):
    url = f"https://us-central1-{project_id}.cloudfunctions.net/{name}"
    r = await call_with_auth_retry(client, "post", url, token, json=encrypt_offer(offer_id))
    return r.json()

# ================= BOT LOOP =================
async def bot_loop(acc: Dict[str, Any]) -> None:
    client = await create_client()
    try:
        cfg = await load_config(client, acc["JSON_URL"])
        tm = TokenManager(acc["FIREBASE_KEY"], acc["REFRESH_TOKEN"])
        log(acc["NAME"], "🟢 STARTED")
        _stats["active_accounts"] += 1

        while True:
            try:
                token, uid = await tm.get(client)
                
                # Check for Offers
                offer = await get_super_offer(client, token, acc["PROJECT_ID"], uid)
                if not offer:
                    await asyncio.sleep(20) # Wait longer if no offers
                    continue

                log(acc["NAME"], f"🎯 Found Offer: {offer['offerId']} | Needs {offer['fees']} Boosts")
                target = offer["fees"] + 1

                # Farm Boosts
                while True:
                    boosts = await get_boosts(client, token, acc["PROJECT_ID"], uid)
                    if boosts >= target:
                        break
                    
                    # Run Boost Batch
                    await asyncio.gather(
                        *(run_fairbid(client, acc, cfg) for _ in range(FAIRBID_BURST)),
                        return_exceptions=True
                    )
                    
                    if FAIRBID_DELAY > 0:
                        await asyncio.sleep(FAIRBID_DELAY)

                # Claim Offer
                log(acc["NAME"], f"🔓 Unlocking {offer['offerId']}...")
                await call_fn(client, token, acc["PROJECT_ID"], "superOffer_unlock", offer["offerId"])
                await asyncio.sleep(1)
                
                log(acc["NAME"], f"🏆 Claiming {offer['offerId']}...")
                claim_res = await call_fn(client, token, acc["PROJECT_ID"], "superOffer_claim", offer["offerId"])
                
                log(acc["NAME"], f"💰 Claimed! Result: {claim_res.get('status', 'OK')}")
                await asyncio.sleep(5)

            except Exception as e:
                log(acc["NAME"], f"⚠️ Loop Error: {e}")
                await asyncio.sleep(10)

    except Exception as e:
        log(acc["NAME"], f"🚨 Bot Crashed: {e}")
    finally:
        _stats["active_accounts"] -= 1
        await client.aclose()

# ================= WEB SERVER =================
async def health_check(request):
    uptime = int(time.time() - _stats["start_time"])
    return web.json_response({
        "status": _stats["status"],
        "uptime_readable": f"{uptime//3600}h {(uptime%3600)//60}m {uptime%60}s",
        "active_accounts": _stats["active_accounts"],
        "total_boosts_farmed": _stats["total_boosts"],
        "system_status": "Running"
    })

async def start_server():
    app = web.Application()
    app.router.add_get("/", health_check)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    log("SYSTEM", f"📡 Web Server running on port {PORT}")

# ================= MAIN =================
async def main() -> None:
    _stats["status"] = "Running"
    log("SYSTEM", f"🚀 Multi-Account Bot Started | Accounts: {len(ACCOUNTS)}")
    
    # Start Web Server and Bots together
    await asyncio.gather(
        start_server(),
        *(bot_loop(acc) for acc in ACCOUNTS),
        return_exceptions=True
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
