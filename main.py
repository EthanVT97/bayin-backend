import os
import time
import json
import hmac
import hashlib
import logging
import asyncio
import datetime
from typing import Optional, Dict, Any

import httpx
import jwt
from fastapi import (
    FastAPI, Request, HTTPException, Depends, status
)
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import create_client, Client
from passlib.hash import bcrypt

# -------------------- Logging Setup --------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler("app.log")]
)
logger = logging.getLogger(__name__)

# -------------------- Environment Variables --------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
VIBER_TOKEN = os.getenv("VIBER_TOKEN")
VIBER_WEBHOOK_SECRET = os.getenv("VIBER_WEBHOOK_SECRET")

if not all([SUPABASE_URL, SUPABASE_KEY, SUPABASE_JWT_SECRET, VIBER_TOKEN]):
    logger.error("Missing critical environment variables! Exiting...")
    raise RuntimeError("Required environment variables are not set.")

# -------------------- Supabase Client --------------------
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# -------------------- Constants --------------------
ADMIN_EMAILS = os.getenv("ADMIN_EMAILS", "").split(",")  # comma separated admin emails
if not ADMIN_EMAILS or ADMIN_EMAILS == [""]:
    logger.warning("No admin emails configured in ADMIN_EMAILS env variable.")

JWT_ALGORITHM = "HS256"
JWT_AUDIENCE = "authenticated"
JWT_EXP_HOURS = 2

# -------------------- Rate Limiter --------------------
class RateLimiter:
    def __init__(self, max_requests: int = 20, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        timestamps = self.requests.get(key, [])
        timestamps = [ts for ts in timestamps if now - ts < self.window_seconds]
        if len(timestamps) >= self.max_requests:
            return False
        timestamps.append(now)
        self.requests[key] = timestamps
        return True

rate_limiter = RateLimiter()

# -------------------- User State --------------------
class UserState:
    AWAITING_ACCOUNT_ID = "AWAITING_ACCOUNT_ID"
    MAIN_MENU = "MAIN_MENU"
    AWAITING_DEPOSIT = "AWAITING_DEPOSIT"
    AWAITING_WITHDRAW = "AWAITING_WITHDRAW"

# -------------------- FastAPI App Setup --------------------
app = FastAPI(title="YGN Real Estate Bot Admin API", version="1.0.0")

# Middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In prod, replace with specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files for admin frontend
if os.path.isdir("admin"):
    app.mount("/admin", StaticFiles(directory="admin", html=True), name="admin")

# HTTP Bearer for JWT auth
security = HTTPBearer()

# -------------------- Lifespan Event --------------------
@app.on_event("startup")
async def startup_event():
    try:
        res = await asyncio.to_thread(lambda: supabase.table("viber_users").select("id").limit(1).execute())
        logger.info(f"Supabase connected: {res}")
    except Exception as e:
        logger.error(f"Supabase connection failed: {e}")
        raise

# -------------------- JWT Token Utilities --------------------
def create_jwt_token(email: str) -> str:
    payload = {
        "email": email,
        "role": "admin",
        "aud": JWT_AUDIENCE,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXP_HOURS),
        "iat": datetime.datetime.utcnow()
    }
    token = jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

async def verify_jwt_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=[JWT_ALGORITHM], audience=JWT_AUDIENCE)
        email = payload.get("email")
        if email not in ADMIN_EMAILS:
            logger.warning(f"Unauthorized email tried to access admin APIs: {email}")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# -------------------- Helper: Verify Admin Credentials --------------------
async def get_admin_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    res = await asyncio.to_thread(lambda: supabase.table("admin_users").select("*").eq("email", email).maybe_single().execute())
    if res and res.data:
        return res.data
    return None

# -------------------- Viber Signature Verification --------------------
def verify_viber_signature(body: bytes, signature: str) -> bool:
    if not VIBER_WEBHOOK_SECRET:
        logger.warning("VIBER_WEBHOOK_SECRET not configured; skipping signature verification")
        return True
    expected = hmac.new(VIBER_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

# -------------------- Viber Message Sender --------------------
async def send_viber_message(client: httpx.AsyncClient, receiver_id: str, message_text: str):
    url = "https://chatapi.viber.com/pa/send_message"
    headers = {"X-Viber-Auth-Token": VIBER_TOKEN}
    payload = {
        "receiver": receiver_id,
        "type": "text",
        "text": message_text,
        "min_api_version": 1
    }
    try:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        logger.info(f"Sent Viber message to {receiver_id}")
    except Exception as e:
        logger.error(f"Failed to send Viber message to {receiver_id}: {e}")

# -------------------- API Routes --------------------

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/auth/login")
async def admin_login(payload: Dict[str, str]):
    email = payload.get("email", "").strip().lower()
    password = payload.get("password", "")
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    user = await get_admin_user_by_email(email)
    if not user:
        logger.warning(f"Admin login failed: user not found for email {email}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not bcrypt.verify(password, user["password_hash"]):
        logger.warning(f"Admin login failed: incorrect password for {email}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if email not in ADMIN_EMAILS:
        logger.warning(f"Unauthorized admin login attempt by {email}")
        raise HTTPException(status_code=403, detail="Unauthorized")

    token = create_jwt_token(email)
    return {"access_token": token}

@app.post("/admin/approve-transaction")
async def approve_transaction(
    payload: Dict[str, Any],
    token_data: Dict[str, Any] = Depends(verify_jwt_token)
):
    tx_id = payload.get("tx_id")
    if not tx_id:
        raise HTTPException(status_code=400, detail="tx_id is required")

    res = await asyncio.to_thread(lambda: supabase.table("transactions")
                                 .select("*").eq("id", tx_id).maybe_single().execute())
    tx = res.data if res else None
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if tx["status"] != "pending":
        raise HTTPException(status_code=400, detail="Transaction already processed")

    await asyncio.to_thread(lambda: supabase.table("transactions")
                           .update({"status": "approved"})
                           .eq("id", tx_id)
                           .execute())

    logger.info(f"Transaction {tx_id} approved by admin {token_data['email']}")
    return {"status": "approved"}

@app.get("/admin/users")
async def get_admin_users(token_data: Dict[str, Any] = Depends(verify_jwt_token)):
    res = await asyncio.to_thread(lambda: supabase.table("admin_users")
                                 .select("email").execute())
    users = res.data if res else []
    return {"admin_users": [u["email"] for u in users]}

@app.get("/payments/summary")
async def payments_summary(token_data: Dict[str, Any] = Depends(verify_jwt_token)):
    total_tx_res = await asyncio.to_thread(lambda: supabase.table("transactions").select("id", count="exact").execute())
    deposit_sum_res = await asyncio.to_thread(lambda: supabase.table("transactions").select("amount").eq("type", "deposit").execute())
    withdraw_sum_res = await asyncio.to_thread(lambda: supabase.table("transactions").select("amount").eq("type", "withdraw").execute())
    
    total_transactions = total_tx_res.count if total_tx_res else 0
    total_deposit_amount = sum(tx["amount"] for tx in deposit_sum_res.data) if deposit_sum_res else 0
    total_withdraw_amount = sum(tx["amount"] for tx in withdraw_sum_res.data) if withdraw_sum_res else 0

    recent_res = await asyncio.to_thread(lambda: supabase.table("transactions")
                                        .select("*")
                                        .order("created_at", desc=True)
                                        .limit(20)
                                        .execute())
    recent_txs = recent_res.data if recent_res else []

    return {
        "total_transactions": total_transactions,
        "total_deposit_amount": total_deposit_amount,
        "total_withdraw_amount": total_withdraw_amount,
        "transactions": recent_txs
    }

@app.get("/admin/analytics")
async def admin_analytics(token_data: Dict[str, Any] = Depends(verify_jwt_token)):
    return await payments_summary(token_data)

@app.post("/viber-webhook")
async def viber_webhook(request: Request):
    http_client: httpx.AsyncClient = httpx.AsyncClient(timeout=10.0)
    try:
        body_bytes = await request.body()
        viber_signature = request.headers.get("X-Viber-Content-Signature", "")
        if not verify_viber_signature(body_bytes, viber_signature):
            logger.warning("Invalid Viber webhook signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        data = json.loads(body_bytes)
        event = data.get("event")
        logger.info(f"Received Viber event: {event}")

        if event == "webhook":
            return {"status": "ok", "message": "Webhook configured"}

        viber_id = data.get("sender", {}).get("id") or data.get("user", {}).get("id")
        if not viber_id:
            logger.error("Viber ID missing in webhook payload")
            return JSONResponse(status_code=400, content={"error": "Viber ID missing"})

        if event == "conversation_started":
            await send_viber_message(http_client, viber_id, "မင်္ဂလာပါ။ Bot မှ ကြိုဆိုပါတယ်။\n\nကျေးဇူးပြု၍ သင့်အကောင့်နံပါတ် (account ID) ကိုထည့်ပေးပါ။")
            await asyncio.to_thread(lambda: supabase.table("viber_users").upsert(
                {"viber_id": viber_id, "state": UserState.AWAITING_ACCOUNT_ID}, on_conflict="viber_id").execute())
            return {"status": "ok"}

        if event == "message":
            message = data.get("message", {})
            if message.get("type") != "text":
                await send_viber_message(http_client, viber_id, "⚠️ ကျေးဇူးပြု၍ စာသားမက်ဆေ့ချ်သာ ပေးပို့ပါ။")
                return {"status": "ok"}

            text = message.get("text", "").strip()
            # Insert message handling logic here...
            await send_viber_message(http_client, viber_id, f"သင်ပေးပို့ထားသော စာသားမှာ: {text}")
            return {"status": "ok"}

        logger.warning(f"Unhandled Viber event type: {event}")
        return {"status": "ignored"}

    except Exception as e:
        logger.error(f"Error processing Viber webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        await http_client.aclose()
