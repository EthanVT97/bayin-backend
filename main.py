from fastapi import FastAPI, Request, HTTPException, Depends, Header, Body, status
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os, requests, jwt, bcrypt, datetime, asyncio, hashlib, hmac
from typing import Optional, Dict, Any
import logging
from contextlib import asynccontextmanager
from supabase import create_client, Client
import httpx
import time
from collections import defaultdict
import json

# -------- Logging Configuration --------

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
# FIX: Use __name__ instead of the undefined variable 'name'
logger = logging.getLogger(__name__)

# -------- State Constants --------
# REFACTOR: Use constants for states to prevent typos and improve readability
class UserState:
    AWAITING_ACCOUNT_ID = "AWAITING_ACCOUNT_ID"
    MAIN_MENU = "MAIN_MENU"
    AWAITING_DEPOSIT = "AWAITING_DEPOSIT"
    AWAITING_WITHDRAW = "AWAITING_WITHDRAW"

# -------- Rate Limiter --------

class RateLimiter:
    # FIX: Renamed 'init' to the correct constructor '__init__'
    def __init__(self, max_requests: int = 20, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, identifier: str) -> bool:
        now = time.time()
        # Filter out old requests
        self.requests[identifier] = [t for t in self.requests[identifier] if now - t < self.window_seconds]
        if len(self.requests[identifier]) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for identifier: {identifier}")
            return False
        self.requests[identifier].append(now)
        return True

rate_limiter = RateLimiter()

# -------- Lifespan --------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 YGN Real Estate Bot starting up...")
    required_vars = ["SUPABASE_URL", "SUPABASE_KEY", "VIBER_TOKEN"]
    missing_vars = [v for v in required_vars if not os.getenv(v)]
    if missing_vars:
        logger.error(f"FATAL: Missing required environment variables: {missing_vars}")
        raise RuntimeError(f"Missing required environment variables: {missing_vars}")

    try:
        # Test database connection
        await asyncio.to_thread(lambda: supabase.table("viber_users").select("id", count='exact').limit(0).execute())
        logger.info("✅ Database connection successful")
    except Exception as e:
        logger.error(f"FATAL: Database connection failed: {e}")
        raise

    # NOTE: OPENAI_API_KEY is checked but not used in the current code.
    if os.getenv("OPENAI_API_KEY"):
        logger.info("✅ OPENAI_API_KEY is set (feature not implemented)")
    else:
        logger.warning("⚠️ OPENAI_API_KEY is not set")

    # Set a default timeout for the httpx client
    app.state.httpx_client = httpx.AsyncClient(timeout=10.0)
    yield
    await app.state.httpx_client.aclose()
    logger.info("🛑 YGN Real Estate Bot shutdown complete")

# -------- App Setup --------

app = FastAPI(lifespan=lifespan, title="YGN Bot API", version="1.0.0")

# BEST PRACTICE: Use ["*"] for development or be explicit for production.
# An empty string is not a valid wildcard.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"]) # Or ["your.domain.com"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Or ["https://your-admin-frontend.com"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------- Env & Clients --------

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
VIBER_TOKEN = os.getenv("VIBER_TOKEN")
VIBER_WEBHOOK_SECRET = os.getenv("VIBER_WEBHOOK_SECRET")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
security = HTTPBearer()

# -------- Static Files --------

if os.path.exists("admin"):
    app.mount("/admin", StaticFiles(directory="admin", html=True), name="admin")

# -------- Signature Verification --------

def verify_viber_signature(body: bytes, signature: str) -> bool:
    if not VIBER_WEBHOOK_SECRET:
        logger.warning("VIBER_WEBHOOK_SECRET not set, skipping signature verification.")
        return True
    expected_signature = hmac.new(VIBER_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected_signature)

# -------- JWT Auth (Unused) --------
# NOTE: This dependency is defined but not attached to any route.
async def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(
            credentials.credentials,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated"
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

# -------- Viber Message Sender --------

async def send_viber_message(client: httpx.AsyncClient, receiver_id: str, message_text: str):
    payload = {"receiver": receiver_id, "type": "text", "text": message_text, "min_api_version": 1}
    headers = {"X-Viber-Auth-Token": VIBER_TOKEN}
    try:
        response = await client.post("https://chatapi.viber.com/pa/send_message", json=payload, headers=headers)
        response.raise_for_status()
        logger.info(f"Message sent to {receiver_id}")
    except httpx.HTTPStatusError as e:
        logger.error(f"Failed to send Viber message to {receiver_id}. Status: {e.response.status_code}, Response: {e.response.text}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while sending Viber message: {e}")

# -------- Routes --------

@app.post("/viber-webhook", status_code=status.HTTP_200_OK)
async def viber_webhook(request: Request):
    http_client = request.app.state.httpx_client
    try:
        body_bytes = await request.body()
        viber_signature = request.headers.get("X-Viber-Content-Signature", "")

        if not verify_viber_signature(body_bytes, viber_signature):
            logger.warning("Invalid Viber signature received.")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")

        data = json.loads(body_bytes)
        event = data.get("event")
        logger.info(f"Received Viber event: {event}")

        if event == "webhook":
            return JSONResponse(content={"status": "ok", "message": "Webhook configured successfully."})

        viber_id = data.get("sender", {}).get("id") or data.get("user", {}).get("id")
        if not viber_id:
            logger.error(f"Could not extract Viber ID from payload: {data}")
            return JSONResponse(status_code=400, content={"error": "Viber ID not found in payload"})

        if event == "conversation_started":
            await send_viber_message(http_client, viber_id, "မင်္ဂလာပါ။ Bot မှ ကြိုဆိုပါတယ်။\n\nကျေးဇူးပြု၍ သင့်အကောင့်နံပါတ် (account ID) ကိုထည့်ပေးပါ။")
            await asyncio.to_thread(
                lambda: supabase.table("viber_users").upsert(
                    {"viber_id": viber_id, "state": UserState.AWAITING_ACCOUNT_ID}, on_conflict="viber_id"
                ).execute()
            )
            return {"status": "ok"}

        if event == "message":
            message = data.get("message", {})
            if message.get("type") != "text":
                await send_viber_message(http_client, viber_id, "⚠️ ကျေးဇူးပြု၍ စာသားမက်ဆေ့ချ်သာ ပေးပို့ပါ။")
                return {"status": "ok_non_text"}

            text = message.get("text", "").strip()
            if not rate_limiter.is_allowed(f"viber:{viber_id}"):
                await send_viber_message(http_client, viber_id, "⚠️ သင်မက်ဆေ့ချ်ပို့ တာမြန်လွန်းနေပါသည်။ ခဏစောင့်ပြီးမှ ပြန်ကြိုးစားပါ။")
                return JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS, content={"status": "rate_limited"})

            user_res = await asyncio.to_thread(lambda: supabase.table("viber_users").select("*").eq("viber_id", viber_id).maybe_single().execute())
            user = user_res.data
            state = user.get("state") if user else UserState.AWAITING_ACCOUNT_ID

            if state == UserState.AWAITING_ACCOUNT_ID:
                acc_id = text
                # SECURITY: Ensure the `account_id` column in Supabase has a UNIQUE constraint.
                # This prevents a race condition where two users claim the same ID.
                exists_res = await asyncio.to_thread(lambda: supabase.table("viber_users").select("id").eq("account_id", acc_id).maybe_single().execute())
                if exists_res.data:
                    await send_viber_message(http_client, viber_id, "❌ ဤအကောင့် ID ကို အခြားအသုံးပြုသူတစ်ဦးမှ ချိတ်ဆက်ပြီးဖြစ်ပါသည်။")
                else:
                    await asyncio.to_thread(lambda: supabase.table("viber_users").update({"account_id": acc_id, "state": UserState.MAIN_MENU}).eq("viber_id", viber_id).execute())
                    await send_viber_message(http_client, viber_id, f"✅ အကောင့် ID '{acc_id}' ဖြင့် အောင်မြင်စွာချိတ်ဆက်ပြီးပါပြီ။\n\nကျေးဇူးပြု၍ ရွေးချယ်ပါ:\n1️⃣ ငွေသွင်းရန်\n2️⃣ ငွေထုတ်ရန်")

            elif state == UserState.MAIN_MENU:
                if text == "1":
                    await asyncio.to_thread(lambda: supabase.table("viber_users").update({"state": UserState.AWAITING_DEPOSIT}).eq("viber_id", viber_id).execute())
                    await send_viber_message(http_client, viber_id, "💵 ကျေးဇူးပြု၍ သွင်းလိုသော ငွေပမာဏကို ရိုက်ထည့်ပါ။")
                elif text == "2":
                    await asyncio.to_thread(lambda: supabase.table("viber_users").update({"state": UserState.AWAITING_WITHDRAW}).eq("viber_id", viber_id).execute())
                    await send_viber_message(http_client, viber_id, "💸 ကျေးဇူးပြု၍ ထုတ်လိုသော ငွေပမာဏကို ရိုက်ထည့်ပါ။")
                else:
                    await send_viber_message(http_client, viber_id, "⚠️ ရွေးချယ်မှု မှားယွင်းနေပါသည်။\n\nကျေးဇူးပြု၍ ရွေးချယ်ပါ:\n1️⃣ ငွေသွင်းရန်\n2️⃣ ငွေထုတ်ရန်")

            elif state in [UserState.AWAITING_DEPOSIT, UserState.AWAITING_WITHDRAW]:
                # FIX: Use 'except ValueError' to only catch errors from int() conversion.
                try:
                    amount = int(text)
                    if amount <= 0:
                        await send_viber_message(http_client, viber_id, "❌ ငွေပမာဏသည် သုညထက်ကြီးသော ကိန်းဂဏန်းဖြစ်ရပါမည်။")
                        return {"status": "ok_invalid_amount"}
                        
                    tx_type = "deposit" if state == UserState.AWAITING_DEPOSIT else "withdraw"
                    await asyncio.to_thread(lambda: supabase.table("transactions").insert({"user_id": user["id"], "type": tx_type, "amount": amount, "status": "pending"}).execute())
                    await asyncio.to_thread(lambda: supabase.table("viber_users").update({"state": UserState.MAIN_MENU}).eq("viber_id", viber_id).execute())
                    await send_viber_message(http_client, viber_id, f"🧾 သင်၏ {amount} MMK {tx_type} ပြုလုပ်ရန် တောင်းဆိုမှုကို လက်ခံရရှိပါသည်။ Admin မှစစ်ဆေးပြီး အတည်ပြုပေးပါမည်။")
                except ValueError:
                    await send_viber_message(http_client, viber_id, "❌ မှားယွင်းနေပါသည်။ ငွေပမာဏကို ကိန်းဂဏန်းဖြင့်သာ ရိုက်ထည့်ပါ (ဥပမာ 5000)။")

            return {"status": "ok_processed"}

        logger.warning(f"Unhandled Viber event type: {event}")
        return {"status": "unhandled_event"}

    except Exception as e:
        logger.error(f"Error processing Viber webhook: {e}", exc_info=True)
        # SECURITY: Do not leak detailed error messages to the public.
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "An internal server error occurred."}
        )

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root():
    return """
    <html>
        <head><title>YGN Bot</title></head>
        <body>
            <h1>YGN Bot is Online</h1>
            <p>The Viber bot is operational. Visit <a href="/docs">/docs</a> for API documentation.</p>
        </body>
    </html>
    """
