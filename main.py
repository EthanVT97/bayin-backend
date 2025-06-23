--- START OF FILE main (1).py ---

# --- START OF FILE main.py ---

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
from openai import OpenAI
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
logger = logging.getLogger(__name__)

# -------- Rate Limiting --------
class RateLimiter:
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
    
    def is_allowed(self, identifier: str) -> bool:
        now = time.time()
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier] 
            if now - req_time < self.window_seconds
        ]
        if len(self.requests[identifier]) >= self.max_requests:
            return False
        self.requests[identifier].append(now)
        return True

rate_limiter = RateLimiter(max_requests=20, window_seconds=60)

# -------- Application Lifespan --------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 YGN Real Estate Bot starting up...")
    required_vars = ["SUPABASE_URL", "SUPABASE_KEY", "VIBER_TOKEN"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        logger.error(f"❌ Missing environment variables: {missing_vars}")
        raise RuntimeError(f"Missing required environment variables: {missing_vars}")
    
    try:
        supabase.table("viber_users").select("id").limit(1).execute()
        logger.info("✅ Database connection established")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        raise RuntimeError("Database connection failed")
    
    try:
        if os.getenv("OPENAI_API_KEY"):
            client.models.list()
            logger.info("✅ OpenAI API connection established")
        else:
            logger.warning("⚠️ OPENAI_API_KEY not set. AI features will be disabled.")
    except Exception as e:
        logger.warning(f"⚠️ OpenAI API connection failed: {e}. Bot will run without AI features.")

    app.state.httpx_client = httpx.AsyncClient()
    
    yield
    
    # Shutdown
    await app.state.httpx_client.aclose()
    logger.info("🛑 YGN Real Estate Bot shutting down...")

app = FastAPI(
    title="YGN Bot Service",
    description="Production-ready Viber bot for financial transactions and admin management.",
    version="2.1.0",
    lifespan=lifespan
)

# -------- Security Middleware --------
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to your frontend domain
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# -------- Environment Setup --------
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
VIBER_TOKEN = os.getenv("VIBER_TOKEN")
VIBER_WEBHOOK_SECRET = os.getenv("VIBER_WEBHOOK_SECRET")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
security = HTTPBearer()

# -------- Static Files --------
if os.path.exists("admin"):
    app.mount("/admin", StaticFiles(directory="admin", html=True), name="admin")
    logger.info("✅ Admin panel mounted at /admin")
else:
    logger.warning("⚠️ 'admin' directory not found; /admin route skipped")

# -------- Signature Verification --------
def verify_viber_signature(body: bytes, signature: str) -> bool:
    if not VIBER_WEBHOOK_SECRET:
        logger.warning("⚠️ VIBER_WEBHOOK_SECRET not set - skipping signature verification")
        return True
    expected_signature = hmac.new(VIBER_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected_signature)

# -------- Authentication Helpers --------
async def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(credentials.credentials, SUPABASE_JWT_SECRET, algorithms=["HS256"], audience="authenticated")
        if not payload.get("sub"):
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"JWT verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication error")

async def verify_admin_token(payload: Dict[str, Any] = Depends(verify_jwt_token)) -> Dict[str, Any]:
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return payload

# -------- Auth Endpoints --------
@app.post("/auth/login", response_model=dict)
async def login_user(request: Request, email: str = Body(...), password: str = Body(...)):
    client_ip = request.client.host
    if not rate_limiter.is_allowed(f"login:{client_ip}"):
        raise HTTPException(status_code=429, detail="Too many login attempts")
    
    try:
        res = supabase.table("users").select("*").eq("email", email).maybe_single().execute()
        if not res.data:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = res.data
        if not user.get("password") or not bcrypt.checkpw(password.encode(), user["password"].encode()):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="Account inactive")
        
        payload = {
            "sub": user["id"], "email": user["email"], "role": user.get("role", "user"),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            "aud": "authenticated", "iat": datetime.datetime.utcnow(),
        }
        token = jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm="HS256")
        
        supabase.table("users").update({
            "last_login": datetime.datetime.utcnow().isoformat(),
            "login_count": user.get("login_count", 0) + 1
        }).eq("id", user["id"]).execute()
        
        logger.info(f"Successful login: {email}")
        return {"access_token": token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error for {email}: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication service unavailable")

# -------- Admin Endpoints --------
@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(f"""
    <html><head><title>YGN Bot Service</title></head>
    <body><h1>🏠 YGN Bot Service</h1><p>✅ Backend Online</p><p>Environment: {ENVIRONMENT}</p>
    <p><a href="/admin">Admin Panel</a> | <a href="/docs">API Docs</a> | <a href="/health">Health Check</a></p></body></html>
    """)

@app.get("/admin/analytics")
async def get_analytics(payload: Dict[str, Any] = Depends(verify_admin_token)):
    try:
        transactions_res = supabase.table("transactions").select("*", count='exact').execute()
        users_res = supabase.table("viber_users").select("*", count='exact').execute()
        return {
            "total_transactions": transactions_res.count,
            "total_viber_users": users_res.count,
            "generated_at": datetime.datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Analytics error: {str(e)}")
        raise HTTPException(status_code=500, detail="Analytics unavailable")

# -------- Health Check --------
@app.get("/health")
async def health_check():
    health = {"status": "healthy", "timestamp": datetime.datetime.utcnow().isoformat(), "checks": {}}
    try:
        supabase.table("viber_users").select("id").limit(1).execute()
        health["checks"]["database"] = "✅ Connected"
    except Exception as e:
        health["checks"]["database"] = f"❌ Error: {str(e)}"
        health["status"] = "degraded"
    try:
        response = requests.get("https://chatapi.viber.com/pa/get_account_info", headers={"X-Viber-Auth-Token": VIBER_TOKEN}, timeout=5)
        health["checks"]["viber"] = "✅ Connected" if response.status_code == 200 else f"❌ HTTP {response.status_code}"
    except Exception as e:
        health["checks"]["viber"] = f"❌ Error: {str(e)}"
        health["status"] = "degraded"
    return health

# -------- Viber Bot Logic --------
async def send_viber_message(client: httpx.AsyncClient, receiver_id: str, message_text: str):
    """Sends a text message to a Viber user."""
    payload = {"receiver": receiver_id, "type": "text", "text": message_text, "min_api_version": 1}
    headers = {"X-Viber-Auth-Token": VIBER_TOKEN}
    try:
        response = await client.post("https://chatapi.viber.com/pa/send_message", json=payload, headers=headers)
        response.raise_for_status()
        logger.info(f"Message sent to {receiver_id}")
    except httpx.HTTPStatusError as e:
        logger.error(f"Failed to send Viber message to {receiver_id}: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while sending Viber message: {e}")

@app.get("/viber-webhook")
async def webhook_verification_get():
    return {"status": "✅ Webhook endpoint active"}

@app.post("/viber-webhook")
async def viber_webhook(request: Request):
    """Viber webhook with stateful payment bot logic."""
    http_client = request.app.state.httpx_client
    try:
        body_bytes = await request.body()
        signature = request.headers.get("X-Viber-Content-Signature", "")
        if not verify_viber_signature(body_bytes, signature):
            logger.warning("Invalid Viber webhook signature")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        body = json.loads(body_bytes.decode())
        event = body.get("event")
        logger.info(f"📨 Viber webhook received: {event}")

        if event == "webhook":
            return {"status": "ok"}
        
        if event == "conversation_started":
            user = body.get("user", {})
            viber_id = user.get("id")
            if viber_id:
                await send_viber_message(http_client, viber_id, "မင်္ဂလာပါ။ Bot မှ ကြိုဆိုပါတယ်။\n\nကျေးဇူးပြု၍ သင့်အကောင့်နံပါတ် (account ID) ကိုထည့်ပေးပါ။")
                supabase.table("viber_users").upsert({
                    "viber_id": viber_id, "name": user.get("name", "Viber User"), "state": "AWAITING_ACCOUNT_ID"
                }, on_conflict="viber_id").execute()
            return {"status": "ok"}

        if event == "message":
            viber_id = body["sender"]["id"]
            user_name = body["sender"]["name"]
            message_text = body["message"]["text"].strip()
            
            if not rate_limiter.is_allowed(f"viber:{viber_id}"):
                await send_viber_message(http_client, viber_id, "⚠️ ခေတ္တစောင့်ဆိုင်းပြီးမှ နောက်တစ်ကြိမ် message ပေးပို့ပါ။")
                return {"status": "rate_limited"}
            
            # --- State Machine Logic ---
            user_res = supabase.table("viber_users").select("*").eq("viber_id", viber_id).maybe_single().execute()
            user_record = user_res.data
            
            if not user_record:
                await send_viber_message(http_client, viber_id, "မင်္ဂလာပါ။ သင့်အကောင့်နံပါတ် (account ID) ကိုထည့်ပေးပါ။")
                supabase.table("viber_users").insert({"viber_id": viber_id, "name": user_name, "state": "AWAITING_ACCOUNT_ID"}).execute()
                return {"status": "user_created"}

            state = user_record.get("state", "AWAITING_ACCOUNT_ID")

            if state == "AWAITING_ACCOUNT_ID":
                account_id = message_text
                existing = supabase.table("viber_users").select("id").eq("account_id", account_id).maybe_single().execute()
                if existing.data:
                    await send_viber_message(http_client, viber_id, "❌ ဤအကောင့် ID သည် အသုံးပြုပြီးဖြစ်သည်။ အခြား ID တစ်ခု ထပ်ထည့်ပါ။")
                else:
                    supabase.table("viber_users").update({"account_id": account_id, "state": "MAIN_MENU"}).eq("viber_id", viber_id).execute()
                    await send_viber_message(http_client, viber_id, f"✅ အကောင့် ID ({account_id}) ဖြင့် အောင်မြင်စွာချိတ်ဆက်ပြီးပါပြီ။\n\nသင်ဘာလုပ်ချင်ပါသလဲ?\n1️⃣ ငွေသွင်းရန်\n2️⃣ ငွေထုတ်ရန်")
            
            elif state == "MAIN_MENU":
                if message_text == "1":
                    supabase.table("viber_users").update({"state": "AWAITING_DEPOSIT"}).eq("viber_id", viber_id).execute()
                    await send_viber_message(http_client, viber_id, "သွင်းလိုသော ငွေပမာဏကိုထည့်ပါ။ (ဥပမာ - 5000)")
                elif message_text == "2":
                    supabase.table("viber_users").update({"state": "AWAITING_WITHDRAW"}).eq("viber_id", viber_id).execute()
                    await send_viber_message(http_client, viber_id, "ထုတ်လိုသော ငွေပမာဏကိုထည့်ပါ။ (ဥပမာ - 5000)")
                else:
                    await send_viber_message(http_client, viber_id, "မှားယွင်းနေပါသည်။\n\n1️⃣ (ငွေသွင်း) သို့မဟုတ် 2️⃣ (ငွေထုတ်) ကို ရွေးပေးပါ။")

            elif state in ["AWAITING_DEPOSIT", "AWAITING_WITHDRAW"]:
                try:
                    amount = int(message_text)
                    if amount <= 0: raise ValueError("Amount must be positive.")
                    
                    tx_type = "deposit" if state == "AWAITING_DEPOSIT" else "withdraw"
                    tx_action_text = "ငွေသွင်း" if tx_type == "deposit" else "ငွေထုတ်"

                    supabase.table("transactions").insert({
                        "user_id": user_record["id"], "type": tx_type, "amount": amount, "status": "pending"
                    }).execute()
                    supabase.table("viber_users").update({"state": "MAIN_MENU"}).eq("viber_id", viber_id).execute()
                    await send_viber_message(http_client, viber_id, f"🧾 {amount} MMK {tx_action_text}ရန် တောင်းဆိုမှုကို လက်ခံရရှိပါသည်။ Admin မှစစ်ဆေးပြီး အတည်ပြုပေးပါမည်။")
                except ValueError:
                    await send_viber_message(http_client, viber_id, "❌ မှားယွင်းနေပါသည်။ ကျေးဇူးပြု၍ ကိန်းဂဏန်းတစ်ခုတည်းသာ ထည့်ပါ။ (ဥပမာ - 10000)")

            else: # Fallback for any unknown state
                supabase.table("viber_users").update({"state": "MAIN_MENU"}).eq("viber_id", viber_id).execute()
                await send_viber_message(http_client, viber_id, "သင်ဘာလုပ်ချင်ပါသလဲ?\n1️⃣ ငွေသွင်းရန်\n2️⃣ ငွေထုတ်ရန်")
            
            return {"status": "ok_processed"}

        return {"status": "ok_unhandled_event"}

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in webhook: {str(e)}")
        return JSONResponse(status_code=400, content={"error": "Invalid JSON format"})
    except Exception as e:
        logger.error(f"Unhandled error in Viber webhook: {str(e)}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

# --- END OF FILE main.py ---
@app.post("/admin/approve-transaction")
async def approve_transaction(
    request: Request,
    payload: Dict[str, Any] = Depends(verify_admin_token),
    tx_id: str = Body(...)
):
    """
    Approves a pending transaction and notifies the user via Viber.
    - Requires admin authentication.
    - Fetches the transaction and related user info.
    - Updates transaction status from 'pending' to 'completed'.
    - Sends a confirmation message to the user on Viber.
    """
    try:
        # 1. Fetch transaction and related user's viber_id in a single query
        # This assumes a foreign key relationship exists from transactions.user_id to viber_users.id
        tx_res = supabase.table("transactions").select("*, viber_users(viber_id)").eq("id", tx_id).maybe_single().execute()
        
        if not tx_res.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found")
            
        transaction = tx_res.data
        
        # 2. Validate transaction status
        if transaction.get("status") != "pending":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Transaction is not pending. Current status: {transaction.get('status')}")

        # 3. Update transaction status in the database
        update_res = supabase.table("transactions").update({"status": "completed"}).eq("id", tx_id).execute()
        if not update_res.data:
             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update transaction status")

        # 4. Send notification to the user via Viber
        user_info = transaction.get("viber_users")
        notification_sent = False
        if user_info and user_info.get("viber_id"):
            viber_id = user_info["viber_id"]
            amount = transaction.get("amount")
            tx_type = transaction.get("type")
            tx_action_text = "ငွေသွင်းခြင်း" if tx_type == "deposit" else "ငွေထုတ်ခြင်း"
            
            notification_message = (
                f"✅ သင်၏ တောင်းဆိုမှု အောင်မြင်ပါသည်။\n\n"
                f"Transaction ID: {transaction['id']}\n"
                f"အမျိုးအစား: {tx_action_text}\n"
                f"ပမာဏ: {amount} MMK"
            )
            
            http_client = request.app.state.httpx_client
            await send_viber_message(http_client, viber_id, notification_message)
            logger.info(f"Sent approval notification for tx_id {tx_id} to viber_id {viber_id}")
            notification_sent = True
        else:
            logger.warning(f"Could not find viber_id for tx_id {tx_id}. Notification not sent.")

        return {"status": "approved", "tx_id": tx_id, "notification_sent": notification_sent}

    except HTTPException as e:
        # Re-raise HTTP exceptions to let FastAPI handle them
        raise e
    except Exception as e:
        logger.error(f"Error approving transaction {tx_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(e)}")
