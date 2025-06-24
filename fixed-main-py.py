import os
import time
import json
import hmac
import hashlib
import logging
import asyncio
import datetime
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

import httpx
import jwt
from fastapi import (
    FastAPI, Request, HTTPException, Depends, status
)
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import create_client, Client
from passlib.hash import bcrypt
from pydantic import BaseModel, EmailStr

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

# Validate critical environment variables
required_env_vars = {
    "SUPABASE_URL": SUPABASE_URL,
    "SUPABASE_KEY": SUPABASE_KEY,
    "SUPABASE_JWT_SECRET": SUPABASE_JWT_SECRET,
    "VIBER_TOKEN": VIBER_TOKEN
}

missing_vars = [key for key, value in required_env_vars.items() if not value]
if missing_vars:
    logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
    raise RuntimeError(f"Required environment variables are not set: {', '.join(missing_vars)}")

# -------------------- Supabase Client --------------------

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    logger.info("Supabase client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {e}")
    raise

# -------------------- Constants --------------------

ADMIN_EMAILS = [email.strip() for email in os.getenv("ADMIN_EMAILS", "").split(",") if email.strip()]
if not ADMIN_EMAILS:
    logger.warning("No admin emails configured in ADMIN_EMAILS env variable.")

JWT_ALGORITHM = "HS256"
JWT_AUDIENCE = "authenticated"
JWT_EXP_HOURS = 1

# -------------------- Pydantic Models --------------------

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TransactionApprovalRequest(BaseModel):
    tx_id: str

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

    def cleanup_old_entries(self):
        """Periodic cleanup to prevent memory leaks"""
        now = time.time()
        for key in list(self.requests.keys()):
            timestamps = [ts for ts in self.requests[key] if now - ts < self.window_seconds]
            if timestamps:
                self.requests[key] = timestamps
            else:
                del self.requests[key]

rate_limiter = RateLimiter()

# -------------------- User State --------------------

class UserState:
    AWAITING_ACCOUNT_ID = "AWAITING_ACCOUNT_ID"
    MAIN_MENU = "MAIN_MENU"
    AWAITING_DEPOSIT = "AWAITING_DEPOSIT"
    AWAITING_WITHDRAW = "AWAITING_WITHDRAW"

# -------------------- Lifespan Context Manager --------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        # Test Supabase connection
        res = await asyncio.to_thread(
            lambda: supabase.table("viber_users").select("id").limit(1).execute()
        )
        logger.info("Supabase connection verified successfully")
        
        # Setup periodic cleanup task
        cleanup_task = asyncio.create_task(periodic_cleanup())
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise
    
    yield
    
    # Shutdown
    try:
        cleanup_task.cancel()
        logger.info("Application shutdown completed")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

async def periodic_cleanup():
    """Periodic cleanup task to prevent memory leaks"""
    while True:
        try:
            await asyncio.sleep(300)  # 5 minutes
            rate_limiter.cleanup_old_entries()
            logger.debug("Periodic cleanup completed")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

# -------------------- FastAPI App Setup --------------------

app = FastAPI(
    title="YGN Real Estate Bot Admin API",
    version="1.0.0",
    lifespan=lifespan
)

# Middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["*"]  # TODO: Configure specific hosts in production
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Configure specific origins in production
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Static files for admin frontend (if exists)
if os.path.isdir("admin"):
    app.mount("/admin", StaticFiles(directory="admin", html=True), name="admin")

# HTTP Bearer security for JWT token validation
security = HTTPBearer()

# -------------------- Root and Health Endpoints --------------------

@app.get("/")
async def root():
    return {"message": "Hello from YGN Real Estate Bot API", "status": "operational"}

@app.get("/health")
async def health():
    try:
        # Quick health check with Supabase
        await asyncio.wait_for(
            asyncio.to_thread(lambda: supabase.table("viber_users").select("id").limit(1).execute()),
            timeout=5.0
        )
        return {"status": "healthy", "database": "connected", "timestamp": datetime.datetime.utcnow().isoformat()}
    except asyncio.TimeoutError:
        raise HTTPException(status_code=503, detail="Database connection timeout")
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")

# -------------------- JWT Token Utils --------------------

def create_jwt_token(user: Dict[str, Any]) -> str:
    """Creates a JWT token for an admin user."""
    now = datetime.datetime.utcnow()
    payload = {
        "sub": user["email"],
        "user_id": str(user["id"]),
        "role": "admin",
        "aud": JWT_AUDIENCE,
        "exp": now + datetime.timedelta(hours=JWT_EXP_HOURS),
        "iat": now,
        "nbf": now
    }
    try:
        token = jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm=JWT_ALGORITHM)
        return token
    except Exception as e:
        logger.error(f"JWT token creation failed: {e}")
        raise HTTPException(status_code=500, detail="Token generation failed")

async def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """
    Decodes JWT, verifies it's for an admin, and returns the payload.
    Raises 401 for invalid/expired tokens, and 403 for insufficient permissions.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE
        )

        # Check for admin role
        role = payload.get("role")
        if role != "admin":
            logger.warning(f"Access attempt by non-admin. Email: {payload.get('sub')}, Role: {role}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions. Admin role required."
            )
        
        # Ensure required claims are present
        if not all([payload.get("sub"), payload.get("user_id")]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing required claims."
            )

        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError as e:
        logger.error(f"JWT validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

# -------------------- Admin User Helper --------------------

async def get_admin_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    try:
        res = await asyncio.wait_for(
            asyncio.to_thread(
                lambda: supabase.table("admin_users").select("*").eq("email", email).maybe_single().execute()
            ),
            timeout=10.0
        )
        return res.data if res and res.data else None
    except asyncio.TimeoutError:
        logger.error(f"Timeout fetching admin user: {email}")
        return None
    except Exception as e:
        logger.error(f"Error fetching admin user by email {email}: {e}")
        return None

# -------------------- Viber Signature Verification --------------------

def verify_viber_signature(body: bytes, signature: str) -> bool:
    if not VIBER_WEBHOOK_SECRET:
        logger.warning("VIBER_WEBHOOK_SECRET not configured; skipping signature verification")
        return True
    
    try:
        expected = hmac.new(VIBER_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

# -------------------- Viber Message Sender --------------------

async def send_viber_message(client: httpx.AsyncClient, receiver_id: str, message_text: str):
    url = "https://chatapi.viber.com/pa/send_message"
    headers = {"X-Viber-Auth-Token": VIBER_TOKEN}
    payload = {
        "receiver": receiver_id,
        "type": "text",
        "text": message_text,
        "min_api_version": 7
    }
    try:
        resp = await client.post(url, json=payload, headers=headers, timeout=30.0)
        resp.raise_for_status()
        logger.info(f"Sent Viber message to {receiver_id}")
    except httpx.TimeoutException:
        logger.error(f"Timeout sending Viber message to {receiver_id}")
    except httpx.HTTPStatusError as e:
        logger.error(f"Failed to send Viber message to {receiver_id}. Status: {e.response.status_code}, Response: {e.response.text}")
    except Exception as e:
        logger.error(f"Failed to send Viber message to {receiver_id}: {e}")

# -------------------- API Routes --------------------

@app.post("/auth/login")
async def admin_login(payload: LoginRequest):
    email = payload.email.lower()
    password = payload.password
    
    if not email or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Email and password are required"
        )

    user = await get_admin_user_by_email(email)
    if not user:
        logger.warning(f"Admin login failed: user not found for email {email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials"
        )

    try:
        if not bcrypt.verify(password, user["password_hash"]):
            logger.warning(f"Admin login failed: incorrect password for {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid credentials"
            )
    except Exception as e:
        logger.error(f"Password verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication system error"
        )

    if email not in ADMIN_EMAILS:
        logger.warning(f"Unauthorized admin login attempt by {email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Access denied"
        )

    token = create_jwt_token(user)
    logger.info(f"Successful admin login: {email}")
    return {"access_token": token, "token_type": "bearer"}

@app.post("/admin/approve-transaction")
async def approve_transaction(
    payload: TransactionApprovalRequest,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    tx_id = payload.tx_id
    if not tx_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="tx_id is required"
        )

    try:
        res = await asyncio.wait_for(
            asyncio.to_thread(
                lambda: supabase.table("transactions")
                .select("*").eq("id", tx_id).maybe_single().execute()
            ),
            timeout=10.0
        )
        
        tx = res.data if res else None
        if not tx:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="Transaction not found"
            )
        
        if tx["status"] != "pending":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Transaction already processed"
            )

        await asyncio.wait_for(
            asyncio.to_thread(
                lambda: supabase.table("transactions")
                .update({"status": "approved"})
                .eq("id", tx_id)
                .execute()
            ),
            timeout=10.0
        )
        
        logger.info(f"Transaction {tx_id} approved by admin {current_admin['sub']}")
        return {"status": "approved", "tx_id": tx_id}
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database operation timeout"
        )
    except Exception as e:
        logger.error(f"Transaction approval failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Transaction approval failed"
        )

@app.get("/admin/users")
async def get_admin_users(current_admin: Dict[str, Any] = Depends(get_current_admin)):
    try:
        res = await asyncio.wait_for(
            asyncio.to_thread(
                lambda: supabase.table("admin_users").select("id, email, created_at").execute()
            ),
            timeout=10.0
        )
        users = res.data if res else []
        return {"admin_users": users}
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database operation timeout"
        )
    except Exception as e:
        logger.error(f"Failed to fetch admin users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch users"
        )

@app.get("/payments/summary")
async def payments_summary(current_admin: Dict[str, Any] = Depends(get_current_admin)):
    try:
        # Execute all queries concurrently with timeout
        tasks = [
            asyncio.wait_for(
                asyncio.to_thread(
                    lambda: supabase.table("transactions").select("id", count="exact").execute()
                ), timeout=10.0
            ),
            asyncio.wait_for(
                asyncio.to_thread(
                    lambda: supabase.table("transactions")
                    .select("amount")
                    .eq("type", "deposit")
                    .eq("status", "approved")
                    .execute()
                ), timeout=10.0
            ),
            asyncio.wait_for(
                asyncio.to_thread(
                    lambda: supabase.table("transactions")
                    .select("amount")
                    .eq("type", "withdraw")
                    .eq("status", "approved")
                    .execute()
                ), timeout=10.0
            ),
            asyncio.wait_for(
                asyncio.to_thread(
                    lambda: supabase.table("transactions")
                    .select("*")
                    .order("created_at", desc=True)
                    .limit(20)
                    .execute()
                ), timeout=10.0
            )
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle results
        total_transactions = results[0].count if not isinstance(results[0], Exception) and results[0] else 0
        
        deposit_data = results[1].data if not isinstance(results[1], Exception) and results[1] else []
        total_deposit_amount = sum(tx.get('amount', 0) for tx in deposit_data)
        
        withdraw_data = results[2].data if not isinstance(results[2], Exception) and results[2] else []
        total_withdraw_amount = sum(tx.get('amount', 0) for tx in withdraw_data)
        
        recent_txs = results[3].data if not isinstance(results[3], Exception) and results[3] else []
        
        return {
            "total_transactions": total_transactions,
            "total_deposit_amount": total_deposit_amount,
            "total_withdraw_amount": total_withdraw_amount,
            "recent_transactions": recent_txs,
            "net_balance": total_deposit_amount - total_withdraw_amount
        }
        
    except Exception as e:
        logger.error(f"Failed to fetch payments summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch payments summary"
        )

@app.post("/viber-webhook")
async def viber_webhook(request: Request):
    http_client = httpx.AsyncClient(timeout=30.0)
    try:
        body_bytes = await request.body()
        viber_signature = request.headers.get("X-Viber-Content-Signature")
        
        if not viber_signature:
            logger.warning("Viber webhook called without signature.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Signature missing"
            )

        if not verify_viber_signature(body_bytes, viber_signature):
            logger.warning("Invalid Viber signature received.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Invalid signature"
            )

        try:
            data = json.loads(body_bytes)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in webhook: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON"
            )
        
        event_type = data.get("event")
        user_id = data.get("sender", {}).get("id") or data.get("user", {}).get("id")

        if not user_id and event_type not in ["webhook"]:
            logger.info(f"Received Viber event '{event_type}' without a user_id. Skipping.")
            return JSONResponse(content={}, status_code=200)

        # Basic rate limiting
        if user_id and not rate_limiter.is_allowed(user_id):
            logger.warning(f"Rate limit exceeded for user {user_id}. Ignoring request.")
            return JSONResponse(content={}, status_code=200)

        logger.info(f"Received Viber event '{event_type}' for user {user_id}")

        # Handle different event types
        if event_type == "message" and user_id:
            await handle_message(http_client, data)
        elif event_type == "subscribed" and user_id:
            await handle_subscribed(http_client, data)
        elif event_type == "conversation_started" and user_id:
            await handle_conversation_started(http_client, data)
        elif event_type == "unsubscribed" and user_id:
            await handle_unsubscribed(data)
        else:
            logger.info(f"Ignoring unhandled Viber event type: {event_type}")

        return JSONResponse(content={}, status_code=200)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        return JSONResponse(content={}, status_code=200)  # Always return 200 to Viber
    finally:
        await http_client.aclose()

# -------------------- Viber Logic Helpers --------------------

async def get_viber_user(viber_id: str) -> Optional[Dict[str, Any]]:
    """Fetches user data from Supabase using their Viber ID."""
    try:
        res = await asyncio.wait_for(
            asyncio.to_thread(
                lambda: supabase.table("viber_users").select("*").eq("viber_id", viber_id).maybe_single().execute()
            ),
            timeout=10.0
        )
        return res.data if res and res.data else None
    except asyncio.TimeoutError:
        logger.error(f"Timeout fetching Viber user {viber_id}")
        return None
    except Exception as e:
        logger.error(f"Error fetching Viber user {viber_id}: {e}")
        return None

async def handle_subscribed(client: httpx.AsyncClient, data: Dict[str, Any]):
    """Handles the 'subscribed' event when a user subscribes to the bot."""
    user = data.get("user", {})
    user_id = user.get("id")
    user_name = user.get("name", "New User")

    if not user_id:
        return

    logger.info(f"User {user_name} ({user_id}) subscribed.")
    try:
        await asyncio.wait_for(
            asyncio.to_thread(
                lambda: supabase.table("viber_users")
                .upsert({
                    "viber_id": user_id, 
                    "state": UserState.AWAITING_ACCOUNT_ID, 
                    "viber_name": user_name
                }, on_conflict="viber_id")
                .execute()
            ),
            timeout=10.0
        )
        await send_viber_message(client, user_id, f"Welcome, {user_name}! To get started, please send your Account ID.")
    except Exception as e:
        logger.error(f"Failed to handle subscription for {user_id}: {e}")

async def handle_conversation_started(client: httpx.AsyncClient, data: Dict[str, Any]):
    """Handles the 'conversation_started' event."""
    user = data.get("user", {})
    user_id = user.get("id")
    if not user_id:
        return

    welcome_message = "Hello! Welcome to the YGN Real Estate Bot.\n\nTo link your account, please send your Account ID."
    await send_viber_message(client, user_id, welcome_message)
    
    try:
        await asyncio.wait_for(
            asyncio.to_thread(
                lambda: supabase.table("viber_users")
                .upsert({"viber_id": user_id, "state": UserState.AWAITING_ACCOUNT_ID}, on_conflict="viber_id")
                .execute()
            ),
            timeout=10.0
        )
    except Exception as e:
        logger.error(f"Failed to handle conversation start for {user_id}: {e}")

async def handle_unsubscribed(data: Dict[str, Any]):
    """Handles the 'unsubscribed' event."""
    user_id = data.get("user_id")
    if not user_id:
        return

    logger.info(f"User {user_id} unsubscribed.")
    try:
        await asyncio.wait_for(
            asyncio.to_thread(
                lambda: supabase.table("viber_users")
                .update({"state": "unsubscribed"})
                .eq("viber_id", user_id)
                .execute()
            ),
            timeout=10.0
        )
    except Exception as e:
        logger.error(f"Failed to handle unsubscribe for {user_id}: {e}")

async def handle_message(client: httpx.AsyncClient, data: Dict[str, Any]):
    """Handles incoming message events from Viber."""
    sender = data.get("sender", {})
    user_id = sender.get("id")
    message = data.get("message", {})
    text = message.get("text", "").strip()

    if not user_id or not text:
        logger.warning("Message event missing sender ID or text.")
        return

    user = await get_viber_user(user_id)
    if not user:
        await handle_conversation_started(client, {"user": sender})
        return

    current_state = user.get("state")

    try:
        if current_state == UserState.AWAITING_ACCOUNT_ID:
            await handle_account_id_input(client, user_id, text)
        elif current_state == UserState.MAIN_MENU:
            await handle_main_menu_input(client, user_id, text)
        elif current_state == UserState.AWAITING_DEPOSIT:
            await handle_transaction_request(client, user, "deposit", text)
        elif current_state == UserState.AWAITING_WITHDRAW:
            await handle_transaction_request(client, user, "withdraw", text)
    except Exception as e:
        logger.error(f"Failed to handle message for {user_id}: {e}")
        await send_viber_message(client, user_id, "Sorry, an error occurred. Please try again.")

async def handle_account_id_input(client: httpx.AsyncClient, user_id: str, account_id: str):
    """Handles account ID input."""
    try:
        await asyncio.wait_for(
            asyncio.to_thread(
                lambda: supabase.table("viber_users")
                .update({"account_id": account_id, "state": UserState.MAIN_MENU})
                .eq("viber_id", user_id)
                .execute()
            ),
            timeout=10.0
        )
        main_menu_text = "Thank you. Your account is linked.\n\nWhat would you like to do?\n- Deposit\n- Withdraw\n- Balance"
        await send_viber_message(client, user_id, main_menu_text)
    except Exception as e:
        logger.error(f"Failed to update account ID for {user_id}: {e}")
        await send_viber_message(client, user_id, "Failed to link your account. Please try again.")

async def handle_main_menu_input(client: httpx.AsyncClient, user_id: str, text: str):
    """Handles main menu input."""
    text_lower = text.lower()
    try:
        if "deposit" in text_lower:
            await asyncio.wait_for(
                asyncio.to_thread(
                    lambda: supabase.table("viber_users")
                    .update({"state": UserState.AWAITING_DEPOSIT})
                    .eq("viber_id", user_id)
                    .execute()
                ),
                timeout=10.0
            )
            await send_viber_message(client, user_id, "Please enter the amount you wish to deposit.")
        elif "withdraw" in text_lower:
            await asyncio.wait_for(
                asyncio.to_thread(
                    lambda: supabase.table("viber_users")
                    .update({"state": UserState.AWAITING_WITHDRAW})
                    .eq("viber_id", user_id)
                    .execute()
                ),
                timeout=10.0
            )
            await send_viber_message(client, user_id, "Please enter the amount you wish to withdraw.")
        elif "balance" in text_lower:
            user = await get_viber_user(user_id)
            if user:
                await handle_balance_check(client, user)
        else:
            await send_viber_message(client, user_id, "Invalid option. Please choose from:\n- Deposit\n- Withdraw\n- Balance")
    except Exception as e:
        logger.error(f"Failed to handle main menu input for {user_id}: {e}")
        await send_viber_message(client, user_id, "An error occurred. Please try again.")

async def handle_balance_check(client: httpx.AsyncClient, user: Dict[str, Any]):
    """Calculates and sends the user's approved balance."""
    user_id = user["viber_id"]
    account_id = user.get("account_id")
    
    if not account_id:
        await send_viber_message(client, user_id, "Error: Account ID not found. Please re-link your account.")
        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    lambda: supabase.table("viber_users")
                    .update({"state": UserState.AWAITING_ACCOUNT_ID})
                    .eq("viber_id", user_id)
                    .execute()
                ),
                timeout=10.0