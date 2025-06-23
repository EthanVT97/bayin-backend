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
from fastapi.responses import JSONResponse
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

ADMIN_EMAILS = os.getenv("ADMIN_EMAILS", "").split(",")
if not ADMIN_EMAILS or ADMIN_EMAILS == [""]:
    logger.warning("No admin emails configured in ADMIN_EMAILS env variable.")

JWT_ALGORITHM = "HS256"
JWT_AUDIENCE = "authenticated"
JWT_EXP_HOURS = 1  # MODIFIED: Changed expiration to 1 hour as per requirement

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
# Note: Use ["*"] for development, but specify actual hosts/origins in production.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # production မှာ domain specify လုပ်ရန်
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files for admin frontend (if exists)
if os.path.isdir("admin"):
    app.mount("/admin", StaticFiles(directory="admin", html=True), name="admin")

# HTTP Bearer security for JWT token validation
security = HTTPBearer()

# -------------------- Lifespan Event --------------------

@app.on_event("startup")
async def startup_event():
    try:
        # Check Supabase connection by making a simple request
        res = await asyncio.to_thread(lambda: supabase.table("viber_users").select("id").limit(1).execute())
        logger.info(f"Supabase connection successful.")
    except Exception as e:
        logger.error(f"Supabase connection failed on startup: {e}")
        raise

# -------------------- Root and Health Endpoints --------------------

@app.get("/")
async def root():
    return {"message": "Hello from YGN Real Estate Bot API"}

@app.get("/health")
async def health():
    return {"status": "ok"}

# -------------------- JWT Token Utils --------------------

# MODIFIED: Function updated to create JWT with required claims
def create_jwt_token(user: Dict[str, Any]) -> str:
    """Creates a JWT token for an admin user."""
    payload = {
        "sub": user["email"],
        "user_id": user["id"],
        "role": "admin",
        "aud": JWT_AUDIENCE,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXP_HOURS),
        "iat": datetime.datetime.utcnow()
    }
    token = jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

# ADDED: New dependency function for role-based JWT verification
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
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

# -------------------- Admin User Helper --------------------

async def get_admin_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    try:
        res = await asyncio.to_thread(lambda: supabase.table("admin_users").select("*").eq("email", email).maybe_single().execute())
        return res.data if res and res.data else None
    except Exception as e:
        logger.error(f"Error fetching admin user by email {email}: {e}")
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
        "min_api_version": 7 # Use a more recent API version
    }
    try:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        logger.info(f"Sent Viber message to {receiver_id}")
    except httpx.HTTPStatusError as e:
        logger.error(f"Failed to send Viber message to {receiver_id}. Status: {e.response.status_code}, Response: {e.response.text}")
    except Exception as e:
        logger.error(f"Failed to send Viber message to {receiver_id}: {e}")

# -------------------- API Routes --------------------

@app.post("/auth/login")
async def admin_login(payload: Dict[str, str]):
    email = payload.get("email", "").strip().lower()
    password = payload.get("password", "")
    if not email or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email and password are required")

    user = await get_admin_user_by_email(email)
    if not user:
        logger.warning(f"Admin login failed: user not found for email {email}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not bcrypt.verify(password, user["password_hash"]):
        logger.warning(f"Admin login failed: incorrect password for {email}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if email not in ADMIN_EMAILS:
        logger.warning(f"Unauthorized admin login attempt by {email}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")

    # MODIFIED: Pass the full user object to create the correct JWT
    token = create_jwt_token(user)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/admin/approve-transaction")
# MODIFIED: Protected with get_current_admin and updated parameter name
async def approve_transaction(
    payload: Dict[str, Any],
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    tx_id = payload.get("tx_id")
    if not tx_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tx_id is required")

    res = await asyncio.to_thread(lambda: supabase.table("transactions")
                                 .select("*").eq("id", tx_id).maybe_single().execute())
    tx = res.data if res else None
    if not tx:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    if tx["status"] != "pending":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Transaction already processed")

    await asyncio.to_thread(lambda: supabase.table("transactions")
                           .update({"status": "approved"})
                           .eq("id", tx_id)
                           .execute())
    
    # MODIFIED: Use 'sub' claim from JWT for admin email
    logger.info(f"Transaction {tx_id} approved by admin {current_admin['sub']}")
    return {"status": "approved"}

@app.get("/admin/users")
# MODIFIED: Protected with get_current_admin
async def get_admin_users(current_admin: Dict[str, Any] = Depends(get_current_admin)):
    res = await asyncio.to_thread(lambda: supabase.table("admin_users").select("id, email, created_at").execute())
    users = res.data if res else []
    return {"admin_users": users}

@app.get("/payments/summary")
# MODIFIED: Protected with get_current_admin
async def payments_summary(current_admin: Dict[str, Any] = Depends(get_current_admin)):
    # Get total count of transactions
    total_tx_res = await asyncio.to_thread(lambda: supabase.table("transactions").select("id", count="exact").execute())
    total_transactions = total_tx_res.count if total_tx_res else 0

    # Sum of deposits
    deposit_res = await asyncio.to_thread(lambda: supabase.rpc("sum_amount_by_type", {"type_in": "deposit"}))
    total_deposit_amount = deposit_res.data if deposit_res and deposit_res.data else 0

    # Sum of withdrawals
    withdraw_res = await asyncio.to_thread(lambda: supabase.rpc("sum_amount_by_type", {"type_in": "withdraw"}))
    total_withdraw_amount = withdraw_res.data if withdraw_res and withdraw_res.data else 0

    # Recent transactions (last 20)
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
        "recent_transactions": recent_txs
    }

@app.post("/viber-webhook")
async def viber_webhook(request: Request):
    http_client = httpx.AsyncClient(timeout=10.0)
    try:
        body_bytes = await request.body()
        viber_signature = request.headers.get("X-Viber-Content-Signature")
        if not viber_signature:
            logger.warning("Viber webhook called without signature.")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Signature missing")

        if not verify_viber_signature(body_bytes, viber_signature):
            logger.warning("Invalid Viber signature received.")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid signature")

        data = json.loads(body_bytes)
        event_type = data.get("event")
        user_id = data.get("sender", {}).get("id") or data.get("user", {}).get("id")

        if not user_id:
            # Some events like 'webhook' might not have a user_id. We can safely ignore them.
            logger.info(f"Received Viber event '{event_type}' without a user_id. Skipping.")
            return JSONResponse(content={}, status_code=200)

        # Basic rate limiting
        if not rate_limiter.is_allowed(user_id):
            logger.warning(f"Rate limit exceeded for user {user_id}. Ignoring request.")
            return JSONResponse(content={}, status_code=200)

        logger.info(f"Received Viber event '{event_type}' for user {user_id}")

        if event_type == "message":
            await handle_message(http_client, data)
        elif event_type == "subscribed":
            await handle_subscribed(http_client, data)
        elif event_type == "conversation_started":
            await handle_conversation_started(http_client, data)
        elif event_type == "unsubscribed":
            await handle_unsubscribed(data)
        else:
            logger.info(f"Ignoring unhandled Viber event type: {event_type}")

        return JSONResponse(content={}, status_code=200)
    finally:
        await http_client.aclose()

# -------------------- Viber Logic Helpers --------------------

async def get_viber_user(viber_id: str) -> Optional[Dict[str, Any]]:
    """Fetches user data from Supabase using their Viber ID."""
    try:
        res = await asyncio.to_thread(
            lambda: supabase.table("viber_users").select("*").eq("viber_id", viber_id).maybe_single().execute()
        )
        return res.data if res and res.data else None
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
    await asyncio.to_thread(
        lambda: supabase.table("viber_users")
            .upsert({"viber_id": user_id, "state": UserState.AWAITING_ACCOUNT_ID, "viber_name": user_name}, on_conflict="viber_id")
            .execute()
    )
    await send_viber_message(client, user_id, f"Welcome, {user_name}! To get started, please send your Account ID.")

async def handle_conversation_started(client: httpx.AsyncClient, data: Dict[str, Any]):
    """
    Handles the 'conversation_started' event. This is often the first interaction.
    Note: This event doesn't guarantee the user has subscribed.
    """
    user = data.get("user", {})
    user_id = user.get("id")
    if not user_id:
        return

    welcome_message = "Hello! Welcome to the YGN Real Estate Bot.\n\nTo link your account, please send your Account ID."
    await send_viber_message(client, user_id, welcome_message)
    # We can create a user entry here if one doesn't exist.
    await asyncio.to_thread(
        lambda: supabase.table("viber_users")
            .upsert({"viber_id": user_id, "state": UserState.AWAITING_ACCOUNT_ID}, on_conflict="viber_id")
            .execute()
    )

async def handle_unsubscribed(data: Dict[str, Any]):
    """Handles the 'unsubscribed' event."""
    user_id = data.get("user_id")
    if not user_id:
        return

    logger.info(f"User {user_id} unsubscribed.")
    await asyncio.to_thread(
        lambda: supabase.table("viber_users")
            .update({"state": "unsubscribed"})
            .eq("viber_id", user_id)
            .execute()
    )

async def handle_message(client: httpx.AsyncClient, data: Dict[str, Any]):
    """Handles incoming message events from Viber, containing the core bot logic."""
    sender = data.get("sender", {})
    user_id = sender.get("id")
    message = data.get("message", {})
    text = message.get("text", "").strip()

    if not user_id or not text:
        logger.warning("Message event missing sender ID or text.")
        return

    user = await get_viber_user(user_id)
    if not user:
        # If user sends a message without being in the DB, treat as a new user.
        await handle_conversation_started(client, {"user": sender})
        return

    current_state = user.get("state")

    # State: Awaiting Account ID
    if current_state == UserState.AWAITING_ACCOUNT_ID:
        account_id = text
        await asyncio.to_thread(
            lambda: supabase.table("viber_users")
                .update({"account_id": account_id, "state": UserState.MAIN_MENU})
                .eq("viber_id", user_id)
                .execute()
        )
        main_menu_text = "Thank you. Your account is linked.\n\nWhat would you like to do?\n- Deposit\n- Withdraw\n- Balance"
        await send_viber_message(client, user_id, main_menu_text)

    # State: Main Menu
    elif current_state == UserState.MAIN_MENU:
        text_lower = text.lower()
        if "deposit" in text_lower:
            await asyncio.to_thread(
                lambda: supabase.table("viber_users").update({"state": UserState.AWAITING_DEPOSIT}).eq("viber_id", user_id).execute()
            )
            await send_viber_message(client, user_id, "Please enter the amount you wish to deposit.")
        elif "withdraw" in text_lower:
            await asyncio.to_thread(
                lambda: supabase.table("viber_users").update({"state": UserState.AWAITING_WITHDRAW}).eq("viber_id", user_id).execute()
            )
            await send_viber_message(client, user_id, "Please enter the amount you wish to withdraw.")
        elif "balance" in text_lower:
            await handle_balance_check(client, user)
        else:
            await send_viber_message(client, user_id, "Invalid option. Please choose from:\n- Deposit\n- Withdraw\n- Balance")

    # State: Awaiting Deposit Amount
    elif current_state == UserState.AWAITING_DEPOSIT:
        await handle_transaction_request(client, user, "deposit", text)

    # State: Awaiting Withdraw Amount
    elif current_state == UserState.AWAITING_WITHDRAW:
        await handle_transaction_request(client, user, "withdraw", text)

async def handle_balance_check(client: httpx.AsyncClient, user: Dict[str, Any]):
    """Calculates and sends the user's approved balance."""
    user_id = user["viber_id"]
    account_id = user.get("account_id")
    if not account_id:
        await send_viber_message(client, user_id, "Error: Account ID not found. Please re-link your account.")
        await asyncio.to_thread(
            lambda: supabase.table("viber_users").update({"state": UserState.AWAITING_ACCOUNT_ID}).eq("viber_id", user_id).execute()
        )
        return

    txs_res = await asyncio.to_thread(
        lambda: supabase.table("transactions")
            .select("amount, type")
            .eq("account_id", account_id)
            .eq("status", "approved")
            .execute()
    )
    if not txs_res.data:
        await send_viber_message(client, user_id, "You have no approved transactions. Your balance is: 0.00")
        return

    total_deposits = sum(tx['amount'] for tx in txs_res.data if tx['type'] == 'deposit')
    total_withdrawals = sum(tx['amount'] for tx in txs_res.data if tx['type'] == 'withdraw')
    balance = total_deposits - total_withdrawals
    await send_viber_message(client, user_id, f"Your current approved balance is: {balance:,.2f}")

async def handle_transaction_request(client: httpx.AsyncClient, user: Dict[str, Any], tx_type: str, text_amount: str):
    """Handles a deposit or withdrawal request."""
    user_id = user["viber_id"]
    account_id = user.get("account_id")

    # This is a safeguard; a user should not be in this state without an account_id.
    if not account_id:
        logger.error(f"User {user_id} in state AWAITING_{tx_type.upper()} but has no account_id.")
        await send_viber_message(client, user_id, "An internal error occurred. We could not find your Account ID. Please start over by sending your Account ID again.")
        await asyncio.to_thread(
            lambda: supabase.table("viber_users").update({"state": UserState.AWAITING_ACCOUNT_ID}).eq("viber_id", user_id).execute()
        )
        return

    try:
        amount = float(text_amount)
        if amount <= 0:
            raise ValueError("Amount must be a positive number.")

        # Insert transaction into Supabase. 'user["id"]' is the viber_users table's primary key.
        await asyncio.to_thread(
            lambda: supabase.table("transactions").insert({
                "account_id": account_id,
                "viber_user_id": user["id"],
                "amount": amount,
                "type": tx_type,
                "status": "pending"  # All transactions require admin approval
            }).execute()
        )

        # Update user state back to the main menu
        await asyncio.to_thread(
            lambda: supabase.table("viber_users").update({"state": UserState.MAIN_MENU}).eq("viber_id", user_id).execute()
        )

        # Confirm to the user
        await send_viber_message(
            client,
            user_id,
            f"Your {tx_type} request for {amount:,.2f} has been received and is pending approval. You are now back in the main menu."
        )

    except ValueError:
        # Handle cases where the text is not a valid, positive number
        await send_viber_message(client, user_id, "Invalid amount. Please enter a valid positive number (e.g., 10000).")
        # The user's state is not changed, allowing them to try entering an amount again.