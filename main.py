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
from prompt import build_prompt
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
        # Clean old requests
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
    
    # Validate critical env vars
    required_vars = ["OPENAI_API_KEY", "SUPABASE_URL", "SUPABASE_KEY", "VIBER_TOKEN"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        logger.error(f"❌ Missing environment variables: {missing_vars}")
        raise RuntimeError(f"Missing required environment variables: {missing_vars}")
    
    # Test database connection
    try:
        supabase.table("settings").select("key").limit(1).execute()
        logger.info("✅ Database connection established")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        raise RuntimeError("Database connection failed")
    
    # Test OpenAI connection
    try:
        client.models.list()
        logger.info("✅ OpenAI API connection established")
    except Exception as e:
        logger.error(f"❌ OpenAI API connection failed: {e}")
        raise RuntimeError("OpenAI API connection failed")
    
    yield
    
    # Shutdown
    logger.info("🛑 YGN Real Estate Bot shutting down...")

app = FastAPI(
    title="YGN Real Estate Bot",
    description="Production-ready Viber bot for real estate inquiries",
    version="2.0.0",
    lifespan=lifespan
)

# -------- Security Middleware --------
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["*"]  # Configure with your actual domains in production
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Replace with actual domain
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Viber-Content-Signature"],
)

# -------- Environment Setup --------
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
VIBER_TOKEN = os.getenv("VIBER_TOKEN")
VIBER_WEBHOOK_SECRET = os.getenv("VIBER_WEBHOOK_SECRET")  # For signature verification
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
security = HTTPBearer()

# -------- Static Files --------
if os.path.exists("admin"):
    app.mount("/admin", StaticFiles(directory="admin", html=True), name="admin")
    logger.info("✅ Admin panel mounted at /admin")
else:
    logger.warning("⚠️  'admin' directory not found; /admin route skipped")

# -------- Signature Verification --------
def verify_viber_signature(body: bytes, signature: str) -> bool:
    """Verify Viber webhook signature for security"""
    if not VIBER_WEBHOOK_SECRET:
        logger.warning("⚠️  VIBER_WEBHOOK_SECRET not set - skipping signature verification")
        return True
    
    expected_signature = hmac.new(
        VIBER_WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected_signature)

# -------- Enhanced Authentication --------
async def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Enhanced JWT verification with proper error handling"""
    try:
        payload = jwt.decode(
            credentials.credentials,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated",
            options={"verify_exp": True},
        )
        
        # Additional validation
        if not payload.get("sub"):
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        return payload
    
    except jwt.ExpiredSignatureError:
        logger.warning(f"Expired token attempt from {payload.get('email', 'unknown')}")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"JWT verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication error")

async def verify_admin_token(payload: Dict[str, Any] = Depends(verify_jwt_token)) -> Dict[str, Any]:
    """Verify admin role"""
    if payload.get("role") != "admin":
        logger.warning(f"Non-admin access attempt: {payload.get('email', 'unknown')}")
        raise HTTPException(status_code=403, detail="Admin access required")
    return payload

# -------- Enhanced Auth Endpoints --------
@app.post("/auth/login", response_model=dict)
async def login_user(request: Request, email: str = Body(...), password: str = Body(...)):
    """Enhanced login with rate limiting and audit logging"""
    client_ip = request.client.host
    
    # Rate limiting
    if not rate_limiter.is_allowed(f"login:{client_ip}"):
        logger.warning(f"Rate limit exceeded for login from {client_ip}")
        raise HTTPException(status_code=429, detail="Too many login attempts")
    
    try:
        # Fetch user
        res = supabase.table("users").select("*").eq("email", email).maybe_single().execute()
        if not res.data:
            logger.warning(f"Login attempt for non-existent user: {email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = res.data
        
        # Verify password
        if not user.get("password") or not user["password"].startswith("$2b$"):
            logger.error(f"Invalid password hash for user: {email}")
            raise HTTPException(status_code=500, detail="Authentication error")
        
        if not bcrypt.checkpw(password.encode(), user["password"].encode()):
            logger.warning(f"Invalid password attempt for user: {email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if user is active
        if not user.get("is_active", True):
            logger.warning(f"Login attempt for inactive user: {email}")
            raise HTTPException(status_code=401, detail="Account inactive")
        
        # Generate token
        payload = {
            "sub": user["id"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            "aud": "authenticated",
            "iat": datetime.datetime.utcnow(),
        }
        
        token = jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm="HS256")
        
        # Update last login
        supabase.table("users").update({
            "last_login": datetime.datetime.utcnow().isoformat(),
            "login_count": user.get("login_count", 0) + 1
        }).eq("id", user["id"]).execute()
        
        logger.info(f"Successful login: {email}")
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 86400,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "role": user["role"]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error for {email}: {str(e)}")
        raise HTTPException(status_code=500, content={"error": "Authentication service unavailable"})

@app.post("/auth/refresh")
async def refresh_token(payload: Dict[str, Any] = Depends(verify_jwt_token)):
    """Token refresh endpoint"""
    try:
        new_payload = {
            "sub": payload["sub"],
            "email": payload["email"],
            "role": payload["role"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            "aud": "authenticated",
            "iat": datetime.datetime.utcnow(),
        }
        
        new_token = jwt.encode(new_payload, SUPABASE_JWT_SECRET, algorithm="HS256")
        
        return {
            "access_token": new_token,
            "token_type": "bearer",
            "expires_in": 86400
        }
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(status_code=500, detail="Token refresh failed")

# -------- Enhanced Admin Endpoints --------
@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html><head>
        <title>YGN Real Estate Bot</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #333; }}
            .status {{ color: #28a745; font-weight: bold; }}
            a {{ color: #007bff; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head><body>
        <div class="container">
            <h1>🏠 YGN Real Estate Bot</h1>
            <p class="status">✅ Backend Service Online</p>
            <p><strong>Environment:</strong> {ENVIRONMENT}</p>
            <p><strong>Version:</strong> 2.0.0</p>
            <hr>
            <p>🔧 <a href="/admin">Admin Panel</a></p>
            <p>📊 <a href="/docs">API Documentation</a></p>
            <p>❤️ <a href="/health">Health Check</a></p>
        </div>
    </body></html>
    """)

@app.get("/admin/users")
async def list_users(payload: Dict[str, Any] = Depends(verify_admin_token)):
    """List all users with pagination"""
    try:
        res = supabase.table("users").select("id,email,role,created_at,last_login,is_active").execute()
        
        return {
            "users": res.data,
            "total": len(res.data),
            "requested_by": payload["email"]
        }
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch users")

@app.get("/admin/analytics")
async def get_analytics(payload: Dict[str, Any] = Depends(verify_admin_token)):
    """Get bot analytics"""
    try:
        # Get message stats
        messages_res = supabase.table("messages").select("*").execute()
        
        # Get user stats
        users_res = supabase.table("users").select("*").execute()
        
        return {
            "total_messages": len(messages_res.data) if messages_res.data else 0,
            "total_users": len(users_res.data) if users_res.data else 0,
            "active_users": len([u for u in (users_res.data or []) if u.get("is_active", True)]),
            "generated_at": datetime.datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Analytics error: {str(e)}")
        raise HTTPException(status_code=500, detail="Analytics unavailable")

@app.get("/payments/summary")
async def payments_summary(payload: Dict[str, Any] = Depends(verify_admin_token)):
    """Enhanced payments summary"""
    try:
        # This would typically query a payments table
        payments_res = supabase.table("payments").select("*").execute()
        
        total_amount = sum(p.get("amount", 0) for p in (payments_res.data or []))
        
        return {
            "total_payments": len(payments_res.data) if payments_res.data else 0,
            "total_amount": total_amount,
            "currency": "MMK",
            "last_updated": datetime.datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Payments summary error: {str(e)}")
        return {"total_payments": 0, "total_amount": 0, "currency": "MMK", "error": "Data unavailable"}

# -------- Settings Management --------
async def get_setting(key: str, default_value: Any = None) -> Any:
    """Get setting with caching and error handling"""
    try:
        res = supabase.table("settings").select("value").eq("key", key).maybe_single().execute()
        if res.data:
            return res.data["value"]
        return default_value
    except Exception as e:
        logger.error(f"Error fetching setting {key}: {str(e)}")
        return default_value

async def get_maintenance_setting() -> bool:
    return await get_setting("maintenance_mode", False) == "true"

async def get_maintenance_message() -> str:
    return await get_setting("maintenance_message", "🔧 System maintenance in progress. Please try again later.")

# -------- Enhanced Health Check --------
@app.get("/health")
async def health_check():
    """Comprehensive health check"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "version": "2.0.0",
        "environment": ENVIRONMENT,
        "checks": {}
    }
    
    # Database check
    try:
        supabase.table("settings").select("key").limit(1).execute()
        health_status["checks"]["database"] = "✅ Connected"
    except Exception as e:
        health_status["checks"]["database"] = f"❌ Error: {str(e)}"
        health_status["status"] = "degraded"
    
    # OpenAI check
    try:
        client.models.list()
        health_status["checks"]["openai"] = "✅ Connected"
    except Exception as e:
        health_status["checks"]["openai"] = f"❌ Error: {str(e)}"
        health_status["status"] = "degraded"
    
    # Viber API check
    try:
        response = requests.get(
            "https://chatapi.viber.com/pa/get_account_info",
            headers={"X-Viber-Auth-Token": VIBER_TOKEN},
            timeout=5
        )
        if response.status_code == 200:
            health_status["checks"]["viber"] = "✅ Connected"
        else:
            health_status["checks"]["viber"] = f"❌ HTTP {response.status_code}"
            health_status["status"] = "degraded"
    except Exception as e:
        health_status["checks"]["viber"] = f"❌ Error: {str(e)}"
        health_status["status"] = "degraded"
    
    return health_status

# -------- Enhanced Viber Webhook --------
@app.get("/viber-webhook")
async def webhook_verification():
    """Webhook verification endpoint"""
    return {
        "status": "✅ Webhook endpoint active",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }

@app.post("/viber-webhook")
async def viber_webhook(request: Request):
    """Enhanced Viber webhook with comprehensive error handling"""
    try:
        # Get raw body for signature verification
        body_bytes = await request.body()
        
        # Verify signature if secret is configured
        signature = request.headers.get("X-Viber-Content-Signature", "")
        if not verify_viber_signature(body_bytes, signature):
            logger.warning("Invalid Viber webhook signature")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        # Parse JSON
        try:
            body = json.loads(body_bytes.decode())
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in webhook: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid JSON")
        
        logger.info(f"📨 Viber webhook received: {body.get('event', 'unknown')}")
        
        event = body.get("event")
        
        # Handle webhook verification
        if event == "webhook":
            logger.info("✅ Webhook verification successful")
            return {"status": "ok", "event_types": ["message_received"]}
        
        # Extract message data with enhanced error handling
        message_data = body.get("data", {})
        contact_data = message_data.get("contact", {})
        content_data = message_data.get("content", {})
        
        contact_id = contact_data.get("id", "")
        user_name = contact_data.get("name", "Anonymous")
        message_text = content_data.get("payload", "")
        message_type = content_data.get("type", "")
        
        logger.info(f"📱 Message from {user_name} ({contact_id}): {message_text[:50]}...")
        
        # Validate required fields
        if not contact_id:
            logger.warning("Missing contact ID in webhook")
            return {"status": "ignored", "reason": "missing_contact_id"}
        
        if not message_text and message_type == "text":
            logger.warning("Missing message text")
            return {"status": "ignored", "reason": "missing_message_text"}
        
        # Rate limiting per user
        if not rate_limiter.is_allowed(f"viber:{contact_id}"):
            logger.warning(f"Rate limit exceeded for user {contact_id}")
            await send_viber_message(contact_id, "⚠️ Please wait a moment before sending another message.")
            return {"status": "rate_limited"}
        
        # Check maintenance mode
        if await get_maintenance_setting():
            maintenance_msg = await get_maintenance_message()
            await send_viber_message(contact_id, maintenance_msg)
            return {"status": "maintenance"}
        
        # Process message
        if event == "message_received" and message_type == "text":
            # Input validation
            if len(message_text) > 2000:
                await send_viber_message(contact_id, "❌ Message too long. Please keep messages under 2000 characters.")
                return {"status": "message_too_long"}
            
            # Log message to database
            try:
                supabase.table("messages").insert({
                    "contact_id": contact_id,
                    "user_name": user_name,
                    "message": message_text,
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "processed": False
                }).execute()
            except Exception as e:
                logger.error(f"Failed to log message: {str(e)}")
            
            # Generate AI response
            try:
                prompt = build_prompt(message_text)
                
                gpt_response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                   
