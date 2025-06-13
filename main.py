from fastapi import FastAPI, Request, HTTPException, Depends, Header, Body
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import os
import requests
import jwt
import bcrypt
import datetime
from supabase import create_client, Client
from openai import OpenAI
from prompt import build_prompt

app = FastAPI()

# Env setup
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
VIBER_TOKEN = os.getenv("VIBER_TOKEN")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Mount admin panel
if os.path.exists("admin"):
    app.mount("/admin", StaticFiles(directory="admin", html=True), name="admin")
else:
    print("[WARN] 'admin' directory does not exist; admin panel not mounted.")

# ---------------------- Auth Section ---------------------- #

@app.post("/auth/login")
async def login_user(email: str = Body(...), password: str = Body(...)):
    try:
        user_result = supabase.table("users").select("*").eq("email", email).single().execute()
        user = user_result.data
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        hashed_pw = user["password"]
        if not bcrypt.checkpw(password.encode(), hashed_pw.encode()):
            raise HTTPException(status_code=401, detail="Invalid password")

        payload = {
            "sub": user["id"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
            "aud": "authenticated"
        }

        token = jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm="HS256")
        return {"access_token": token}
    except Exception as e:
        print(f"[ERROR] Login error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

def verify_jwt_token(auth_header: str = Header(...)):
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header format")

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated",
            options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return payload

# ---------------------- Admin Panel ---------------------- #

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html><head><title>YGN Real Estate Bot</title></head><body>
    <h1>Welcome to YGN Real Estate Bot Backend</h1>
    <p>Visit <a href="/admin">/admin</a> for the Admin Panel</p>
    </body></html>
    """

@app.get("/admin/users")
async def list_users(payload=Depends(verify_jwt_token)):
    return {
        "users": [
            {"id": "user1", "name": "Admin အကိုကြီး", "access_level": "basic"},
            {"id": "user2", "name": "Admin ညီမလေး", "access_level": "admin"},
        ]
    }

@app.get("/payments/summary")
async def payments_summary(payload=Depends(verify_jwt_token)):
    return {
        "total_payments": 25,
        "total_amount": 1250000,
        "currency": "MMK",
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

# ---------------------- Maintenance System ---------------------- #

def get_maintenance_setting():
    try:
        res = supabase.table("settings").select("*").eq("key", "maintenance_mode").single().execute()
        return res.data and res.data.get("value") == "true"
    except Exception as e:
        print(f"[ERROR] maintenance_mode: {e}")
        return False

def get_maintenance_message():
    try:
        res = supabase.table("settings").select("*").eq("key", "maintenance_message").single().execute()
        return res.data.get("value") if res.data else "Server maintenance. Please try again later."
    except Exception as e:
        print(f"[ERROR] maintenance_message: {e}")
        return "Server maintenance. Please try again later."

# ---------------------- Viber Webhook ---------------------- #

@app.get("/viber-webhook")
async def webhook_check():
    return {"status": "ok", "message": "Viber webhook live"}

@app.post("/viber-webhook")
async def viber_webhook(req: Request):
    try:
        body = await req.json()
        print("[DEBUG] Viber payload:", body)

        event = body.get("event")
        sender_id = body.get("sender", {}).get("id", "")
        message_text = body.get("message", {}).get("text", "")

        if get_maintenance_setting():
            if event == "message":
                maintenance_msg = get_maintenance_message()
                requests.post(
                    "https://chatapi.viber.com/pa/send_message",
                    json={
                        "receiver": sender_id,
                        "min_api_version": 1,
                        "sender": {"name": "YGN Real Estate Bot"},
                        "type": "text",
                        "text": maintenance_msg,
                    },
                    headers={"X-Viber-Auth-Token": VIBER_TOKEN},
                )
            return {"status": 0}

        if event == "message":
            prompt = build_prompt(message_text)
            gpt_reply = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
            ).choices[0].message.content

            print(f"[INFO] GPT reply: {gpt_reply}")

            requests.post(
                "https://chatapi.viber.com/pa/send_message",
                json={
                    "receiver": sender_id,
                    "min_api_version": 1,
                    "sender": {"name": "YGN Real Estate Bot"},
                    "type": "text",
                    "text": gpt_reply,
                },
                headers={"X-Viber-Auth-Token": VIBER_TOKEN},
            )

        return {"status": 0}

    except Exception as e:
        print(f"[ERROR] Viber webhook error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.getenv("PORT", 8000))  # Render provided or fallback
    uvicorn.run("main:app", host="0.0.0.0", port=port)


