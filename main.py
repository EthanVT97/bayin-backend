from fastapi import FastAPI, Request, HTTPException, Depends, Header, Body
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import os, requests, jwt, bcrypt, datetime
from supabase import create_client, Client
from openai import OpenAI
from prompt import build_prompt

app = FastAPI()

# -------- Env setup --------
client                  = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
SUPABASE_URL            = os.getenv("SUPABASE_URL")
SUPABASE_KEY            = os.getenv("SUPABASE_KEY")
SUPABASE_JWT_SECRET     = os.getenv("SUPABASE_JWT_SECRET")
VIBER_TOKEN             = os.getenv("VIBER_TOKEN")
supabase: Client        = create_client(SUPABASE_URL, SUPABASE_KEY)

# -------- Static admin panel --------
if os.path.exists("admin"):
    app.mount("/admin", StaticFiles(directory="admin", html=True), name="admin")
else:
    print("[WARN] 'admin' directory not found; /admin route skipped.")

# ---------------- Auth ----------------
@app.post("/auth/login")
async def login_user(email: str = Body(...), password: str = Body(...)):
    try:
        res = supabase.table("users").select("*").eq("email", email).maybe_single().execute()
        if res is None or res.data is None:
            raise HTTPException(status_code=404, detail="User not found")
        user = res.data

        if not bcrypt.checkpw(password.encode(), user["password"].encode()):
            raise HTTPException(status_code=401, detail="Invalid password")

        payload = {
            "sub":  user["id"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "exp":  datetime.datetime.utcnow() + datetime.timedelta(days=1),
            "aud":  "authenticated",
        }
        token = jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm="HS256")
        return {"access_token": token}
    except HTTPException:
        raise
    except Exception as e:
        print("[ERROR] login_user:", e)
        return JSONResponse(status_code=500, content={"error": str(e)})

def verify_jwt_token(auth: str = Header(...)):
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bad auth header")
    token = auth.split(" ")[1]
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
        raise HTTPException(status_code=403, detail="Admin only")
    return payload

# --------------- Admin UI helpers ---------------
@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(
        """
        <html><head><title>YGN Real Estate Bot</title></head><body>
        <h1>Welcome to YGN Real Estate Bot Backend</h1>
        <p>Visit <a href="/admin">/admin</a> for the Admin Panel</p>
        </body></html>
        """
    )

@app.get("/admin/users")
async def list_users(_: dict = Depends(verify_jwt_token)):
    return {
        "users": [
            {"id": "user1", "name": "Admin အကိုကြီး", "access_level": "basic"},
            {"id": "user2", "name": "Admin ညီမလေး", "access_level": "admin"},
        ]
    }

@app.get("/payments/summary")
async def payments_summary(_: dict = Depends(verify_jwt_token)):
    return {"total_payments": 25, "total_amount": 1_250_000, "currency": "MMK"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

# --------------- Maintenance helpers ---------------
def get_maintenance_setting() -> bool:
    try:
        res = supabase.table("settings").select("*").eq("key", "maintenance_mode").maybe_single().execute()
        return bool(res and res.data and res.data.get("value") == "true")
    except Exception as e:
        print("[ERROR] maintenance_mode:", e)
        return False

def get_maintenance_message() -> str:
    try:
        res = supabase.table("settings").select("*").eq("key", "maintenance_message").maybe_single().execute()
        if res and res.data:
            return res.data.get("value", "Server maintenance. Please try again later.")
    except Exception as e:
        print("[ERROR] maintenance_message:", e)
    return "Server maintenance. Please try again later."

# --------------- Viber webhook ---------------
@app.get("/viber-webhook")
async def webhook_check():
    return {"status": "ok", "message": "Viber webhook live"}

@app.post("/viber-webhook")
async def viber_webhook(req: Request):
    try:
        body = await req.json()
        print("[DEBUG] Viber payload:", body)

        event        = body.get("event")
        sender_id    = body.get("sender", {}).get("id", "")
        message_text = body.get("message", {}).get("text", "")

        if get_maintenance_setting():
            if event == "message":
                requests.post(
                    "https://chatapi.viber.com/pa/send_message",
                    json={
                        "receiver": sender_id,
                        "min_api_version": 1,
                        "sender": {"name": "YGN Real Estate Bot"},
                        "type": "text",
                        "text": get_maintenance_message(),
                    },
                    headers={"X-Viber-Auth-Token": VIBER_TOKEN},
                )
            return {"status": 0}

        if event == "message":
            prompt     = build_prompt(message_text)
            gpt_reply  = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
            ).choices[0].message.content

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
        print("[ERROR] Viber webhook:", e)
        return JSONResponse(status_code=500, content={"error": str(e)})

# --------------- Entrypoint ---------------
if __name__ == "__main__":
    import uvicorn, os
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))

