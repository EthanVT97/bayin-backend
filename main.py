from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import os
import requests
from openai import OpenAI
from supabase import create_client, Client
from prompt import build_prompt

app = FastAPI()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
VIBER_TOKEN = os.getenv("VIBER_TOKEN")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Mount admin panel static folder only if exists
if os.path.exists("admin"):
    app.mount("/admin", StaticFiles(directory="admin", html=True), name="admin")
else:
    print("[WARN] 'admin' directory does not exist; admin panel not mounted.")

@app.get("/", response_class=HTMLResponse)
async def root():
    content = """
    <html><head><title>YGN Real Estate Bot</title></head><body>
    <h1>Welcome to YGN Real Estate Bot Backend</h1>
    <p>Visit <a href="/admin">/admin</a> for the Admin Panel (if available)</p>
    </body></html>
    """
    return HTMLResponse(content=content)

def get_maintenance_setting():
    # Supabase မှာ settings table မှာ maintenance_mode flag နဲ့ message ရှာဖို့ logic
    try:
        response = supabase.table("settings").select("*").eq("key", "maintenance_mode").single().execute()
        maintenance_mode = False
        if response.data:
            maintenance_mode = response.data.get("value") == "true"
        else:
            maintenance_mode = False
    except Exception as e:
        print(f"[ERROR] Failed to fetch maintenance_mode setting: {e}")
        maintenance_mode = False
    return maintenance_mode

def get_maintenance_message():
    # Supabase မှာ maintenance_message ရှိရင်ယူမယ်၊ မရှိရင် default message ပြန်မယ်
    try:
        response = supabase.table("settings").select("*").eq("key", "maintenance_message").single().execute()
        if response.data and response.data.get("value"):
            return response.data.get("value")
    except Exception as e:
        print(f"[ERROR] Failed to fetch maintenance_message setting: {e}")
    return "Server maintenance. Please try again later."

@app.get("/viber-webhook")
async def viber_webhook_get():
    return {"status": "ok", "message": "Viber webhook endpoint is live"}

@app.post("/viber-webhook")
async def viber_webhook_post(req: Request):
    try:
        body = await req.json()
        print("[DEBUG] Incoming webhook payload:", body)
        event = body.get("event")

        maintenance_mode = get_maintenance_setting()
        if maintenance_mode:
            # Maintenance mode ON ဖြစ်ရင် message event တွေကို maintenance message နဲ့ reply ပေးမယ်
            if event == "message":
                sender_id = body["sender"]["id"]
                maintenance_msg = get_maintenance_message()

                resp = requests.post(
                    "https://chatapi.viber.com/pa/send_message",
                    json={
                        "receiver": sender_id,
                        "min_api_version": 1,
                        "sender": {
                            "name": "YGN Real Estate Bot"
                        },
                        "type": "text",
                        "text": maintenance_msg
                    },
                    headers={"X-Viber-Auth-Token": VIBER_TOKEN}
                )
                print(f"[INFO] Maintenance reply sent with status {resp.status_code}")
                return {"status": 0}

            # Message event မဟုတ်ရင် maintenance mode response ပြန်ပေး
            return {"status": 0}

        # Maintenance mode off ဖြစ်ရင် existing bot logic လုပ်ဆောင်မယ်
        if event == "message":
            sender_id = body["sender"]["id"]
            message_text = body["message"]["text"]
            print(f"[INFO] Message from {sender_id}: {message_text}")

            prompt = build_prompt(message_text)

            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}]
            )
            reply = response.choices[0].message.content
            print(f"[INFO] GPT reply: {reply}")

            resp = requests.post(
                "https://chatapi.viber.com/pa/send_message",
                json={
                    "receiver": sender_id,
                    "min_api_version": 1,
                    "sender": {
                        "name": "YGN Real Estate Bot"
                    },
                    "type": "text",
                    "text": reply
                },
                headers={"X-Viber-Auth-Token": VIBER_TOKEN}
            )
            print(f"[INFO] Viber send_message response status: {resp.status_code}, body: {resp.text}")

        return {"status": 0}

    except Exception as e:
        print(f"[ERROR] Exception in /viber-webhook: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# Example API to list user data (placeholder)
@app.get("/users")
async def list_users():
    users = [
        {"id": "user1", "name": "Admin အကိုကြီး", "access_level": "basic"},
        {"id": "user2", "name": "Admin ညီမလေး", "access_level": "admin"},
    ]
    return {"users": users}

# Example API to get payment summary (placeholder)
@app.get("/payments/summary")
async def payments_summary():
    summary = {
        "total_payments": 25,
        "total_amount": 1250000,
        "currency": "MMK"
    }
    return summary

# Health check
@app.get("/health")
async def health():
    return {"status": "healthy"}
