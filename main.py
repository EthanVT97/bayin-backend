from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import requests
import os
from openai import OpenAI
from supabase import create_client, Client
from prompt import build_prompt

app = FastAPI()

# Environment Variables
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
VIBER_TOKEN = os.getenv("VIBER_TOKEN")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# 🔹 Root Route for status check
@app.get("/")
async def root():
    return {"status": "ok", "message": "YGN Real Estate Bot API is running"}

# 🔹 Viber Webhook: GET (for health check)
@app.get("/viber-webhook")
async def viber_webhook_get():
    return {"status": "ok", "message": "Viber webhook endpoint is live"}

# 🔹 Viber Webhook: POST (message handler)
@app.post("/viber-webhook")
async def viber_webhook_post(req: Request):
    try:
        body = await req.json()
        print("[DEBUG] Incoming webhook payload:", body)
        event = body.get("event")

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

            # Send reply to Viber
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
            print(f"[INFO] Viber send_message response: {resp.status_code}, body: {resp.text}")

        return {"status": 0}

    except Exception as e:
        print(f"[ERROR] Exception in /viber-webhook: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# 🔹 Admin: List all users from Supabase
@app.get("/admin/users")
async def list_users():
    try:
        data = supabase.table("users").select("*").execute()
        return data.data
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# 🔹 Admin: List latest chat messages
@app.get("/admin/messages")
async def list_messages():
    try:
        data = supabase.table("messages").select("*").order("created_at", desc=True).limit(50).execute()
        return data.data
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# 🔹 Admin: List recent payments
@app.get("/admin/payments")
async def list_payments():
    try:
        data = supabase.table("payments").select("*").order("created_at", desc=True).limit(20).execute()
        return data.data
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# 🔹 Admin Panel Static Files (Optional - place index.html inside ./admin/)
app.mount("/admin", StaticFiles(directory="admin", html=True), name="admin")
