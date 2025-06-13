from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import requests
import openai
import os
from supabase import create_client, Client
from prompt import build_prompt

app = FastAPI()

openai.api_key = os.getenv("OPENAI_API_KEY")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
VIBER_TOKEN = os.getenv("VIBER_TOKEN")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.get("/viber-webhook")
async def viber_webhook_get():
    return {"status": "ok", "message": "Viber webhook endpoint is live"}

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

            # Build prompt
            prompt = build_prompt(message_text)

            # Call OpenAI
            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}]
            )
            reply = completion.choices[0].message["content"]
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
            print(f"[INFO] Viber send_message response status: {resp.status_code}, body: {resp.text}")

        return {"status": 0}

    except Exception as e:
        print(f"[ERROR] Exception in /viber-webhook: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
