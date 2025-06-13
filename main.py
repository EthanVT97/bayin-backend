from fastapi import FastAPI, Request
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

@app.post("/viber-webhook")
async def viber_webhook(req: Request):
    body = await req.json()
    event = body.get("event")

    if event == "message":
        sender_id = body["sender"]["id"]
        message_text = body["message"]["text"]

        # Build prompt
        prompt = build_prompt(message_text)

        # Call OpenAI
        completion = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        reply = completion.choices[0].message["content"]

        # Send reply to Viber
        requests.post(
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

    return {"status": "ok"}
