from fastapi import FastAPI, Request
import httpx
import os
from dotenv import load_dotenv
from prompt import build_prompt

load_dotenv()
app = FastAPI()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VIBER_TOKEN = os.getenv("VIBER_TOKEN")

@app.post("/webhook/viber/")
async def viber_webhook(req: Request):
    data = await req.json()
    user_msg = data.get("message", {}).get("text", "")
    user_id = data.get("sender", {}).get("id", "")

    messages = build_prompt(user_msg)

    async with httpx.AsyncClient() as client:
        chat_resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={"model": "gpt-3.5-turbo", "messages": messages}
        )
        reply = chat_resp.json()["choices"][0]["message"]["content"]

        await client.post("https://chatapi.viber.com/pa/send_message", headers={
            "X-Viber-Auth-Token": VIBER_TOKEN
        }, json={
            "receiver": user_id,
            "type": "text",
            "text": reply
        })

    return {"status": "ok"}
