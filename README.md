
# YGN Real Estate Bot (Demo)

YGN Real Estate Bot သည် GPT-3.5 အခြေခံပြီး ရန်ကုန်မြို့ အိမ်ခြံမြေသတင်းများကို Viber မှတဆင့် အမြန်ဆုံး ဖြေကြားပေးသော chatbot ဖြစ်ပါသည်။

## Features

- အိမ်ခြံမြေ ငှားရန် / ရောင်းရန် မေးခွန်းများကို ဖြေကြားနိုင်ခြင်း
- မြေကွက်၊ တိုက်ခန်း စျေးနှုန်း မေးခွန်းများ
- တည်နေရာအထောက်အထားများ (ဥပမာ - ဒဂုံမြို့သစ်မြောက်ပိုင်း)
- ဈေးနှုန်း နှိုင်းယှဉ်ခြင်း
- လစဉ်ငှားစျေးနှင့် ငွေပေးချေမှု ရွေးချယ်စရာများ

## Requirements

- Python 3.9+
- Supabase account and project
- Viber Public Account with webhook setup
- OpenAI API key (GPT-3.5 Turbo)

## Setup

1. `.env` ဖိုင်ကို root folder ထဲမှာဖန်တီးပြီး အောက်ပါအတိုင်း သင့် credentials များ ထည့်သွင်းပါ။

```env
OPENAI_API_KEY=your_openai_api_key_here
SUPABASE_URL=https://your_supabase_url.supabase.co
SUPABASE_KEY=your_supabase_anon_or_service_key
SUPABASE_JWT_SECRET=your_supabase_jwt_secret
VIBER_TOKEN=your_viber_auth_token
PORT=8000
```

2. Python dependencies များ install လုပ်ပါ။

```bash
pip install fastapi uvicorn supabase openai bcrypt pyjwt requests
```

3. Local သို့ Run

```bash
uvicorn main:app --reload
```

4. Public URL ရရှိရန် ngrok သို့မဟုတ် Cloud deployment (Render, Railway, Heroku) အသုံးပြုပါ။

5. Viber bot dashboard မှ webhook URL ကို

```
https://yourdomain.com/viber-webhook
```

အဖြစ် သတ်မှတ်ပါ။

## API Endpoints

- `POST /auth/login` – Email နဲ့ Password ဖြင့် login လုပ်ပြီး JWT token ရယူခြင်း
- `GET /admin/users` – Admin user list ကို token ဖြင့် access
- `GET /payments/summary` – Payment summary များကို admin access ဖြင့်
- `GET /health` – Server health status
- `GET /viber-webhook` – Viber webhook check
- `POST /viber-webhook` – Viber message event handler

## Security

- Passwords are hashed with bcrypt
- JWT token authentication with role-based access control (admin-only routes)
- Maintenance mode controlled from Supabase settings

## Maintenance Mode

- Maintenance mode ဖွင့်ထားလျှင် Viber users များအား အလိုအလျောက် maintenance message ပေးပို့ပါသည်။

## License

MIT License

---

## Contact

Project maintained by Ethan  
Email: info@ygnb2b.com  
GitHub: https://github.com/EthanVT97
