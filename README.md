YGN Bot Service - Viber ဘော့တ်

ဒီ project ဟာ FastAPI ကို အသုံးပြုပြီးတည်ဆောက်ထားတဲ့ Viber Bot တစ်ခုဖြစ်ပါတယ်။ ငွေသွင်း/ငွေထုတ် တောင်းဆိုမှုတွေကို stateful conversation logic နဲ့ကိုင်တွယ်ပေးနိုင်ပြီး၊ Admin တွေအတွက် JWT authentication ပါဝင်တဲ့ dashboard တစ်ခုလည်း ပါရှိပါတယ်။ Database အတွက် Supabase ကို အသုံးပြုထားပါတယ်။

အဓိက Features များ

Viber Bot Integration: ငွေသွင်း၊ ငွေထုတ် လုပ်ငန်းစဥ်များအတွက် အဆင့်လိုက်တုံ့ပြန်မှု (Stateful Logic)။

Admin Panel: Admin များအတွက် Login, Analytics နှင့် Transaction Approval ပြုလုပ်နိုင်သော Endpoint များ။

JWT Authentication: Admin Endpoint များကို HS256 JWT ဖြင့် လုံခြုံအောင်ပြုလုပ်ထားခြင်း။

Supabase Integration: User data, transaction logs များကို Supabase (PostgreSQL) တွင် သိမ်းဆည်းခြင်း။

Rate Limiting: Request များ အလွန်အကျွံဝင်လာခြင်းကို ကာကွယ်ပေးခြင်း။

Health Check: Service ၏ ကျန်းမာရေးအခြေအနေကို စစ်ဆေးနိုင်သော /health endpoint။

Webhook Security: Viber မှ ပေးပို့သော request များကို X-Viber-Content-Signature ဖြင့် စစ်ဆေးခြင်း။

Environment-based Configuration: .env ဖိုင်ဖြင့် လွယ်ကူစွာ setup ပြုလုပ်နိုင်ခြင်း။

အသုံးပြုထားသော နည်းပညာများ

Backend: Python 3, FastAPI

Database: Supabase (PostgreSQL)

Authentication: PyJWT, bcrypt

API Client: HTTPX, Requests

ASGI Server: Uvicorn

Local မှာ Setup ပြုလုပ်ခြင်း
၁။ Project ကို Clone ပြုလုပ်ပါ
Generated bash
git clone <your-repository-url>
cd <your-repository-folder>

၂။ Virtual Environment สร้างပြီး Activate လုပ်ပါ
Generated bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END
၃။ requirements.txt ဖိုင်สร้างပါ

သင့် project folder ထဲမှာ requirements.txt ဆိုတဲ့ဖိုင်တစ်ခုဆောက်ပြီး အောက်ပါ dependency များကို ထည့်သွင်းပါ။

Generated txt
fastapi
uvicorn[standard]
supabase
python-dotenv
pyjwt
bcrypt
httpx
requests
gunicorn
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Txt
IGNORE_WHEN_COPYING_END
၄။ Dependency များကို Install လုပ်ပါ
Generated bash
pip install -r requirements.txt
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END
၅။ Environment Variables (.env) ဖိုင်ပြင်ဆင်ပါ

Project folder ထဲမှာ .env ဆိုတဲ့ ဖိုင်တစ်ခုဆောက်ပြီး အောက်ပါအတိုင်း သင့်ရဲ့ key များကို ဖြည့်စွက်ပါ။

Generated env
# Supabase
SUPABASE_URL="https://your-project-ref.supabase.co"
SUPABASE_KEY="your-supabase-anon-key"
SUPABASE_JWT_SECRET="your-supabase-jwt-secret" # Supabase > Project Settings > API > JWT Secret

# Viber
VIBER_TOKEN="your-viber-bot-auth-token"
VIBER_WEBHOOK_SECRET="some-very-strong-secret-string-for-webhook" # လုံခြုံရေးအတွက် ကိုယ်တိုင်สร้างထားတဲ့ စာတန်း

# OpenAI (Optional)
# OPENAI_API_KEY="your-openai-key"

# Environment
ENVIRONMENT="development"
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Env
IGNORE_WHEN_COPYING_END
၆။ Supabase Database Setup

Supabase project ထဲက SQL Editor မှာ အောက်ပါ table များကို run ပြီး สร้างပါ။

<details>
<summary>Supabase SQL Schema (နှိပ်ပြီးကြည့်ပါ)</summary>

Generated sql
-- viber_users table (Viber မှ user များကို မှတ်ရန်)
CREATE TABLE viber_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    viber_id TEXT NOT NULL UNIQUE,
    name TEXT,
    account_id TEXT UNIQUE,
    state TEXT DEFAULT 'AWAITING_ACCOUNT_ID',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- transactions table (ငွေသွင်း/ငွေထုတ် မှတ်တမ်း)
CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES viber_users(id),
    type TEXT NOT NULL, -- 'deposit' or 'withdraw'
    amount NUMERIC NOT NULL,
    status TEXT DEFAULT 'pending', -- 'pending', 'completed', 'rejected'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- users table (Admin panel အတွက်)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMPTZ,
    login_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Admin user တစ်ယောက်ကို စမ်းသပ်ရန်အတွက် ထည့်သွင်းခြင်း
-- မှတ်ချက်: password ကို bcrypt ဖြင့် hash လုပ်ပြီးမှ ထည့်ရန်လိုအပ်ပါသည်။
-- Local မှာ python script တစ်ခုဖြင့် hash လုပ်ပြီးမှ Supabase မှာထည့်ပါ။
-- INSERT INTO users (email, password, role) VALUES ('admin@example.com', 'hashed_password_here', 'admin');
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
SQL
IGNORE_WHEN_COPYING_END
</details>

၇။ Local Server ကို Run ပါ
Generated bash
uvicorn main:app --reload
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Browser မှာ http://127.0.0.1:8000 ကိုသွားပြီး "🏠 YGN Bot Service" စာတန်းကိုမြင်ရရင် အောင်မြင်ပါတယ်။

Render.com တွင် Deploy ပြုလုပ်ခြင်း

Render မှာ deploy ပြုလုပ်ရန် အလွန်လွယ်ကူပါတယ်။

အဆင့် ၁: New Web Service สร้างပါ

Render Dashboard မှာ "New +" ကိုနှိပ်ပြီး "Web Service" ကိုရွေးပါ။

သင့် GitHub account ကိုချိတ်ဆက်ပြီး ဒီ project repository ကို ရွေးချယ်ပါ။

အဆင့် ၂: Settings များကို ဖြည့်စွက်ပါ

Name: သင့် service အတွက် နာမည်တစ်ခုပေးပါ (ဥပမာ ygn-bot-service)။

Region: သင့်နဲ့အနီးဆုံး region ကိုရွေးပါ။

Branch: main (သို့) သင်အသုံးပြုလိုသော branch ကိုရွေးပါ။

Root Directory: . (そのままထားပါ)

Runtime: Python 3

Build Command: pip install -r requirements.txt

Start Command: gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app

(သို့မဟုတ်) uvicorn main:app --host 0.0.0.0 --port $PORT

အဆင့် ၃: Environment Variables များကို ထည့်သွင်းပါ

"Advanced" ကိုနှိပ်ပြီး "Add Environment Variable" ဖြင့် သင့် .env ဖိုင်ထဲက key တွေအားလုံးကို တစ်ခုချင်းစီ ထည့်သွင်းပါ။

Key: SUPABASE_URL, Value: https://...

Key: SUPABASE_KEY, Value: your-key...

Key: SUPABASE_JWT_SECRET, Value: your-jwt-secret...

Key: VIBER_TOKEN, Value: your-viber-token...

Key: VIBER_WEBHOOK_SECRET, Value: your-secret-string...

Key: ENVIRONMENT, Value: production

အဆင့် ၄: Deploy ပြုလုပ်ပါ

"Create Web Service" ကိုနှိပ်ပြီး deploy process ကိုစောင့်ပါ။

Deploy ပြီးသွားရင် Render က သင့် service အတွက် public URL တစ်ခုပေးပါလိမ့်မယ်။ (ဥပမာ https://ygn-bot-service.onrender.com)

အဆင့် ၅: Viber Webhook ကို Set လုပ်ပါ

သင်၏ Viber Admin Panel ကိုသွားပါ။

"Webhook URL" နေရာမှာ Render ကပေးတဲ့ URL နောက်မှာ /viber-webhook ကိုထည့်ပေးပါ။

ဥပမာ: https://ygn-bot-service.onrender.com/viber-webhook

Event Types တွေအားလုံးကို အမှန်ခြစ်ပေးပြီး Save လုပ်ပါ။

ယခုဆိုလျှင် သင်၏ Viber bot သည် Render server ပေါ်တွင် အလုပ်လုပ်နေပြီဖြစ်ပါသည်။

API Endpoints

GET /: Root endpoint.

GET /docs: FastAPI Swagger UI (API Documentation).

GET /health: Service health check.

POST /viber-webhook: Viber မှ data လက်ခံမည့် အဓိက endpoint။

POST /auth/login: Admin များအတွက် login endpoint။

GET /admin/analytics: Admin များအတွက် analytics data ကြည့်ရန်။

POST /admin/approve-transaction: Admin များအတွက် transaction ကို approve လုပ်ရန်။

GET /admin: Admin panel frontend (static files)။
