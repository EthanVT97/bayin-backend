# YGN Bot Service - Viber Banking Bot

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A production-ready Viber bot service built with FastAPI for handling banking transactions (deposits/withdrawals) with stateful conversation logic, JWT-authenticated admin dashboard, and Supabase integration.

## 🚀 Features

- **Viber Bot Integration**: Stateful conversation flows for deposit/withdrawal operations
- **Admin Dashboard**: JWT-secured admin panel with analytics and transaction approval
- **Database Integration**: Supabase (PostgreSQL) for persistent data storage
- **Security**: Webhook signature verification, JWT authentication, rate limiting
- **Production Ready**: Docker support, health checks, comprehensive logging
- **Multi-language Support**: Myanmar Unicode support for Viber messages

## 🏗️ Architecture

```
├── main.py              # FastAPI application entry
├── routers/            # API route handlers
├── models/             # Database models
├── services/           # Business logic
├── utils/              # Helper functions
├── static/             # Admin dashboard assets
└── templates/          # HTML templates
```

## 🛠️ Tech Stack

- **Backend**: Python 3.8+, FastAPI, Uvicorn
- **Database**: Supabase (PostgreSQL)
- **Authentication**: PyJWT, bcrypt
- **HTTP Client**: HTTPX, Requests
- **Deployment**: Docker, Render.com, Gunicorn

## 📋 Prerequisites

- Python 3.8+
- Supabase account
- Viber Bot Token
- Git

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/EthanVT97/bayin-backend.git
cd bayin-backend
```

### 2. Environment Setup

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Variables

Create `.env` file:

```env
# Supabase Configuration
SUPABASE_URL="https://your-project-ref.supabase.co"
SUPABASE_KEY="your-supabase-anon-key"
SUPABASE_JWT_SECRET="your-supabase-jwt-secret"

# Viber Bot Configuration
VIBER_TOKEN="your-viber-bot-auth-token"
VIBER_WEBHOOK_SECRET="your-webhook-signature-secret"

# Optional: OpenAI Integration
OPENAI_API_KEY="your-openai-api-key"

# Environment
ENVIRONMENT="development"
DEBUG="true"

# Security
JWT_SECRET_KEY="your-jwt-secret-for-admin-auth"
JWT_ALGORITHM="HS256"
JWT_EXPIRE_MINUTES=30
```

### 4. Database Setup

Execute in Supabase SQL Editor:

```sql
-- Users table for Viber bot interactions
CREATE TABLE viber_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    viber_id TEXT NOT NULL UNIQUE,
    name TEXT,
    account_id TEXT UNIQUE,
    state TEXT DEFAULT 'AWAITING_ACCOUNT_ID',
    balance NUMERIC DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Transaction records
CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES viber_users(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN ('deposit', 'withdraw')),
    amount NUMERIC NOT NULL CHECK (amount > 0),
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    description TEXT,
    admin_notes TEXT,
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Admin users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'admin' CHECK (role IN ('admin', 'super_admin')),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMPTZ,
    login_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_viber_users_viber_id ON viber_users(viber_id);
CREATE INDEX idx_transactions_user_id ON transactions(user_id);
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_created_at ON transactions(created_at);

-- Create admin user (replace with hashed password)
-- Use bcrypt to hash password before inserting
-- INSERT INTO users (email, password, role) VALUES 
-- ('admin@ygn-bot.com', '$2b$12$hashedpasswordhere', 'super_admin');
```

### 5. Create Admin User

```python
# create_admin.py
import bcrypt
from supabase import create_client

# Hash password
password = "your_secure_password"
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Insert to Supabase
supabase = create_client("your_url", "your_key")
result = supabase.table("users").insert({
    "email": "admin@ygn-bot.com",
    "password": hashed,
    "role": "super_admin"
}).execute()

print("Admin user created successfully!")
```

### 6. Run Development Server

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Visit:
- **API**: http://localhost:8000
- **Docs**: http://localhost:8000/docs
- **Admin**: http://localhost:8000/admin

## 🐳 Docker Deployment

### Build & Run

```bash
# Build image
docker build -t ygn-bot-service .

# Run container
docker run -p 8000:8000 --env-file .env ygn-bot-service
```

### Docker Compose

```yaml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8000"
    env_file:
      - .env
    environment:
      - ENVIRONMENT=production
    restart: unless-stopped
```

## ☁️ Production Deployment

### Render.com (Recommended)

1. **Create New Web Service**
   - Connect GitHub repository
   - Select `main` branch

2. **Configure Build**
   ```
   Build Command: pip install -r requirements.txt
   Start Command: gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT
   ```

3. **Set Environment Variables**
   - Add all variables from `.env`
   - Set `ENVIRONMENT=production`

4. **Configure Viber Webhook**
   ```
   Webhook URL: https://your-app.onrender.com/viber-webhook
   ```

### Alternative Platforms

<details>
<summary>Railway</summary>

```yaml
# railway.json
{
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT",
    "restartPolicyType": "ON_FAILURE"
  }
}
```
</details>

<details>
<summary>Vercel</summary>

```json
// vercel.json
{
  "builds": [
    {
      "src": "main.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "main.py"
    }
  ]
}
```
</details>

## 🔌 API Reference

### Bot Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Service status |
| `GET` | `/health` | Health check |
| `POST` | `/viber-webhook` | Viber webhook handler |

### Admin Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/auth/login` | Admin login | ❌ |
| `GET` | `/admin/analytics` | Dashboard analytics | ✅ |
| `POST` | `/admin/approve-transaction` | Approve transaction | ✅ |
| `GET` | `/admin/transactions` | List transactions | ✅ |
| `PUT` | `/admin/transaction/{id}` | Update transaction | ✅ |

### Authentication

```bash
# Login
curl -X POST "https://your-app.com/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "password"}'

# Use token
curl -X GET "https://your-app.com/admin/analytics" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🔒 Security Features

- **Webhook Signature Verification**: Validates Viber requests
- **JWT Authentication**: Secure admin access
- **Rate Limiting**: Prevents abuse
- **CORS Protection**: Configurable origins
- **Input Validation**: Pydantic models
- **SQL Injection Prevention**: Parameterized queries

## 🧪 Testing

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest tests/

# With coverage
pytest --cov=app tests/
```

## 📊 Monitoring

### Health Check

```bash
curl https://your-app.com/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "database": "connected"
}
```

### Logs

```bash
# View application logs
tail -f logs/app.log

# Docker logs
docker logs -f container_name
```

## 🤝 Contributing

1. **Fork** the repository
2. **Create** feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** changes: `git commit -m 'Add amazing feature'`
4. **Push** to branch: `git push origin feature/amazing-feature`
5. **Open** Pull Request

### Development Setup

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run linting
black .
flake8 .
isort .
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/EthanVT97/bayin-backend/issues)
- **Discussions**: [GitHub Discussions](https://github.com/EthanVT97/bayin-backend/discussions)
- **Email**: support@ygn-bot.com

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [Supabase](https://supabase.com/) - Open source Firebase alternative
- [Viber](https://developers.viber.com/) - Messaging platform API

---

**Built with ❤️ in Myanmar** 🇲🇲
