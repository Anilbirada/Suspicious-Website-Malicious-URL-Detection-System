# Setup and Deployment Guide

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Version**: 1.0.0  

---

## 1. System Requirements

- **Python**: `3.11` or `3.12`
- **Node.js**: `18.x` or newer (`npm 9+`)
- **Operating System**: Windows, Linux, or macOS

---

## 2. Local Development Setup

### Step 1: Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### Step 2: Install Python Backend Dependencies
```bash
python -m pip install -r backend/requirements.txt
```

### Step 3: Run the ML Training & Evaluation Pipeline
Generate/verify the benchmark dataset, data quality report, held-out evaluation report, and calibrated `.joblib` model artefact:
```bash
python ml/scripts/train_and_evaluate.py
```

### Step 4: Run Backend Automated Tests
```bash
python -m pytest backend/tests -v
```

### Step 5: Start the FastAPI Backend Server
```bash
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

### Step 6: Install, Test, and Start the React Frontend
```bash
cd frontend
npm install
npm run test
npm run dev
```
*(On Windows PowerShell with script execution policies disabled, use `npm.cmd install`, `npm.cmd run test`, and `npm.cmd run dev`.)*

---

## 3. Production Build & Deployment Considerations

1. **Frontend Production Build**:
   ```bash
   cd frontend
   npm run build
   ```
   This compiles TypeScript (`tsc -b`) and bundles static assets into `frontend/dist/`.
2. **Environment Separation**:
   - Set `APP_ENV="production"` in `.env`.
   - Restrict `CORS_ORIGINS` to the exact production frontend origin.
   - Set `ENABLE_HISTORY=false` or `STORE_RAW_URL_IN_HISTORY=false` for shared multi-user deployments where URL query privacy is required.
   - Use PostgreSQL via `DATABASE_URL` if persistent shared storage is desired.
3. **Reverse Proxy**: Run `uvicorn` behind a TLS-terminating reverse proxy (e.g., Nginx or Caddy) with request body size limits enabled.
