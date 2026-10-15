# Hybrid Bot Defense System

VM-based obfuscation + behavioral analysis. MSc CS Cybersecurity research project.

## Architecture

```
Browser ──GET /challenge/js──►  Go server (challenge generator)
                                       │
                                       ▼
                                    Redis (session store, TTL 90s)

Browser ──POST /challenge/verify──►  Go server (validation)
                                       │
                                       ▼
                                 Python ML service (RF classifier)
                                       │
                                       ▼
                   Signed HttpOnly cookie, opaque 403, or 503 (ML down, fail closed)

Browser ──GET /api/data (+ bd_token)──►  BotGuard middleware ──► protected handler
```

## Layout

```
bot-defense/
├── main.go                 Entry point, HTTP router wiring
├── config/                 Env var loader
├── challenge/              Module 2 — per-request VM challenge generation
│   ├── isa.go              Opcode constants, environment IDs
│   ├── bytecode.go         Logical program → byte sequence compiler
│   ├── crypto.go           Session material, RC4, opcode remapping, key splitting
│   ├── obfuscator.go       Name mangling, dead code, string encoding
│   ├── template.go         JavaScript VM runtime template (Go raw string)
│   └── generator.go        Orchestrator: builds the full ChallengePayload
├── validation/             Module 3 — payload validation + ML scoring + cookies
│   ├── features.go         27 engineered features from sensor payload
│   ├── token.go            Server-side recomputation of the per-session token
│   ├── handler.go          POST /challenge/verify handler
│   ├── ml_client.go        HTTP client for Python inference service
│   └── cookie.go           HMAC-SHA256 signed, context-bound bd_token
├── middleware/
│   └── bot_guard.go        Cookie-enforcing middleware for protected routes
├── session/
│   └── store.go            Redis-backed session CRUD (90s TTL, single use)
└── ml/                     Python Flask ML service
    ├── features.py         Shared feature-name truth file
    ├── train_model.py      Trains rf_model.pkl from ml/data/synthetic_bot_dataset.csv
    ├── inference_server.py Flask /predict endpoint
    └── data/               Dataset quality report (the dataset itself is not included)
```

## Build & Run (Local)

1. Train model (once). This needs the training dataset at
   `ml/data/synthetic_bot_dataset.csv`, which is not included in this repository:
   ```bash
   cd ml/
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   python train_model.py
   ```
2. Start ML service:
   ```bash
   python inference_server.py   # listens on 127.0.0.1:5001
   ```
3. Start Redis:
   ```bash
   redis-server                  # or: docker run -d -p 6379:6379 redis:7-alpine
   ```
4. Build & run Go server:
   ```bash
   go mod tidy
   go run .                      # listens on :8080
   ```

## Protecting a page

Serve your page from the same origin as the Go server and load the
challenge script. It runs invisibly, posts its result to
`/challenge/verify`, and on success the browser receives the `bd_token`
cookie required by routes behind `BotGuard`:

```html
<script src="/challenge/js"></script>
<script>
  window.addEventListener('bd-cleared', () => fetch('/api/data'));
  window.addEventListener('bd-blocked', () => { /* access denied */ });
</script>
```

## Docker (All Components)

This project ships with full Docker support for:

- Go app (`app`)
- Python ML inference service (`ml`)
- Redis session store (`redis`)

### Prerequisites

- Docker + Docker Compose plugin
- A `.env` file at project root with at least:
  - `COOKIE_SECRET` (32+ chars)
- A trained model at `ml/rf_model.pkl` (step 1 above). The model is not
  committed; the `ml` container exits with an error if it is missing,
  unless `ML_AUTO_TRAIN_IF_MISSING=true` is set in `docker-compose.yml`.

### Start everything

```bash
docker compose up --build
```

What happens:

- `redis` starts on `localhost:6379`
- `ml` starts on `localhost:5001`
- `app` starts on `localhost:8080` and talks to `redis` + `ml` via internal service DNS.

Check:

- ML health: `http://localhost:5001/health`

### Stop

```bash
docker compose down
```

## Tests

```bash
go test ./...
```
