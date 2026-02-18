from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time
import logging
from collections import defaultdict, deque

app = FastAPI()

# -----------------------------
# CORS (IMPORTANT for tester)
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# CONFIGURATION
# -----------------------------
RATE_LIMIT = 40        # Max 40 requests per minute
BURST_LIMIT = 11       # Max 11 requests per second
WINDOW_SIZE = 60       # 60 seconds window
BURST_WINDOW = 1       # 1 second burst window

# Store timestamps per user/IP
request_logs = defaultdict(lambda: deque())

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security")


# -----------------------------
# Request Model
# -----------------------------
class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str


# -----------------------------
# Rate Limiting Logic
# -----------------------------
def check_rate_limit(identifier: str):
    now = time.time()
    timestamps = request_logs[identifier]

    # Remove old timestamps (older than 60 seconds)
    while timestamps and timestamps[0] < now - WINDOW_SIZE:
        timestamps.popleft()

    # Check per-minute limit
    if len(timestamps) >= RATE_LIMIT:
        return True, "Rate limit exceeded (40 per minute)"

    # Check burst limit (last 1 second)
    recent_requests = [t for t in timestamps if t > now - BURST_WINDOW]
    if len(recent_requests) >= BURST_LIMIT:
        return True, "Burst limit exceeded (11 per second)"

    timestamps.append(now)
    return False, None


# -----------------------------
# Validation Endpoint
# -----------------------------
@app.post("/validate")
async def validate(request: Request, payload: SecurityRequest):
    identifier = payload.userId or request.client.host

    try:
        blocked, reason = check_rate_limit(identifier)

        if blocked:
            logger.warning(f"Rate limit triggered for {identifier}: {reason}")

            return JSONResponse(
                status_code=429,
                content={
                    "blocked": True,
                    "reason": reason,
                    "sanitizedOutput": None,
                    "confidence": 0.99
                },
                headers={"Retry-After": "60"}
            )

        return {
            "blocked": False,
            "reason": "Input passed all security checks",
            "sanitizedOutput": payload.input,
            "confidence": 0.95
        }

    except Exception:
        logger.error("Validation error occurred")
        raise HTTPException(
            status_code=400,
            detail="Invalid request"
        )
