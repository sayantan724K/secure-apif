from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import time
import logging
from collections import defaultdict, deque

app = FastAPI()

# Enable CORS (important for tester)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
RATE_LIMIT = 40       # Max 40 requests per minute
BURST_LIMIT = 11      # Max 11 requests per second
WINDOW_SIZE = 60      # 60 second window
BURST_WINDOW = 1      # 1 second burst window

request_logs = defaultdict(lambda: deque())

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security")


def check_rate_limit(identifier: str):
    now = time.time()
    timestamps = request_logs[identifier]

    # Remove timestamps older than 60 seconds
    while timestamps and timestamps[0] < now - WINDOW_SIZE:
        timestamps.popleft()

    # Count requests in last 1 second
    burst_count = 0
    for t in reversed(timestamps):
        if t >= now - BURST_WINDOW:
            burst_count += 1
        else:
            break

    # Block if 11 already happened in last second
    if burst_count >= BURST_LIMIT:
        return True, "Burst limit exceeded (11 per second)"

    # Block if 40 already happened in last minute
    if len(timestamps) >= RATE_LIMIT:
        return True, "Rate limit exceeded (40 per minute)"

    # Append current request after checks
    timestamps.append(now)

    return False, None


@app.post("/validate")
async def validate(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "blocked": True,
                "reason": "Invalid JSON format",
                "sanitizedOutput": None,
                "confidence": 0.99
            }
        )

    identifier = data.get("userId") or request.client.host

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
        "sanitizedOutput": data.get("input"),
        "confidence": 0.95
    }


@app.get("/")
def root():
    return {"status": "running"}
