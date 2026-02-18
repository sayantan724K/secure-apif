from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import time
import logging
from collections import defaultdict, deque

app = FastAPI()

RATE_LIMIT = 40
BURST_LIMIT = 11
WINDOW_SIZE = 60
BURST_WINDOW = 1

request_logs = defaultdict(lambda: deque())

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security")

class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str


def check_rate_limit(identifier: str):
    now = time.time()
    timestamps = request_logs[identifier]

    # Remove requests older than 60 seconds
    while timestamps and timestamps[0] < now - WINDOW_SIZE:
        timestamps.popleft()

    # Per-minute limit
    if len(timestamps) >= RATE_LIMIT:
        return True, "Rate limit exceeded (40 per minute)"

    # Burst limit (within 1 second)
    recent = [t for t in timestamps if t > now - BURST_WINDOW]
    if len(recent) >= BURST_LIMIT:
        return True, "Burst limit exceeded (11 per second)"

    timestamps.append(now)
    return False, None


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
        raise HTTPException(status_code=400, detail="Invalid request")
