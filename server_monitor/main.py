"""FastAPI application entrypoint (placeholder endpoints, full API in #3)."""

from fastapi import FastAPI

app = FastAPI(title="server-monitor")


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "server-monitor placeholder"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
