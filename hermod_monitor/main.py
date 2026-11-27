"""FastAPI application entrypoint (placeholder endpoints, full API in #3)."""

from fastapi import FastAPI

app = FastAPI(title="hermod-monitor")


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "hermod-monitor placeholder"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
