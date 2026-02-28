"""FastAPI application setup."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from crypto_lab import __version__
from crypto_lab.web.routers import algorithms, encrypt, decrypt

# Load cipher modules so they register
import crypto_lab.classical  # noqa: F401
import crypto_lab.modern  # noqa: F401

app = FastAPI(
    title="Crypto Lab",
    description="Educational & Modern Cryptography Playground",
    version=__version__,
)

app.include_router(algorithms.router)
app.include_router(encrypt.router)
app.include_router(decrypt.router)

# Static assets
WEB_ROOT = Path(__file__).resolve().parent
static_dir = WEB_ROOT / "static"
if static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
def index():
    """Serve the playground single-page app."""
    index_path = WEB_ROOT / "templates" / "index.html"
    if index_path.is_file():
        return FileResponse(index_path)
    return {"message": "Crypto Lab API", "docs": "/docs"}
