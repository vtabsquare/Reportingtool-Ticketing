from __future__ import annotations

import importlib.util
import subprocess
import sys
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def ensure_dependencies() -> None:
    missing = [name for name in ("fastapi", "uvicorn", "multipart") if importlib.util.find_spec(name) is None]
    if not missing:
        return
    print("Installing VTAB Ticket Center dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")])


def main() -> None:
    ensure_dependencies()
    from app.config import settings
    import uvicorn

    url = f"http://{settings.host}:{settings.port}"
    print("VTAB Ticket Center")
    print(f"Open: {url}")
    print(f"Environment: {settings.environment}")
    print(f"Storage: {settings.database_path}")
    webbrowser.open(url)
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, app_dir=str(ROOT))


if __name__ == "__main__":
    main()

