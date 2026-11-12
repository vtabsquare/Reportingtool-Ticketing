"""Isolated Desktop adapter; does not modify the Reporting Studio codebase."""
from __future__ import annotations

import json
import platform
import urllib.request
import webbrowser


def open_ticket_portal(api_base: str, app_version: str, workspace_id: str | None, user_email: str, recent_errors: str = "") -> str:
    payload = json.dumps({
        "app_version": app_version,
        "os_info": {"platform": platform.platform(), "machine": platform.machine()},
        "workspace_id": workspace_id,
        "session_user": user_email,
        "recent_errors": recent_errors[-12000:],
    }).encode()
    request = urllib.request.Request(api_base.rstrip("/") + "/api/diagnostics/session", data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        report_url = json.loads(response.read())["report_url"]
    webbrowser.open(report_url)
    return report_url

